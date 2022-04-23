use super::*;
use crate::elf::*;
use crate::os::udbg::{EventHandler, HandleResult};
use crate::range::RangeValue;

use anyhow::Context;
use goblin::elf::sym::Sym;
use nix::sys::ptrace::Options;
use nix::sys::wait::waitpid;
use parking_lot::RwLock;
use procfs::process::{Stat as ThreadStat, Task};
use serde_value::Value;
use std::cell::{Cell, UnsafeCell};
use std::collections::HashSet;
use std::mem::transmute;
use std::ops::Deref;
use std::time::{Duration, Instant};

const TRAP_BRKPT: i32 = 1;
const TRAP_TRACE: i32 = 2;
const TRAP_BRANCH: i32 = 3;
const TRAP_HWBKPT: i32 = 4;
const TRAP_UNK: i32 = 5;

cfg_if! {
    if #[cfg(target_os = "android")] {
        const PTRACE_INTERRUPT: c_uint = 0x4207;
        const PTRACE_SEIZE: c_uint = 0x4206;
    }
}

pub struct ElfSymbol {
    pub sym: Sym,
    pub name: Arc<str>,
}

impl Deref for ElfSymbol {
    type Target = Sym;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.sym
    }
}

impl From<ElfSym<'_>> for ElfSymbol {
    fn from(s: ElfSym<'_>) -> Self {
        ElfSymbol {
            sym: s.sym,
            name: s.name.into(),
        }
    }
}

#[derive(Deref)]
pub struct NixThread {
    #[deref]
    base: ThreadData,
    stat: ThreadStat,
}

impl TryFrom<Task> for NixThread {
    type Error = procfs::ProcError;

    fn try_from(task: Task) -> Result<Self, Self::Error> {
        Ok(NixThread {
            base: ThreadData {
                tid: task.tid,
                wow64: false,
            },
            stat: task.stat()?,
        })
    }
}

impl GetProp for NixThread {}

impl UDbgThread for NixThread {
    fn name(&self) -> Arc<str> {
        self.stat.comm.as_str().into()
    }
    fn status(&self) -> Arc<str> {
        self.stat.state.to_string().into()
    }
    fn priority(&self) -> Option<i64> {
        Some(self.stat.priority)
    }
}

#[inline(always)]
fn to_symbol(s: ElfSym) -> Symbol {
    let flags = if s.is_function() {
        SymbolFlags::FUNCTION
    } else {
        SymbolFlags::NONE
    };
    Symbol {
        offset: s.st_value as u32,
        name: s.name.into(),
        flags: flags.bits(),
        len: s.st_size as u32,
        type_id: 0,
    }
}

impl SymbolsData {
    fn from_elf(path: &str) -> Self {
        let mut this = Self::default();
        this.load(path);
        this
    }

    fn load(&mut self, path: &str) -> Result<(), String> {
        let map = Utils::mapfile(path.as_ref()).ok_or("map failed")?;
        let e = ElfHelper::parse(&map).ok_or("parse failed")?;
        let mut push_symbol = |s: ElfSym| {
            if s.name.starts_with("$x.") {
                return;
            }
            self.exports
                .entry(s.offset())
                .or_insert_with(|| to_symbol(s));
        };
        e.enum_symbol().for_each(&mut push_symbol);
        e.enum_export().for_each(&mut push_symbol);
        Ok(())
    }
}

struct TimeCheck {
    last: Cell<Instant>,
    pub duration: Cell<Duration>,
}

impl TimeCheck {
    pub fn new(duration: Duration) -> Self {
        Self {
            last: Instant::now().checked_sub(duration).unwrap().into(),
            duration: duration.into(),
        }
    }

    pub fn check(&self, mut callback: impl FnMut()) {
        if self.last.get().elapsed() > self.duration.get() {
            callback();
            self.last.set(Instant::now());
        }
    }
}

#[derive(Deref)]
pub struct CommonAdaptor {
    #[deref]
    _base: CommonBase,
    pub threads: RwLock<HashSet<tid_t>>,
    tc_module: TimeCheck,
    tc_memory: TimeCheck,
    mem_pages: RwLock<Vec<MemoryPage>>,
    waiting: Cell<bool>,
    pub trace_opts: Options,
    pub hwbps: UnsafeCell<user_hwdebug_state>,
}

impl CommonAdaptor {
    pub fn new(ps: Process) -> Self {
        const TIMEOUT: Duration = Duration::from_secs(5);

        let mut base = CommonBase::new(ps);
        let image_path = base.process.image_path().unwrap_or_default();
        base.process
            .enum_module()
            .ok()
            .and_then(|mut iter| iter.find(|m| m.path.as_ref() == &image_path))
            .map(|m| base.image_base = m.base);

        let trace_opts = Options::PTRACE_O_EXITKILL
            | Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACEFORK;
        Self {
            _base: base,
            tc_module: TimeCheck::new(Duration::from_secs(10)),
            tc_memory: TimeCheck::new(Duration::from_secs(10)),
            mem_pages: RwLock::new(Vec::new()),
            threads: RwLock::new(HashSet::new()),
            trace_opts,
            waiting: Cell::new(false),
            hwbps: unsafe { core::mem::zeroed() },
        }
    }

    pub fn update_memory_page(&self) -> IoResult<()> {
        *self.mem_pages.write() = self.process.enum_memory()?.collect::<Vec<_>>();
        Ok(())
    }

    fn update_memory_page_check_time(&self) {
        self.tc_memory.check(|| {
            self.update_memory_page();
        });
    }

    // fn update_thread(&self) {
    //     let ts = unsafe { mutable(&self.threads) };
    //     let mut maps: HashSet<pid_t> = HashSet::new();
    //     for tid in process_tasks(self.pid) {
    //         if !ts.contains(&tid) {
    //             self.dbg.map(|d| d.thread_create(tid as u32));
    //         }
    //         maps.insert(tid);
    //     }
    //     *ts = maps;
    // }

    fn module_name<'a>(&self, name: &'a str) -> &'a str {
        let tv = trim_ver(name);
        let te = trim_allext(name);
        let base = self.symgr.base.read();
        if tv.len() < te.len() && !base.contains(tv) {
            return tv;
        }
        if !base.contains(te) {
            return te;
        }
        let te = trim_lastext(name);
        if !base.contains(te) {
            return te;
        }
        name
    }

    pub fn update_module(&self) -> IoResult<()> {
        use goblin::elf::header::header32::Header as Header32;
        use goblin::elf::header::header64::Header as Header64;
        use std::io::Read;

        // self.md.write().clear();
        for m in self.process.enum_module()? {
            if self.find_module(m.base).is_some()
                || m.name.ends_with(".oat")
                || m.name.ends_with(".apk")
            {
                continue;
            }
            let name = self.module_name(&m.name);

            // TODO: use memory data
            let mut f = match File::open(m.path.as_ref()) {
                Ok(f) => f,
                Err(_) => {
                    error!("open module file: {}", m.path);
                    continue;
                }
            };
            let mut buf: Header64 = unsafe { std::mem::zeroed() };
            if f.read_exact(buf.as_mut_byte_array()).is_err() {
                error!("read file: {}", m.path);
                continue;
            }

            let arch = match ElfHelper::arch_name(buf.e_machine) {
                Some(a) => a,
                None => {
                    error!("error e_machine: {} {}", buf.e_machine, m.path);
                    continue;
                }
            };

            let entry = match arch {
                "arm64" | "x86_64" => buf.e_entry as usize,
                "x86" | "arm" => unsafe { transmute::<_, &Header32>(&buf).e_entry as usize },
                a => {
                    error!("error arch: {}", a);
                    continue;
                }
            };

            let base = m.base;
            let path = m.path.clone();
            self.symgr.base.write().add(Module {
                data: ModuleData {
                    base,
                    size: m.size,
                    arch,
                    entry,
                    user_module: false.into(),
                    name: name.into(),
                    path: path.clone(),
                },
                loaded: false.into(),
                syms: SymbolsData::from_elf(&path).into(),
            });
            // TODO:
            // self.base.module_load(&path, base);
        }
        Ok(())
    }

    fn wait_event(&self, tb: &mut TraceBuf) -> Option<WaitStatus> {
        self.waiting.set(true);
        let mut status = 0;
        let tid = unsafe { libc::waitpid(-1, &mut status, __WALL | WUNTRACED) };
        // let status = ::nix::sys::wait::waitpid(None, WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD | WaitPidFlag::WNOHANG).unwrap();
        self.waiting.set(false);
        self.base.event_tid.set(tid);

        if tid <= 0 {
            return None;
        }

        let status = WaitStatus::from_raw(Pid::from_raw(tid), status).unwrap();
        println!("[status] {status:?}");
        Some(status)
    }

    pub fn hwbps(&self) -> &mut user_hwdebug_state {
        unsafe { self.hwbps.get().as_mut().unwrap() }
    }

    pub fn get_bp_(&self, id: BpID) -> Option<Arc<Breakpoint>> {
        Some(self.bp_map.read().get(&id)?.clone())
    }

    pub fn handle_breakpoint(
        &self,
        this: &dyn UDbgTarget,
        eh: &mut dyn EventHandler,
        tb: &mut TraceBuf,
    ) -> UDbgResult<HandleResult> {
        // correct the pc register
        let mut address = *tb.user.regs.ip();
        let is_step = tb.si.si_code == TRAP_TRACE;
        if IS_X86 && tb.si.si_signo == SIGTRAP {
            if is_step || tb.si.si_code == TRAP_HWBKPT {
                address = unsafe { tb.si.si_addr() as _ };
            } else {
                address -= 1;
            }
        }
        *tb.user.regs.ip() = address;

        let tid = self.base.event_tid.get();
        let bp = match self
            .get_bp_(address as _)
            .or_else(|| self.get_hwbp(tb))
            .ok_or(UDbgError::NotFound)
        {
            Ok(bp) => bp,
            Err(_) if is_step => {
                tb.user.set_step(false);
                self.handle_reply(this, tb.call(UEvent::Step), &mut tb.user);
                return Ok(None);
            }
            Err(err) => return Err(err),
        };

        bp.hit_count.set(bp.hit_count.get() + 1);
        if bp.temp.get() {
            self.remove_breakpoint(this, &bp);
        }

        // handle by user
        let hitted = bp.hit_tid.map(|t| t == tid).unwrap_or(true);
        if hitted {
            self.handle_reply(this, tb.call(UEvent::Breakpoint(bp.clone())), &mut tb.user);
        }

        let id = bp.get_id();

        #[cfg(target_arch = "x86_64")]
        if bp.is_hard() && self.get_bp(id).is_some() {
            tb.user.disable_hwbp_temporarily();
        }

        // int3 breakpoint revert
        if bp.is_soft() && self.get_bp(id).is_some() {
            // if bp is not deleted by user during the interruption
            if bp.enabled.get() {
                // disabled temporarily, in order to be able to continue
                self.enable_breadpoint(this, &bp, false)
                    .log_error("disable bp");
                assert_ne!(&this.read_value::<BpInsn>(bp.address()).unwrap(), BP_INSN);

                let user_step = tb.user.is_step();

                // step once and revert
                tb.user.set_step(true);
                loop {
                    eh.cont(None, tb);
                    match eh.fetch(tb) {
                        Some(_) => {
                            if core::ptr::eq(self, &tb.target.0) && self.base.event_tid.get() == tid
                            {
                                break;
                            } else if let Some(s) = eh.handle(tb) {
                                eh.cont(s, tb);
                            } else {
                                return Ok(None);
                            }
                        }
                        None => return Ok(None),
                    }
                }

                self.enable_breadpoint(this, &bp, true)
                    .log_error("enable bp");
                return if user_step {
                    Ok(eh.handle(tb).unwrap_or(None))
                } else {
                    tb.user.set_step(false);
                    // tb.regs_dirty = false;
                    Ok(None)
                };
            }
        }

        Ok(None)
    }

    fn enum_module<'a>(
        &'a self,
    ) -> UDbgResult<Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a>> {
        self.update_module();
        Ok(self.symgr.enum_module())
    }

    fn enum_memory<'a>(&'a self) -> Result<Box<dyn Iterator<Item = MemoryPage> + 'a>, UDbgError> {
        self.update_memory_page();
        Ok(Box::new(self.mem_pages.read().clone().into_iter()))
    }

    fn get_memory_map(&self) -> Vec<MemoryPageInfo> {
        self.enum_memory()
            .unwrap()
            .map(|m| {
                let mut flags = 0u32;
                if m.usage.as_ref() == "[heap]" {
                    flags |= MF_HEAP;
                }
                if m.usage.as_ref() == "[stack]" {
                    flags |= MF_STACK;
                }
                MemoryPageInfo {
                    base: m.base,
                    size: m.size,
                    flags,
                    type_: m.type_str().into(),
                    protect: m.protect().into(),
                    usage: m.usage.clone(),
                }
            })
            .collect::<Vec<_>>()
    }

    fn enum_handle<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = HandleInfo> + 'a>> {
        use std::os::unix::fs::FileTypeExt;

        let pid = self.process.pid;
        Ok(Box::new(
            PidIter::proc_fd(pid)?
                .filter_map(move |id| {
                    Some((id, read_link(format!("/proc/{}/fd/{}", pid, id)).ok()?))
                })
                .map(|(id, path)| {
                    let ps = &path.to_string_lossy();
                    let ts = path
                        .metadata()
                        .map(|m| {
                            let ft = m.file_type();
                            if ft.is_fifo() {
                                "FIFO"
                            } else if ft.is_socket() {
                                "Socket"
                            } else if ft.is_block_device() {
                                "Block"
                            } else {
                                "File"
                            }
                        })
                        .unwrap_or_else(|_| {
                            if ps.starts_with("socket:") {
                                "Socket"
                            } else if ps.starts_with("pipe:") {
                                "Pipe"
                            } else {
                                ""
                            }
                        });
                    HandleInfo {
                        ty: 0,
                        handle: id as _,
                        type_name: ts.to_string(),
                        name: ps.to_string(),
                    }
                }),
        ))
    }

    pub fn enable_hwbp(
        &self,
        dbg: &dyn UDbgTarget,
        bp: &Breakpoint,
        info: HwbpInfo,
        enable: bool,
    ) -> UDbgResult<bool> {
        let mut result = Ok(enable);
        // Set Context for each thread
        for &tid in self.threads.read().iter() {
            if bp.hit_tid.is_some() && bp.hit_tid != Some(tid) {
                continue;
            }
            // Set Debug Register
            result = self.enable_hwbp_for_thread(tid, bp, info, enable);
            if let Err(e) = &result {
                udbg_ui().error(format!("enable_hwbp_for_thread for {} failed {:?}", tid, e));
                // break;
            }
        }
        // TODO: Set Context for current thread, update eflags from user

        if result.is_ok() {
            bp.enabled.set(enable);
        }
        result
    }

    // #[cfg(target_arch = "x86_64")]
    // fn get_reg(&self, reg: &str, r: Option<&mut Registers>) -> Result<CpuReg, UDbgError> {
    //     let regs = self.regs();
    //     if let Some(r) = r {
    //         r.rax = regs.rax;
    //         r.rbx = regs.rbx;
    //         r.rcx = regs.rcx;
    //         r.rdx = regs.rdx;
    //         r.rbp = regs.rbp;
    //         r.rsp = regs.rsp;
    //         r.rsi = regs.rsi;
    //         r.rdi = regs.rdi;
    //         r.r8 = regs.r8;
    //         r.r9 = regs.r9;
    //         r.r10 = regs.r10;
    //         r.r11 = regs.r11;
    //         r.r12 = regs.r12;
    //         r.r13 = regs.r13;
    //         r.r14 = regs.r14;
    //         r.r15 = regs.r15;
    //         r.rip = regs.rip;
    //         r.rflags = regs.eflags as reg_t;
    //         Ok(0.into())
    //     } else {
    //         Ok(CpuReg::Int(match reg {
    //             "rax" => regs.rax,
    //             "rbx" => regs.rbx,
    //             "rcx" => regs.rcx,
    //             "rdx" => regs.rdx,
    //             "rbp" => regs.rbp,
    //             "rsp" | "_sp" => regs.rsp,
    //             "rsi" => regs.rsi,
    //             "rdi" => regs.rdi,
    //             "r8" => regs.r8,
    //             "r9" => regs.r9,
    //             "r10" => regs.r10,
    //             "r11" => regs.r11,
    //             "r12" => regs.r12,
    //             "r13" => regs.r13,
    //             "r14" => regs.r14,
    //             "r15" => regs.r15,
    //             "rip" | "_pc" => regs.rip,
    //             "rflags" => regs.eflags as reg_t,
    //             _ => return Err(UDbgError::InvalidRegister),
    //         } as usize))
    //     }
    // }

    // #[cfg(target_arch = "arm")]
    // fn get_reg(&self, reg: &str, r: Option<&mut Registers>) -> Result<CpuReg, UDbgError> {
    //     let regs = self.regs();
    //     if let Some(r) = r {
    //         *r = unsafe { transmute(*regs) };
    //         Ok(CpuReg::Int(0))
    //     } else {
    //         Ok(CpuReg::Int(match reg {
    //             "r0" => regs.regs[0],
    //             "r1" => regs.regs[1],
    //             "r2" => regs.regs[2],
    //             "r3" => regs.regs[3],
    //             "r4" => regs.regs[4],
    //             "r5" => regs.regs[5],
    //             "r6" => regs.regs[6],
    //             "r7" => regs.regs[7],
    //             "r8" => regs.regs[8],
    //             "r9" => regs.regs[9],
    //             "r10" => regs.regs[10],
    //             "r11" => regs.regs[11],
    //             "r12" => regs.regs[12],
    //             "_sp" | "r13" => regs.regs[13],
    //             "r14" => regs.regs[14],
    //             "_pc" | "r15" => regs.regs[15],
    //             "r16" => regs.regs[16],
    //             "r17" => regs.regs[17],
    //             _ => return Err(UDbgError::InvalidRegister),
    //         } as usize))
    //     }
    // }

    // #[cfg(target_arch = "aarch64")]
    // fn get_reg(&self, reg: &str, r: Option<&mut Registers>) -> Result<CpuReg, UDbgError> {
    //     let regs = self.regs();
    //     if let Some(r) = r {
    //         *r = unsafe { transmute(*regs) };
    //         Ok(CpuReg::Int(0))
    //     } else {
    //         Ok(CpuReg::Int(match reg {
    //             "pc" | "_pc" => regs.pc,
    //             "sp" | "_sp" => regs.sp,
    //             "pstate" => regs.pstate,
    //             "x0" => regs.regs[0],
    //             "x1" => regs.regs[1],
    //             "x2" => regs.regs[2],
    //             "x3" => regs.regs[3],
    //             "x4" => regs.regs[4],
    //             "x5" => regs.regs[5],
    //             "x6" => regs.regs[6],
    //             "x7" => regs.regs[7],
    //             "x8" => regs.regs[8],
    //             "x9" => regs.regs[9],
    //             "x10" => regs.regs[10],
    //             "x11" => regs.regs[11],
    //             "x12" => regs.regs[12],
    //             "x13" => regs.regs[13],
    //             "x14" => regs.regs[14],
    //             "x15" => regs.regs[15],
    //             "x16" => regs.regs[16],
    //             "x17" => regs.regs[17],
    //             "x18" => regs.regs[18],
    //             "x19" => regs.regs[19],
    //             "x20" => regs.regs[20],
    //             "x21" => regs.regs[21],
    //             "x22" => regs.regs[22],
    //             "x23" => regs.regs[23],
    //             "x24" => regs.regs[24],
    //             "x25" => regs.regs[25],
    //             "x26" => regs.regs[26],
    //             "x27" => regs.regs[27],
    //             "x28" => regs.regs[28],
    //             "x29" => regs.regs[29],
    //             "x30" => regs.regs[30],
    //             _ => return Err(UDbgError::InvalidRegister),
    //         } as usize))
    //     }
    // }
}

fn trim_ver(name: &str) -> &str {
    use regex::Regex;
    &name[..Regex::new(r"-\d")
        .unwrap()
        .find(name)
        .map(|p| p.start())
        .unwrap_or(name.len())]
}

#[inline]
fn trim_allext(name: &str) -> &str {
    &name[..name.find(|c| c == '.').unwrap_or(name.len())]
}

#[inline]
fn trim_lastext(name: &str) -> &str {
    &name[..name.rfind(|c| c == '.').unwrap_or(name.len())]
}

pub fn ptrace_interrupt(tid: tid_t) -> bool {
    unsafe { ptrace(PTRACE_INTERRUPT as _, tid, 0, 0) == 0 }
}

pub fn ptrace_seize(tid: tid_t, flags: c_int) -> bool {
    unsafe { ptrace(PTRACE_SEIZE as _, tid, 0, flags) == 0 }
}

pub fn ptrace_getevtmsg<T: Copy>(tid: tid_t, result: &mut T) -> bool {
    unsafe { ptrace(PTRACE_GETEVENTMSG, tid, 0, result) == 0 }
}

pub fn ptrace_step_and_wait(tid: pid_t) -> bool {
    let tid = Pid::from_raw(tid);
    ptrace::step(tid, None);
    match waitpid(tid, None) {
        Ok(t) => {
            let pid = t.pid();
            if pid == Some(tid) {
                return true;
            }
            udbg_ui().error(format!("step unexpect tid: {pid:?}"));
            false
        }
        Err(_) => false,
    }
}

#[derive(Deref)]
pub struct StandardAdaptor(pub CommonAdaptor);

unsafe impl Send for StandardAdaptor {}
unsafe impl Sync for StandardAdaptor {}

impl StandardAdaptor {
    pub fn open(pid: pid_t) -> UDbgResult<Arc<Self>> {
        let ps = Process::from_pid(pid)?;
        Ok(Arc::new(Self(CommonAdaptor::new(ps))))
    }

    pub fn insert_thread(&self, tid: tid_t) -> bool {
        if self.threads.write().insert(tid) {
            if let Err(err) = ptrace::setoptions(Pid::from_raw(tid), self.trace_opts) {
                udbg_ui().error(format!("ptrace_setopt {tid} {err:?}",));
            }
            true
        } else {
            false
        }
    }

    pub fn remove_thread(&self, tid: tid_t, s: i32, tb: &mut TraceBuf) {
        let mut threads = self.threads.write();
        if threads.remove(&tid) {
            tb.call(UEvent::ThreadExit(s as u32));
            if threads.is_empty() {
                tb.call(UEvent::ProcessExit(s as u32));
            }
        } else {
            udbg_ui().error(&format!("tid {tid} not found"));
        }
    }
}

impl WriteMemory for StandardAdaptor {
    fn write_memory(&self, addr: usize, data: &[u8]) -> Option<usize> {
        self.process.write_memory(addr, data)
        // ptrace_write(self.pid.get(), addr, data);
        // Some(data.len())
    }
}

impl TargetMemory for StandardAdaptor {
    fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        self.0.enum_memory()
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        self.update_memory_page_check_time();
        RangeValue::binary_search(&self.mem_pages.read().as_slice(), address).map(|r| r.clone())
    }

    fn collect_memory_info(&self) -> Vec<MemoryPageInfo> {
        self.0.get_memory_map()
    }
}

impl GetProp for StandardAdaptor {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        // match key {
        //     "moduleTimeout" => { self.tc_module.duration.set(Duration::from_secs_f64(s.args(3))); }
        //     "memoryTimeout" => { self.tc_memory.duration.set(Duration::from_secs_f64(s.args(3))); }
        //     _ => {}
        // }
        Ok(Value::Unit)
    }
}

impl TargetControl for StandardAdaptor {
    fn detach(&self) -> UDbgResult<()> {
        self.base.status.set(UDbgStatus::Detaching);
        if self.waiting.get() {
            self.breakk()
        } else {
            // self.base.reply(UserReply::Run);
            Ok(())
        }
    }

    fn kill(&self) -> UDbgResult<()> {
        if unsafe { kill(self.process.pid, SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(UDbgError::system())
        }
    }

    fn breakk(&self) -> UDbgResult<()> {
        self.base.check_attached()?;
        // for tid in self.enum_thread()? {
        //     if ptrace_interrupt(tid) {
        //         return Ok(());
        //     } else {
        //         println!("ptrace_interrupt({tid}) failed");
        //     }
        // }
        // return Err(UDbgError::system());
        match unsafe { kill(self.process.pid, SIGSTOP) } {
            0 => Ok(()),
            code => Err(UDbgError::system()),
        }
    }
}

// impl TargetSymbol for StandardAdaptor {
// }

impl Target for StandardAdaptor {
    fn base(&self) -> &TargetBase {
        &self._base
    }

    fn process(&self) -> Option<&Process> {
        Some(&self.process)
    }

    fn enum_module<'a>(
        &'a self,
    ) -> UDbgResult<Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a>> {
        self.0.enum_module()
    }

    fn find_module(&self, module: usize) -> Option<Arc<dyn UDbgModule>> {
        let mut result = self.symgr.find_module(module);
        self.tc_module.check(|| {
            self.update_module();
            result = self.symgr.find_module(module);
        });
        Some(result?)
    }

    fn get_module(&self, module: &str) -> Option<Arc<dyn UDbgModule>> {
        Some(self.symgr.get_module(module).or_else(|| {
            self.0.update_module();
            self.symgr.get_module(module)
        })?)
    }

    fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<dyn UDbgThread>> {
        let task = Task::new(self.process.pid, tid).context("task")?;
        Ok(Box::new(NixThread {
            base: ThreadData { tid, wow64: false },
            stat: task.stat().context("stat")?,
        }))
    }

    fn enum_handle<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = HandleInfo> + 'a>> {
        self.0.enum_handle()
    }

    fn enum_thread(
        &self,
        detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>> {
        Ok(Box::new(
            self.process
                .tasks()?
                .filter_map(Result::ok)
                .filter_map(|task| {
                    Some(Box::new(NixThread::try_from(task).log_error("task stat")?)
                        as Box<dyn UDbgThread>)
                }),
        ))
    }
}

impl UDbgTarget for StandardAdaptor {}

impl EventHandler for DefaultEngine {
    fn fetch(&mut self, buf: &mut TraceBuf) -> Option<()> {
        loop {
            self.status = waitpid(None, Some(WaitPidFlag::__WALL)).ok()?;
            // info!("[status] {:?}", self.status);
            self.tid = self
                .status
                .pid()
                .map(|p| p.as_raw() as tid_t)
                .unwrap_or_default();

            if matches!(
                self.status,
                WaitStatus::Stopped(_, _) //  | WaitStatus::Signaled(_, _, _)
            ) {
                buf.update_regs(self.tid);
                buf.update_siginfo(self.tid);
                // info!(
                //     "si: {:?}, address: {:p}, ip: {:x}",
                //     buf.si,
                //     unsafe { buf.si.si_addr() },
                //     *crate::register::AbstractRegs::ip(&mut buf.user)
                // );
            }

            let target = self
                .targets
                .iter()
                .find(|&t| self.tid == t.pid() as tid_t || t.threads.read().contains(&self.tid))
                .cloned()
                .or_else(|| {
                    self.targets
                        .iter()
                        .find(|&t| procfs::process::Task::new(t.process.pid, self.tid).is_ok())
                        .cloned()
                });

            if let Some(target) = target {
                buf.target = target.clone();
                buf.target.base.event_tid.set(self.tid as _);

                if target.base.status.get() == UDbgStatus::Detaching {
                    break;
                }

                let mut cont = false;
                if target.base.status.get() < UDbgStatus::Attached {
                    target.base.status.set(UDbgStatus::Attached);
                    // buf.call(UEvent::ProcessCreate);
                    cont = true;
                }

                // set trace options for new thread
                if buf.target.insert_thread(self.tid) {
                    buf.call(UEvent::ThreadCreate(self.tid));
                    cont = true;
                }

                if cont {
                    ptrace::cont(Pid::from_raw(self.tid), None);
                    continue;
                }

                break;
            } else {
                udbg_ui().warn(format!("{} is not traced", self.tid));
                ptrace::cont(Pid::from_raw(self.tid), None);
            }
        }
        Some(())
    }

    fn handle(&mut self, buf: &mut TraceBuf) -> Option<HandleResult> {
        let status = self.status.clone();
        let this = buf.target.clone();
        let tid = self.tid;

        if this.base.status.get() == UDbgStatus::Detaching {
            return Some(None);
        }
        Some(match status {
            WaitStatus::Stopped(_, sig) => loop {
                if sig == Signal::SIGTRAP {
                    if let Some(result) = this
                        .handle_breakpoint(this.as_ref(), self, buf)
                        .log_error("handle trap")
                    {
                        break result;
                    }
                }
                break match buf.call(UEvent::Exception {
                    first: true,
                    code: sig as _,
                }) {
                    UserReply::Run(false) => Some(sig),
                    reply => {
                        this.handle_reply(this.as_ref(), reply, &mut buf.user);
                        None
                    }
                };
            },
            WaitStatus::PtraceEvent(_, sig, code) => {
                match code {
                    PTRACE_EVENT_STOP => {
                        this.insert_thread(tid);
                    }
                    PTRACE_EVENT_CLONE => {
                        let new_tid =
                            ptrace::getevent(Pid::from_raw(tid)).unwrap_or_default() as tid_t;
                        buf.call(UEvent::ThreadCreate(new_tid));
                        // trace new thread
                        ptrace::attach(Pid::from_raw(new_tid));
                    }
                    PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK => {
                        let new_pid =
                            ptrace::getevent(Pid::from_raw(tid)).unwrap_or_default() as pid_t;
                        // info!("forked new pid: {new_pid}");
                        // let newpid = Pid::from_raw(new_pid);
                        // ptrace::detach(newpid, None);
                        // ptrace::cont(newpid, None);
                        StandardAdaptor::open(new_pid)
                            .log_error("open child")
                            .map(|t| {
                                t.base.status.set(if udbg_ui().base().trace_child.get() {
                                    UDbgStatus::Attached
                                } else {
                                    UDbgStatus::Detaching
                                });
                                self.targets.push(t);
                            });
                    }
                    PTRACE_EVENT_EXEC => {
                        buf.call(UEvent::ProcessCreate);
                    }
                    _ => {}
                }
                None
            }
            // exited with exception
            WaitStatus::Signaled(_, sig, coredump) => {
                buf.call(UEvent::Exception {
                    first: false,
                    code: sig as _,
                });
                let code = ptrace::getevent(Pid::from_raw(self.tid)).unwrap_or(-1);
                if !matches!(sig, Signal::SIGSTOP) {
                    this.remove_thread(tid, code as _, buf);
                }
                Some(sig)
            }
            // exited normally
            WaitStatus::Exited(_, code) => {
                this.remove_thread(tid, code, buf);
                if this.threads.read().is_empty() {
                    self.targets.retain(|t| !Arc::ptr_eq(t, &this));
                }
                if self.targets.is_empty() {
                    return None;
                }
                None
            }
            _ => unreachable!("status: {status:?}"),
        })
    }

    fn cont(&mut self, sig: HandleResult, buf: &mut TraceBuf) {
        let this = buf.target.clone();
        let tid = Pid::from_raw(self.tid as _);

        if this.base.status.get() == UDbgStatus::Detaching {
            for bp in this.get_breakpoints() {
                bp.enable(false);
            }
            for &tid in this.threads.read().iter() {
                ptrace::detach(Pid::from_raw(tid as _), None)
                    .log_error_with(|err| format!("ptrace_detach({tid}) failed: {err:?}"));
            }
            self.targets.retain(|t| !Arc::ptr_eq(&this, t));
        } else if buf.regs_dirty {
            buf.regs_dirty = false;
            buf.write_regs(self.tid);
        }

        ptrace::cont(tid, sig);
    }
}

pub struct DefaultEngine {
    pub targets: Vec<Arc<StandardAdaptor>>,
    pub status: WaitStatus,
    pub inited: bool,
    pub cloned_tids: HashSet<tid_t>,
    pub tid: tid_t,
}

impl Default for DefaultEngine {
    fn default() -> Self {
        Self {
            targets: Default::default(),
            status: WaitStatus::StillAlive,
            inited: false,
            tid: 0,
            cloned_tids: Default::default(),
        }
    }
}

impl UDbgEngine for DefaultEngine {
    fn open(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgTarget>> {
        Ok(StandardAdaptor::open(pid)?)
    }

    fn attach(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgTarget>> {
        let this = StandardAdaptor::open(pid)?;
        // attach each of threads
        for tid in this.process.tasks()?.filter_map(|t| t.ok().map(|t| t.tid)) {
            ptrace::attach(Pid::from_raw(tid)).with_context(|| format!("attach {tid}"))?;
        }
        // wait main thread
        waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WUNTRACED))
            .with_context(|| format!("waitpid({pid})"))?;
        self.targets.push(this.clone());
        Ok(this)
    }

    fn create(
        &mut self,
        path: &str,
        cwd: Option<&str>,
        args: &[&str],
    ) -> UDbgResult<Arc<dyn UDbgTarget>> {
        match unsafe { libc::fork() } {
            0 => unsafe {
                use std::ffi::CString;
                ptrace::traceme();
                let path = CString::new(path).unwrap();
                let args = args
                    .iter()
                    .map(|&arg| CString::new(arg).unwrap())
                    .collect::<Vec<_>>();
                let mut argv = args.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
                argv.insert(0, path.as_ptr());
                argv.push(core::ptr::null());
                libc::execvp(path.as_ptr().cast(), argv.as_ptr());
                unreachable!();
            },
            -1 => Err(UDbgError::system()),
            pid => {
                waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WUNTRACED))
                    .with_context(|| format!("waitpid({pid})"))?;
                let ps = Process::from_pid(pid).context("open")?;
                let this = Arc::new(StandardAdaptor(CommonAdaptor::new(ps)));
                self.targets.push(this.clone());
                Ok(this)
            }
        }
    }

    fn event_loop<'a>(&mut self, callback: &mut UDbgCallback<'a>) -> UDbgResult<()> {
        self.targets.iter().for_each(|t| {
            t.update_module();
            t.update_memory_page();
        });

        let target = self
            .targets
            .iter()
            .next()
            .map(Clone::clone)
            .context("no attached target")?;

        self.tid = target.process.pid;
        target.base.event_tid.set(self.tid);
        target.base.status.set(UDbgStatus::Attached);

        let buf = &mut TraceBuf {
            callback,
            user: unsafe { core::mem::zeroed() },
            si: unsafe { core::mem::zeroed() },
            regs_dirty: false,
            target,
        };
        buf.call(UEvent::InitBp);
        buf.call(UEvent::ProcessCreate);
        buf.target.insert_thread(self.tid);
        buf.call(UEvent::ThreadCreate(self.tid));
        ptrace::cont(Pid::from_raw(self.tid), None);

        while let Some(s) = self.fetch(buf).and_then(|_| self.handle(buf)) {
            self.cont(s, buf);
        }

        Ok(())
    }
}
