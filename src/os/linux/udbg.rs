use super::*;
use crate::elf::*;
use crate::os::udbg::EventHandler;
use crate::range::RangeValue;

use anyhow::Context;
use goblin::elf::sym::Sym;
use nix::sys::ptrace::Options;
use nix::sys::wait::waitpid;
use parking_lot::RwLock;
use procfs::process::{Stat as ThreadStat, Task};
use serde_value::Value;
use std::cell::Cell;
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

impl GetProp for NixThread {}

impl UDbgThread for NixThread {
    fn name(&self) -> Arc<str> {
        self.stat.comm.as_str().into()
    }
    fn status(&self) -> Arc<str> {
        self.stat.state.to_string().into()
    }
    fn priority(&self) -> Arc<str> {
        format!("{}", self.stat.priority).into()
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
    pub detaching: Cell<bool>,
    waiting: Cell<bool>,
    pub trace_opts: Options,
}

impl CommonAdaptor {
    pub fn new(ps: Process) -> Self {
        const TIMEOUT: Duration = Duration::from_secs(5);

        let base = CommonBase::new(ps);
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
            detaching: Cell::new(false),
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
            self.symgr.base.write().add(NixModule {
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
        self.base.status.set(UDbgStatus::Running);
        self.waiting.set(true);
        let mut status = 0;
        let tid = unsafe { libc::waitpid(-1, &mut status, __WALL | WUNTRACED) };
        // let status = ::nix::sys::wait::waitpid(None, WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD | WaitPidFlag::WNOHANG).unwrap();
        self.waiting.set(false);
        self.base.event_tid.set(tid);
        self.base.status.set(UDbgStatus::Paused);

        if tid <= 0 {
            return None;
        }

        let status = WaitStatus::from_raw(Pid::from_raw(tid), status).unwrap();
        println!("[status] {status:?}");
        Some(status)
    }

    fn handle_event(&self, tb: &mut TraceBuf) {}

    fn handle_reply(
        &self,
        this: &dyn UDbgAdaptor,
        mut reply: UserReply,
        tb: &mut TraceBuf,
    ) -> UserReply {
        let mut temp_address: Option<usize> = None;
        match reply {
            UserReply::StepOut => {
                temp_address = this.check_call(*tb.user.regs.ip() as usize);
                if temp_address.is_none() {
                    reply = UserReply::StepIn;
                }
            }
            UserReply::Goto(a) => {
                temp_address = Some(a);
            }
            UserReply::StepIn => {}
            _ => {}
        }

        if let Some(address) = temp_address {
            this.add_bp(BpOpt::int3(address).enable(true).temp(true));
        }
        reply
    }

    pub fn get_bp_(&self, id: BpID) -> Option<Arc<Breakpoint>> {
        Some(self.bp_map.read().get(&id)?.clone())
    }

    pub fn handle_breakpoint(
        &self,
        this: &dyn UDbgAdaptor,
        eh: &mut dyn EventHandler,
        tb: &mut TraceBuf,
        si: &siginfo_t,
    ) -> UDbgResult<()> {
        // correct the pc register
        let ip = *tb.user.regs.ip();
        let address = if si.si_signo == SIGTRAP && ip > 0 {
            ip - 1
        } else {
            ip
        };
        *tb.user.regs.ip() = address;

        let tid = self.base.event_tid.get();
        let bp = self
            .get_bp_(address as _)
            .or_else(|| self.get_hwbp(tb))
            .ok_or(UDbgError::NotFound)?;

        bp.hit_count.set(bp.hit_count.get() + 1);
        if bp.temp.get() {
            self.remove_breakpoint(this, &bp);
        }

        // handle by user
        let hitted = bp.hit_tid.map(|t| t == tid).unwrap_or(true);
        let mut reply = UserReply::Run(true);
        if hitted {
            reply = self.handle_reply(this, tb.call(UEvent::Breakpoint(bp.clone())), tb);
        }

        let mut user_step = reply == UserReply::StepIn;
        let id = bp.get_id();

        #[cfg(target_arch = "x86_64")]
        if bp.is_hard() && self.get_bp(id).is_some() {
            tb.user.set_rf();
        }

        // int3 breakpoint revert
        if bp.is_soft() && self.get_bp(id).is_some() {
            // if bp is not deleted by user during the interruption
            if bp.enabled.get() {
                // disabled temporarily, in order to be able to continue
                self.enable_breadpoint(this, &bp, false)
                    .log_error("disable bp");

                // step once and revert
                loop {
                    ptrace::step(Pid::from_raw(tid), None);
                    match eh.fetch(tb) {
                        Some(_) => {
                            if core::ptr::eq(self, &tb.target.0) && self.base.event_tid.get() == tid
                            {
                                break;
                            } else if let Some(s) = eh.handle(tb) {
                                eh.cont(s, tb);
                            } else {
                                return Ok(());
                            }
                        }
                        None => return Ok(()),
                    }
                }

                self.enable_breadpoint(this, &bp, true)
                    .log_error("enable bp");
            }
        }

        while user_step {
            ptrace::step(Pid::from_raw(tid), None);
            reply = self.handle_reply(this, tb.call(UEvent::Step), tb);
            user_step = reply == UserReply::StepIn;
        }

        Ok(())
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

    fn enum_handle<'a>(&'a self) -> Result<Box<dyn Iterator<Item = HandleInfo> + 'a>, UDbgError> {
        use std::os::unix::fs::FileTypeExt;

        Ok(Box::new(
            process_fd(self.process.pid)
                .ok_or(UDbgError::system())?
                .map(|(id, path)| {
                    let ps = path.to_str().unwrap_or("");
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
                        handle: id,
                        type_name: ts.to_string(),
                        name: ps.to_string(),
                    }
                }),
        ))
    }

    pub fn enable_hwbp(
        &self,
        dbg: &dyn UDbgAdaptor,
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
            result = self.enable_hwbp_for_thread(tid, info, enable);
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

    pub fn insert_thread(&self, tid: tid_t) {
        if self.threads.write().insert(tid) {
            if let Err(err) = ptrace::setoptions(Pid::from_raw(tid), self.trace_opts) {
                udbg_ui().error(format!("ptrace_setopt {tid} {err:?}",));
            }
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

impl ReadMemory for StandardAdaptor {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        self.process.read(addr, data)
    }
}

impl WriteMemory for StandardAdaptor {
    fn write_memory(&self, addr: usize, data: &[u8]) -> Option<usize> {
        self.process.write(addr, data)
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
        if self.base.is_opened() {
            self.base.status.set(UDbgStatus::Ended);
            return Ok(());
        }
        self.detaching.set(true);
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
        self.base.check_opened()?;
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
                .enum_thread()
                .filter_map(|tid| self.open_thread(tid).ok()),
        ))
    }
}

impl UDbgAdaptor for StandardAdaptor {}
