
use super::*;
use crate::{elf::*, util, AdaptorSpec};

use std::cell::Cell;
use std::ops::Deref;
use std::time::{Instant, Duration};
use std::sync::Arc;
use parking_lot::RwLock;
use std::mem::{transmute, zeroed, size_of};
use std::collections::{HashMap, HashSet};

use goblin::elf::sym::Sym;

use ::nix::sys::wait::*;
use ::nix::unistd::Pid;
use ::nix::sys::signal::Signal;

cfg_if! {
    if #[cfg(target_os = "android")] {
        const PTRACE_INTERRUPT: c_uint = 0x4207;
        const PTRACE_SEIZE: c_uint = 0x4206;
    }
}

#[inline]
unsafe fn mutable<T: Sized>(t: &T) -> &mut T {
    transmute(transmute::<_, usize>(t))
}

pub struct ElfSymbol {
    pub sym: Sym,
    pub name: Arc<str>,
}

impl Deref for ElfSymbol {
    type Target = Sym;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.sym }
}

impl From<ElfSym<'_>> for ElfSymbol {
    fn from(s: ElfSym<'_>) -> Self {
        ElfSymbol { sym: s.sym, name: s.name.into() }
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
    fn name(&self) -> Arc<str> { self.stat.name.as_str().into() }
    fn status(&self) -> Arc<str> { self.stat.state().into() }
    fn priority(&self) -> Arc<str> { format!("{}", self.stat.priority).into() }
}

#[inline(always)]
fn to_symbol(s: ElfSym) -> Symbol {
    let flags = if s.is_function() { SymbolFlags::FUNCTION } else { SymbolFlags::NONE };
    Symbol { offset: s.st_value as u32, name: s.name.into(), flags: flags.bits(), len: s.st_size as u32, type_id: 0 }
}

impl SymbolsData {
    fn from_elf(path: &str) -> Self {
        let mut this = Self::default();
        this.load(path);
        this
    }

    fn load(&mut self, path: &str) -> Result<(), String> {
        let map = util::mapfile(path.as_ref()).ok_or("map failed")?;
        let e = elf::parse(&map).ok_or("parse failed")?;
        let mut push_symbol = |s: ElfSym| {
            if s.name.starts_with("$x.") { return; }
            self.exports.entry(s.offset()).or_insert_with(|| to_symbol(s));
        };
        e.enum_symbol().for_each(&mut push_symbol);
        e.enum_export().for_each(&mut push_symbol);
        Ok(())
    }
}

pub struct NixModule {
    /// 模块基本信息
    pub data: ModuleData,
    /// 模块符号信息
    pub syms: SymbolsData,
    /// 是否已尝试过加载模块符号
    pub loaded: Cell<bool>,
}

impl NixModule {
    // fn check_loaded(&self) {
    //     if self.loaded.get() { return; }
    //     let mut s = self.syms.write();
    //     self.loaded.set(true);
    //     match s.load(&self.data.path) {
    //         Ok(_) => {
    //         }
    //         Err(e) => {
    //             error!("{}", e);
    //         }
    //     }
    // }
}

impl UDbgModule for NixModule {
    fn data(&self) -> &ModuleData { &self.data }
    // fn is_32(&self) -> bool { IS_ARCH_X64 || IS_ARCH_ARM64 }
    fn symbol_status(&self) -> SymbolStatus {
        if self.syms.pdb.read().is_some() {
            SymbolStatus::Loaded
        } else {
            SymbolStatus::Unload
        }
    }
    fn add_symbol(&self, offset: usize, name: &str) -> UDbgResult<()> {
        self.syms.add_symbol(offset, name)
    }
    fn find_symbol(&self, offset: usize, max_offset: usize) -> Option<Symbol> {
        self.syms.find_symbol(offset, max_offset)
    }
    fn get_symbol(&self, name: &str) -> Option<Symbol> {
        self.syms.get_symbol(name)
    }
    fn symbol_file(&self) -> Option<Arc<dyn SymbolFile>> {
        self.syms.pdb.read().clone()
    }

    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item=Symbol>>> {
        Ok(Box::new(self.syms.enum_symbol(pat)?.into_iter()))
    }
    fn get_exports(&self) -> Option<Vec<Symbol>> {
        Some(self.syms.exports.iter().map(|i| i.1.clone()).collect())
    }
    // fn load_symbol_file(&self, path: &str) -> UDbgResult<()> {
    //     // self.syms.write().load_from_pdb(path)?; Ok(())
    //     Ok(())  // TODO:
    // }
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

pub struct CommonAdaptor {
    base: UDbgBase,
    ps: Process,
    symgr: SymbolManager<NixModule>,
    pub bp_map: RwLock<HashMap<BpID, Arc<Breakpoint>>>,
    regs: user_regs_struct,
    threads: RwLock<HashSet<pid_t>>,
    tc_module: TimeCheck,
    tc_memory: TimeCheck,
    mem_pages: RwLock<Vec<MemoryPage>>,
    detaching: Cell<bool>,
    waiting: Cell<bool>,
    pub trace_opts: c_int,
}

impl CommonAdaptor {
    fn new(mut base: UDbgBase, ps: Process) -> Self {
        const TIMEOUT: Duration = Duration::from_secs(5);

        let mut trace_opts: c_int = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
        if udbg_ui().get_config::<bool>("trace_fork").unwrap_or(false) {
            trace_opts |= PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK;
        }

        base.pid.set(ps.pid());
        base.image_path = ps.image_path().unwrap_or_default();
        Self {
            base, ps, regs: unsafe { zeroed() },
            bp_map: RwLock::new(HashMap::new()),
            symgr: SymbolManager::<NixModule>::new("".into()),
            tc_module: TimeCheck::new(Duration::from_secs(10)),
            tc_memory: TimeCheck::new(Duration::from_secs(10)),
            mem_pages: RwLock::new(Vec::new()),
            threads: RwLock::new(HashSet::new()),
            trace_opts,
            waiting: Cell::new(false), detaching: Cell::new(false),
        }
    }

    fn update_memory_page(&self) -> Result<(), String> {
        *self.mem_pages.write() = self.ps.enum_memory()?.collect::<Vec<_>>();
        Ok(())
    }

    fn update_memory_page_check_time(&self) {
        self.tc_memory.check(|| { self.update_memory_page(); });
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
        if !base.contains(te) { return te; }
        let te = trim_lastext(name);
        if !base.contains(te) { return te; }
        name
    }

    fn update_module(&self) -> Result<(), String> {
        use goblin::elf::header::header32::Header as Header32;
        use goblin::elf::header::header64::Header as Header64;
        use std::io::Read;
        use std::fs::File;

        // self.md.write().clear();
        for m in self.ps.enum_module()? {
            if self.find_module(m.base).is_some() ||
                m.name.ends_with(".oat") || m.name.ends_with(".apk") { continue; }
            let name = self.module_name(&m.name);

            // TODO: use memory data
            let mut f = match File::open(m.path.as_ref()) {
                Ok(f) => f, Err(_) => {
                    error!("open module file: {}", m.path);
                    continue;
                }
            };
            let mut buf: Header64 = unsafe { std::mem::zeroed() };
            if f.read_exact(buf.as_mut_byte_array()).is_err() {
                error!("read file: {}", m.path);
                continue;
            }
            
            let arch = match elf::machine_to_arch(buf.e_machine) {
                Some(a) => a, None => {
                    error!("error e_machine: {} {}", buf.e_machine, m.path);
                    continue;
                }
            };

            let entry = match arch {
                "arm64" | "x86_64" => buf.e_entry as usize,
                "x86" | "arm" => unsafe { transmute::<_, &Header32>(&buf).e_entry as usize }
                a => { error!("error arch: {}", a); continue; }
            };

            let base = m.base;
            let path = m.path.clone();
            self.symgr.base.write().add(NixModule {
                data: ModuleData {
                    base, size: m.size,
                    arch, entry,
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

    #[inline(always)]
    fn find_module(&self, address: usize) -> Option<Arc<NixModule>> {
        self.symgr.find_module(address)
    }

    #[inline(always)]
    fn bp_exists(&self, id: BpID) -> bool {
        self.bp_map.read().get(&id).is_some()
    }

    pub fn enable_breadpoint(&self, bp: &Breakpoint, enable: bool) -> Result<bool, UDbgError> {
        match bp.bp_type {
            InnerBpType::Soft(origin) => {
                let written = if enable {
                    self.ps.write(bp.address, &BP_INSN)
                } else {
                    self.ps.write(bp.address, &origin)
                };
                if written.unwrap_or(0) > 0 {
                    bp.enabled.set(enable);
                    Ok(enable)
                } else { Err(UDbgError::MemoryError) }
            }
            _ => { Err(UDbgError::NotSupport) }
        }
    }

    fn readv<T: Copy>(&self, address: usize) -> Option<T> {
        unsafe {
            let mut val: T = zeroed();
            let size = size_of::<T>();
            let pdata: *mut u8 = transmute(&mut val);
            let mut data = std::slice::from_raw_parts_mut(pdata, size);
            let readed = self.ps.read(address, &mut data);
            if readed?.len() == size { Some(val) } else { None }
        }
    }

    fn update_regs(&self, tid: pid_t) {
        if let Some(regs) = self.ps.get_regs(tid) {
            unsafe { *mutable(&self.regs) = regs; }
        } else {
            error!("get_regs failed: {}", get_last_error_string());
        }
    }

    fn set_regs(&self) -> UDbgResult<()> {
        if !ptrace_setregs(self.base.event_tid.get(), &self.regs) {
            Err(UDbgError::system())
        } else { Ok(()) }
    }

    #[cfg(target_arch = "aarch64")]
    fn set_reg(&self, r: &str, val: CpuReg) -> UDbgResult<()> {
        let regs = unsafe { mutable(&self.regs) };
        let val = val.as_int() as u64;
        match r {
            "pc" | "_pc" => regs.pc = val,
            "sp" | "_sp" => regs.sp = val,
            "pstate" => regs.pstate = val,
            "x0" => regs.regs[0] = val,
            "x1" => regs.regs[1] = val,
            "x2" => regs.regs[2] = val,
            "x3" => regs.regs[3] = val,
            "x4" => regs.regs[4] = val,
            "x5" => regs.regs[5] = val,
            "x6" => regs.regs[6] = val,
            "x7" => regs.regs[7] = val,
            "x8" => regs.regs[8] = val,
            "x9" => regs.regs[9] = val,
            "x10" => regs.regs[10] = val,
            "x11" => regs.regs[11] = val,
            "x12" => regs.regs[12] = val,
            "x13" => regs.regs[13] = val,
            "x14" => regs.regs[14] = val,
            "x15" => regs.regs[15] = val,
            "x16" => regs.regs[16] = val,
            "x17" => regs.regs[17] = val,
            "x18" => regs.regs[18] = val,
            "x19" => regs.regs[19] = val,
            "x20" => regs.regs[20] = val,
            "x21" => regs.regs[21] = val,
            "x22" => regs.regs[22] = val,
            "x23" => regs.regs[23] = val,
            "x24" => regs.regs[24] = val,
            "x25" => regs.regs[25] = val,
            "x26" => regs.regs[26] = val,
            "x27" => regs.regs[27] = val,
            "x28" => regs.regs[28] = val,
            "x29" => regs.regs[29] = val,
            "x30" => regs.regs[30] = val,
            _ => return Err(UDbgError::InvalidRegister),
        };
        self.set_regs()
    }

    fn wait_event(&self, tb: &mut TraceBuf) -> Option<WaitStatus> {
        self.base.status.set(UDbgStatus::Running);
        self.waiting.set(true);
        let mut status = 0;
        let tid = unsafe {
            libc::waitpid(-1, &mut status, __WALL | WUNTRACED)
        };
        // let status = ::nix::sys::wait::waitpid(None, WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD | WaitPidFlag::WNOHANG).unwrap();
        self.waiting.set(false);
        self.base.event_tid.set(tid);
        self.base.status.set(UDbgStatus::Paused);

        if tid <= 0 { return None; }

        let status = WaitStatus::from_raw(Pid::from_raw(tid), status).unwrap();
        println!("[status] {status:?}");
        Some(status)
    }

    fn handle_event(&self, tb: &mut TraceBuf) {

    }

    fn handle_reply(&self, this: &dyn UDbgAdaptor, mut reply: UserReply, tid: pid_t, bpid: Option<BpID>) -> UserReply {
        let mut revert = None;
        let ui = udbg_ui();
        if let Some(bpid) = bpid {
            this.get_bp(bpid).map(|bp| if bp.enabled() {
                // Disable breakpoint temporarily
                bp.enable(false);
                revert = Some(bpid);
            });
        }
        ptrace_step_and_wait(tid);
        // TODO:
        // if let Some(bpid) = revert { this.enable_bp(bpid, true); }

        let mut temp_address: Option<usize> = None;
        match reply {
            UserReply::StepOut => {
                let regs = unsafe { mutable(&self.regs) };
                temp_address = this.check_call(*regs.ip() as usize);
                if temp_address.is_none() { reply = UserReply::StepIn; }
            }
            UserReply::Goto(a) => {
                temp_address = Some(a);
            }
            UserReply::StepIn => {} _ => {}
        }

        if let Some(address) = temp_address {
            this.add_bp(BpOpt::int3(address).enable(true).temp(true));
        }

        self.update_regs(tid); reply
    }

    fn get_bp_(&self, id: BpID) -> Option<Arc<Breakpoint>> {
        Some(self.bp_map.read().get(&id)?.clone())
    }

    pub fn handle_breakpoint(&self, this: &dyn UDbgAdaptor, tid: pid_t, info: &siginfo_t, bp: Arc<Breakpoint>, callback: &mut UDbgCallback) {
        bp.hit_count.set(bp.hit_count.get() + 1);
        let regs = unsafe { mutable(&self.regs) };
        if bp.temp.get() { bp.remove(); }
        let mut reply = self.handle_reply(this, callback(UEvent::Breakpoint(bp.clone())), tid, Some(bp.get_id()));
        while reply == UserReply::StepIn {
            reply = self.handle_reply(this, callback(UEvent::Step), tid, None);
        }
    }

    pub fn attach_and_stop(&self, tid: tid_t) -> bool {
        ptrace_attach(tid)      // will cause Stopped(Signal::SIGSTOP)
        // ptrace_seize(tid, self.trace_opts) &&
        // ptrace_interrupt(tid)   // will cause PTRACE_EVENT_STOP
    }

    fn enum_module<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=Arc<dyn UDbgModule+'a>>+'a>> {
        self.update_module();
        Ok(self.symgr.enum_module())
    }

    fn enum_memory<'a>(&'a self) -> Result<Box<dyn Iterator<Item = MemoryPage> + 'a>, UDbgError> {
        self.update_memory_page();
        Ok(Box::new(self.mem_pages.read().clone().into_iter()))
    }

    fn get_memory_map(&self) -> Vec<UiMemory> {
        self.enum_memory().unwrap().map(|m| {
            let mut flags = 0u32;
            if m.usage.as_ref() == "[heap]" {
                flags |= MF_HEAP;
            }
            if m.usage.as_ref() == "[stack]" {
                flags |= MF_STACK;
            }
            UiMemory {
                base: m.base, size: m.size, flags,
                type_: m.type_str().into(),
                protect: m.protect().into(),
                usage: m.usage.clone(),
            }
        }).collect::<Vec<_>>()
    }

    fn enum_handle<'a>(&'a self) -> Result<Box<dyn Iterator<Item = UiHandle> + 'a>, UDbgError> {
        use std::os::unix::fs::FileTypeExt;

        Ok(Box::new(process_fd(self.ps.pid).ok_or(UDbgError::system())?.map(|(id, path)| {
            let ps = path.to_str().unwrap_or("");
            let ts = path.metadata().map(|m| {
                let ft = m.file_type();
                if ft.is_fifo() { "FIFO" }
                else if ft.is_socket() { "Socket" }
                else if ft.is_block_device() { "Block" }
                else { "File" }
            }).unwrap_or_else(|_|
                if ps.starts_with("socket:") { "Socket" }
                else if ps.starts_with("pipe:") { "Pipe" }
                else { "" }
            );
            UiHandle {
                ty: 0,
                handle: id,
                type_name: ts.to_string(),
                name: ps.to_string(),
            }
        })))
    }

    fn get_regs(&self) -> UDbgResult<Registers> {
        unsafe {
            let mut result: Registers = zeroed();
            self.get_reg("", Some(&mut result))?;
            Ok(result)
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn get_reg(&self, reg: &str, r: Option<&mut Registers>) -> Result<CpuReg, UDbgError> {
        let regs = &self.regs;
        if let Some(r) = r {
            r.rax = regs.rax;
            r.rbx = regs.rbx;
            r.rcx = regs.rcx;
            r.rdx = regs.rdx;
            r.rbp = regs.rbp;
            r.rsp = regs.rsp;
            r.rsi = regs.rsi;
            r.rdi = regs.rdi;
            r.r8 = regs.r8;
            r.r9 = regs.r9;
            r.r10 = regs.r10;
            r.r11 = regs.r11;
            r.r12 = regs.r12;
            r.r13 = regs.r13;
            r.r14 = regs.r14;
            r.r15 = regs.r15;
            r.rip = regs.rip;
            r.rflags = regs.eflags as reg_t;
            Ok(0.into())
        } else {
            Ok(CpuReg::Int(match reg {
                "rax" => regs.rax,
                "rbx" => regs.rbx,
                "rcx" => regs.rcx,
                "rdx" => regs.rdx,
                "rbp" => regs.rbp,
                "rsp" | "_sp" => regs.rsp,
                "rsi" => regs.rsi,
                "rdi" => regs.rdi,
                "r8" => regs.r8,
                "r9" => regs.r9,
                "r10" => regs.r10,
                "r11" => regs.r11,
                "r12" => regs.r12,
                "r13" => regs.r13,
                "r14" => regs.r14,
                "r15" => regs.r15,
                "rip" | "_pc" => regs.rip,
                "rflags" => regs.eflags as reg_t,
                _ => return Err(UDbgError::InvalidRegister),
            } as usize))
        }
    }

    #[cfg(target_arch = "arm")]
    fn get_reg(&self, reg: &str, r: Option<&mut Registers>) -> Result<CpuReg, UDbgError> {
        let regs = &self.regs;
        if let Some(r) = r {
            *r = unsafe { transmute(*regs) };
            Ok(CpuReg::Int(0))
        } else {
            Ok(CpuReg::Int(match reg {
                "r0" => regs.regs[0],
                "r1" => regs.regs[1],
                "r2" => regs.regs[2],
                "r3" => regs.regs[3],
                "r4" => regs.regs[4],
                "r5" => regs.regs[5],
                "r6" => regs.regs[6],
                "r7" => regs.regs[7],
                "r8" => regs.regs[8],
                "r9" => regs.regs[9],
                "r10" => regs.regs[10],
                "r11" => regs.regs[11],
                "r12" => regs.regs[12],
                "_sp" | "r13" => regs.regs[13],
                "r14" => regs.regs[14],
                "_pc" | "r15" => regs.regs[15],
                "r16" => regs.regs[16],
                "r17" => regs.regs[17],
                _ => return Err(UDbgError::InvalidRegister),
            } as usize))
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn get_reg(&self, reg: &str, r: Option<&mut Registers>) -> Result<CpuReg, UDbgError> {
        let regs = &self.regs;
        if let Some(r) = r {
            *r = unsafe { transmute(*regs) };
            Ok(CpuReg::Int(0))
        } else {
            Ok(CpuReg::Int(match reg {
                "pc" | "_pc" => regs.pc,
                "sp" | "_sp" => regs.sp,
                "pstate" => regs.pstate,
                "x0" => regs.regs[0],
                "x1" => regs.regs[1],
                "x2" => regs.regs[2],
                "x3" => regs.regs[3],
                "x4" => regs.regs[4],
                "x5" => regs.regs[5],
                "x6" => regs.regs[6],
                "x7" => regs.regs[7],
                "x8" => regs.regs[8],
                "x9" => regs.regs[9],
                "x10" => regs.regs[10],
                "x11" => regs.regs[11],
                "x12" => regs.regs[12],
                "x13" => regs.regs[13],
                "x14" => regs.regs[14],
                "x15" => regs.regs[15],
                "x16" => regs.regs[16],
                "x17" => regs.regs[17],
                "x18" => regs.regs[18],
                "x19" => regs.regs[19],
                "x20" => regs.regs[20],
                "x21" => regs.regs[21],
                "x22" => regs.regs[22],
                "x23" => regs.regs[23],
                "x24" => regs.regs[24],
                "x25" => regs.regs[25],
                "x26" => regs.regs[26],
                "x27" => regs.regs[27],
                "x28" => regs.regs[28],
                "x29" => regs.regs[29],
                "x30" => regs.regs[30],
                _ => return Err(UDbgError::InvalidRegister),
            } as usize))
        }
    }
}

pub struct TraceBuf<'a> {
    pub callback: &'a mut UDbgCallback<'a>,
}

fn trim_ver(name: &str) -> &str {
    use ::regex::Regex;
    &name[..Regex::new(r"-\d").unwrap().find(name).map(|p| p.start()).unwrap_or(name.len())]
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
    ptrace_step(tid);
    match ptrace::waitpid(tid, 0) {
        Some(t) => {
            if t.0 == tid {
                return true;
            }
            error!("step unexpect tid: {}", t.0);
            false
        }
        None => false
    }
}

#[derive(Deref)]
pub struct StandardAdaptor(CommonAdaptor);

unsafe impl Send for StandardAdaptor {}
unsafe impl Sync for StandardAdaptor {}

impl StandardAdaptor {
    pub fn create(base: UDbgBase, path: &str, args: &[&str]) -> UDbgResult<Arc<Self>> {
        use std::ffi::CString;
        unsafe {
            match libc::fork() {
                0 => {
                    ptrace(PTRACE_TRACEME, 0, 0, 0);
                    let path = CString::new(path).unwrap();
                    let args = args.iter().map(|&arg| CString::new(arg).unwrap()).collect::<Vec<_>>();
                    let mut argv = args.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
                    argv.insert(0, path.as_ptr());
                    argv.push(core::ptr::null());
                    execvp(path.as_ptr() as *const c_char, argv.as_ptr());
                    unreachable!();
                }
                -1 => {
                    error!("fork failed: {}", get_last_error_string());
                    Err(UDbgError::system())
                }
                pid => {
                    let ps = Process::from_pid(pid).ok_or_else(|| UDbgError::system())?;
                    let this = Self(CommonAdaptor::new(base, ps));
                    ptrace_setopt(pid, this.0.trace_opts);
                    this.threads.write().insert(pid);
                    Ok(Arc::new(this))
                }
            }
        }
    }

    pub fn open(base: UDbgBase, pid: pid_t) -> Result<Arc<Self>, UDbgError> {
        let ps = Process::from_pid(pid).ok_or(UDbgError::system())?;
        Ok(Arc::new(Self(CommonAdaptor::new(base, ps))))
    }

    pub fn remove_thread(&self, tid: tid_t, s: i32, callback: &mut UDbgCallback) -> bool {
        let mut threads = self.threads.write();
        if threads.remove(&tid) {
            callback(UEvent::ThreadExit(s as u32));
            if threads.is_empty() {
                callback(UEvent::ProcessExit(s as u32));
                true
            } else { false }
        } else {
            udbg_ui().error(&format!("tid {} not found", tid));
            // ui.on_pause();
            true
        }
    }
}

impl AdaptorSpec for StandardAdaptor {}

// #[intertrait::cast_to]
impl ReadMemory for StandardAdaptor {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        self.ps.read(addr, data)
    }
}

// #[intertrait::cast_to]
impl WriteMemory for StandardAdaptor {
    fn write_memory(&self, addr: usize, data: &[u8]) -> Option<usize> {
        self.ps.write(addr, data)
    }
}

impl GetProp for StandardAdaptor {}

impl UDbgAdaptor for StandardAdaptor {
    fn base(&self) -> &UDbgBase { &self.base }

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
        if unsafe { kill(self.ps.pid, SIGKILL) } == 0 { Ok(()) } else { Err(UDbgError::system()) }
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
        match unsafe { kill(self.ps.pid, SIGSTOP) } {
            0 => Ok(()), code => Err(UDbgError::system())
        }
    }

    fn enum_thread<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=tid_t>+'a>> {
        Ok(Box::new(self.ps.enum_thread()))
    }

    fn enum_module<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=Arc<dyn UDbgModule+'a>>+'a>> {
        self.0.enum_module()
    }

    fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        self.0.enum_memory()
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        self.update_memory_page_check_time();
        RangeValue::binary_search(&self.mem_pages.read().as_slice(), address).map(|r| r.clone())
    }

    // fn symbol_manager(&self) -> Option<&dyn UDbgSymMgr> {
    //     Some(&self.symgr)
    // }

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

    fn get_registers<'a>(&'a self) -> UDbgResult<&'a mut dyn UDbgRegs> {
        Ok(unsafe { mutable(&self.regs) as &mut dyn UDbgRegs })
    }

    fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<dyn UDbgBreakpoint>> {
        self.base.check_opened()?;
        if self.bp_exists(opt.address as BpID) { return Err(UDbgError::BpExists); }

        let enable = opt.enable;
        let result = if let Some(rw) = opt.rw {
            return Err(UDbgError::NotSupport);
        } else {
            if let Some(origin) = self.readv::<BpInsn>(opt.address) {
                let bp = Breakpoint {
                    address: opt.address,
                    enabled: Cell::new(false),
                    temp: Cell::new(opt.temp),
                    hit_tid: opt.tid,
                    hit_count: Cell::new(0),
                    bp_type: InnerBpType::Soft(origin),

                    target: to_weak(self),
                    common: &self.0,
                };
                let bp = Arc::new(bp);
                self.bp_map.write().insert(bp.get_id(), bp.clone());
                Ok(bp)
            } else { Err(UDbgError::InvalidAddress) }
        };

        Ok(result.map(|bp| { if enable { bp.enable(true); } bp})?)
    }

    fn get_bp<'a>(&'a self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        Some(self.bp_map.read().get(&id)?.clone())
    }

    fn get_bp_list(&self) -> Vec<BpID> {
        self.bp_map.read().keys().cloned().collect()
    }

    fn get_memory_map(&self) -> Vec<UiMemory> {
        self.0.get_memory_map()
    }

    fn open_thread(&self, tid: tid_t) -> Result<Box<dyn UDbgThread>, UDbgError> {
        Ok(Box::new(NixThread {
            base: ThreadData {tid, wow64: false},
            stat: ThreadStat::from(self.ps.pid, tid).ok_or(UDbgError::system())?
        }))
    }

    fn enum_handle<'a>(&'a self) -> Result<Box<dyn Iterator<Item = UiHandle> + 'a>, UDbgError> {
        self.0.enum_handle()
    }

    // TODO: lua
    // fn lua_call(&self, s: &State) -> UDbgResult<i32> {
    //     match s.args::<&str>(2) {
    //         "moduleTimeout" => { self.tc_module.duration.set(Duration::from_secs_f64(s.args(3))); }
    //         "memoryTimeout" => { self.tc_memory.duration.set(Duration::from_secs_f64(s.args(3))); }
    //         _ => {}
    //     }
    //     Ok(0)
    // }

    fn event_loop<'a>(&self, callback: &mut UDbgCallback<'a>) -> UDbgResult<()> {
        use UEvent::*;
    
        self.update_module();
        self.update_memory_page();
    
        if self.base.is_opened() {
            use std::time::Duration;
            while self.base.status.get() != UDbgStatus::Ended {
                std::thread::sleep(Duration::from_millis(10));
            }
            return Ok(());
        }
    
        let base = &self.base;
        let ui = udbg_ui();
        let mut inited = false;
        let INVALID_SIGNAL_NUMBER: Signal = unsafe { core::mem::transmute_copy(&-1) };
    
        loop {unsafe {
            let mut status: c_int = 0;
            
            // http://man7.org/linux/man-pages/man2/waitpid.2.html
            self.base.status.set(UDbgStatus::Running);
            self.waiting.set(true);
            let tid = libc::waitpid(-1, &mut status, __WALL | WUNTRACED);
            // let status = ::nix::sys::wait::waitpid(None, WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD | WaitPidFlag::WNOHANG).unwrap();
            self.waiting.set(false);
            if tid <= 0 { break; }
            
            self.base.event_tid.set(tid);
            base.status.set(UDbgStatus::Paused);
            
            let status = WaitStatus::from_raw(Pid::from_raw(tid), status).unwrap();
            println!("[status] {status:?}");
    
            let insert_thread = |tid| {
                if self.threads.write().insert(tid) {
                    if !ptrace_setopt(tid, self.trace_opts) {
                        ui.error(&format!("ptrace_setopt {} {}", tid, get_last_error_string()));
                    }
                    return true;
                }
                self.detaching.get()
            };
            let mut handle_initbp = || {
                callback(InitBp);
                insert_thread(tid);
                true
            };
    
            let mut cont_sig = 0;
            if match status {
                WaitStatus::Stopped(_, sig) => loop {
                    self.update_regs(tid);
                    let regs = mutable(&self.regs);
                    if !inited && matches!(sig, Signal::SIGSTOP | Signal::SIGTRAP) {
                        inited = handle_initbp();
                        break false;
                    }
                    match sig {
                        // maybe thread created (by ptrace_attach or ptrace_interrupt)
                        // maybe kill by SIGSTOP
                        Signal::SIGSTOP => {
                            if self.threads.read().get(&tid).is_none() {
                                insert_thread(tid);
                                break false;
                            }
                        }
                        Signal::SIGTRAP | Signal::SIGILL => {
                            let si = ::nix::sys::ptrace::getsiginfo(Pid::from_raw(tid)).expect("siginfo");
                            // let info = self.ps.siginfo(tid).expect("siginfo");
                            println!("stop info: {si:?}, pc: {:p}", si.si_addr());
                            // match info.si_code {
                            //     TRAP_BRKPT => println!("info.si_code TRAP_BRKPT"),
                            //     TRAP_HWBKPT => println!("info.si_code TRAP_HWBKPT"),
                            //     TRAP_TRACE => println!("info.si_code TRAP_TRACE"),
                            //     code => println!("info.si_code {}", code),
                            // };
                            let ip = *regs.ip();
                            let address = if sig == Signal::SIGTRAP && ip > 0 { ip - 1 } else { ip };
                            *regs.ip() = address;
                            // println!("sigtrap address {:x}", address);
                            if let Some(bp) = self.get_bp_(address as BpID) {
                                self.handle_breakpoint(self, tid, &si, bp, callback);
                                break false;
                            }
                        }
                        _ => {}
                    }
                    cont_sig = sig as _;
                    callback(UEvent::Exception {first: true, code: sig as _});
                    break false;
                }
                WaitStatus::PtraceEvent(_, sig, code) => {
                    match code {
                        PTRACE_EVENT_STOP => {
                            insert_thread(tid);
                            if !inited && tid == self.ps.pid {
                                inited = handle_initbp();
                            }
                        }
                        PTRACE_EVENT_CLONE => {
                            let mut new_tid: tid_t = 0;
                            ptrace_getevtmsg(tid, &mut new_tid);
                            callback(ThreadCreate(new_tid));
                            self.attach_and_stop(new_tid);
                        }
                        PTRACE_EVENT_FORK => {
                        }
                        _ => {}
                    }
                    false
                }
                // exited with exception
                WaitStatus::Signaled(_, sig, coredump) => {
                    cont_sig = sig as _;
                    callback(UEvent::Exception {first: false, code: sig as _});
                    if !matches!(sig, Signal::SIGSTOP) {
                        self.remove_thread(tid, -1, callback)
                    } else { false }
                }
                // exited normally
                WaitStatus::Exited(_, code) => {
                    self.remove_thread(tid, code, callback)
                }
                _ => unreachable!("status: {status:?}"),
            } {
                println!("breaking...");
                break;
            }
    
            // if WIFSTOPPED(status) {
            //     this.update_regs(tid);
            //     let regs = mutable(&this.regs);
            //     // ui.on_info(&format!("WIFSTOPPED {} status: {:x}", tid, status));
            //     let event = (status >> 16) & 0xffff;
            //     let sig = WSTOPSIG(status);
            //     // https://www.mkssoftware.com/docs/man5/siginfo_t.5.asp#Signal_Codes
    
            //     match (event, sig) {
            //         // Stop before return from clone(2).
            //         (PTRACE_EVENT_CLONE, _) => {
            //             let mut new_tid: tid_t = 0;
            //             ptrace_getevtmsg(tid, &mut new_tid);
            //             this.base.event_tid.set(new_tid);   // TODO: new_tid
            //             state.on(ThreadCreate).await;
            //             ptrace_attach(new_tid);
            //             handle_thread(new_tid);
            //         }
            //         // Stop before return from execve(2)
            //         (PTRACE_EVENT_EXEC, _) => {
            //             // TODO:
            //             // let mut new_tid: tid_t = 0;
            //             // ptrace_getevtmsg(tid, &mut new_tid);
            //             // ui.check_event_pause(new_tid, c_str!("on_event_exec"));
            //             info!("PTRACE_EVENT_EXEC");
            //             if sig == SIGTRAP && !init {
            //                 init = true;
            //                 state.on(InitBp).await;
            //             }
            //         }
            //         // Stop before return from fork(2) or clone(2) with the exit sig‐nal set to SIGCHLD
            //         (PTRACE_EVENT_FORK, _) => {
            //             // TODO:
            //             // let mut new_tid: tid_t = 0;
            //             // ptrace_getevtmsg(tid, &mut new_tid);
            //             // ui.check_event_pause(new_tid, c_str!("on_event_fork"));
            //         }
            //         // Stop before return from vfork(2) or clone(2) with the CLONE_VFORK flag
            //         (PTRACE_EVENT_VFORK, _) => {
            //             // TODO:
            //             // let mut new_tid: tid_t = 0;
            //             // ptrace_getevtmsg(tid, &mut new_tid);
            //             // ui.check_event_pause(new_tid, c_str!("on_event_vfork"));
            //         }
            //         (PTRACE_EVENT_VFORK_DONE, _) => {
            //             // TODO:
            //             // let mut new_tid: tid_t = 0;
            //             // ptrace_getevtmsg(tid, &mut new_tid);
            //             // ui.check_event_pause(new_tid, c_str!("on_event_vfork_done"));
            //         }
            //         // Stop before exit
            //         (PTRACE_EVENT_EXIT, _) => {
            //             // TODO:
            //             // let mut status: c_int = 0;
            //             // ptrace_getevtmsg(tid, &mut status);
            //             // ui.check_event_pause(status, c_str!("on_event_exit"));
            //         }
            //         // Stop induced by PTRACE_INTERRUPT command, or group-stop, or
            //         //   initial ptrace-stop when a new child is attached (only if attached using PTRACE_SEIZE)
            //         (PTRACE_EVENT_STOP, _) => {
            //             if sig == SIGTRAP {
            //                 if !init {
            //                     init = true;
            //                     state.on(InitBp).await;
            //                 }
            //                 handle_thread(tid);
            //                 // nothing
            //             } else {
            //                 let not_except = sig == SIGSTOP && this.detaching.get();
            //                 if !not_except {
            //                     // TODO:
            //                     // ui.check_event_pause((tid, sig), c_str!("on_event_stop"));
            //                 }
            //             }
            //         }
            ptrace_cont(tid, cont_sig as _);
            if self.detaching.get() {
                for bp in self.get_breakpoints() {
                    bp.remove();
                }
                for &tid in self.threads.read().iter() {
                    if !ptrace_detach(tid) {
                        error!("ptrace_detach({tid}) failed");
                    }
                }
                break;
            }
        }}
        Ok(())
    }
}

pub struct DefaultEngine;

impl UDbgEngine for DefaultEngine {
    fn open(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(StandardAdaptor::open(base, pid)?)
    }

    fn attach(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        let this = StandardAdaptor::open(base, pid)?;
        for tid in this.ps.enum_thread() {
            if !this.attach_and_stop(tid) {
                return Err(UDbgError::system());
            }
        }
        Ok(this)
    }
    
    fn create(&self, base: UDbgBase, path: &str, cwd: Option<&str>, args: &[&str]) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(StandardAdaptor::create(base, path, args)?)
    }
}