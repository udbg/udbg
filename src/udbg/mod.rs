
pub mod bp;
pub mod event;

use std::cell::Cell;
use std::sync::Arc;
use std::any::Any;
use core::ops::Deref;
use serde::{Deserialize, Serialize};
pub use std::io::{Error as IoError, ErrorKind, Result as IoResult};

#[cfg(windows)]
use winapi::um::winnt::{PCONTEXT, PEXCEPTION_RECORD, EXCEPTION_POINTERS};

pub use bp::*;
pub use event::*;
use crate::{*, regs::*};

mod error {
    use std::fmt;
    use super::*;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum UDbgError {
        NotSupport,
        BpExists,
        NotFound,
        NoTarget,
        TimeOut,
        InvalidAddress,
        InvalidRegister,
        MemoryError,
        HWBPSlotMiss,
        BindFailed,
        SpawnFailed,
        TargetIsBusy,
        GetContext(u32),
        SetContext(u32),
        Text(String),
        System(String),
        Code(usize),
        #[error(transparent)]
        Other(#[from] anyhow::Error),
    }
    pub type UDbgResult<T>  = std::result::Result<T, UDbgError>;

    impl UDbgError {
        #[inline]
        pub fn system() -> UDbgError { UDbgError::System(get_last_error_string()) }
    }

    impl From<&str> for UDbgError {
        fn from(s: &str) -> Self { UDbgError::Text(s.to_string()) }
    }

    impl From<String> for UDbgError {
        fn from(s: String) -> Self { UDbgError::Text(s) }
    }

    impl fmt::Display for UDbgError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "")
        }
    }
}
pub use error::*;

#[cfg(target_arch = "x86_64")]
pub const UDBG_ARCH: u32 = ARCH_X64;
#[cfg(target_arch = "x86")]
pub const UDBG_ARCH: u32 = ARCH_X86;
#[cfg(target_arch = "arm")]
pub const UDBG_ARCH: u32 = ARCH_ARM;
#[cfg(target_arch = "aarch64")]
pub const UDBG_ARCH: u32 = ARCH_ARM64;

bitflags! {
    pub struct UFlags: u32 {
        const NONE = 0b00000000;
        const UNDEC_TYPE = 1 << 0;
        const UNDEC_RETN = 1 << 1;
        const UNDEC_NAME_ONLY = 1 << 2;

        const DISASM_RAW = 1 << 8;
        const DISASM_SYMBOL = 1 << 9;
        // const DISASM_SYMBOL = 1 << 3;

        const SHOW_OUTPUT = 1 << 16;
    }
}

impl Default for UFlags {
    fn default() -> Self {
        Self::SHOW_OUTPUT | Self::UNDEC_NAME_ONLY
    }
}

pub const UFLAG_NAME_ONLY: usize = 1 << 8;
pub const UFLAG_UNDEC_TYPE: usize = 1 << 0;     // undecorate full type of function
pub const UFLAG_UNDEC_RETN: usize = 1 << 1;     // undecorate the return type of function

pub const DISASM_RAW: u32 = 0;
pub const DISASM_MODULE: u32 = 1;
pub const DISASM_SYMBOL: u32 = 2;

pub struct DebugOption {
    pub disasm: Cell<u32>,
}
unsafe impl Sync for DebugOption {}

pub static G_OPT: DebugOption = DebugOption {
    disasm: Cell::new(DISASM_SYMBOL),
};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum UDbgStatus {
    Idle,
    Opened,
    Attached,
    Paused,
    Running,
    Ended,
}

#[derive(Clone)]
pub struct PauseContext {
    pub arch: Cell<u32>,
    pub psize: Cell<usize>,
}

impl Default for PauseContext {
    fn default() -> Self {
        Self {
            arch: UDBG_ARCH.into(),
            psize: core::mem::size_of::<usize>().into()
        }
    }
}

impl PauseContext {
    pub fn update(&self, arch: u32) {
        self.arch.set(arch);
        match arch {
            ARCH_X86 | ARCH_ARM => self.psize.set(4),
            ARCH_X64  | ARCH_ARM64 => self.psize.set(8),
            _ => {}
        };
    }
}

#[derive(Clone, Serialize)]
pub struct UDbgBase {
    pub pid: Cell<pid_t>,
    pub event_tid: Cell<pid_t>,
    pub event_pc: Cell<usize>,
    pub image_path: String,
    pub image_base: usize,
    pub arch: &'static str,
    #[serde(skip)]
    pub flags: Cell<UFlags>,
    #[serde(skip)]
    pub context: PauseContext,
    #[serde(skip)]
    pub status: Cell<UDbgStatus>,
    #[serde(skip)]
    pub update: fn(u32),
}

impl UDbgBase {
    #[inline]
    pub fn is_ptr32(&self) -> bool {
        self.ptrsize() == 4
    }

    #[inline]
    pub fn ptrsize(&self) -> usize {
        self.context.psize.get()
    }

    pub fn update_arch(&self, arch: u32) {
        if arch == self.context.arch.get() { return; }
        self.context.update(arch);
        (self.update)(arch);
    }

    pub fn is_opened(&self) -> bool {
        self.status.get() == UDbgStatus::Opened
    }

    pub fn is_paused(&self) -> bool {
        self.status.get() == UDbgStatus::Paused
    }

    pub fn check_opened(&self) -> UDbgResult<()> {
        if self.is_opened() { Err(UDbgError::NotSupport) } else { Ok(()) }
    }

    #[inline(always)]
    pub fn undec_sym(&self, sym: &str) -> Option<String> {
        undecorate_symbol(sym, self.flags.get())
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct UiThread {
    pub tid: u32,
    pub entry: usize,
    pub teb: usize,
    pub name: Arc<str>,
    pub status: Arc<str>,
    pub priority: Arc<str>,
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct UiMemory {
    pub base: usize,
    pub size: usize,
    pub flags: u32,     // MF_*
    #[serde(rename="type")]
    pub type_: Arc<str>,
    pub protect: Arc<str>,
    pub usage: Arc<str>,
    #[cfg(windows)]
    pub alloc_base: usize,
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct UiHandle {
    pub ty: u32,
    pub handle: usize,
    pub type_name: String,
    pub name: String,
}

pub struct ThreadData {
    pub tid: tid_t,
    pub wow64: bool,
    #[cfg(windows)]
    pub handle: Handle,
}

#[cfg(windows)]
pub type ThreadContext = winapi::um::winnt::CONTEXT;
#[cfg(windows)]
pub type ThreadContext32 = winapi::um::winnt::WOW64_CONTEXT;

pub trait UDbgThread: Any + Deref<Target=ThreadData> {
    fn name(&self) -> Arc<str> { "".into() }
    fn status(&self) -> Arc<str> { "".into() }

    /// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority#return-value
    #[cfg(windows)]
    fn priority(&self) -> Option<i32> { None }

    #[cfg(not(windows))]
    fn priority(&self) -> Arc<str> { "".into() }

    fn suspend(&self) -> IoResult<i32> { Err(ErrorKind::Unsupported.into()) }
    fn resume(&self) -> IoResult<u32> { Err(ErrorKind::Unsupported.into()) }
    #[cfg(windows)]
    fn get_context(&self, cx: &mut ThreadContext) -> IoResult<()> {
        Err(IoError::from(ErrorKind::Unsupported))
    }
    #[cfg(windows)]
    fn set_context(&self, cx: &ThreadContext) -> IoResult<()> {
        Err(IoError::from(ErrorKind::Unsupported))
    }
    #[cfg(windows)]
    fn get_context32(&self, cx: &mut ThreadContext32) -> IoResult<()> {
        Err(IoError::from(ErrorKind::Unsupported))
    }
    #[cfg(windows)]
    fn set_context32(&self, cx: &ThreadContext32) -> IoResult<()> {
        Err(IoError::from(ErrorKind::Unsupported))
    }
    #[cfg(windows)]
    fn teb(&self) -> Option<usize> { None }
    /// start address
    #[cfg(windows)]
    fn entry(&self) -> usize { 0 }
    // extra function
    fn lua_call(&self, s: &llua::State) -> i32 { 0 }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolStatus {
    Unload,
    Failed,
    Loaded,
}

#[cfg(windows)]
pub type UModFunc = winapi::um::winnt::RUNTIME_FUNCTION;

pub trait UDbgModule {
    fn data(&self) -> &sym::ModuleData;
    fn is_32(&self) -> bool { IS_ARCH_X64 || IS_ARCH_ARM64 }
    fn symbol_status(&self) -> SymbolStatus;
    fn add_symbol(&self, offset: usize, name: &str) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    fn find_symbol(&self, offset: usize, max_offset: usize) -> Option<sym::Symbol> {
        None
    }
    #[cfg(windows)]
    fn runtime_function(&self) -> Option<&[UModFunc]> { None }
    #[cfg(windows)]
    fn find_function(&self, offset: usize) -> Option<&UModFunc> {
        let funcs = self.runtime_function()?;
        let offset = offset as u32;
        let i = funcs.binary_search_by(|f| {
            use std::cmp::Ordering;
            if offset >= f.BeginAddress && offset < f.EndAddress {
                Ordering::Equal
            } else if offset < f.BeginAddress {
                Ordering::Greater
            } else { Ordering::Less }
        }).ok()?;
        funcs.get(i)
    }
    fn get_symbol(&self, name: &str) -> Option<sym::Symbol> { None }
    fn symbol_file(&self) -> Option<Arc<dyn sym::SymbolFile>> { None }
    fn load_symbol_file(&self, path: &str) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item=sym::Symbol>>> {
        Err(UDbgError::NotSupport)
    }
    fn get_exports(&self) -> Option<Vec<sym::Symbol>> { None }
    // extra function
    fn call(&self, s: &llua::State) -> i32 { 0 }
}

pub trait UDbgBreakpoint {
    fn get_id(&self) -> BpID;
    fn address(&self) -> usize;
    fn enabled(&self) -> bool;
    fn get_type(&self) -> BpType;
    /// count of this breakpoint hitted
    fn hit_count(&self) -> usize;
    /// set count of the to be used,
    /// when hit_count() > this count, bp will be delete
    fn set_count(&self, count: usize);
    /// set the which can hit the bp. if tid == 0, all thread used
    fn set_hit_thread(&self, tid: tid_t);
    /// current tid setted by set_hit_thread()
    fn hit_tid(&self) -> tid_t;
    /// original bytes written by software breakpoint
    fn origin_bytes<'a>(&'a self) -> Option<&'a [u8]>;

    fn enable(&self, enable: bool) -> UDbgResult<()>;
    fn remove(&self) -> UDbgResult<()>;
}

/// 表示一个目标(进程)的模块符号管理器
pub trait UDbgSymMgr {
    /// 查找address所处的模块，address可以是模块基址，也可以是模块范围内的任意地址
    fn find_module(&self, address: usize) -> Option<Arc<dyn UDbgModule>>;
    /// 根据模块名查找模块
    fn get_module(&self, name: &str) -> Option<Arc<dyn UDbgModule>>;
    /// 枚举模块
    fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item=Arc<dyn UDbgModule + 'a>> + 'a>;
    /// 枚举符号
    fn enum_symbol<'a>(&'a self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item=sym::Symbol>+'a>> {
        Err(UDbgError::NotSupport)
    }
    /// 移除模块及其符号，通过基址定位模块
    fn remove(&self, address: usize);
    #[cfg(windows)]
    fn check_load_module(&self, read: &dyn ReadMemory, base: usize, size: usize, path: &str, file: winapi::um::winnt::HANDLE) -> bool { false }
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct PsInfo {
    pub pid: pid_t,
    pub wow64: bool,
    pub name: String,
    pub path: String,
    pub cmdline: String,
}

pub trait UDbgEngine {
    fn enum_process(&self) -> Box<dyn Iterator<Item=PsInfo>> {
        enum_psinfo()
    }

    fn open(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>>;

    fn attach(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>>;

    fn create(&self, base: UDbgBase, path: &str, cwd: Option<&str>, args: &[&str]) -> UDbgResult<Arc<dyn UDbgAdaptor>>;
}

pub trait UDbgAdaptor: Any + Send + Sync + 'static + ReadMemory + WriteMemory {
    fn base(&self) -> &UDbgBase;

    // target control
    fn detach(&self) -> UDbgResult<()>;
    fn breakk(&self) -> UDbgResult<()> { Err(UDbgError::NotSupport) }
    fn kill(&self) -> UDbgResult<()>;
    fn suspend(&self) -> UDbgResult<()> { Ok(()) }
    fn resume(&self) -> UDbgResult<()> { Ok(()) }

    // memory infomation
    fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>>;
    fn virtual_query(&self, address: usize) -> Option<MemoryPage>;
    fn get_memory_map(&self) -> Vec<UiMemory>;
    // size: usize, type: RWX, commit/reverse
    fn virtual_alloc(&self, address: usize, size: usize, ty: &str) -> UDbgResult<usize> { Err(UDbgError::NotSupport) }
    fn virtual_free(&self, address: usize) {}

    // thread infomation
    fn get_thread_context(&self, tid: u32) -> Option<Registers> { None }
    fn enum_thread<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=tid_t>+'a>>;
    fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<dyn UDbgThread>> { Err(UDbgError::NotSupport) }
    fn open_all_thread(&self) -> Vec<(tid_t, Box<dyn UDbgThread>)> {
        let mut result = Vec::with_capacity(2);
        if let Ok(iter) = self.enum_thread() {
            for tid in iter {
                if let Ok(t) = self.open_thread(tid) {
                    result.push((tid, t));
                }
            }
        }
        result
    }

    // breakpoint
    fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<dyn UDbgBreakpoint>> { Err(UDbgError::NotSupport) }
    fn get_bp<'a>(&'a self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + 'a>> { None }
    fn get_bp_by_address<'a>(&'a self, a: usize) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        self.get_bp(a as BpID)
    }
    fn get_bp_list(&self) -> Vec<BpID> { vec![] }
    fn get_breakpoints<'a>(&'a self) -> Vec<Arc<dyn UDbgBreakpoint + 'a>> {
        self.get_bp_list().into_iter().filter_map(|id| self.get_bp(id)).collect()
    }

    // symbol infomation
    fn symbol_manager(&self) -> Option<&dyn UDbgSymMgr> { None }
    fn enum_module<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=Arc<dyn UDbgModule+'a>>+'a>> {
        Ok(self.symbol_manager().ok_or(UDbgError::NotSupport)?.enum_module())
    }
    fn find_module(&self, module: usize) -> Option<Arc<dyn UDbgModule>> {
        self.symbol_manager()?.find_module(module)
    }
    fn get_module(&self, module: &str) -> Option<Arc<dyn UDbgModule>> {
        self.symbol_manager()?.get_module(module)
    }
    fn get_address_by_symbol(&self, symbol: &str) -> Option<usize> {
        let (left, right) = symbol.find('!')
        .map(|pos| ((&symbol[..pos]).trim(), (&symbol[pos + 1..]).trim()))
        .unwrap_or((symbol, ""));
        if right.is_empty() {
            if let Some(m) = self.get_module(left) {
                // as module name
                Some(m.data().base)
            } else {
                // as symbol name
                self.enum_module().ok()?.filter_map(|m| m.get_symbol(left).map(|s| s.offset as usize + m.data().base)).next()
            }
        } else {
            let m = self.get_module(left)?;
            let d = m.data();
            if right == "$entry" { return Some(d.entry + d.base); }
            m.get_symbol(right).map(|s| d.base + s.offset as usize)
        }
    }
    fn get_symbol(&self, addr: usize, max_offset: usize) -> Option<SymbolInfo> {
        self.find_module(addr).and_then(|m| {
            let d = m.data();
            let offset = addr - d.base;
            m.find_symbol(offset, max_offset).and_then(|s| {
                let soffset = offset - s.offset as usize;
                if soffset > max_offset { return None; }
                Some(SymbolInfo {
                    mod_base: d.base, offset: soffset, module: d.name.clone(),
                    symbol: if let Some(n) = self.base().undec_sym(s.name.as_ref()) { n.into() } else { s.name }
                })
            }).or_else(|| /* if let Some((b, e, _)) = m.find_function(offset) {
                Some(SymbolInfo { mod_base: d.base, offset: offset - b as usize, module: d.name.clone(), symbol: format!("${:x}", d.base + b as usize).into() })
            } else */ if max_offset > 0 {
                Some(SymbolInfo { mod_base: d.base, offset, module: d.name.clone(), symbol: "".into() })
            } else { None })
        })
    }

    fn enum_handle<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=UiHandle>+'a>> { Err(UDbgError::NotSupport) }
    fn get_registers<'a>(&'a self) -> UDbgResult<&'a mut dyn UDbgRegs> {
        Err(UDbgError::NotSupport)
    }

    #[cfg(windows)]
    fn exception_context(&self) -> UDbgResult<PCONTEXT> {
        Err(UDbgError::NotSupport)
    }
    #[cfg(windows)]
    fn exception_record(&self) -> UDbgResult<PEXCEPTION_RECORD> {
        Err(UDbgError::NotSupport)
    }
    #[cfg(windows)]
    fn exception_pointers(&self) -> UDbgResult<EXCEPTION_POINTERS> {
        Ok(EXCEPTION_POINTERS {
            ExceptionRecord: self.exception_record()?,
            ContextRecord: self.exception_context()?,
        })
    }

    fn except_param(&self, i: usize) -> Option<usize> { None }
    fn lua_call(&self, s: &State) -> UDbgResult<i32> { Ok(0) }
    fn sync_option(&self, s: &State) -> UDbgResult<()> { Err(UDbgError::NotSupport) }
    fn do_cmd(&self, cmd: &str) -> UDbgResult<()> { Err(UDbgError::NotSupport) }

    fn loop_event(self: Arc<Self>, state: UEventState) -> EventPumper;
}

pub trait UDbgDebug: UDbgAdaptor {}

pub trait UDbgAdaptorUtil {
    fn read_ptr(&self, a: usize) -> Option<usize>;
    fn write_ptr(&self, a: usize, p: usize) -> Option<usize>;
}

impl<'a> UDbgAdaptorUtil for dyn UDbgAdaptor + 'a {
    fn read_ptr(&self, a: usize) -> Option<usize> {
        if self.base().is_ptr32() {
            self.read_value::<u32>(a).map(|r| r as usize)
        } else {
            self.read_value::<u64>(a).map(|r| r as usize)
        }
    }

    fn write_ptr(&self, a: usize, p: usize) -> Option<usize> {
        if self.base().is_ptr32() {
            self.write_value(a, &(p as u32))
        } else {
            self.write_value(a, &(p as u64))
        }
    }
}

use crate::range::RangeValue;

impl RangeValue for UiMemory {
    #[inline]
    fn as_range(&self) -> core::ops::Range<usize> { self.base..self.base+self.size }
}

impl RangeValue for MemoryPage {
    #[inline]
    fn as_range(&self) -> core::ops::Range<usize> { self.base..self.base+self.size }
}

use llua::State;

pub trait UiProxy {
    fn with_lua(&self, cb: &dyn Fn(&State));
    fn register_engine(&self, name: &str, engine: Box<dyn UDbgEngine>);

    fn target(&self) -> Option<Arc<dyn UDbgAdaptor>>;

    fn user_reply(&self, r: UserReply);

    fn log_(&self, level: u32, msg: &str);
    fn logc(&self, c: u32, msg: &str);

    #[cfg(windows)]
    fn new_symgr(&self) -> Arc<dyn UDbgSymMgr>;
    fn get_util(&self) -> &'static dyn UDbgUtil;
}

pub trait UiUtil {
    fn log(&self, data: impl AsRef<str>);
    fn warn(&self, err: impl AsRef<str>);
    fn info(&self, err: impl AsRef<str>);
    fn error(&self, err: impl AsRef<str>);
}

const INFO: u32 = 3;
const LOG: u32 = 4;
const WARN: u32 = 5;
const ERROR: u32 = 6;

impl<T: UiProxy + ?Sized> UiUtil for T {
    #[inline(always)]
    fn log(&self, data: impl AsRef<str>) { self.log_(LOG, data.as_ref()); }
    #[inline(always)]
    fn warn(&self, err: impl AsRef<str>) { self.log_(WARN, err.as_ref()); }
    #[inline(always)]
    fn error(&self, err: impl AsRef<str>) { self.log_(ERROR, err.as_ref()); }
    #[inline(always)]
    fn info(&self, msg: impl AsRef<str>) { self.log_(INFO, msg.as_ref()); }
}

pub trait UDbgUtil {
    #[cfg(windows)]
    fn enum_process_handle<'a>(&self, pid: pid_t, p: HANDLE) -> UDbgResult<Box<dyn Iterator<Item = UiHandle> + 'a>>;
    #[cfg(not(windows))]
    fn enum_process_handle<'a>(&self, pid: pid_t) -> UDbgResult<Box<dyn Iterator<Item = UiHandle> + 'a>> {
        Err(UDbgError::NotSupport)
    }
    #[cfg(windows)]
    fn get_memory_map(&self, p: &Process, this: &dyn UDbgAdaptor) -> Vec<UiMemory>;
    #[cfg(windows)]
    fn open_all_thread(&self, p: &Process, pid: pid_t) -> Vec<(tid_t, Box<dyn UDbgThread>)>;
}

pub static mut UDBG_UI: Option<Arc<dyn UiProxy>> = None;

#[no_mangle]
pub fn plugin_load(ui: &Arc<dyn UiProxy>) -> bool {
    unsafe {
        let loaded = UDBG_UI.is_some();
        UDBG_UI.get_or_insert_with(|| ui.clone());
        loaded
    }
}

pub fn udbg_ui() -> &'static dyn UiProxy {
    unsafe { UDBG_UI.as_ref().expect("plugin not inited").as_ref() }
}

#[cfg(windows)]
pub fn undecorate_symbol(sym: &str, flags: UFlags) -> Option<String> {
    use msvc_demangler::*;

    let mut sym_flags = DemangleFlags::COMPLETE;
    if flags.contains(UFlags::UNDEC_NAME_ONLY) {
        sym_flags = DemangleFlags::NAME_ONLY;
    } else {
        // if flags & UFLAG_UNDEC_TYPE == 0 { sym_flags |= DemangleFlags::NO_ARGUMENTS; }
        if !flags.contains(UFlags::UNDEC_RETN) { sym_flags |= DemangleFlags::NO_FUNCTION_RETURNS; }
    }

    demangle(sym, sym_flags).ok()
}

#[cfg(not(windows))]
pub fn undecorate_symbol(sym: &str, flags: UFlags) -> Option<String> {
    use cpp_demangle::{Symbol, DemangleOptions};
    Symbol::new(sym).ok().and_then(|s| {
        let mut opts = DemangleOptions::new();
        if flags.contains(UFlags::UNDEC_TYPE) { opts = opts.no_params(); }
        if flags.contains(UFlags::UNDEC_RETN) { opts = opts.no_return_type(); }
        s.demangle(&opts).ok()
    })
}

#[cfg(windows)]
pub fn enum_psinfo() -> Box<dyn Iterator<Item=PsInfo>> {
    use crate::*;
    use winapi::um::winnt::*;

    Box::new(enum_process().map(|p| {
        let pid = p.pid();
        let mut result = PsInfo {
            pid, name: p.name(), wow64: false,
            // window: get_window(pid).map(|w| w.get_text()).unwrap_or(String::new()),
            path: String::new(),
            cmdline: String::new(),
        };
        Process::open(pid, Some(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)).map(|p| {
            result.wow64 = p.is_wow64();
            p.image_path().map(|path| result.path = path);
            p.cmdline().map(|cmd| result.cmdline = cmd);
        });
        result
    }))
}

#[cfg(not(windows))]
pub fn enum_psinfo() -> Box<dyn Iterator<Item=PsInfo>> {
    Box::new(enum_pid().map(|pid| {
        PsInfo {
            pid, wow64: false,
            name: process_name(pid).unwrap_or(String::new()),
            path: process_path(pid).unwrap_or(String::new()),
            cmdline: process_cmdline(pid).join(" "),
        }
    }))
}