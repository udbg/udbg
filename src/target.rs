//!
//! Traits && types for debugger target, such as memory page, module, thread, process, etc., and their iterators.
//!

use crate::os::{priority_t, Module, Process};
use crate::{pe::*, prelude::*, register::*};

use core::ops::Deref;
use parking_lot::RwLock;
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::io::{ErrorKind, Result as IoResult};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum UDbgStatus {
    Opened,
    Attached,
    Detaching,
    Detached,
}

impl UDbgStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            UDbgStatus::Opened => "opened",
            UDbgStatus::Attached => "attached",
            UDbgStatus::Detaching => "detaching",
            UDbgStatus::Detached => "detached",
        }
    }
}

impl FromStr for UDbgStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "opened" => UDbgStatus::Opened,
            "attached" => UDbgStatus::Attached,
            "detaching" => UDbgStatus::Detaching,
            "detached" => UDbgStatus::Detached,
            _ => return Err(()),
        })
    }
}

/// Common data for debugger target
#[derive(Debug, Clone, Serialize)]
pub struct TargetBase {
    /// Process ID of target, if target is a process
    pub pid: Cell<pid_t>,
    /// Thread ID of target triggers the debug event
    pub event_tid: Cell<tid_t>,
    /// Module base address of executable image
    pub image_base: usize,
    /// Architecture of target, one value of the [std::env::consts::ARCH]
    pub arch: &'static str,
    /// Context architecture when target interruptted
    pub context_arch: Cell<u32>,
    #[serde(skip)]
    pub flags: Cell<UDbgFlags>,
    #[serde(skip)]
    pub status: Cell<UDbgStatus>,
}

impl Default for TargetBase {
    fn default() -> Self {
        Self {
            image_base: 0,
            event_tid: Default::default(),
            pid: Cell::new(0),
            flags: Default::default(),
            arch: std::env::consts::ARCH,
            context_arch: Cell::new(UDBG_ARCH),
            status: Cell::new(UDbgStatus::Opened),
        }
    }
}

impl TargetBase {
    #[inline]
    pub fn is_ptr32(&self) -> bool {
        self.pointer_size() == 4
    }

    /// if the target is a [WOW64](https://docs.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications) process
    #[inline]
    pub fn is_wow64(&self) -> bool {
        self.context_arch.get() == ARCH_X86
    }

    #[inline]
    pub fn status(&self) -> UDbgStatus {
        self.status.get()
    }

    #[inline]
    pub fn pointer_size(&self) -> usize {
        match self.context_arch.get() {
            ARCH_X86 | ARCH_ARM => 4,
            _ => core::mem::size_of::<usize>(),
        }
    }

    pub fn check_attached(&self) -> UDbgResult<()> {
        if self.status.get() < UDbgStatus::Attached {
            Err(UDbgError::NotAttached)
        } else {
            Ok(())
        }
    }
}

#[derive(Deref, DerefMut)]
pub struct CommonBase {
    #[deref]
    #[deref_mut]
    pub base: TargetBase,
    pub process: Process,
    pub step_tid: Cell<tid_t>,
    pub symgr: SymbolManager<Module>,
    pub bp_map: RwLock<HashMap<BpID, Arc<Breakpoint>>>,
    pub dbg_reg: [Cell<usize>; 4],
}

impl CommonBase {
    pub fn new(ps: Process) -> Self {
        let base = TargetBase::default();
        base.pid.set(ps.pid());
        Self {
            base,
            process: ps,
            step_tid: Cell::new(0),
            symgr: Default::default(),
            dbg_reg: Default::default(),
            bp_map: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_hwbp_index(&self) -> Option<usize> {
        for (i, p) in self.dbg_reg.iter().enumerate() {
            if p.get() == 0 {
                return Some(i);
            }
        }
        None
    }

    pub fn set_hwbp(&self, index: usize, p: usize) {
        self.dbg_reg.get(index).map(|cell| cell.set(p));
    }

    #[inline]
    pub fn enable_hwbp_for_context<C: HWBPRegs>(&self, cx: &mut C, info: HwbpInfo, enable: bool) {
        let i = info.index as usize;
        if enable {
            cx.set_bp(self.dbg_reg[i].get(), i, info.rw, info.len);
        } else {
            cx.unset_bp(i);
        }
    }

    pub fn find_table_bp_index(&self) -> Option<isize> {
        for i in -10000..-10 {
            if self.bp_map.read().get(&i).is_none() {
                return Some(i);
            }
        }
        None
    }

    #[inline(always)]
    pub fn find_module(&self, address: usize) -> Option<Arc<Module>> {
        self.symgr.find_module(address)
    }

    #[inline(always)]
    pub fn bp_exists(&self, id: BpID) -> bool {
        self.bp_map.read().get(&id).is_some()
    }

    pub fn get_bp<'a>(&'a self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint>> {
        Some(self.bp_map.read().get(&id)?.clone())
    }
}

/// Common thread fields
pub struct ThreadData {
    pub tid: tid_t,
    pub wow64: bool,
    #[cfg(windows)]
    pub handle: crate::os::ThreadHandle,
    #[cfg(target_os = "macos")]
    pub handle: crate::os::macos::ThreadAct,
}

#[cfg(windows)]
pub type ThreadContext = windows::Win32::System::Diagnostics::Debug::CONTEXT;
#[cfg(windows)]
pub type ThreadContext32 = super::register::CONTEXT32;

/// Represents a thread in target
pub trait UDbgThread: Deref<Target = ThreadData> + GetProp {
    /// Thread name
    fn name(&self) -> Arc<str> {
        "".into()
    }

    fn status(&self) -> Arc<str> {
        "".into()
    }

    /// Get thread's priority
    fn priority(&self) -> Option<priority_t> {
        None
    }

    /// Suspend the thread, and return the suspend count if success
    fn suspend(&self) -> IoResult<i32> {
        Err(ErrorKind::Unsupported.into())
    }

    /// Resume the thread, and return the suspend count if success
    fn resume(&self) -> IoResult<u32> {
        Err(ErrorKind::Unsupported.into())
    }

    /// Get thread's suspend count
    fn suspend_count(&self) -> usize {
        0
    }

    #[cfg(windows)]
    fn get_context(&self, cx: &mut ThreadContext) -> IoResult<()> {
        Err(ErrorKind::Unsupported.into())
    }
    #[cfg(windows)]
    fn set_context(&self, cx: &ThreadContext) -> IoResult<()> {
        Err(ErrorKind::Unsupported.into())
    }
    #[cfg(windows)]
    fn get_context32(&self, cx: &mut ThreadContext32) -> IoResult<()> {
        Err(ErrorKind::Unsupported.into())
    }
    #[cfg(windows)]
    fn set_context32(&self, cx: &ThreadContext32) -> IoResult<()> {
        Err(ErrorKind::Unsupported.into())
    }
    #[cfg(windows)]
    fn teb(&self) -> Option<usize> {
        None
    }
    /// start address
    #[cfg(windows)]
    fn entry(&self) -> usize {
        0
    }
    fn last_error(&self) -> Option<u32> {
        None
    }

    #[cfg(windows)]
    fn terminate(&self) -> anyhow::Result<()> {
        self.handle.terminate(2)?;
        Ok(())
    }

    #[cfg(unix)]
    fn terminate(&self) -> anyhow::Result<()> {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.tid),
            nix::sys::signal::SIGTERM,
        )?;
        Ok(())
    }
}

impl core::fmt::Debug for dyn UDbgThread {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut ds = f.debug_struct("UDbgThread");
        ds.field("tid", &self.tid)
            .field("name", &self.name())
            .field("status", &self.status())
            .field("priority", &self.priority())
            .field("suspend_count", &self.suspend_count());
        #[cfg(windows)]
        ds.field("entry", &self.entry()).field("teb", &self.teb());
        ds.finish()
    }
}

/// Debugger Engine, interfaces of debugging
pub trait UDbgEngine {
    fn enum_process(&self) -> UDbgResult<Box<dyn Iterator<Item = ProcessInfo>>> {
        Ok(Box::new(ProcessInfo::enumerate()?))
    }

    /// Open a process, not attach, for non-invasive debugging purpose
    fn open(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgTarget>> {
        Err(UDbgError::NotSupport)
    }

    fn open_self(&mut self) -> UDbgResult<Arc<dyn UDbgTarget>> {
        self.open(std::process::id() as _)
    }

    /// Attach to a active process
    fn attach(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgTarget>>;

    /// Create and debug a process
    fn create(
        &mut self,
        path: &str,
        cwd: Option<&str>,
        args: &[&str],
    ) -> UDbgResult<Arc<dyn UDbgTarget>>;

    /// Start the debug event loop, with a event callback
    fn event_loop<'a>(&mut self, callback: &mut UDbgCallback<'a>) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }

    /// Start the debug event loop, wraps a async task as event callback
    fn task_loop(&mut self, mut task: DebugTask) -> UDbgResult<()> {
        self.event_loop(&mut |ctx, event| {
            task.state.ctx.set(unsafe { core::mem::transmute(ctx) });
            match task.run_step(event) {
                Some(reply) => reply,
                // None if ef.ended => {
                //     // TODO: kill all
                //     panic!("")
                // }
                None => UserReply::Run(false),
            }
        })
    }
}

pub type UDbgCallback<'a> = dyn FnMut(&mut dyn TraceContext, UEvent) -> UserReply + 'a;

/// Trait for getting property dynamically
pub trait GetProp {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        Err(UDbgError::NotSupport)
    }
}

/// Common interface for controlling the target running
pub trait TargetControl {
    /// detach from debugging target
    fn detach(&self) -> UDbgResult<()>;
    /// interrupt the target running
    fn breakk(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    /// kill target
    fn kill(&self) -> UDbgResult<()>;
    /// suspend target
    fn suspend(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    /// resume target
    fn resume(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    /// wait for target to exit
    fn wait_exit(&self, timeout: Option<u32>) -> UDbgResult<Option<u32>> {
        Err(UDbgError::NotSupport)
    }
}

/// Represent a debugable target, could be a process, core dump, etc.
pub trait Target: GetProp + TargetMemory + TargetControl {
    fn base(&self) -> &TargetBase;

    /// Return the reference of processs if self is a process
    fn process(&self) -> Option<&Process> {
        None
    }

    /// Executable image path of target
    fn image_path(&self) -> UDbgResult<String> {
        Ok(self.process().ok_or(UDbgError::NoTarget)?.image_path()?)
    }

    /// Raw process handle, if target is a process
    #[cfg(windows)]
    fn handle(&self) -> ::windows::Win32::Foundation::HANDLE {
        Default::default()
    }

    fn enum_thread(
        &self,
        detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>>;

    fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<dyn UDbgThread>> {
        Err(UDbgError::NotSupport)
    }

    // optional symbol manager
    fn symbol_manager(&self) -> Option<&dyn TargetSymbol> {
        None
    }
    fn enum_module(&self) -> UDbgResult<Box<dyn Iterator<Item = Arc<dyn UDbgModule + '_>> + '_>> {
        Ok(self
            .symbol_manager()
            .ok_or(UDbgError::NotSupport)?
            .enum_module())
    }
    fn find_module(&self, module: usize) -> Option<Arc<dyn UDbgModule>> {
        self.symbol_manager()?.find_module(module)
    }
    fn get_module(&self, module: &str) -> Option<Arc<dyn UDbgModule>> {
        self.symbol_manager()?.get_module(module)
    }
    fn get_address_by_symbol(&self, symbol: &str) -> Option<usize> {
        let (left, right) = symbol
            .find('!')
            .map(|pos| ((&symbol[..pos]).trim(), (&symbol[pos + 1..]).trim()))
            .unwrap_or((symbol, ""));
        if right.is_empty() {
            if let Some(m) = self.get_module(left) {
                // as module name
                Some(m.data().base)
            } else {
                // as symbol name
                self.enum_module()
                    .ok()?
                    .filter_map(|m| {
                        m.get_symbol(left)
                            .map(|s| s.offset as usize + m.data().base)
                    })
                    .next()
            }
        } else {
            let m = self.get_module(left)?;
            let d = m.data();
            if right == "$entry" {
                return Some(d.entry + d.base);
            }
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
                    symbol: if let Some(n) = Symbol::undecorate(s.name.as_ref(), self.base().flags.get()) { n.into() } else { s.name }
                })
            }).or_else(|| /* if let Some((b, e, _)) = m.find_function(offset) {
                Some(SymbolInfo { mod_base: d.base, offset: offset - b as usize, module: d.name.clone(), symbol: format!("${:x}", d.base + b as usize).into() })
            } else */ if max_offset > 0 {
                Some(SymbolInfo { mod_base: d.base, offset, module: d.name.clone(), symbol: "".into() })
            } else { None })
        })
    }

    fn enum_handle(&self) -> UDbgResult<Box<dyn Iterator<Item = HandleInfo> + '_>> {
        Err(UDbgError::NotSupport)
    }
}

/// Represent a debugable target, which is used in udbg
pub trait UDbgTarget: Send + Sync + Target + BreakpointManager + 'static {}

impl core::fmt::Debug for dyn UDbgTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let base = self.base();
        f.debug_struct("UDbgTarget")
            .field("pid", &base.pid.get())
            .field("image_path", &self.image_path())
            .finish()
    }
}

/// Practical functions based on [`UDbgTarget`]
pub trait TargetUtil: UDbgTarget {
    fn add_bp(&self, opt: impl Into<BpOpt>) -> UDbgResult<Arc<dyn UDbgBreakpoint>> {
        self.add_breakpoint(opt.into())
    }

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

    fn read_argument(
        &self,
        reg: &dyn UDbgRegs,
        i: usize,
        cc: Option<CallingConv>,
    ) -> Option<usize> {
        match reg.argument(i, cc) {
            Ok(id) => Some(reg.get_reg(id)?.as_int()),
            Err(n) => self.read_ptr(
                reg.get_reg(regid::COMM_REG_SP)?.as_int() + n * self.base().pointer_size(),
            ),
        }
    }

    fn get_symbol_(&self, addr: usize, o: Option<usize>) -> Option<SymbolInfo> {
        Target::get_symbol(self, addr, o.unwrap_or(0x100))
    }

    fn get_symbol_string(&self, addr: usize) -> Option<String> {
        self.get_symbol_(addr, None).map(|s| s.to_string(addr))
    }

    fn get_symbol_module_info(&self, addr: usize) -> Option<String> {
        self.find_module(addr).map(|m| {
            let data = m.data();
            let offset = addr - data.base;
            if offset > 0 {
                format!("{}+{:x}", data.name, offset)
            } else {
                data.name.to_string()
            }
        })
    }

    fn get_main_module<'a>(&'a self) -> Option<Arc<dyn UDbgModule + 'a>> {
        let base = self.base();
        if base.image_base > 0 {
            self.find_module(base.image_base)
        } else {
            let image_base = self.base().image_base;
            for m in self.enum_module().ok()? {
                if image_base == m.data().base {
                    return Some(m);
                }
            }
            None
        }
    }

    #[cfg(not(windows))]
    fn get_module_entry(&self, base: usize) -> usize {
        use goblin::elf32::header::Header as Header32;
        use goblin::elf64::header::Header as Header64;

        let mut buf = vec![0u8; core::mem::size_of::<Header64>()];
        if let Some(header) = self.read_memory(base, &mut buf) {
            base + Header64::parse(header)
                .ok()
                .map(|h| h.e_entry as usize)
                .or_else(|| Header32::parse(header).map(|h| h.e_entry as usize).ok())
                .unwrap_or_default()
        } else {
            0
        }
    }

    #[cfg(windows)]
    fn get_module_entry(&self, base: usize) -> usize {
        self.read_nt_header(base)
            .map(|(nt, _)| base + nt.OptionalHeader.AddressOfEntryPoint as usize)
            .unwrap_or(0)
    }

    fn detect_string(&self, a: usize, max: usize) -> Option<(bool, String)> {
        fn ascii_count(s: &str) -> usize {
            let mut r = 0usize;
            for c in s.chars() {
                if c.is_ascii() {
                    r += 1;
                }
            }
            return r;
        }
        // guess string
        #[cfg(windows)]
        let ws = self.read_wstring(a, max);
        #[cfg(not(windows))]
        let ws: Option<String> = None;
        if let Some(s) = self.read_utf8(a, max) {
            return if let Some(ws) = ws {
                if ascii_count(&s) > ascii_count(&ws) {
                    Some((false, s))
                } else {
                    Some((true, ws))
                }
            } else {
                Some((false, s))
            };
        }
        None
    }

    #[inline]
    fn pid(&self) -> pid_t {
        self.base().pid.get()
    }
}
impl<'a, T: UDbgTarget + ?Sized + 'a> TargetUtil for T {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub trait TargetArchUtil: UDbgTarget {
    fn disasm(&self, address: usize) -> Option<iced_x86::Instruction> {
        use iced_x86::{Decoder, DecoderOptions, Instruction};

        let buffer = self.read_bytes(address, MAX_INSN_SIZE);
        let mut decoder = Decoder::new(
            if self.base().is_ptr32() { 32 } else { 64 },
            buffer.as_slice(),
            DecoderOptions::NONE,
        );
        let mut insn = Instruction::default();
        if decoder.can_decode() {
            decoder.decode_out(&mut insn);
            Some(insn)
        } else {
            None
        }
    }

    #[inline(always)]
    fn check_call(&self, address: usize) -> Option<usize> {
        use iced_x86::Mnemonic::*;

        self.disasm(address).and_then(|insn| {
            if matches!(insn.mnemonic(), Call | Syscall | Sysenter) || insn.has_rep_prefix() {
                Some(address + insn.len())
            } else {
                None
            }
        })
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub trait TargetArchUtil: UDbgTarget {
    #[inline(always)]
    fn check_call(&self, address: usize) -> Option<usize> {
        todo!();
    }
}

impl<'a, T: UDbgTarget + ?Sized + 'a> TargetArchUtil for T {}

/// Context information during the debugging target interruption
pub trait TraceContext {
    /// Registers of debugging thread
    fn register(&mut self) -> Option<&mut dyn UDbgRegs>;
    /// Interruptted debugging target
    fn target(&self) -> Arc<dyn UDbgTarget>;
    /// Parameter of exception
    fn exception_param(&self, i: usize) -> Option<usize> {
        None
    }

    /// Context architecture, used for WOW64 debugging. Returned value is one of udbg::consts::ARCH_*
    fn arch(&self) -> u32 {
        crate::consts::UDBG_ARCH
    }

    fn pointer_size(&self) -> usize {
        match self.arch() {
            ARCH_X86 | ARCH_ARM => 4,
            _ => core::mem::size_of::<usize>(),
        }
    }
}

impl MemoryPage {
    #[inline]
    pub fn is_commit(&self) -> bool {
        if self.is_windows() {
            self.state & MEM_COMMIT > 0
        } else {
            true
        }
    }

    #[inline]
    pub fn is_reserve(&self) -> bool {
        if self.is_windows() {
            self.state & MEM_RESERVE > 0
        } else {
            false
        }
    }

    #[inline]
    pub fn is_free(&self) -> bool {
        if self.is_windows() {
            self.state & MEM_FREE > 0
        } else {
            false
        }
    }

    pub fn protect(&self) -> Cow<str> {
        if self.is_windows() {
            let result = match self.protect & !PAGE_GUARD {
                PAGE_NOACCESS => "-----",
                PAGE_READONLY => "-R---",
                PAGE_READWRITE => "-RW--",
                PAGE_WRITECOPY => "-RWC-",
                PAGE_EXECUTE => "E----",
                PAGE_EXECUTE_READ => "ER---",
                PAGE_EXECUTE_READWRITE => "ERW--",
                PAGE_EXECUTE_WRITECOPY => "ERWC-",
                _ => "?????",
            };
            if self.protect & PAGE_GUARD > 0 {
                let mut res = result.to_string();
                unsafe {
                    res.as_bytes_mut()[4] = b'G';
                }
                res.into()
            } else {
                result.into()
            }
        } else {
            unsafe { core::str::from_utf8_unchecked(self.as_linux_protect()) }.into()
        }
    }

    pub fn info(&self) -> &str {
        self.info.as_ref().map(AsRef::as_ref).unwrap_or_default()
    }

    pub fn type_(&self) -> &'static str {
        if self.is_windows() {
            match self.type_ {
                MEM_PRIVATE => "PRV",
                MEM_IMAGE => "IMG",
                MEM_MAPPED => "MAP",
                _ => "",
            }
        } else if self.is_private() {
            "PRV"
        } else if self.is_shared() {
            "SHR"
        } else {
            ""
        }
    }

    #[inline]
    pub fn is_private(&self) -> bool {
        if self.is_windows() {
            self.type_ & MEM_PRIVATE > 0
        } else {
            self.as_linux_protect()[3] == b'p'
        }
    }

    #[inline]
    pub fn is_shared(&self) -> bool {
        self.as_linux_protect()[3] == b's'
    }

    pub fn is_executable(&self) -> bool {
        if self.is_windows() {
            self.protect & 0xF0 > 0
        } else {
            self.as_linux_protect()[2] == b'x'
        }
    }

    pub fn is_writable(&self) -> bool {
        if self.is_windows() {
            self.protect & 0xCC > 0
        } else {
            self.as_linux_protect()[1] == b'w'
        }
    }

    pub fn is_readonly(&self) -> bool {
        if self.is_windows() {
            self.protect == PAGE_READONLY
        } else {
            self.as_linux_protect()[0] == b'r' && !self.is_writable() && !self.is_executable()
        }
    }
}
