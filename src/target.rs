//!
//! Traits && types for debugger target
//!

use core::ops::Deref;
use std::cell::Cell;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::sync::Arc;

#[cfg(windows)]
use winapi::um::winnt::{EXCEPTION_POINTERS, PCONTEXT, PEXCEPTION_RECORD};

pub use crate::os::udbg::*;
use crate::{prelude::*, regs::*};

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
            psize: core::mem::size_of::<usize>().into(),
        }
    }
}

impl PauseContext {
    pub fn update(&self, arch: u32) {
        self.arch.set(arch);
        match arch {
            ARCH_X86 | ARCH_ARM => self.psize.set(4),
            ARCH_X64 | ARCH_ARM64 => self.psize.set(8),
            _ => {}
        };
    }
}

/// Common data for debugger target
#[derive(Clone, Serialize)]
pub struct TargetBase {
    /// process id of target
    pub pid: Cell<pid_t>,
    /// thread id of target triggers the debug event
    pub event_tid: Cell<tid_t>,
    pub event_pc: Cell<usize>,
    /// executable image path of target
    pub image_path: String,
    pub image_base: usize,
    /// architecture of target, one value of the [std::env::consts::ARCH]
    pub arch: &'static str,
    /// if the target is a [WOW64](https://docs.microsoft.com/en-us/windows/win32/winprog64/running-32-bit-applications) process
    #[cfg(windows)]
    pub wow64: Cell<bool>,
    #[serde(skip)]
    pub flags: Cell<UFlags>,
    #[serde(skip)]
    pub context: PauseContext,
    #[serde(skip)]
    pub status: Cell<UDbgStatus>,
}

impl Default for TargetBase {
    fn default() -> Self {
        Self {
            image_path: "".into(),
            image_base: 0,
            context: Default::default(),
            event_pc: Default::default(),
            event_tid: Default::default(),
            pid: Cell::new(0),
            flags: Default::default(),
            #[cfg(windows)]
            wow64: Cell::new(false),
            arch: std::env::consts::ARCH,
            status: Cell::new(UDbgStatus::Attached),
        }
    }
}

impl TargetBase {
    #[inline]
    pub fn is_ptr32(&self) -> bool {
        self.ptrsize() == 4
    }

    #[inline]
    pub fn ptrsize(&self) -> usize {
        self.context.psize.get()
    }

    pub fn update_arch(&self, arch: u32) {
        if arch == self.context.arch.get() {
            return;
        }
        self.context.update(arch);
        udbg_ui().update_arch(arch);
    }

    pub fn is_opened(&self) -> bool {
        self.status.get() == UDbgStatus::Opened
    }

    pub fn is_paused(&self) -> bool {
        self.status.get() == UDbgStatus::Paused
    }

    pub fn check_opened(&self) -> UDbgResult<()> {
        if self.is_opened() {
            Err(UDbgError::NotSupport)
        } else {
            Ok(())
        }
    }

    #[inline(always)]
    pub fn undec_sym(&self, sym: &str) -> Option<String> {
        crate::util::undecorate_symbol(sym, self.flags.get())
    }
}

/// Thread information for UI
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub entry: usize,
    pub teb: usize,
    pub name: Arc<str>,
    pub status: Arc<str>,
    pub priority: Arc<str>,
}

/// Handle/FD information for UI
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct HandleInfo {
    pub ty: u32,
    pub handle: usize,
    pub type_name: String,
    pub name: String,
}

/// Common thread fields
pub struct ThreadData {
    pub tid: tid_t,
    pub wow64: bool,
    #[cfg(windows)]
    pub handle: crate::Handle,
    #[cfg(target_os = "macos")]
    pub handle: crate::process::ThreadAct,
}

#[cfg(windows)]
pub type ThreadContext = winapi::um::winnt::CONTEXT;
#[cfg(windows)]
pub type ThreadContext32 = super::regs::CONTEXT32;

pub trait UDbgThread: Deref<Target = ThreadData> + GetProp {
    fn name(&self) -> Arc<str> {
        "".into()
    }
    fn status(&self) -> Arc<str> {
        "".into()
    }

    /// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority#return-value
    #[cfg(windows)]
    fn priority(&self) -> Option<i32> {
        None
    }

    #[cfg(not(windows))]
    fn priority(&self) -> Arc<str> {
        "".into()
    }

    fn suspend(&self) -> IoResult<i32> {
        Err(ErrorKind::Unsupported.into())
    }
    fn resume(&self) -> IoResult<u32> {
        Err(ErrorKind::Unsupported.into())
    }
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
}

/// Debug Engine
pub trait UDbgEngine {
    fn enum_process(&self) -> Box<dyn Iterator<Item = crate::util::PsInfo>> {
        crate::util::enum_psinfo()
    }

    fn open(&self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Err(UDbgError::NotSupport)
    }

    fn open_self(&self) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        self.open(std::process::id() as _)
    }

    fn attach(&self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>>;

    fn create(
        &self,
        path: &str,
        cwd: Option<&str>,
        args: &[&str],
    ) -> UDbgResult<Arc<dyn UDbgAdaptor>>;
}

pub type UDbgCallback<'a> = dyn FnMut(UEvent) -> UserReply + 'a;

#[cfg(windows)]
pub trait AdaptorSpec {
    fn exception_context(&self) -> UDbgResult<PCONTEXT> {
        Err(UDbgError::NotSupport)
    }

    fn exception_record(&self) -> UDbgResult<PEXCEPTION_RECORD> {
        Err(UDbgError::NotSupport)
    }

    fn exception_pointers(&self) -> UDbgResult<EXCEPTION_POINTERS> {
        Ok(EXCEPTION_POINTERS {
            ExceptionRecord: self.exception_record()?,
            ContextRecord: self.exception_context()?,
        })
    }
}

#[cfg(not(windows))]
pub trait AdaptorSpec {}

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
}

/// Represent a debugable target, could be a process, core dump, etc.
pub trait Target: GetProp + TargetMemory + TargetControl + BreakpointManager {
    fn base(&self) -> &TargetBase;

    /// the process handle, if target is a process
    #[cfg(windows)]
    fn handle(&self) -> winapi::um::winnt::HANDLE {
        core::ptr::null_mut()
    }

    fn enum_thread(
        &self,
        detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>>;

    fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<dyn UDbgThread>> {
        Err(UDbgError::NotSupport)
    }

    // optional symbol manager
    fn symbol_manager(&self) -> Option<&dyn UDbgSymMgr> {
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
                    symbol: if let Some(n) = self.base().undec_sym(s.name.as_ref()) { n.into() } else { s.name }
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

pub trait UDbgAdaptor: Send + Sync + Target + 'static {
    fn get_registers(&self) -> UDbgResult<&mut dyn UDbgRegs> {
        Err(UDbgError::NotSupport)
    }

    fn except_param(&self, i: usize) -> Option<usize> {
        None
    }

    fn do_cmd(&self, cmd: &str) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }

    fn event_loop<'a>(&self, callback: &mut UDbgCallback<'a>) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
}

pub trait UDbgDebug: UDbgAdaptor {}

pub trait AdaptorUtil: UDbgAdaptor {
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

    fn get_reg(&self, r: &str) -> UDbgResult<CpuReg> {
        self.get_registers()?
            .get_reg(get_regid(r).ok_or(UDbgError::InvalidRegister)?)
            .ok_or(UDbgError::InvalidRegister)
    }

    fn set_reg(&self, r: &str, val: CpuReg) -> UDbgResult<()> {
        self.get_registers()?
            .set_reg(get_regid(r).ok_or(UDbgError::InvalidRegister)?, val);
        Ok(())
    }

    fn parse_address(&self, symbol: &str) -> Option<usize> {
        let (mut left, right) = match symbol.find('+') {
            Some(pos) => ((&symbol[..pos]).trim(), Some((&symbol[pos + 1..]).trim())),
            None => (symbol.trim(), None),
        };

        let mut val = if let Ok(val) = self.get_reg(left) {
            val.as_int()
        } else {
            if left.starts_with("0x") || left.starts_with("0X") {
                left = &left[2..];
            }
            if let Ok(address) = usize::from_str_radix(left, 16) {
                address
            } else {
                self.get_address_by_symbol(left)?
            }
        };

        if let Some(right) = right {
            val += self.parse_address(right)?;
        }

        Some(val)
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
            let image_path = &self.base().image_path;
            for m in self.enum_module().ok()? {
                let path = m.data().path.clone();
                #[cfg(windows)]
                {
                    if path.eq_ignore_ascii_case(&image_path) {
                        return Some(m);
                    }
                }
                #[cfg(not(windows))]
                {
                    if path.as_ref() == image_path {
                        return Some(m);
                    }
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

    fn loop_event<
        U: std::future::Future<Output = ()> + 'static,
        F: FnOnce(Arc<Self>, UEventState) -> U,
    >(
        self: Arc<Self>,
        callback: F,
    ) {
        let state = UEventState::new();
        let mut fetcher = ReplyFetcher::new(Box::pin(callback(self.clone(), state.clone())), state);
        self.event_loop(&mut |event| fetcher.fetch(event).unwrap_or(UserReply::Run(false)));
        fetcher.fetch(None);
    }
}
impl<'a, T: UDbgAdaptor + ?Sized + 'a> AdaptorUtil for T {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub trait AdaptorArchUtil: UDbgAdaptor {
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
pub trait AdaptorArchUtil: UDbgAdaptor {
    #[inline(always)]
    fn check_call(&self, address: usize) -> Option<usize> {
        todo!();
    }
}

impl<'a, T: UDbgAdaptor + ?Sized + 'a> AdaptorArchUtil for T {}
