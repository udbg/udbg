use super::*;

use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::{HashMap, HashSet};
use std::mem::transmute;
use std::ops::Deref;
use std::ptr::null_mut;
use std::sync::Arc;

use ntapi::FIELD_OFFSET;
use winapi::um::winnt::CONTEXT_ALL;
use winapi::um::{errhandlingapi::GetLastError, winnt::CONTEXT_DEBUG_REGISTERS};

use crossbeam::atomic::AtomicCell;
use ntapi::ntexapi::SYSTEM_THREAD_INFORMATION;
use ntapi::ntpebteb::{PEB, TEB};
use parking_lot::RwLock;
use serde_value::Value as SerdeVal;
use windows::Win32::{
    Foundation::*,
    Storage::FileSystem::GETFINALPATHNAMEBYHANDLE_FLAGS,
    System::{
        Diagnostics::Debug::*, Kernel::NT_TIB, Memory::*, ProcessStatus::*, SystemInformation::*,
        Threading::*,
    },
};

use super::ntdll::*;
use crate::{pe::PeHelper, range::*, register::*, shell::udbg_ui};

#[repr(u32)]
#[derive(Copy, Clone, PartialEq)]
pub enum HandleResult {
    Continue = winapi::um::winnt::DBG_CONTINUE,
    Handled = winapi::um::winnt::DBG_EXCEPTION_HANDLED,
    NotHandled = winapi::um::winnt::DBG_EXCEPTION_NOT_HANDLED,
}

// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/specific-exceptions
// pub const DBG_PRINTEXCEPTION_C: u32 = 0x40010006;
// pub const DBG_PRINTEXCEPTION_WIDE_C: u32 = 0x4001000A;

pub struct Module {
    pub data: ModuleData,
    pub syms: SymbolsData,
    pub funcs: Vec<RUNTIME_FUNCTION>,
    file: HANDLE,
}

impl Module {}

impl GetProp for Module {
    fn get_prop(&self, key: &str) -> UDbgResult<SerdeVal> {
        Ok(SerdeVal::String(match key {
            "pdb_sig" => self.syms.pdb_sig.to_string(),
            "pdb_name" => self.syms.pdb_name.to_string(),
            "pdb_path" => self
                .syms
                .pdb
                .read()
                .as_ref()
                .map(|s| s.path().to_string())
                .unwrap_or_default(),
            _ => return Ok(SerdeVal::Unit),
        }))
    }
}

impl UDbgModule for Module {
    fn data(&self) -> &ModuleData {
        &self.data
    }
    // fn is_32(&self) -> bool { IS_ARCH_X64 || IS_ARCH_ARM64 }
    fn symbol_status(&self) -> SymbolStatus {
        if self.syms.pdb.read().is_some() {
            SymbolStatus::Loaded
        } else {
            SymbolStatus::Unload
        }
    }

    fn symbols_data(&self) -> Option<&SymbolsData> {
        Some(&self.syms)
    }

    fn runtime_function(&self) -> Option<&[RUNTIME_FUNCTION]> {
        self.funcs.as_slice().into()
    }
}

fn system_root() -> &'static str {
    static mut ROOT: Option<Box<str>> = None;
    unsafe {
        ROOT.get_or_insert_with(|| {
            std::env::var("SystemRoot")
                .map(Into::into)
                .unwrap_or_else(|_| r"C:\Windows".into())
        })
    }
}

impl TargetSymbol for SymbolManager<Module> {
    fn check_load_module(
        &self,
        read: &dyn ReadMemory,
        base: usize,
        size: usize,
        path: &str,
        file: HANDLE,
    ) -> bool {
        use goblin::pe::header::*;

        let mut symgr = self.base.write();
        if symgr.exists(base) {
            return false;
        }
        // println!("check_load_module: {:x} {} {}", base, path, symgr.list.len());

        let ui = udbg_ui();
        let mut buf = vec![0u8; 0x1000];
        let mmap = map_or_open(file, path);
        let m = match &mmap {
            Ok(m) => m,
            Err(err) => {
                ui.warn(format!("map {path} failed: {err:?}"));
                if read.read_memory(base, &mut buf).is_none() {
                    ui.error(format!("read pe falied: {:x} {}", base, path));
                    return false;
                }
                buf.as_slice()
            }
        };
        let h = match Header::parse(&m) {
            Ok(h) => h,
            Err(err) => {
                ui.error(format!("parse {} failed: {:?}", path, err));
                return false;
            }
        };
        let o = match &h.optional_header {
            Some(o) => o,
            None => {
                ui.error(format!("no optional_header: {}", path));
                return false;
            }
        };
        let name = match path.rfind(|c| c == '\\' || c == '/') {
            Some(p) => &path[p + 1..],
            None => &path,
        };

        let entry = o.standard_fields.address_of_entry_point as usize;
        let size = if size > 0 {
            size
        } else {
            o.windows_fields.size_of_image as usize
        };
        let arch = PeHelper::arch_name(h.coff_header.machine).unwrap_or_default();
        // info!("load {:x} {} {}", base, arch, name);

        let mut name: Arc<str> = name.into();
        if self.is_wow64.get() && h.coff_header.machine == COFF_MACHINE_X86_64 {
            name = match name.as_ref() {
                "ntdll.dll" => "ntdll64.dll".into(),
                _ => name,
            };
        }
        let root = system_root();
        let data = ModuleData {
            user_module: (unicase::Ascii::new(root)
                != path.chars().take(root.len()).collect::<String>())
            .into(),
            base,
            size,
            entry,
            arch,
            name,
            path: path.into(),
        };

        let mut funcs: Vec<RUNTIME_FUNCTION> = Default::default();
        let syms = if let Ok(pe) = PeHelper::parse(&m) {
            funcs = pe.runtime_functions();
            pe.symbols_data(path)
        } else {
            SymbolsData::default()
        };
        symgr.add(Module {
            data,
            funcs,
            syms: syms.into(),
            file,
        });
        true
    }
}

#[derive(Deref)]
pub struct TargetCommon {
    #[deref]
    _base: CommonBase,
    pub protected_thread: RwLock<Vec<u32>>,
    pub context: Cell<*mut CONTEXT>,
    pub cx32: Cell<*mut CONTEXT32>,
    pub show_debug_string: Cell<bool>,
    pub uspy_tid: Cell<u32>,
    hwbps: UnsafeCell<CONTEXT>,
}

impl<T> GetProp for T
where
    T: Deref<Target = TargetCommon>,
{
    default fn get_prop(&self, key: &str) -> UDbgResult<SerdeVal> {
        Ok(match key {
            "peb" => SerdeVal::U64(self.process.peb().ok_or(UDbgError::NotFound)? as _),
            "wow64" => SerdeVal::Bool(self.symgr.is_wow64.get()),
            "handle" => SerdeVal::U64(self.process.handle.as_winapi() as usize as _),
            _ => return Err(UDbgError::NotFound),
        })
    }
}

impl<T> TargetMemory for T
where
    T: Deref<Target = TargetCommon> + UDbgTarget,
{
    default fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        self.deref().enum_memory()
    }

    default fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        self.deref().virtual_query(address)
    }

    default fn collect_memory_info(&self) -> Vec<MemoryPage> {
        collect_memory_info(&self.process, self)
    }
}

impl<T> TargetControl for T
where
    T: Deref<Target = TargetCommon>,
{
    default fn detach(&self) -> UDbgResult<()> {
        self.base.status.set(UDbgStatus::Detaching);
        Ok(())
    }

    default fn breakk(&self) -> UDbgResult<()> {
        self.base.check_attached()?;
        unsafe {
            DebugBreakProcess(*self.process.handle)?;
        }
        Ok(())
    }

    default fn suspend(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }

    default fn resume(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }

    default fn kill(&self) -> UDbgResult<()> {
        self.terminate_process()
    }

    default fn wait_exit(&self, timeout: Option<u32>) -> UDbgResult<Option<u32>> {
        Ok(if self.wait_process_exit(timeout) {
            self.process.get_exit_code()
        } else {
            None
        })
    }
}

impl TargetCommon {
    pub fn new(p: Process) -> TargetCommon {
        let ui = udbg_ui();
        let image_base = p
            .peb()
            .and_then(|peb| p.read_value::<PEB>(peb))
            .map(|peb| peb.ImageBaseAddress)
            .unwrap_or(null_mut()) as usize;
        let mut base = CommonBase::new(p);
        let sds = ui.get_config::<bool>("show_debug_string").unwrap_or(true);
        base.symgr.is_wow64.set(base.process.is_wow64());
        base.image_base = image_base;

        let result = Self {
            _base: base,
            show_debug_string: sds.into(),
            protected_thread: vec![].into(),
            cx32: Cell::new(null_mut()),
            context: Cell::new(null_mut()),
            uspy_tid: Cell::new(0),
            hwbps: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        };
        result.check_all_module(&result.process);
        result
    }

    fn hwbps(&self) -> &mut CONTEXT {
        unsafe { self.hwbps.get().as_mut().unwrap() }
    }

    pub fn get_mapped_file_name(&self, module: usize) -> Option<String> {
        self.process.get_mapped_file_name(module)
    }

    pub fn get_registers(&self, tid: u32) -> windows::core::Result<Registers> {
        let handle = ThreadHandle::open(tid, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, false)?;
        handle
            .suspend_context(CONTEXT_FLAGS(CONTEXT_ALL))
            .map(|ctx| context_to_regs(&ctx))
    }

    pub fn set_thread_context(&self, tid: u32, context: &CONTEXT) -> windows::core::Result<()> {
        let handle = ThreadHandle::open(tid, THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT, false)?;
        handle.suspend_set_context(context)
    }

    pub fn terminate_process(&self) -> UDbgResult<()> {
        self.process.terminate()?;
        Ok(())
    }

    pub fn wait_process_exit(&self, timeout: Option<u32>) -> bool {
        unsafe {
            WAIT_TIMEOUT != {
                WaitForSingleObject(*self.process.handle, timeout.unwrap_or(INFINITE))
            }
        }
    }

    #[inline(always)]
    pub fn bp_exists(&self, id: BpID) -> bool {
        self.bp_map.read().get(&id).is_some()
    }

    fn get_bp(&self, id: BpID) -> Option<Arc<Breakpoint>> {
        Some(self.bp_map.read().get(&id)?.clone())
    }

    pub fn user_handle_exception<T: UDbgTarget>(
        &self,
        first: bool,
        tb: &mut TraceBuf<T>,
    ) -> HandleResult {
        let reply = tb.call(UEvent::Exception {
            first,
            code: tb.record.code,
        });
        if reply == UserReply::Run(true) {
            HandleResult::Continue
        } else {
            HandleResult::NotHandled
        }
    }

    pub fn handle_breakpoint<C: DbgContext, T: Deref<Target = Self> + UDbgTarget>(
        &self,
        eh: &mut dyn EventHandler<T>,
        first: bool,
        tb: &mut TraceBuf<T>,
        context: &mut C,
    ) -> HandleResult {
        let address = tb.record.address;
        let step = matches!(
            NTSTATUS(tb.record.code as _),
            STATUS_WX86_BREAKPOINT | EXCEPTION_SINGLE_STEP
        );
        // info!("record: {:x?}", tb.record);
        let possible_hwbp = step || cfg!(target_arch = "aarch64");
        let id = address as BpID;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let get_hwbp = || context.hwbp_index();
        #[cfg(any(target_arch = "aarch64"))]
        let get_hwbp = || self.hwbps().hwbp_index(tb.record.params[1] as _);
        if let Some(bp) = self.get_bp(id).or_else(|| {
            possible_hwbp
                .then(get_hwbp)
                .flatten()
                .map(|i| -(i + 1))
                .and_then(|hwid| self.get_bp(hwid))
        }) {
            if let InnerBpType::Hard(info) = bp.bp_type {
                // check the address for HWBP
                if info.rw == HwbpType::Execute as u8 && bp.address as u64 != address {
                    return HandleResult::NotHandled;
                }
                if !bp.temp.get() {
                    // disable the HWBP temporarily
                    context.disable_hwbp_temporarily();
                }
            }
            self.handle_bp_has_data(eh, bp, tb, context)
        } else {
            // breakpoint not exists, it's possible a step action from user
            let tid = self.base.event_tid.get();
            if step && self.step_tid.get() == tid {
                self.step_tid.set(0);
                self.handle_reply(tb.target.clone().as_ref(), tb.call(UEvent::Step), context);
                return HandleResult::Continue;
            }
            HandleResult::NotHandled
        }
    }

    pub fn handle_bp_has_data<C: DbgContext, T: Deref<Target = Self> + UDbgTarget>(
        &self,
        eh: &mut dyn EventHandler<T>,
        bp: Arc<Breakpoint>,
        tb: &mut TraceBuf<T>,
        context: &mut C,
    ) -> HandleResult {
        let this = tb.target.clone();
        let this = this.as_ref();

        bp.hit_count.set(bp.hit_count.get() + 1);
        if bp.temp.get() {
            self.remove_breakpoint(this, &bp);
        }

        // correct the pc register
        let pc = match bp.bp_type {
            InnerBpType::Table { origin, .. } => C::REG::from_usize(origin),
            InnerBpType::Soft(_) | InnerBpType::Hard { .. } => {
                C::REG::from_usize(tb.record.address as usize)
            }
        };
        // info!("correct the pc: {:x}", pc.to_usize());
        *context.ip() = pc;

        // handle by user
        let tid = self.base.event_tid.get();
        let hitted = bp.hit_tid.map(|t| t == tid).unwrap_or(true);
        if hitted {
            self.handle_reply(this, tb.call(UEvent::Breakpoint(bp.clone())), context);
        }

        let id = bp.get_id();
        // int3 breakpoint revert
        if bp.is_soft() && self.get_bp(id).is_some() {
            // if bp is not deleted by user during the interruption
            if bp.enabled.get() {
                // disabled temporarily, in order to be able to continue
                self.enable_breadpoint(this, &bp, false)
                    .log_error("disable bp");

                // step once and revert
                let user_step = context.is_step();
                if !user_step {
                    context.set_step(true);
                }
                eh.cont(HandleResult::Handled, tb);
                loop {
                    match eh.fetch(tb) {
                        Some(_) => {
                            if core::ptr::eq(self, tb.target.deref().deref())
                                && self.base.event_tid.get() == tid
                            {
                                // TODO: maybe other exception?
                                // assert!(matches!(
                                //     tb.record.code,
                                //     EXCEPTION_SINGLE_STEP | EXCEPTION_WX86_SINGLE_STEP
                                // ));
                                if !matches!(
                                    tb.record.code_status(),
                                    EXCEPTION_SINGLE_STEP | STATUS_WX86_SINGLE_STEP
                                ) {
                                    udbg_ui().warn(format!(
                                        "[bp]@{:x} expect step, but {:x} occured",
                                        bp.address, tb.record.code
                                    ));
                                    return HandleResult::NotHandled;
                                }
                                break;
                            } else if let Some(s) = eh.handle(tb) {
                                eh.cont(s, tb);
                            } else {
                                return HandleResult::Handled;
                            }
                        }
                        None => return HandleResult::Handled,
                    }
                }
                self.enable_breadpoint(this, &bp, true)
                    .log_error("enable bp");
                return if user_step {
                    eh.handle(tb).unwrap_or(HandleResult::Handled)
                } else {
                    // avoid to set context in the subsequent
                    self.cx32.set(null_mut());
                    self.context.set(null_mut());

                    HandleResult::Continue
                };
            }
        }
        HandleResult::Continue
    }

    pub fn handle_possible_table_bp<C: DbgContext, T: Deref<Target = Self> + UDbgTarget>(
        &self,
        eh: &mut dyn EventHandler<T>,
        tb: &mut TraceBuf<T>,
        context: &mut C,
    ) -> HandleResult {
        let pc = if C::IS_32 {
            context.ip().to_usize() as i32 as isize
        } else {
            context.ip().to_usize() as isize
        };
        // info!("exception address: {:x}", pc);
        if pc > 0 {
            return HandleResult::NotHandled;
        }

        // self.get_bp(pc as BpID).map(|bp| self.handle_bp_has_data(tid, &bp, record, context)).unwrap_or(C::NOT_HANDLED)
        if let Some(bp) = self.get_bp(pc as BpID) {
            self.handle_bp_has_data(eh, bp, tb, context)
        } else {
            HandleResult::NotHandled
        }
    }

    pub fn open_thread(&self, tid: u32) -> UDbgResult<Box<WinThread>> {
        WinThread::open(&self.process, tid)
    }

    pub fn enum_thread<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = u32> + 'a>> {
        Ok(Box::new(self.process.enum_thread()?.map(|e| e.tid())))
    }

    pub fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        Ok(Box::new(MemoryIter {
            dbg: self,
            address: 0,
        }))
    }

    pub fn enable_hwbp_for_thread(
        &self,
        handle: HANDLE,
        info: HwbpInfo,
        enable: bool,
    ) -> anyhow::Result<bool> {
        let mut result = Ok(enable);
        let mut cx = unsafe { Align16::<CONTEXT>::new_zeroed() };
        let mut wow64cx = unsafe { Align16::<WOW64_CONTEXT>::new_zeroed() };
        let context = cx.as_mut();
        let cx32 = wow64cx.as_mut();
        cx32.ContextFlags = WOW64_CONTEXT_FLAGS(CONTEXT_DEBUG_REGISTERS);
        context.ContextFlags = CONTEXT_FLAGS(CONTEXT_DEBUG_REGISTERS);
        unsafe {
            let handle = ThreadHandle::borrow_raw(&handle);
            let tid = handle.tid();
            let count = handle.suspend() as i32;
            if count < 0 {
                udbg_ui().error(format!(
                    "SuspendThread: {tid}:{handle:?} {}",
                    GetLastError()
                ));
            }
            #[cfg(target_arch = "aarch64")]
            self.enable_hwbp_for_context(self.hwbps(), info, enable);

            for _ in 0..1 {
                if let Err(err) = handle.get_context(context) {
                    result = Err(err.into());
                    break;
                }
                self.enable_hwbp_for_context(context, info, enable);
                if let Err(err) = handle.set_context(context) {
                    result = Err(err.into());
                    break;
                }
                #[cfg(target_arch = "x86_64")]
                if handle.get_wow64_context(cx32).is_ok() {
                    self.enable_hwbp_for_context(cx32, info, enable);
                    handle.set_wow64_context(cx32);
                }
            }
            handle.resume();
        }
        result
    }

    pub fn enable_all_hwbp_for_thread(&self, handle: HANDLE, enable: bool) {
        for i in 0..4 {
            self.get_bp(-i).map(|bp| {
                if let InnerBpType::Hard(info) = bp.bp_type {
                    self.enable_hwbp_for_thread(handle, info, enable).ok();
                }
            });
        }
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
        for tid in self.enum_thread()? {
            // Ignore threads
            if self.protected_thread.read().contains(&tid) {
                continue;
            }
            if bp.hit_tid.is_some() && bp.hit_tid != Some(tid) {
                continue;
            }
            // Set Debug Register
            let th = match dbg.open_thread(tid) {
                Ok(r) => r,
                Err(e) => {
                    udbg_ui().error(format!("open thread {} failed {:?}", tid, e));
                    continue;
                }
            };
            result = self.enable_hwbp_for_thread(**th.handle, info, enable);
            if let Err(e) = &result {
                udbg_ui().error(format!("enable_hwbp_for_thread for {} failed {:?}", tid, e));
                // break;
            }
        }
        // Set Context for current thread
        for _ in 0..1 {
            if bp.hit_tid.is_some() && bp.hit_tid != Some(self.base.event_tid.get()) {
                break;
            }
            if !self.context.get().is_null() {
                self.enable_hwbp_for_context(
                    unsafe { self.context.get().as_mut().unwrap() },
                    info,
                    enable,
                );
            }
            let cx32 = self.cx32.get();
            if !cx32.is_null() {
                self.enable_hwbp_for_context(
                    unsafe { self.cx32.get().as_mut().unwrap() },
                    info,
                    enable,
                );
            }
        }
        // TODO: wow64
        if result.is_ok() {
            bp.enabled.set(enable);
        }
        Ok(result?)
    }

    pub fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        self.process.virtual_query(address)
    }

    pub fn get_symbol(&self, addr: usize, max_offset: usize) -> Option<SymbolInfo> {
        self.symgr.base.read().get_symbol_info(addr, max_offset)
    }

    pub fn check_all_module(&self, dbg: &dyn ReadMemory) {
        let mut rest_loaded = HashSet::new();
        for m in self.symgr.enum_module() {
            rest_loaded.insert(m.data().base);
        }
        // for m in self.process.enum_module() {
        //     let base = m.base();
        //     rest_loaded.remove(&base);
        //     self.symgr.check_load_module(dbg, base, m.size(), m.path().as_ref(), null_mut());
        // }
        for m in self
            .process
            .get_module_list(LIST_MODULES_ALL)
            .unwrap_or_default()
        {
            rest_loaded.remove(&m);
            if self.symgr.base.read().exists(m) {
                continue;
            }

            #[allow(deprecated)]
            let path = self
                .process
                .get_mapped_file_name(m)
                // get_module_path() returns 64-bit path in WOW64 process, so put it last
                .unwrap_or_else(|| self.process.get_module_path(m).unwrap_or_default());
            self.process.get_module_info(m).map(|m| {
                self.symgr.check_load_module(
                    dbg,
                    m.lpBaseOfDll as usize,
                    m.SizeOfImage as usize,
                    path.as_ref(),
                    Default::default(),
                );
            });
        }
        // 移除已经卸载了的模块
        for m in rest_loaded {
            // println!("remove: {:x}", m);
            self.symgr.remove(m);
        }
    }

    pub fn output_debug_string(&self, dbg: &dyn UDbgTarget, address: usize, count: usize) {
        if self.base.flags.get().contains(UDbgFlags::SHOW_OUTPUT) {
            if let Some(s) = dbg.read_utf8_or_ansi(address, count) {
                udbg_ui().debug(&s);
            }
        }
    }

    pub fn output_debug_string_wide(&self, dbg: &dyn UDbgTarget, address: usize, count: usize) {
        if self.base.flags.get().contains(UDbgFlags::SHOW_OUTPUT) {
            if let Some(s) = dbg.read_wstring(address, count) {
                udbg_ui().debug(&s);
            }
        }
    }
}

pub fn check_dont_set_hwbp() -> bool {
    udbg_ui().get_config("DONT_SET_HWBP").unwrap_or(false)
}

pub trait NtHeader {
    fn as_32(&self) -> &IMAGE_NT_HEADERS32;
    fn as_64(&self) -> &IMAGE_NT_HEADERS64;
    fn is_32(&self) -> bool;
}

impl NtHeader for IMAGE_NT_HEADERS {
    #[inline]
    fn as_32(&self) -> &IMAGE_NT_HEADERS32 {
        unsafe { transmute(self) }
    }
    #[inline]
    fn as_64(&self) -> &IMAGE_NT_HEADERS64 {
        unsafe { transmute(self) }
    }
    #[inline]
    fn is_32(&self) -> bool {
        self.FileHeader.Machine == IMAGE_FILE_MACHINE_I386.0
    }
}

impl MemoryPage {
    pub fn page_type(&self) -> PAGE_TYPE {
        PAGE_TYPE(self.type_)
    }
}

pub fn collect_memory_info(p: &Process, this: &dyn UDbgTarget) -> Vec<MemoryPage> {
    const PAGE_SIZE: usize = 0x1000;
    const MAX_HEAPS: usize = 1000;

    let peb = p.peb().unwrap_or_default();
    let mut result = this
        .enum_memory()
        .unwrap()
        .map(|mut page| {
            let mut usage = String::new();
            let mut flags = match page.page_type() {
                MEM_PRIVATE => MemoryFlags::PRIVATE,
                MEM_IMAGE => MemoryFlags::IMAGE,
                MEM_MAPPED => MemoryFlags::MAP,
                _ => MemoryFlags::Normal,
            };
            if page.base == 0x7FFE0000 {
                usage.push_str("KUSER_SHARED_DATA");
            } else if page.base == peb {
                usage.push_str("PEB");
                flags |= MemoryFlags::PEB;
            }

            page.flags = flags;
            page.info = Some(usage.into());
            page
        })
        .collect::<Vec<_>>();

    // Mark the thread's stack
    for t in this.enum_thread(false).unwrap() {
        let stack = t.teb().and_then(|teb| {
            this.read_value::<NT_TIB>(teb + FIELD_OFFSET!(TEB, NtTib))
                .map(|tib| tib.StackLimit as usize)
        });
        stack.map(|stack| {
            RangeValue::binary_search_mut(&mut result, stack).map(|m| {
                m.info = Some(format!("Stack ~{}", t.tid).into());
                m.flags |= MemoryFlags::STACK;
            })
        });
    }

    // Mark the process heaps
    let heaps_num = if peb > 0 {
        this.read_value::<u32>(peb + FIELD_OFFSET!(PEB, NumberOfHeaps))
            .unwrap_or(0)
    } else {
        0
    } as usize;

    if heaps_num > 0 && heaps_num < MAX_HEAPS {
        let mut buf = vec![0usize; heaps_num];
        this.read_value::<usize>(peb + FIELD_OFFSET!(PEB, ProcessHeaps))
            .map(|p_heaps| {
                let len = this.read_to_array(p_heaps, &mut buf);
                buf.resize(len, 0);
            });
        for i in 0..buf.len() {
            RangeValue::binary_search_mut(&mut result, buf[i]).map(|m| {
                m.info = Some(format!("Heap #{}", i).into());
                m.flags |= MemoryFlags::HEAP;
            });
        }
    }

    // Mark the Executable modules
    let mut i = 0;
    while i < result.len() {
        let mut module = 0usize;
        let mut module_size = 0usize;
        let sections: Option<Vec<IMAGE_SECTION_HEADER>> = {
            let m = &mut result[i];
            i += 1;
            p.get_mapped_file_name(m.base).and_then(|p| {
                module = m.base;
                m.info = Some(p.into());
                if !m.flags.contains(MemoryFlags::IMAGE) {
                    return None;
                }

                this.read_nt_header(m.base).map(|(nt, nt_offset)| {
                    module_size = if nt.is_32() {
                        nt.as_32().OptionalHeader.SizeOfImage
                    } else {
                        nt.as_64().OptionalHeader.SizeOfImage
                    } as usize;
                    let p_section_header = module
                        + nt_offset
                        + FIELD_OFFSET!(IMAGE_NT_HEADERS, OptionalHeader)
                        + nt.FileHeader.SizeOfOptionalHeader as usize;
                    let mut buf = vec![
                        unsafe { core::mem::zeroed::<IMAGE_SECTION_HEADER>() };
                        nt.FileHeader.NumberOfSections as usize
                    ];
                    this.read_to_array(p_section_header, &mut buf);
                    buf
                })
            })
        };
        if let Some(sections) = sections {
            while i < result.len() && result[i].base - module < module_size {
                let m = &mut result[i];
                i += 1;
                sections
                    .iter()
                    .find(|sec| m.base == sec.VirtualAddress as usize + module)
                    .map(|sec| {
                        let name = &sec.Name;
                        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                        let name = &name[..len];
                        let sec_name = unsafe { std::str::from_utf8_unchecked(name) };
                        m.info = Some(sec_name.into());
                        m.flags |= MemoryFlags::SECTION;
                    });
            }
        }
    }
    result
}

pub struct MemoryIter<'a> {
    dbg: &'a TargetCommon,
    address: usize,
}

impl<'a> Iterator for MemoryIter<'a> {
    type Item = MemoryPage;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(p) = self.dbg.virtual_query(self.address) {
            self.address += p.size;
            if p.is_commit() {
                return Some(p);
            }
        }
        return None;
    }
}

#[derive(Deref)]
pub struct ProcessTarget {
    #[deref]
    pub _common: TargetCommon,
    pub record: UnsafeCell<ExceptionRecord>,
    pub threads: RefCell<HashMap<u32, DbgThread>>,
    pub attached: Cell<bool>, // create by attach
}

unsafe impl Send for ProcessTarget {}
unsafe impl Sync for ProcessTarget {}

impl ProcessTarget {
    pub fn open(pid: u32) -> UDbgResult<Arc<ProcessTarget>> {
        let p = Process::open(pid, None)?;
        Ok(Self::new(p))
    }

    fn new(p: Process) -> Arc<Self> {
        Arc::new(Self {
            _common: TargetCommon::new(p),
            record: UnsafeCell::new(unsafe { core::mem::zeroed() }),
            threads: HashMap::new().into(),
            attached: false.into(),
        })
    }

    pub fn try_load_module(&self, pname: usize, base: usize, file: HANDLE, unicode: bool) {
        use std::path::Path;
        // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
        use windows::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

        let this: &dyn UDbgTarget = self;
        let mut path = this.read_ptr(pname).and_then(|a| {
            if unicode {
                self.process.read_wstring(a, MAX_PATH as usize)
            } else {
                self.process.read_utf8_or_ansi(a, MAX_PATH as usize)
            }
        });
        // Win7上ntdll.dll得到的是相对路径
        let exists = path
            .as_ref()
            .map(|p| Path::new(p).exists())
            .unwrap_or_default();
        if !exists {
            path = self.process.get_mapped_file_name(base).or_else(|| unsafe {
                let mut buf = [0u16; 500];
                if GetFinalPathNameByHandleW(file, &mut buf, GETFINALPATHNAMEBYHANDLE_FLAGS(2)) > 0
                {
                    to_dos_path(&mut buf)
                        .map(String::from_wide)
                        .or_else(|| Some(String::from_wide(&buf)))
                } else {
                    error!("GetFinalPathNameByHandleW");
                    None
                }
            });
        }
        if let Some(path) = path {
            self.symgr.check_load_module(self, base, 0, &path, file);
            // self.base().module_load(&path, base);
        } else {
            error!("get path of module: 0x{:x} failed", base);
        }
    }

    #[inline]
    pub fn record(&self) -> &mut ExceptionRecord {
        unsafe { &mut *self.record.get() }
    }

    pub fn context(&self) -> Option<&mut CONTEXT> {
        unsafe { transmute(self.context.get()) }
    }

    pub fn open_thread(&self, tid: u32) -> UDbgResult<Box<WinThread>> {
        if let Some(t) = self.threads.borrow().get(&tid) {
            let wow64 = self.symgr.is_wow64.get();
            let handle = ThreadHandle(unsafe { Handle::clone_from_raw(t.handle) }?);
            Ok(Box::new(WinThread {
                base: ThreadData {
                    tid: t.tid,
                    wow64,
                    handle,
                },
                process: &self.process,
                teb: AtomicCell::new(t.local_base),
                detail: None,
            }))
        } else {
            self._common.open_thread(tid)
        }
    }

    pub fn get_context<C: DbgContext>(&self, tid: u32, context: &mut C) -> bool {
        if let Some(t) = self.threads.borrow().get(&tid) {
            context.get_context(t.handle)
        } else {
            warn!("thread {} not found in debugger", tid);
            get_thread_context(tid, context, CONTEXT_ALL)
        }
    }

    pub fn set_context<C: DbgContext>(&self, tid: u32, c: &C) {
        let suc = if let Some(t) = self.threads.borrow().get(&tid) {
            c.set_context(t.handle)
        } else {
            warn!("thread {} not found in debugger", tid);
            set_thread_context(tid, c)
        };
        if !suc {
            error!(
                "fatal: SetThreadContext {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[inline(always)]
pub fn wait_for_debug_event(timeout: u32) -> Option<DEBUG_EVENT> {
    unsafe {
        let mut dv: DEBUG_EVENT = core::mem::zeroed();
        if WaitForDebugEvent(&mut dv, timeout).is_err() {
            None
        } else {
            Some(dv)
        }
    }
}

#[inline(always)]
pub fn continue_debug_event(pid: u32, tid: u32, status: NTSTATUS) -> bool {
    unsafe { ContinueDebugEvent(pid, tid, status).is_ok() }
}

impl Target for ProcessTarget {
    fn base(&self) -> &TargetBase {
        &self.base
    }

    fn process(&self) -> Option<&Process> {
        Some(&self.process)
    }

    fn handle(&self) -> HANDLE {
        *self.process.handle
    }

    fn symbol_manager(&self) -> Option<&dyn TargetSymbol> {
        Some(&self.symgr)
    }

    fn enum_module<'a>(
        &'a self,
    ) -> UDbgResult<Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a>> {
        if self.base.check_attached().is_err() {
            self.check_all_module(self);
        }
        Ok(self.symgr.enum_module())
    }

    fn open_thread(&self, tid: u32) -> Result<Box<dyn UDbgThread>, UDbgError> {
        ProcessTarget::open_thread(self, tid).map(|r| r as Box<dyn UDbgThread>)
    }

    fn enum_thread(
        &self,
        detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>> {
        enum_udbg_thread(&self.process, self.base.pid.get(), detail, Some(self))
    }

    fn enum_handle<'a>(&'a self) -> Result<Box<dyn Iterator<Item = HandleInfo> + 'a>, UDbgError> {
        Ok(Box::new(
            self.process.enum_handle(self.base.pid.get().into()),
        ))
    }
}

impl UDbgTarget for ProcessTarget {}

pub struct TraceBuf<'a, T = ProcessTarget> {
    pub callback: *mut UDbgCallback<'a>,
    pub target: Arc<T>,
    pub record: ExceptionRecord,
    pub wow64: bool,
    pub cx: *mut CONTEXT,
    pub cx32: *mut CONTEXT32,
    pub first_bp_hitted: bool,
    pub first_bp32_hitted: bool,
}

impl<T: UDbgTarget> TraceBuf<'_, T> {
    #[inline]
    pub fn call(&mut self, event: UEvent) -> UserReply {
        self.target.base().context_arch.set(self.arch());
        unsafe { (self.callback.as_mut().unwrap())(self, event) }
    }
}

impl<T: UDbgTarget> TraceContext for TraceBuf<'_, T> {
    fn register(&mut self) -> Option<&mut dyn UDbgRegs> {
        if self.wow64 {
            Some(unsafe { self.cx32.as_mut() }?)
        } else {
            Some(unsafe { self.cx.as_mut() }?)
        }
    }

    fn target(&self) -> Arc<dyn UDbgTarget> {
        self.target.clone()
    }

    fn exception_param(&self, i: usize) -> Option<usize> {
        self.record.params.get(i).map(|v| *v as usize)
    }

    fn arch(&self) -> u32 {
        if self.wow64 {
            ARCH_X86
        } else {
            UDBG_ARCH
        }
    }
}

pub trait EventHandler<T = ProcessTarget> {
    /// fetch a debug event
    fn fetch(&mut self, buf: &mut TraceBuf<T>) -> Option<()>;
    /// handle the debug event
    fn handle(&mut self, buf: &mut TraceBuf<T>) -> Option<HandleResult>;
    /// continue debug event
    fn cont(&mut self, _: HandleResult, buf: &mut TraceBuf<T>);
}

pub fn enum_udbg_thread<'a>(
    p: *const Process,
    pid: u32,
    detail: bool,
    a: Option<&'a ProcessTarget>,
) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + 'a>> {
    let mut info_iter = detail
        .then(system_process_information)
        .transpose()?
        .map(|spi| spi.flat_map(|iter| iter.threads().iter()));

    let mut cache: HashMap<u32, Box<SYSTEM_THREAD_INFORMATION>> = HashMap::new();
    let mut threads = enum_thread()?.filter(move |t| t.pid() == pid);
    Ok(Box::new(core::iter::from_fn(move || {
        let thread = threads.next()?;
        let tid = thread.th32ThreadID;
        let mut info = cache.remove(&tid);
        if info.is_none() {
            info_iter
                .as_mut()
                .and_then(|sp| {
                    sp.find(|&t| {
                        let result = t.ClientId.UniqueThread as u32 == tid;
                        if !result && t.ClientId.UniqueProcess as u32 == pid {
                            cache.insert(t.ClientId.UniqueThread as u32, Box::new(*t));
                        }
                        result
                    })
                })
                .map(|si| {
                    info = Some(Box::new(*si));
                });
        }
        let mut result = a
            .and_then(|a| ProcessTarget::open_thread(a, tid).ok())
            .or_else(|| WinThread::open(p, tid).ok())
            .or_else(|| Some(Box::new(WinThread::new(tid)?)))?;
        result.detail = info;
        Some(result as Box<dyn UDbgThread>)
    })))
}

pub struct DefaultEngine {
    targets: Vec<Arc<ProcessTarget>>,
    event: DEBUG_EVENT,
}

impl Default for DefaultEngine {
    fn default() -> Self {
        Self {
            targets: vec![],
            event: unsafe { core::mem::zeroed() },
        }
    }
}

impl DefaultEngine {
    fn update_context(&mut self, tb: &mut TraceBuf) {
        let this = tb.target.clone();
        let cx = unsafe { tb.cx.as_mut().unwrap() };
        if this.get_context(self.event.dwThreadId, cx) {
            this.context.set(cx);
        } else {
            warn!(
                "get_thread_context {} failed {}",
                self.event.dwThreadId,
                std::io::Error::last_os_error()
            );
        }
    }
}

impl UDbgEngine for DefaultEngine {
    fn open(&mut self, pid: u32) -> UDbgResult<Arc<dyn UDbgTarget>> {
        let result = ProcessTarget::open(pid)?;
        self.targets.push(result.clone());
        Ok(result)
    }

    fn attach(&mut self, pid: u32) -> UDbgResult<Arc<dyn UDbgTarget>> {
        unsafe {
            DebugActiveProcess(pid)?;
            let result = ProcessTarget::open(pid)?;
            result.attached.set(true);
            self.targets.push(result.clone());
            Ok(result)
        }
    }

    fn create(
        &mut self,
        path: &str,
        cwd: Option<&str>,
        args: &[&str],
    ) -> UDbgResult<Arc<dyn UDbgTarget>> {
        let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
        let ppid = udbg_ui().get_config("ppid");
        let result = ProcessTarget::new(create_debug_process(path, cwd, args, &mut pi, ppid)?);
        self.targets.push(result.clone());
        Ok(result)
    }

    fn event_loop(&mut self, callback: &mut UDbgCallback) -> UDbgResult<()> {
        let mut cx = unsafe { Align16::<CONTEXT>::new_zeroed() };
        let mut cx32 = unsafe { core::mem::zeroed() };

        let target = self
            .targets
            .iter()
            .next()
            .map(Clone::clone)
            .expect("no attached target");
        target.base.status.set(UDbgStatus::Attached);

        let mut buf = TraceBuf {
            callback,
            wow64: false,
            target,
            cx: cx.as_mut(),
            cx32: &mut cx32,
            record: unsafe { core::mem::zeroed() },
            first_bp_hitted: false,
            first_bp32_hitted: false,
        };

        while let Some(s) = self.fetch(&mut buf).and_then(|_| self.handle(&mut buf)) {
            self.cont(s, &mut buf);
        }

        Ok(())
    }
}

impl EventHandler for DefaultEngine {
    fn fetch(&mut self, tb: &mut TraceBuf) -> Option<()> {
        self.event = wait_for_debug_event(INFINITE)?;
        if self.event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
            if self
                .targets
                .iter()
                .find(|p| p.base.pid.get() == self.event.dwProcessId)
                .is_none()
            {
                let target =
                    ProcessTarget::open(self.event.dwProcessId).expect("attach child process");
                target
                    .base
                    .status
                    .set(if udbg_ui().base().trace_child.get() {
                        UDbgStatus::Attached
                    } else {
                        UDbgStatus::Detaching
                    });
                self.targets.push(target);
            }
        }

        let this = self
            .targets
            .iter()
            .find(|p| p.base.pid.get() == self.event.dwProcessId)
            .expect("not a traced process")
            .clone();

        tb.target = this.clone();
        let base = &this.base;
        base.event_tid.set(self.event.dwThreadId);
        if self.event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            tb.record
                .copy(unsafe { &self.event.u.Exception.ExceptionRecord });
            *this.record() = tb.record;
        }
        Some(())
    }

    fn handle(&mut self, tb: &mut TraceBuf) -> Option<HandleResult> {
        let mut cotinue_status = HandleResult::Continue;
        unsafe {
            use UEvent::*;

            let tid = self.event.dwThreadId;
            let this = tb.target.clone();
            let this = this.as_ref();
            let base = &this.base;

            match self.event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    if this.status.get() == UDbgStatus::Detaching {
                        self.targets.pop();
                        return Some(cotinue_status);
                    }
                    let info = self.event.u.CreateProcessInfo;
                    if info.hThread.is_invalid() {
                        udbg_ui().error(format!("CREATE_PROCESS_DEBUG_EVENT {}", tid));
                    }
                    this.threads
                        .borrow_mut()
                        .insert(tid, DbgThread::from(&info));
                    this.try_load_module(
                        info.lpImageName as usize,
                        info.lpBaseOfImage as usize,
                        info.hFile,
                        info.fUnicode > 0,
                    );
                    self.update_context(tb);
                    tb.call(ProcessCreate);
                    tb.call(ThreadCreate(tid));
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    self.update_context(tb);
                    let code = self.event.u.ExitProcess.dwExitCode;
                    tb.call(ProcessExit(code));
                    self.targets
                        .retain(|p| p.base.pid.get() != self.event.dwProcessId);
                    if self.targets.is_empty() {
                        return None;
                    }
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let info = self.event.u.CreateThread;
                    if info.hThread.is_invalid() {
                        udbg_ui().error(format!("CREATE_THREAD_DEBUG_EVENT {}", tid));
                    }
                    if !check_dont_set_hwbp() {
                        this.enable_all_hwbp_for_thread(info.hThread, true);
                    }
                    this.threads
                        .borrow_mut()
                        .insert(tid, DbgThread::from(&info));
                    self.update_context(tb);
                    tb.call(ThreadCreate(tid));
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    self.update_context(tb);
                    this.threads.borrow_mut().remove(&tid);
                    this.context.set(null_mut());
                    tb.call(ThreadExit(self.event.u.ExitThread.dwExitCode));
                }
                LOAD_DLL_DEBUG_EVENT => {
                    self.update_context(tb);
                    // https://docs.microsoft.com/zh-cn/windows/win32/api/minwinbase/ns-minwinbase-load_dll_debug_info
                    let info = self.event.u.LoadDll;
                    this.try_load_module(
                        info.lpImageName as usize,
                        info.lpBaseOfDll as usize,
                        info.hFile,
                        info.fUnicode > 0,
                    );
                    if let Some(m) = this.symgr.find_module(info.lpBaseOfDll as usize) {
                        tb.call(ModuleLoad(m));
                    }
                }
                UNLOAD_DLL_DEBUG_EVENT => {
                    self.update_context(tb);
                    let info = &self.event.u.UnloadDll;
                    let base = info.lpBaseOfDll as usize;
                    // let path = self.process.get_module_path(base).unwrap_or("".into());
                    if let Some(m) = this.symgr.find_module(base) {
                        tb.call(ModuleUnload(m));
                    }
                    this.symgr.remove(base);
                }
                OUTPUT_DEBUG_STRING_EVENT => {
                    if this.show_debug_string.get() {
                        let s = self.event.u.DebugString;
                        if s.fUnicode > 0 {
                            this.output_debug_string_wide(
                                this,
                                s.lpDebugStringData.0 as usize,
                                s.nDebugStringLength as usize,
                            );
                        } else {
                            this.output_debug_string(
                                this,
                                s.lpDebugStringData.0 as usize,
                                s.nDebugStringLength as usize,
                            );
                        }
                    } else {
                        cotinue_status = HandleResult::NotHandled;
                    }
                }
                RIP_EVENT => {
                    // https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-rip_info
                    let info = self.event.u.RipInfo;
                    udbg_ui().error(format!(
                        "RIP_EVENT: Error: {:x} Type: {:?}",
                        info.dwError, info.dwType
                    ));
                }
                EXCEPTION_DEBUG_EVENT => {
                    self.update_context(tb);
                    let first = self.event.u.Exception.dwFirstChance > 0;
                    // align the context's address with 16
                    let cx = tb.cx.as_mut().unwrap();
                    let cx32 = tb.cx32.as_mut().unwrap();

                    let record = this.record();
                    let wow64 = this.symgr.is_wow64.get()
                        && match NTSTATUS(record.code) {
                            STATUS_WX86_BREAKPOINT
                            | STATUS_WX86_SINGLE_STEP
                            | STATUS_WX86_UNSIMULATE
                            | STATUS_WX86_INTERNAL_ERROR
                            | STATUS_WX86_FLOAT_STACK_CHECK => true,
                            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                            _ => cx.SegCs == 0x23,
                            #[cfg(any(target_arch = "aarch64"))]
                            _ => false,
                        };
                    // println!("record.code: {:x} wow64: {}", record.code, wow64);
                    tb.wow64 = wow64;
                    if wow64 {
                        this.get_context(tid, cx32);
                        *cx32.ip() = u32::from_usize(this.record().address as usize);
                        this.cx32.set(cx32);
                    }
                    cotinue_status = match record.code_status() {
                        STATUS_WX86_BREAKPOINT => {
                            if tb.first_bp32_hitted {
                                this.handle_breakpoint(self, first, tb, cx32)
                            } else {
                                tb.first_bp32_hitted = true;
                                this.handle_reply(this, tb.call(InitBp), cx32);
                                HandleResult::NotHandled
                            }
                        }
                        EXCEPTION_BREAKPOINT => {
                            if tb.first_bp_hitted {
                                this.handle_breakpoint(self, first, tb, cx)
                            } else {
                                tb.first_bp_hitted = true;
                                // 创建32位进程时忽略 附加32位进程时不忽略
                                if !this.symgr.is_wow64.get() || this.attached.get() {
                                    this.handle_reply(this, tb.call(InitBp), cx);
                                }
                                HandleResult::Continue
                            }
                        }
                        STATUS_WX86_SINGLE_STEP => {
                            let mut result = this.handle_breakpoint(self, first, tb, cx);
                            if result == HandleResult::NotHandled {
                                result = this.user_handle_exception(first, tb);
                            }
                            result
                        }
                        EXCEPTION_SINGLE_STEP => {
                            let mut result = this.handle_breakpoint(self, first, tb, cx);
                            if result == HandleResult::NotHandled {
                                result = this.user_handle_exception(first, tb);
                            }
                            result
                        }
                        code => {
                            if code == STATUS_WX86_CREATEWX86TIB {
                                info!("STATUS_WX86_CREATEWX86TIB");
                            }
                            let mut result = if code == EXCEPTION_ACCESS_VIOLATION {
                                if wow64 {
                                    this.handle_possible_table_bp(self, tb, cx32)
                                } else {
                                    this.handle_possible_table_bp(self, tb, cx)
                                }
                            } else {
                                HandleResult::NotHandled
                            };
                            if result == HandleResult::NotHandled
                                && this.base.status.get() != UDbgStatus::Detaching
                            {
                                result = this.user_handle_exception(first, tb);
                            }
                            result
                        }
                    };
                }
                _code => panic!("Invalid DebugEventCode {_code:?}"),
            };
        }

        Some(cotinue_status)
    }

    fn cont(&mut self, status: HandleResult, tb: &mut TraceBuf) {
        let this = tb.target.clone();
        let cx32 = this.cx32.get();
        if !cx32.is_null() {
            this.set_context(self.event.dwThreadId, unsafe { &*cx32 });
            this.cx32.set(null_mut());
        } else {
            let cx = this.context.get();
            if !cx.is_null() {
                this.set_context(self.event.dwThreadId, unsafe { &*cx });
            }
        }
        this.context.set(null_mut());
        continue_debug_event(
            self.event.dwProcessId,
            self.event.dwThreadId,
            NTSTATUS(status as _),
        );

        if this.status.get() == UDbgStatus::Detaching {
            if unsafe { DebugActiveProcessStop(self.event.dwProcessId).is_err() } {
                udbg_ui().error(format!(
                    "detach {}: {:?}",
                    self.event.dwProcessId,
                    UDbgError::system()
                ));
            }
            self.targets.retain(|t| !Arc::ptr_eq(&this, t));
        }
    }
}
