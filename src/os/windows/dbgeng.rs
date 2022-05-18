//! Adaptive wrapper for microsoft's [dbgeng](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-overview)

use super::Handle;
use crate::prelude::*;
use std::{
    cell::Cell,
    collections::HashMap,
    ffi::CStr,
    sync::{self, Arc},
};

use anyhow::Context;
use parking_lot::RwLock;
use winapi::um::{
    libloaderapi::{GetProcAddress, LoadLibraryA},
    processthreadsapi::GetThreadId,
    winbase::{CREATE_NEW_CONSOLE, DEBUG_PROCESS},
    winnt::{CONTEXT, HANDLE},
};
use windows::{core::*, Win32::System::Diagnostics::Debug::*};

type DebugCreateFn = extern "system" fn(
    *const ::windows::core::GUID,
    *mut *mut ::core::ffi::c_void,
) -> ::windows::core::HRESULT;

#[implement(IDebugEventCallbacksWide)]
pub struct EventCallbacks(&'static mut UDbgCallback<'static>, *mut DebugEngine);

fn reply2status(reply: UserReply) -> HRESULT {
    HRESULT(match reply {
        UserReply::Run(true) => DEBUG_STATUS_GO_HANDLED,
        UserReply::Run(false) => DEBUG_STATUS_GO_NOT_HANDLED,
        UserReply::StepIn => DEBUG_STATUS_STEP_INTO,
        UserReply::StepOut => DEBUG_STATUS_STEP_OVER,
        UserReply::Native(code) => code as _,
        _ => DEBUG_STATUS_BREAK,
    } as _)
}

impl EventCallbacks {
    #[inline(always)]
    fn call(&self, event: UEvent) -> Result<()> {
        // TODO:
        let target = Arc::new(DebugTarget::from(self.engine() as &DebugEngine));
        reply2status(unsafe { mutable(self).0(target, event) }).ok()
    }

    #[inline(always)]
    fn engine(&self) -> &mut DebugEngine {
        unsafe { self.1.as_mut().unwrap() }
    }
}

impl IDebugEventCallbacksWide_Impl for EventCallbacks {
    fn GetInterestMask(&self) -> windows::core::Result<u32> {
        Ok(DEBUG_EVENT_BREAKPOINT
            | DEBUG_EVENT_LOAD_MODULE
            | DEBUG_EVENT_EXCEPTION
            | DEBUG_EVENT_CREATE_THREAD
            | DEBUG_EVENT_EXIT_THREAD
            | DEBUG_EVENT_CREATE_PROCESS
            | DEBUG_EVENT_EXIT_PROCESS
            | DEBUG_EVENT_UNLOAD_MODULE
            | DEBUG_EVENT_SYSTEM_ERROR
            | DEBUG_EVENT_SESSION_STATUS
            | DEBUG_EVENT_CHANGE_DEBUGGEE_STATE
            | DEBUG_EVENT_CHANGE_ENGINE_STATE
            | DEBUG_EVENT_CHANGE_SYMBOL_STATE)
    }

    fn Breakpoint(
        &self,
        bp: &core::option::Option<IDebugBreakpoint2>,
    ) -> windows::core::Result<()> {
        bp.as_ref()
            .map(Clone::clone)
            .map(|bp| {
                self.call(UEvent::Breakpoint(Arc::new(IDbgBpWrapper(
                    bp,
                    self.engine().ctrl.clone(),
                ))))
            })
            .unwrap_or(HRESULT(DEBUG_STATUS_BREAK as _).ok())
    }

    fn Exception(
        &self,
        exception: *const EXCEPTION_RECORD64,
        firstchance: u32,
    ) -> windows::core::Result<()> {
        unsafe {
            let e = exception.as_ref().unwrap();
            self.call(UEvent::Exception {
                first: firstchance != 0,
                code: e.ExceptionCode.0 as _,
            })
        }
    }

    fn CreateThread(
        &self,
        handle: u64,
        dataoffset: u64,
        startoffset: u64,
    ) -> windows::core::Result<()> {
        self.call(UEvent::ThreadCreate(unsafe { GetThreadId(handle as _) }))
    }

    fn ExitThread(&self, exitcode: u32) -> windows::core::Result<()> {
        self.call(UEvent::ThreadExit(exitcode))
    }

    fn CreateProcessA(
        &self,
        imagefilehandle: u64,
        handle: u64,
        baseoffset: u64,
        modulesize: u32,
        modulename: &windows::core::PCWSTR,
        imagename: &windows::core::PCWSTR,
        checksum: u32,
        timedatestamp: u32,
        initialthreadhandle: u64,
        threaddataoffset: u64,
        startoffset: u64,
    ) -> windows::core::Result<()> {
        let modulename = String::from_wide_ptr(modulename.0);
        let imagename = String::from_wide_ptr(imagename.0);
        println!("[load] image {modulename} {imagename}");
        self.call(UEvent::ProcessCreate)
    }

    fn ExitProcess(&self, exitcode: u32) -> windows::core::Result<()> {
        self.call(UEvent::ProcessExit(exitcode))
    }

    fn LoadModule(
        &self,
        imagefilehandle: u64,
        baseoffset: u64,
        modulesize: u32,
        modulename: &windows::core::PCWSTR,
        imagename: &windows::core::PCWSTR,
        checksum: u32,
        timedatestamp: u32,
    ) -> windows::core::Result<()> {
        let modulename = String::from_wide_ptr(modulename.0);
        let imagename = String::from_wide_ptr(imagename.0);
        println!("[load] {modulename} {imagename}");
        Ok(())
    }

    fn UnloadModule(
        &self,
        imagebasename: &windows::core::PCWSTR,
        baseoffset: u64,
    ) -> windows::core::Result<()> {
        let imagebasename = String::from_wide_ptr(imagebasename.0);
        println!("[load] {imagebasename}");
        Ok(())
    }

    fn SystemError(&self, error: u32, level: u32) -> windows::core::Result<()> {
        udbg_ui().error(format!("[SystemError] {error:x?} {level:x?}"));
        Ok(())
    }

    fn SessionStatus(&self, status: u32) -> windows::core::Result<()> {
        udbg_ui().error(format!("[SessionStatus] {status:x?}"));
        Ok(())
    }

    fn ChangeDebuggeeState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeEngineState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        Ok(())
    }

    fn ChangeSymbolState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        Ok(())
    }
}

#[implement(IDebugOutputCallbacksWide)]
pub struct OutputCallbacks(sync::Weak<DebugEngine>);

impl IDebugOutputCallbacksWide_Impl for OutputCallbacks {
    fn Output(&self, mask: u32, text: &windows::core::PCWSTR) -> windows::core::Result<()> {
        let text = String::from_wide_ptr(text.0);
        udbg_ui().print(&text);
        Ok(())
    }
}

#[derive(Clone)]
pub struct DebugEngine {
    client: IDebugClient5,
    ctrl: IDebugControl4,
    spaces: IDebugDataSpaces4,
    registers: IDebugRegisters2,
    symbols: IDebugSymbols3,
    sysobjs: IDebugSystemObjects4,
    advanced: IDebugAdvanced3,
}

impl DebugEngine {
    pub fn create() -> anyhow::Result<Arc<Self>> {
        unsafe {
            let hmod = LoadLibraryA(cstr!("dbgeng.dll").as_ptr().cast());
            let DebugCreate: Option<DebugCreateFn> =
                core::mem::transmute(GetProcAddress(hmod, cstr!("DebugCreate").as_ptr().cast()));
            let DebugCreate = DebugCreate.context("get DebugCreate")?;

            let mut client = core::ptr::null_mut();
            DebugCreate(&IDebugClient5::IID, &mut client)
                .ok()
                .context("DebugCreate")?;

            let client: IDebugClient5 = core::mem::transmute(client);
            let this = Arc::new(Self {
                ctrl: client.cast().context("IDebugControl4")?,
                spaces: client.cast().context("IDebugDataSpaces4")?,
                registers: client.cast().context("IDebugRegisters2")?,
                symbols: client.cast().context("IDebugSymbols3")?,
                sysobjs: client.cast().context("IDebugSystemObjects4")?,
                advanced: client.cast().context("IDebugAdvanced3")?,
                client,
            });

            let output: IDebugOutputCallbacksWide = OutputCallbacks(Arc::downgrade(&this)).into();
            this.client.SetOutputCallbacksWide(output);

            this.ctrl
                .AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK | DEBUG_ENGOPT_FINAL_BREAK)?;
            this.ctrl.SetInterruptTimeout(1)?;

            Ok(this)
        }
    }
}

impl UDbgTarget for DebugTarget {}

impl UDbgEngine for DebugEngine {
    fn attach(&mut self, pid: u32) -> UDbgResult<Arc<dyn UDbgTarget>> {
        unsafe {
            self.client
                .AttachProcess(0, pid, DEBUG_ATTACH_DEFAULT)
                .context("AttachProcess")?;
            Ok(Arc::new(DebugTarget::from(self as &Self)))
        }
    }

    fn create(
        &mut self,
        path: &str,
        cwd: Option<&str>,
        args: &[&str],
    ) -> UDbgResult<Arc<dyn UDbgTarget>> {
        unsafe {
            // let mut ty = WDbgType::Normal;
            if path.ends_with(".dmp") || path.ends_with(".DMP") {
                // ty = WDbgType::Dump;
                // base.status.set(UDbgStatus::Opened);
                self.client.OpenDumpFileWide(path, 0)
            } else if path.starts_with("com:") {
                // ty = WDbgType::Kernel;
                const DEBUG_ATTACH_KERNEL_CONNECTION: u32 = 0x00000000;
                const DEBUG_ATTACH_LOCAL_KERNEL: u32 = 0x00000001;
                const DEBUG_ATTACH_EXDI_DRIVER: u32 = 0x00000002;
                const DEBUG_ATTACH_INSTALL_DRIVER: u32 = 0x00000004;
                self.client
                    .AttachKernelWide(DEBUG_ATTACH_KERNEL_CONNECTION, path)
            } else {
                let mut args = args
                    .into_iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let mut path = path.to_string();
                if path.find(|c: char| c.is_whitespace()).is_some() {
                    path = format!("\"{}\"", path);
                }
                args.insert(0, path);
                let cmdline = args.join(" ");
                self.client.CreateProcessWide(
                    0,
                    cmdline.as_str(),
                    CREATE_NEW_CONSOLE | DEBUG_PROCESS,
                )
            }
            .context("")?;
            Ok(Arc::new(DebugTarget::from(self as &Self)))
        }
    }

    fn do_cmd(&self, cmd: &str) -> UDbgResult<()> {
        unsafe {
            self.ctrl.ExecuteWide(0, cmd, 0).context("")?;
            Ok(())
        }
    }

    fn event_loop(&mut self, callback: &mut UDbgCallback) -> UDbgResult<()> {
        unsafe {
            let event: IDebugEventCallbacksWide =
                EventCallbacks(core::mem::transmute(callback), self).into();
            self.client.SetEventCallbacksWide(event);

            loop {
                match self.ctrl.WaitForEvent(0, winapi::um::winbase::INFINITE) {
                    Ok(_) => {}
                    Err(err) => break,
                }
            }
        }
        Ok(())
    }
}

#[derive(Deref)]
pub struct DebugTarget {
    base: TargetBase,
    regs: RwLock<HashMap<Box<str>, usize>>,
    // event: Option<UEvent>,
    context: CONTEXT,
    paused: Cell<bool>,
    // bp: RwLock<(HashMap<u32, usize>, HashMap<usize, IDbgBpWrapper>)>,
    #[deref]
    _engine: DebugEngine,
}

unsafe impl Send for DebugTarget {}
unsafe impl Sync for DebugTarget {}

impl From<&DebugEngine> for DebugTarget {
    fn from(eng: &DebugEngine) -> Self {
        Self {
            base: unsafe {
                let mut base = TargetBase::default();
                let mut buf = [0u16; 500];
                let mut len = 0u32;
                // eng.syms.GetImagePathWide(buf.as_mut_ptr(), buf.len() as u32, &mut len);
                eng.sysobjs
                    .GetCurrentProcessExecutableNameWide(&mut buf, &mut len);
                base.image_path = buf.to_utf8();
                base.pid
                    .set(eng.sysobjs.GetCurrentProcessSystemId().unwrap_or_default());
                if base.image_path.is_empty() {
                    udbg_ui().warn("GetImagePath failed");
                    // base.image_path = path.to_string();
                }
                base
            },
            regs: Default::default(),
            context: unsafe { core::mem::zeroed() },
            paused: Default::default(),
            _engine: eng.clone(),
        }
    }
}

impl ReadMemory for DebugTarget {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        unsafe {
            let mut r = 0;
            self.spaces
                .ReadVirtual(
                    addr as u64,
                    data.as_mut_ptr().cast(),
                    data.len() as u32,
                    &mut r,
                )
                .ok()?;
            if r > 0 {
                Some(&mut data[..r as usize])
            } else {
                None
            }
        }
    }
}

impl WriteMemory for DebugTarget {
    fn write_memory(&self, addr: usize, data: &[u8]) -> Option<usize> {
        unsafe {
            Some(
                self.spaces
                    .WriteVirtual(addr as u64, data.as_ptr().cast(), data.len() as u32)
                    .ok()? as _,
            )
        }
    }

    // TODO: flush
}

impl TargetMemory for DebugTarget {
    fn enum_memory(&self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + '_>> {
        // TODO:
        // if self.ty == WDbgType::Kernel {
        //     return Err(UDbgError::NotSupport);
        // }
        let mut address = 0;
        Ok(Box::new(std::iter::from_fn(move || {
            while let Some(p) = self.virtual_query(address) {
                address += p.size;
                if p.is_commit() {
                    return Some(p);
                }
            }
            return None;
        })))
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        unsafe {
            if let Ok(mbi) = self.spaces.QueryVirtual(address as _) {
                Some(MemoryPage {
                    base: mbi.BaseAddress as usize,
                    alloc_base: mbi.AllocationBase as usize,
                    size: mbi.RegionSize as usize,
                    type_: mbi.Type.0,
                    state: mbi.State.0,
                    protect: mbi.Protect.0,
                    alloc_protect: mbi.AllocationProtect.0,
                })
            // } else if self.ty == WDbgType::Kernel {
            //     Some(MemoryPage {
            //         base: address & !0xFFF,
            //         alloc_base: address & !0xFFF,
            //         size: 0x1000,
            //         type_: MEM_FREE,
            //         state: MEM_COMMIT,
            //         protect: PAGE_READONLY,
            //         alloc_protect: PAGE_READONLY,
            //     })
            } else {
                None
            }
        }
    }

    fn collect_memory_info(&self) -> Vec<MemoryPageInfo> {
        let peb = unsafe { self.sysobjs.GetCurrentProcessPeb().unwrap_or(0) };
        self.enum_memory()
            .map(|iter| {
                use winapi::um::winnt::{MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE};

                iter.map(|m| {
                    let mut usage = String::new();
                    let mut flags = match m.type_ {
                        MEM_PRIVATE => MF_PRIVATE,
                        MEM_IMAGE => MF_IMAGE,
                        MEM_MAPPED => MF_MAP,
                        _ => 0,
                    };
                    if m.base == 0x7FFE0000 {
                        usage.push_str("KUSER_SHARED_DATA");
                    } else if m.base == peb as usize {
                        usage.push_str("PEB");
                        flags |= MF_PEB;
                    }
                    // if self.ty != WDbgType::Kernel {
                    //     // TODO:
                    // }
                    MemoryPageInfo {
                        alloc_base: m.alloc_base,
                        base: m.base,
                        size: m.size,
                        flags,
                        usage: usage.into(),
                        type_: m.type_().into(),
                        protect: m.protect().into(),
                    }
                })
                .collect()
            })
            .unwrap_or_default()
    }
}

impl TargetControl for DebugTarget {
    fn detach(&self) -> UDbgResult<()> {
        self.base.status.set(UDbgStatus::Detaching);
        unsafe {
            self.client
                .DetachCurrentProcess()
                .context("DetachCurrentProcess")?;
        }
        Ok(())
    }

    fn breakk(&self) -> UDbgResult<()> {
        unsafe {
            if !self.paused.get() {
                self.ctrl.SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
            }
        }

        Ok(())
    }

    fn kill(&self) -> UDbgResult<()> {
        if self.base.is_opened() {
            self.base.status.set(UDbgStatus::Ended);
        } else {
            self.breakk()?;
            unsafe {
                self.client.TerminateCurrentProcess().context("")?;
            }
        }
        Ok(())
    }
}

impl TargetSymbol for DebugTarget {
    fn enum_module(&self) -> Box<dyn Iterator<Item = Arc<dyn UDbgModule + '_>> + '_> {
        unsafe {
            let mut loaded = 0;
            let mut unloaded = 0;
            self.symbols.GetNumberModules(&mut loaded, &mut unloaded);
            let mut buf = Vec::with_capacity(loaded as _);
            buf.resize(buf.capacity(), core::mem::zeroed());
            self.symbols.GetModuleParameters(
                buf.len() as _,
                core::ptr::null(),
                0,
                buf.as_mut_ptr(),
            );
            let iter = buf
                .into_iter()
                .filter(|p| p.Flags & DEBUG_MODULE_UNLOADED == 0)
                .map(move |p| Arc::new(self.new_module(&p)) as Arc<dyn UDbgModule>);
            Box::new(iter)
        }
    }
    fn remove(&self, address: usize) {}
    fn check_load_module(
        &self,
        read: &dyn ReadMemory,
        base: usize,
        size: usize,
        path: &str,
        file: HANDLE,
    ) -> bool {
        false
    }
    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item = Symbol> + '_>> {
        Ok(Box::new(
            self.symbols
                .enum_symbol(pat.unwrap_or_default())?
                .map(|(name, a)| Symbol {
                    offset: a as u32,
                    len: SYM_NOLEN,
                    type_id: 0,
                    flags: 0,
                    name: name.into(),
                }),
        ))
    }

    fn find_module(&self, module: usize) -> Option<Arc<dyn UDbgModule>> {
        let base = self.symbols.find_module(module as u64).ok()?;
        Some(Arc::new(self.module_from_base(base.1)?))
    }

    fn get_module(&self, module: &str) -> Option<Arc<dyn UDbgModule>> {
        let base = self.symbols.get_module(module).ok()?;
        Some(Arc::new(self.module_from_base(base.1)?))
    }
}

#[extend::ext(pub)]
impl IDebugControl4 {
    fn add_bp(&self, ty: u32) -> Result<IDebugBreakpoint2> {
        unsafe { self.AddBreakpoint2(ty, DEBUG_ANY_ID) }
    }

    fn system_version(&self, which: u32) -> String {
        let mut buf = [0u16; 300];
        unsafe {
            self.GetSystemVersionStringWide(which, &mut buf, core::ptr::null_mut());
            buf.to_utf8()
        }
    }

    #[allow(unused_must_use)]
    fn remove_bp(&self, id: BpID) {
        self.get_bp_by_id(id)
            .map(|bp| unsafe { self.RemoveBreakpoint2(bp.clone()) });
    }

    fn get_bp_by_index(&self, index: usize) -> Result<IDebugBreakpoint2> {
        unsafe { self.GetBreakpointByIndex2(index as u32) }
    }

    fn get_bp_by_id(&self, id: BpID) -> Result<IDebugBreakpoint2> {
        unsafe { self.GetBreakpointById2(id as _) }
    }

    fn bp_list(&self) -> Vec<IDebugBreakpoint2> {
        let mut result = vec![];
        for i in 0..10000 {
            match self.get_bp_by_index(i) {
                Ok(r) => result.push(r),
                Err(_) => break,
            }
        }
        result
    }
}

impl BreakpointManager for DebugTarget {
    fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<(dyn UDbgBreakpoint + 'static)>> {
        if opt.table {
            return Err(UDbgError::NotSupport);
        }
        unsafe {
            let bp = if let Some(rw) = opt.rw {
                let bp = self.ctrl.add_bp(DEBUG_BREAKPOINT_DATA).context("")?;
                bp.SetDataParameters(
                    opt.len.map(|l| l.to_int()).unwrap_or(1),
                    match rw {
                        HwbpType::Execute => DEBUG_BREAK_EXECUTE,
                        HwbpType::Write => DEBUG_BREAK_WRITE,
                        HwbpType::Access => DEBUG_BREAK_READ,
                    },
                );
                bp
            } else {
                self.ctrl.add_bp(DEBUG_BREAKPOINT_CODE).context("")?
            };
            bp.SetOffset(opt.address as u64).context("SetOffset")?;

            if opt.temp {
                bp.AddFlags(DEBUG_BREAKPOINT_ONE_SHOT);
            }
            if let Some(tid) = opt.tid {
                bp.SetMatchThreadId(tid).context("SetMatchThreadId")?;
            }
            let bp = IDbgBpWrapper(bp, self.ctrl.clone());
            if opt.enable {
                bp.enable(opt.enable)?;
            }
            Ok(Arc::new(bp))
        }
    }

    fn get_bp<'a>(&'a self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        // self.ctrl.get_bp_by_id(id).map_err(hresult_errcode)?;
        Some(Arc::new(IDbgBpWrapper(
            self.ctrl.get_bp_by_id(id).ok()?,
            self.ctrl.clone(),
        )))
    }

    fn get_bp_by_address(&self, a: usize) -> Option<Arc<dyn UDbgBreakpoint + '_>> {
        // self.bp
        //     .read()
        //     .1
        //     .get(&a)
        //     .map(|bp| Arc::new(*bp) as Arc<dyn UDbgBreakpoint>)
        None
    }

    fn get_bp_list(&self) -> Vec<BpID> {
        self.ctrl
            .bp_list()
            .into_iter()
            .map(|bp| unsafe { bp.GetId().unwrap_or_default() as BpID })
            .collect()
    }

    fn get_breakpoints(&self) -> Vec<Arc<dyn UDbgBreakpoint + '_>> {
        self.ctrl
            .bp_list()
            .into_iter()
            .map(|bp| Arc::new(IDbgBpWrapper(bp, self.ctrl.clone())) as Arc<dyn UDbgBreakpoint>)
            .collect()
    }
}

#[derive(Deref, Clone)]
struct IDbgBpWrapper(#[deref] IDebugBreakpoint2, IDebugControl4);

impl UDbgBreakpoint for IDbgBpWrapper {
    fn get_id(&self) -> BpID {
        unsafe { self.GetId().map(|id| id as BpID).unwrap_or(0) }
    }
    fn address(&self) -> usize {
        unsafe { self.GetOffset().unwrap_or_default() as _ }
    }
    fn enabled(&self) -> bool {
        unsafe { self.GetFlags().unwrap_or_default() & DEBUG_BREAKPOINT_ENABLED > 0 }
    }
    fn get_type(&self) -> BpType {
        // TODO:
        BpType::Soft
    }
    /// count of this breakpoint hitted
    fn hit_count(&self) -> usize {
        unsafe { self.GetPassCount().unwrap_or_default() as _ }
    }
    /// set count of the to be used,
    /// when hit_count() > this count, bp will be delete
    fn set_count(&self, count: usize) {
        unsafe {
            self.SetPassCount(count as _);
        }
    }
    /// set the which can hit the bp. if tid == 0, all thread used
    fn set_hit_thread(&self, tid: u32) {
        // TODO: Engine TID
        unsafe {
            self.SetMatchThreadId(tid);
        }
    }
    /// current tid setted by set_hit_thread()
    fn hit_tid(&self) -> u32 {
        unsafe { self.GetMatchThreadId().unwrap_or_default() }
    }
    /// original bytes written by software breakpoint
    fn origin_bytes<'a>(&'a self) -> Option<&'a [u8]> {
        None
    }

    fn enable(&self, enable: bool) -> UDbgResult<()> {
        Ok(unsafe {
            if enable {
                self.AddFlags(DEBUG_BREAKPOINT_ENABLED)
            } else {
                self.RemoveFlags(DEBUG_BREAKPOINT_ENABLED)
            }
        }
        .context("")?)
    }

    fn remove(&self) -> UDbgResult<()> {
        unsafe {
            self.1.RemoveBreakpoint2(self.0.clone()).context("")?;
            Ok(())
        }
    }
}

impl GetProp for DebugTarget {}

impl Target for DebugTarget {
    fn base(&self) -> &TargetBase {
        &self.base
    }

    fn handle(&self) -> winapi::um::winnt::HANDLE {
        unsafe { self.sysobjs.GetCurrentProcessHandle().unwrap_or_default() as _ }
    }

    fn enum_thread(
        &self,
        _detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>> {
        unsafe {
            let count = self.sysobjs.GetNumberThreads().context("context")?;
            let mut buf = vec![0; count as usize];
            self.sysobjs
                .GetThreadIdsByIndex(0, count, core::ptr::null_mut(), buf.as_mut_ptr());
            Ok(Box::new(
                buf.into_iter().filter_map(|tid| self.open_thread(tid).ok()),
            ))
        }
    }

    fn open_thread(&self, tid: u32) -> UDbgResult<Box<dyn UDbgThread>> {
        udbg_ui().info(format!("open thread: {}", tid));
        Ok(Box::new(WDbgThread {
            data: ThreadData {
                tid,
                wow64: false,
                handle: unsafe { Handle::from_raw_handle(core::ptr::null_mut()) },
            },
        }) as Box<dyn UDbgThread>)
    }

    fn enum_handle(&self) -> UDbgResult<Box<dyn Iterator<Item = HandleInfo> + '_>> {
        let handle = self.handle();
        if !handle.is_null() {
            super::udbg::enum_process_handle(
                unsafe { self.sysobjs.GetCurrentProcessSystemId().unwrap_or(0) },
                handle,
            )
        } else {
            Err(UDbgError::NotSupport)
        }
    }

    fn symbol_manager(&self) -> Option<&dyn TargetSymbol> {
        Some(self)
    }

    fn get_address_by_symbol(&self, symbol: &str) -> Option<usize> {
        unsafe { Some(self.symbols.GetOffsetByNameWide(symbol).ok()? as _) }
    }

    fn get_symbol(&self, addr: usize, max_offset: usize) -> Option<SymbolInfo> {
        unsafe {
            let mut buf = [0; 1024];
            let mut disp = 0u64;
            let mut size = 0;
            self.symbols
                .GetNameByOffset(addr as _, &mut buf, &mut size, &mut disp);

            if size > 0 {
                let name = CStr::from_ptr(buf.as_ptr().cast()).to_string_lossy();
                let mut iter = name.split("!");
                let m = iter.next();
                let n = iter.next();
                Some(SymbolInfo {
                    module: m.unwrap_or_default().into(),
                    symbol: n.unwrap_or_default().into(),
                    offset: disp as usize,
                    mod_base: self.symbols.find_module(addr as u64).ok()?.1 as usize,
                })
            } else {
                None
            }
        }
    }
    // fn parse_address(&self, symbol: &str) -> Option<usize> {
    //     unsafe {
    //         self.get_reg(symbol).ok().map(|r| r.as_int()).or_else(|| {
    //             let r = wdbg_evaluate(self.ctrl, symbol.to_wide().as_ptr());
    //             if r > 0 { Some(r) } else { None }
    //         })
    //     }
    // }
}

#[extend::ext(pub)]
impl IDebugSymbols3 {
    fn enum_symbol(&self, pat: &str) -> UDbgResult<Box<dyn Iterator<Item = (String, u64)> + '_>> {
        unsafe {
            let handle = self.StartSymbolMatchWide(pat).context("")?;

            struct SymHandle(IDebugSymbols3, u64);
            impl Drop for SymHandle {
                fn drop(&mut self) {
                    unsafe {
                        self.0.EndSymbolMatch(self.1);
                    }
                }
            }
            let h = SymHandle(self.clone(), handle);
            Ok(Box::new(std::iter::from_fn(move || {
                // let handle = h.handle;
                let mut buf = [0; 1000];
                let mut offset = 0;
                if h.0
                    .GetNextSymbolMatchWide(h.1, &mut buf, core::ptr::null_mut(), &mut offset)
                    .is_ok()
                {
                    Some((buf.to_utf8(), offset))
                } else {
                    None
                }
            })))
        }
    }

    fn get_module_parameters(
        &self,
        count: u32,
        bases: &[u64],
        params: &mut [DEBUG_MODULE_PARAMETERS],
    ) -> Result<()> {
        unsafe {
            self.GetModuleParameters(
                count,
                bases.as_ptr(),
                bases.len() as u32,
                params.as_mut_ptr(),
            )
        }
    }

    fn get_module_params(&self, base: u64) -> Result<DEBUG_MODULE_PARAMETERS> {
        unsafe {
            let mut buf = [core::mem::zeroed(); 1];
            self.get_module_parameters(1, &[base], &mut buf)?;
            Ok(buf[0])
        }
    }

    fn get_module_name_string(&self, which: u32, base: u64) -> Result<String> {
        let mut buf = [0; 500];
        unsafe {
            self.GetModuleNameStringWide(
                which,
                DEBUG_ANY_ID,
                base,
                &mut buf,
                core::ptr::null_mut(),
            )?;
            Ok(buf.to_utf8())
        }
    }

    fn find_module(&self, a: u64) -> Result<(u32, u64)> {
        let mut i = 0;
        let mut base = 0;
        unsafe {
            self.GetModuleByOffset(a, 0, &mut i, &mut base)?;
        }
        Ok((i, base))
    }

    fn get_module<'a, N: IntoParam<'a, PCWSTR>>(&self, name: N) -> Result<(u32, u64)> {
        let mut i = 0;
        let mut base = 0;
        unsafe {
            self.GetModuleByModuleNameWide(name, 0, &mut i, &mut base)?;
        }
        Ok((i, base))
    }
}

impl DebugTarget {
    pub fn module_from_base(&self, base: u64) -> Option<WDbgModule> {
        let info = self.symbols.get_module_params(base).ok()?;
        self.new_module(&info).into()
    }

    pub fn new_module(&self, info: &DEBUG_MODULE_PARAMETERS) -> WDbgModule {
        unsafe {
            let name = self
                .symbols
                .get_module_name_string(DEBUG_MODNAME_MODULE, info.Base)
                .unwrap_or_default();
            let path = self
                .symbols
                .get_module_name_string(DEBUG_MODNAME_IMAGE, info.Base)
                .unwrap_or_default();
            let h = self.spaces.ReadImageNtHeaders(info.Base).unwrap();
            WDbgModule {
                symbols: self.symbols.clone(),
                param: *info,
                data: ModuleData {
                    base: info.Base as usize,
                    size: info.Size as usize,
                    name: name.into(),
                    path: path.into(),
                    arch: crate::pe::PeHelper::arch_name(h.FileHeader.Machine.0)
                        .unwrap_or_default(),
                    entry: h.OptionalHeader.AddressOfEntryPoint as usize,
                    user_module: Cell::new(false),
                },
            }
        }
    }
}

#[derive(Deref)]
struct WDbgThread {
    #[deref]
    data: ThreadData,
}

impl GetProp for WDbgThread {}

impl UDbgThread for WDbgThread {
    fn name(&self) -> Arc<str> {
        "".into()
    }
    fn status(&self) -> Arc<str> {
        "".into()
    }
}

pub struct WDbgModule {
    data: ModuleData,
    symbols: IDebugSymbols3,
    param: DEBUG_MODULE_PARAMETERS,
}

impl GetProp for WDbgModule {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        use serde_value::Value::*;

        Ok(match key {
            "pdb_path" => {
                if self.param.SymbolType != DEBUG_SYMTYPE_EXPORT
                    && self.param.SymbolType != DEBUG_SYMTYPE_NONE
                {
                    match self
                        .symbols
                        .get_module_name_string(DEBUG_MODNAME_SYMBOL_FILE, self.data.base as u64)
                    {
                        Ok(path) => String(path),
                        Err(_) => Unit,
                    }
                    // return s.pushx((path, self.param.SymbolType));
                } else {
                    Unit
                }
            }
            _ => Unit,
        })
    }
}

impl UDbgModule for WDbgModule {
    fn data(&self) -> &ModuleData {
        &self.data
    }
    fn symbol_status(&self) -> SymbolStatus {
        SymbolStatus::Unload
    }
    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item = Symbol> + '_>> {
        let base = self.data.base as u64;
        Ok(Box::new(
            self.symbols
                .enum_symbol(&format!("{}!{}", self.data.name, pat.unwrap_or("*")))?
                .map(move |(name, offset)| Symbol {
                    offset: (offset - base) as u32,
                    len: SYM_NOLEN,
                    type_id: 0,
                    flags: 0,
                    name: match name.split_once("!") {
                        Some((_, s)) => s.into(),
                        None => name.into(),
                    },
                }),
        ))
    }
}
