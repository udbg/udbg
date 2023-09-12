use std::io::{Error as IoErr, Result as IoRes};
use std::{ffi::c_void, sync::Arc};

use crossbeam::atomic::AtomicCell;
use ntapi::ntexapi::SYSTEM_THREAD_INFORMATION;
use ntapi::ntpebteb::TEB;
use ntapi::ntpsapi::THREAD_BASIC_INFORMATION;
use winapi::um::winnt::CONTEXT_ALL;
use windows::{
    core::{s, w, HRESULT, PWSTR},
    Win32::{
        Foundation::*,
        System::{
            Diagnostics::Debug::*, Threading::*, WindowsProgramming::THREAD_PRIORITY_ERROR_RETURN,
        },
    },
};

use super::{
    ntdll::{query_thread, SystemThreadInformation, ThreadInfoClass},
    Align16, Handle, Process,
};
use crate::{
    error::*,
    prelude::ReadMemoryUtils,
    register::*,
    target::{GetProp, ThreadContext, ThreadContext32, ThreadData, UDbgThread},
};

#[derive(Debug, Clone, Deref)]
pub struct ThreadHandle(pub Handle);

impl ThreadHandle {
    #[inline]
    pub unsafe fn borrow_raw(handle: &windows::Win32::Foundation::HANDLE) -> &Self {
        Self::borrow_handle(Handle::borrow(handle))
    }

    #[inline]
    pub unsafe fn borrow_handle(handle: &Handle) -> &Self {
        &*(handle as *const _ as *const Self)
    }

    #[inline]
    pub fn open(
        tid: u32,
        access: THREAD_ACCESS_RIGHTS,
        inherit: bool,
    ) -> ::windows::core::Result<Self> {
        unsafe {
            OpenThread(access, inherit, tid)
                .map(|x| Handle::from_raw_handle(x))
                .map(Self)
        }
    }

    pub fn tid(&self) -> u32 {
        unsafe { GetThreadId(*self.0) }
    }

    pub fn suspend_thread(tid: u32) -> ::windows::core::Result<Self> {
        let this = Self::open(tid, THREAD_SUSPEND_RESUME, false)?;
        if this.is_valid() {
            this.suspend();
        }
        Ok(this)
    }

    #[inline]
    pub fn suspend(&self) -> u32 {
        unsafe { SuspendThread(*self.0) }
    }

    #[inline]
    pub fn resume(&self) -> u32 {
        unsafe { ResumeThread(*self.0) }
    }

    pub fn terminate(&self, code: u32) -> windows::core::Result<()> {
        unsafe { TerminateThread(*self.0, code) }
    }

    pub fn priority(&self) -> i32 {
        unsafe { GetThreadPriority(*self.0) }
    }
}

pub trait IntoThreadProc {
    fn into_thread_fn(self) -> (LPTHREAD_START_ROUTINE, *const c_void);
}

impl<F: FnOnce()> IntoThreadProc for F {
    fn into_thread_fn(self) -> (LPTHREAD_START_ROUTINE, *const c_void) {
        unsafe extern "system" fn wrapper(p: *mut c_void) -> u32 {
            let closure: Box<Box<dyn FnOnce()>> = Box::from_raw(core::mem::transmute(p));
            closure();
            0
        }
        let closure: Box<dyn FnOnce()> = Box::new(self);
        (
            Some(wrapper),
            Box::into_raw(Box::new(closure)) as *const c_void,
        )
    }
}

pub fn create_thread(proc: impl IntoThreadProc) -> ::windows::core::Result<(ThreadHandle, u32)> {
    unsafe {
        let mut id: u32 = 0;
        let (f, p) = proc.into_thread_fn();
        let handle = CreateThread(None, 0, f, Some(p), Default::default(), Some(&mut id))?;
        Ok((ThreadHandle(Handle::from_raw_handle(handle)), id))
    }
}

#[derive(Deref)]
pub struct WinThread {
    #[deref]
    pub base: ThreadData,
    pub teb: AtomicCell<usize>,
    pub process: *const Process,
    pub detail: Option<Box<SYSTEM_THREAD_INFORMATION>>,
}

impl WinThread {
    pub fn new(tid: u32) -> Option<Self> {
        Some(WinThread {
            base: ThreadData {
                wow64: false,
                tid,
                handle: ThreadHandle::open(tid, THREAD_ALL_ACCESS, false).ok()?,
            },
            process: std::ptr::null(),
            teb: AtomicCell::new(0),
            detail: None,
        })
    }

    pub fn open(process: *const Process, tid: u32) -> UDbgResult<Box<WinThread>> {
        Self::new(tid)
            .map(|mut t| unsafe {
                t.process = process;
                t.base.wow64 = process.as_ref().map(|p| p.is_wow64()).unwrap_or_default();
                Box::new(t)
            })
            .ok_or(UDbgError::system())
    }

    fn get_reg(&self, r: &str) -> UDbgResult<CpuReg> {
        if self.wow64 {
            let mut cx = unsafe { Align16::<CONTEXT32>::new_zeroed() };
            let context = cx.as_mut();
            self.handle.get_wow64_context(context);
            context.get(r).ok_or(UDbgError::InvalidRegister)
        } else {
            let mut cx = unsafe { Align16::<CONTEXT>::new_zeroed() };
            let context = cx.as_mut();
            self.handle.get_context(context);
            context.get(r).ok_or(UDbgError::InvalidRegister)
        }
    }
}

static mut GetThreadDescription: Option<extern "system" fn(HANDLE, *mut PWSTR) -> HRESULT> = None;

#[ctor::ctor]
unsafe fn init_imp() {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    GetThreadDescription = core::mem::transmute(crate::os::get_proc_address(
        GetModuleHandleW(w!("kernelbase")).unwrap_or_default(),
        s!("GetThreadDescription"),
    ));
}

impl GetProp for WinThread {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        if let Some(reg) = key.strip_prefix("@") {
            Ok(serde_value::to_value(self.get_reg(reg)?).unwrap())
        } else {
            Err(UDbgError::NotSupport)
        }
    }
}

impl UDbgThread for WinThread {
    fn name(&self) -> Arc<str> {
        unsafe {
            GetThreadDescription
                .map(|get| {
                    let mut s = PWSTR::null();
                    get(**self.handle, &mut s);
                    let result = s.to_string().unwrap_or_default();
                    LocalFree(HLOCAL(s.as_ptr().cast()));
                    result
                })
                .unwrap_or_default()
                .into()
        }
    }

    fn status(&self) -> Arc<str> {
        self.detail
            .as_ref()
            .map(|t| t.status())
            .unwrap_or_default()
            .into()
    }

    fn priority(&self) -> Option<i32> {
        let mut p = if self.handle.0.is_null() {
            ThreadHandle::open(self.tid, THREAD_QUERY_INFORMATION, false)
                .ok()?
                .priority()
        } else {
            self.handle.priority()
        };
        if p == THREAD_PRIORITY_ERROR_RETURN as i32 {
            self.detail.as_ref().map(|t| p = t.Priority);
        }
        Some(p)
    }

    fn teb(&self) -> Option<usize> {
        let mut teb = self.teb.load();
        if teb == 0 {
            teb = if self.handle.0.is_null() {
                ThreadHandle::open(self.tid, THREAD_QUERY_INFORMATION, false)
                    .ok()
                    .and_then(|h| {
                        query_thread::<THREAD_BASIC_INFORMATION>(
                            h.as_winapi(),
                            ThreadInfoClass::BasicInformation,
                            None,
                        )
                    })
            } else {
                query_thread::<THREAD_BASIC_INFORMATION>(
                    self.handle.as_winapi(),
                    ThreadInfoClass::BasicInformation,
                    None,
                )
            }
            .map(|t| t.TebBaseAddress as usize)
            .unwrap_or(0);
            self.teb.store(teb);
        }
        if teb > 0 {
            teb.into()
        } else {
            None
        }
    }

    fn entry(&self) -> usize {
        if self.handle.is_null() {
            ThreadHandle::open(self.tid, THREAD_QUERY_INFORMATION, false)
                .ok()
                .and_then(|h| {
                    query_thread::<usize>(
                        h.as_winapi(),
                        ThreadInfoClass::QuerySetWin32StartAddress,
                        None,
                    )
                })
        } else {
            query_thread::<usize>(
                self.handle.as_winapi(),
                ThreadInfoClass::QuerySetWin32StartAddress,
                None,
            )
        }
        .or_else(|| self.detail.as_ref().map(|t| t.StartAddress as usize))
        .unwrap_or(0)
    }

    fn suspend(&self) -> IoRes<i32> {
        unsafe {
            Ok(if self.wow64 {
                Wow64SuspendThread(*self.handle.0)
            } else {
                self.handle.suspend()
            } as i32)
        }
    }

    fn resume(&self) -> IoRes<u32> {
        Ok(self.handle.resume())
    }

    fn get_context(&self, cx: &mut ThreadContext) -> IoRes<()> {
        if cx.get_context(**self.handle) {
            Ok(())
        } else {
            Err(IoErr::last_os_error())
        }
    }

    fn set_context(&self, cx: &ThreadContext) -> IoRes<()> {
        if cx.set_context(**self.handle) {
            Ok(())
        } else {
            Err(IoErr::last_os_error())
        }
    }
    fn get_context32(&self, cx: &mut ThreadContext32) -> IoRes<()> {
        if cx.get_context(**self.handle) {
            Ok(())
        } else {
            Err(IoErr::last_os_error())
        }
    }
    fn set_context32(&self, cx: &ThreadContext32) -> IoRes<()> {
        if cx.set_context(**self.handle) {
            Ok(())
        } else {
            Err(IoErr::last_os_error())
        }
    }

    fn last_error(&self) -> Option<u32> {
        self.teb().and_then(|teb| unsafe {
            self.process
                .as_ref()?
                .read_value::<u32>(teb + ntapi::FIELD_OFFSET!(TEB, LastErrorValue))
        })
    }
}

impl ThreadHandle {
    /// Suspend, GetThreadContext and Resume
    pub fn suspend_context(&self, flags: CONTEXT_FLAGS) -> windows::core::Result<CONTEXT> {
        unsafe {
            let mut context: CONTEXT = core::mem::zeroed();
            context.ContextFlags = flags;
            self.suspend();
            let res = self.get_context(&mut context);
            self.resume();
            res.map(|_| context)
        }
    }

    pub fn get_wow64_context(&self, ctx: &mut ThreadContext32) -> windows::core::Result<()> {
        unsafe { Wow64GetThreadContext(*self.0, ctx) }
    }

    pub fn get_context(&self, ctx: &mut CONTEXT) -> windows::core::Result<()> {
        unsafe { GetThreadContext(*self.0, ctx) }
    }

    pub fn set_context(&self, context: &CONTEXT) -> windows::core::Result<()> {
        unsafe { SetThreadContext(*self.0, context as *const _) }
    }

    pub fn set_wow64_context(&self, ctx: &ThreadContext32) -> windows::core::Result<()> {
        unsafe { Wow64SetThreadContext(*self.0, ctx) }
    }

    /// Suspend, SetThreadContext and Resume
    pub fn suspend_set_context(&self, context: &CONTEXT) -> windows::core::Result<()> {
        self.suspend();
        let result = self.set_context(context);
        self.resume();
        result
    }

    pub fn selector_entry(&self, s: u32) -> usize {
        unsafe {
            let mut ldt: LDT_ENTRY = core::mem::zeroed();
            let r = GetThreadSelectorEntry(*self.0, s, core::mem::transmute(&mut ldt));
            ldt.BaseLow as usize
                | ((ldt.HighWord.Bytes.BaseMid as usize) << 16)
                | ((ldt.HighWord.Bytes.BaseHi as usize) << 24)
        }
    }

    pub fn selector_entry_wow64(&self, s: u32) -> u32 {
        unsafe {
            let mut ldt: WOW64_LDT_ENTRY = core::mem::zeroed();
            let r = Wow64GetThreadSelectorEntry(*self.0, s, &mut ldt);
            ldt.BaseLow as u32
                | ((ldt.HighWord.Bytes.BaseMid as u32) << 16)
                | ((ldt.HighWord.Bytes.BaseHi as u32) << 24)
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl HWBPRegs for CONTEXT {
    #[inline(always)]
    fn eflags(&mut self) -> &mut u32 {
        &mut self.EFlags
    }

    #[inline(always)]
    fn dr(&self, i: usize) -> reg_t {
        match i {
            0 => self.Dr0,
            1 => self.Dr1,
            2 => self.Dr2,
            3 => self.Dr3,
            6 => self.Dr6,
            7 => self.Dr7,
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    fn set_dr(&mut self, i: usize, v: reg_t) {
        *match i {
            0 => &mut self.Dr0,
            1 => &mut self.Dr1,
            2 => &mut self.Dr2,
            3 => &mut self.Dr3,
            6 => &mut self.Dr6,
            7 => &mut self.Dr7,
            _ => unreachable!(),
        } = v;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl HWBPRegs for CONTEXT32 {
    #[inline(always)]
    fn eflags(&mut self) -> &mut u32 {
        &mut self.EFlags
    }

    #[inline(always)]
    fn dr(&self, i: usize) -> reg_t {
        (match i {
            0 => self.Dr0,
            1 => self.Dr1,
            2 => self.Dr2,
            3 => self.Dr3,
            6 => self.Dr6,
            7 => self.Dr7,
            _ => unreachable!(),
        }) as reg_t
    }

    #[inline(always)]
    fn set_dr(&mut self, i: usize, v: reg_t) {
        *match i {
            0 => &mut self.Dr0,
            1 => &mut self.Dr1,
            2 => &mut self.Dr2,
            3 => &mut self.Dr3,
            6 => &mut self.Dr6,
            7 => &mut self.Dr7,
            _ => unreachable!(),
        } = v as _;
    }
}

#[cfg(target_arch = "aarch64")]
impl HWBPRegs for CONTEXT {
    fn cpsr(&mut self) -> &mut u32 {
        &mut self.Cpsr
    }

    fn get_ctrl(&mut self, i: usize) -> &mut u32 {
        &mut self.Wcr[i]
    }
    fn get_addr(&mut self, i: usize) -> &mut reg_t {
        &mut self.Wvr[i]
    }
}

#[cfg(target_arch = "aarch64")]
impl HWBPRegs for CONTEXT32 {
    fn cpsr(&mut self) -> &mut u32 {
        unimplemented!();
    }

    fn get_ctrl(&mut self, i: usize) -> &mut u32 {
        unimplemented!();
    }
    fn get_addr(&mut self, i: usize) -> &mut reg_t {
        unimplemented!();
    }
}

pub trait DbgContext: HWBPRegs {
    const IS_32: bool = false;

    fn get_context(&mut self, t: HANDLE) -> bool;
    fn set_context(&self, t: HANDLE) -> bool;
}

impl DbgContext for CONTEXT {
    #[inline(always)]
    fn get_context(&mut self, t: HANDLE) -> bool {
        self.ContextFlags = CONTEXT_FLAGS(CONTEXT_ALL);
        unsafe { ThreadHandle::borrow_raw(&t).get_context(self).is_ok() }
    }

    #[inline(always)]
    fn set_context(&self, t: HANDLE) -> bool {
        unsafe { ThreadHandle::borrow_raw(&t).set_context(self).is_ok() }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl DbgContext for CONTEXT32 {
    const IS_32: bool = true;

    #[inline(always)]
    fn get_context(&mut self, t: HANDLE) -> bool {
        // self.ContextFlags = WOW64_CONTEXT_ALL;
        self.ContextFlags = WOW64_CONTEXT_FLAGS(CONTEXT_ALL);
        unsafe { Wow64GetThreadContext(t, self).is_ok() }
    }

    #[inline(always)]
    fn set_context(&self, t: HANDLE) -> bool {
        unsafe { Wow64SetThreadContext(t, self).is_ok() }
    }
}

pub fn get_thread_handle_context<C: DbgContext>(handle: &Handle, c: &mut C, flags: u32) -> bool {
    unsafe {
        SuspendThread(handle.0);
        let r = c.get_context(handle.0);
        ResumeThread(handle.0);
        return r;
    }
}

#[inline(always)]
pub fn get_thread_context<C: DbgContext>(tid: u32, c: &mut C, flags: u32) -> bool {
    ThreadHandle::open(tid, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, false)
        .map(|handle| get_thread_handle_context(&handle, c, flags))
        .unwrap_or(false)
}

pub fn set_thread_context<C: DbgContext>(tid: u32, c: &C) -> bool {
    ThreadHandle::open(tid, THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT, false)
        .map(|handle| {
            handle.suspend();
            let r = c.set_context(*handle.0);
            handle.resume();
            return r;
        })
        .unwrap_or(false)
}

pub struct DbgThread {
    pub tid: u32,
    pub handle: HANDLE,
    pub local_base: usize,
    pub start_address: usize,
}

impl DbgThread {
    pub fn new(thread: HANDLE, local_base: usize, start_address: usize) -> Self {
        unsafe {
            DbgThread {
                handle: thread,
                tid: GetThreadId(thread),
                local_base,
                start_address,
            }
        }
    }
}

impl From<&CREATE_THREAD_DEBUG_INFO> for DbgThread {
    fn from(info: &CREATE_THREAD_DEBUG_INFO) -> DbgThread {
        DbgThread::new(info.hThread, info.lpThreadLocalBase as usize, unsafe {
            core::mem::transmute(info.lpStartAddress)
        })
    }
}

impl From<&CREATE_PROCESS_DEBUG_INFO> for DbgThread {
    fn from(info: &CREATE_PROCESS_DEBUG_INFO) -> DbgThread {
        DbgThread::new(info.hThread, info.lpThreadLocalBase as usize, unsafe {
            core::mem::transmute(info.lpStartAddress)
        })
    }
}
