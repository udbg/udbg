use std::ffi::c_void;

use windows::Win32::System::Threading::*;

use super::Handle;

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
