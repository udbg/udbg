use std::{fmt::Debug, os::windows::prelude::*};

use windows::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_EVENT,
    },
    System::Threading::{GetCurrentProcess, WaitForSingleObject, INFINITE},
};

#[derive(Deref)]
pub struct Handle(pub(crate) HANDLE);

unsafe impl Send for Handle {}

impl Handle {
    #[inline]
    pub fn borrow(handle: &HANDLE) -> &Self {
        unsafe { &*(handle as *const _ as *const Self) }
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.0 != INVALID_HANDLE_VALUE
    }

    pub fn is_null(&self) -> bool {
        self.0 .0 == 0
    }

    pub fn as_windows_handle(&self) -> HANDLE {
        self.0
    }

    pub fn as_winapi(&self) -> winapi::um::winnt::HANDLE {
        self.0 .0 as _
    }

    pub fn into_owned_handle(self) -> OwnedHandle {
        let result = unsafe { OwnedHandle::from_raw_handle(self.as_raw_handle()) };
        core::mem::forget(self);
        result
    }

    #[inline]
    pub fn success(&self) -> bool {
        self.is_valid() && !self.is_null()
    }

    #[inline(always)]
    pub unsafe fn from_raw_handle(handle: HANDLE) -> Self {
        Self(handle)
    }

    #[inline(always)]
    pub unsafe fn from_winapi_handle(handle: winapi::um::winnt::HANDLE) -> Self {
        Self(HANDLE(handle as _))
    }

    pub unsafe fn clone_from_raw(handle: HANDLE) -> windows::core::Result<Self> {
        let mut result = HANDLE::default();
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut result,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )?;
        Ok(Self::from_raw_handle(result))
    }

    #[inline(always)]
    pub fn try_clone(&self) -> windows::core::Result<Self> {
        unsafe { Self::clone_from_raw(self.0) }
    }
}

impl Handle {
    pub fn wait_single(&self, timeout: Option<u32>) -> WAIT_EVENT {
        unsafe { WaitForSingleObject(self.0, timeout.unwrap_or(INFINITE)) }
    }
}

impl Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        Handle::try_clone(self).expect("clone")
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0).expect("CloseHandle");
        }
    }
}

impl AsRawHandle for Handle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0 .0 as RawHandle
    }
}

impl AsHandle for Handle {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        unsafe { BorrowedHandle::borrow_raw(self.as_raw_handle()) }
    }
}

impl IntoRawHandle for Handle {
    fn into_raw_handle(self) -> RawHandle {
        todo!()
    }
}

macro_rules! typed_handle {
    ($ty:ident: $handle:ty) => {
        #[derive(Debug, Clone, Deref)]
        pub struct $ty(pub $handle);

        impl $ty {
            #[inline]
            pub unsafe fn borrow_raw(handle: &::windows::Win32::Foundation::HANDLE) -> &Self {
                Self::borrow_handle(<$handle>::borrow(handle))
            }

            #[inline]
            pub unsafe fn borrow_handle(handle: &$handle) -> &Self {
                &*(handle as *const _ as *const Self)
            }
        }
    };
}

typed_handle!(ThreadHandle: Handle);
typed_handle!(EventHandle: Handle);
