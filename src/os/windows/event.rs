use windows::{
    core::PCWSTR,
    Win32::System::Threading::{
        CreateEventW, OpenEventW, ResetEvent, SetEvent, SYNCHRONIZATION_ACCESS_RIGHTS,
    },
};

use super::{EventHandle, Handle};

impl EventHandle {
    #[inline]
    pub fn open(
        flags: SYNCHRONIZATION_ACCESS_RIGHTS,
        inherit: bool,
        name: PCWSTR,
    ) -> ::windows::core::Result<Self> {
        unsafe {
            Ok(Self(Handle::from_raw_handle(OpenEventW(
                flags, inherit, name,
            )?)))
        }
    }

    #[inline]
    pub fn create(manual: bool, init: bool, name: PCWSTR) -> ::windows::core::Result<Self> {
        unsafe {
            Ok(Self(Handle::from_raw_handle(CreateEventW(
                None, manual, init, name,
            )?)))
        }
    }

    pub fn signal(&self) -> ::windows::core::Result<()> {
        unsafe { SetEvent(*self.0) }
    }

    pub fn reset(&self) -> ::windows::core::Result<()> {
        unsafe { ResetEvent(*self.0) }
    }
}
