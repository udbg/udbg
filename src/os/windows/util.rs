use super::*;
use ::windows::{
    core::PCSTR,
    Win32::{
        Foundation::{FARPROC, HANDLE, HMODULE, LUID},
        Security::*,
        Storage::FileSystem::QueryDosDeviceW,
        System::{
            Diagnostics::Debug::OutputDebugStringW, LibraryLoader::GetProcAddress, Threading::*,
        },
    },
};
use alloc::vec::Vec;
use anyhow::Context;
use core::marker::PhantomData;
use core::mem;
use core::ops::{Deref, DerefMut};
use failed_result::*;
use winapi::shared::ntdef::{InitializeObjectAttributes, OBJECT_ATTRIBUTES, PUNICODE_STRING};

#[inline]
pub fn get_current_tid() -> u32 {
    unsafe { GetCurrentThreadId() }
}

pub fn get_proc_address(module: HMODULE, name: PCSTR) -> FARPROC {
    unsafe { GetProcAddress(module, name) }
}

pub fn enable_privilege(name: PCWSTR) -> anyhow::Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        let mut tp: TOKEN_PRIVILEGES = zeroed();
        let mut luid: LUID = zeroed();

        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token)
            .context("open")?;

        let token = Handle(token);
        LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid).context("lookup")?;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(
            token.0,
            false,
            Some(&tp),
            size_of_val(&tp) as u32,
            None,
            None,
        )
        .context("adjust")?;

        Ok(())
    }
}

pub fn enable_debug_privilege() -> anyhow::Result<()> {
    enable_privilege(SE_DEBUG_NAME)
}

pub fn output_debug_string<T: AsRef<str>>(s: T) {
    let s = s.as_ref().to_unicode_with_null();
    unsafe { OutputDebugStringW(PCWSTR(s.as_ptr())) }
}

// refer to PhCallNtQueryObjectWithTimeout
pub fn call_with_timeout<T>(
    timeout: std::time::Duration,
    callback: impl FnOnce() -> T,
) -> Option<T> {
    use std::sync::mpsc::*;

    let (sender, recver) = channel::<T>();
    let (th, tid) = create_thread(move || match sender.send(callback()) {
        _ => {}
    })
    .ok()?;
    let result = recver.recv_timeout(timeout).ok();
    if result.is_none() {
        th.terminate(1).ok();
    }
    result
}

pub fn to_dos_path(path: &mut [u16]) -> Option<&[u16]> {
    let mut buf = [016; 100];
    for d in b'C'..=b'Z' {
        unsafe {
            let mut len =
                QueryDosDeviceW(PCWSTR([d as u16, b':' as u16, 0].as_ptr()), Some(&mut buf))
                    as usize;
            while len > 0 && buf[len - 1] == 0 {
                len -= 1;
            }
            if len > 0 && path.starts_with(&buf[..len]) {
                path[len - 2] = d as u16;
                path[len - 1] = b':' as u16;
                return Some(&path[len - 2..]);
            }
        }
    }
    None
}

pub fn normalize_path(mut path: String) -> String {
    const PREFIX: &str = r#"\SystemRoot"#;
    const PR2: &str = r#"\??\"#;
    const PR3: &str = r#"\\?\"#;

    if path.starts_with(PREFIX) {
        // TODO: https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya
        path.replace_range(..PREFIX.len(), "C:\\Windows");
    }
    if path.starts_with(PR2) {
        path.replace_range(..PR2.len(), "");
    }
    if path.starts_with(PR3) {
        path.replace_range(..PR3.len(), "");
    }
    path
}

#[derive(Clone)]
pub struct BufferType<T>(pub Vec<u8>, PhantomData<T>);

impl<T> BufferType<T> {
    pub fn with_size(size: usize) -> Self {
        let mut r = Vec::with_capacity(size);
        r.resize(r.capacity(), 0);
        Self(r, PhantomData)
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self(data, PhantomData)
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        unsafe { mem::transmute(self.0.as_mut_ptr()) }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<T> Deref for BufferType<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { mem::transmute(self.0.as_ptr()) }
    }
}

impl<T> DerefMut for BufferType<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { mem::transmute(self.0.as_mut_ptr()) }
    }
}

#[repr(C)]
pub struct Align16<T> {
    _align: u64,
    data: T,
}

impl<T: Copy> Align16<T> {
    pub unsafe fn new_zeroed() -> Self {
        Self {
            _align: 0,
            data: core::mem::zeroed(),
        }
    }

    pub fn as_mut(&mut self) -> &mut T {
        unsafe {
            let align_address = transmute::<_, usize>(&self._align);
            if align_address & 0x0F > 0 {
                &mut self.data
            } else {
                transmute(align_address)
            }
        }
    }
}

pub fn register_dll_notification(handler: PLDR_DLL_NOTIFICATION_FUNCTION) -> WindowsResult<()> {
    use winapi::shared::ntstatus::STATUS_NOT_FOUND;
    use winapi::um::libloaderapi::*;

    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr().cast());
        let fun: Option<FnLdrRegisterDllNotification> = transmute(GetProcAddress(
            ntdll,
            b"LdrRegisterDllNotification\0".as_ptr().cast(),
        ));
        if let Some(LdrRegisterDllNotification) = fun {
            let mut dll_cookie = 0usize;
            LdrRegisterDllNotification(0, handler, null_mut(), &mut dll_cookie).ntstatus_result()
        } else {
            STATUS_NOT_FOUND.ntstatus_result()
        }
    }
}

#[inline]
pub fn init_object_attributes(name: PUNICODE_STRING, attr: u32) -> OBJECT_ATTRIBUTES {
    unsafe {
        let mut result = mem::zeroed();
        InitializeObjectAttributes(&mut result, name, attr, null_mut(), null_mut());
        result
    }
}

pub fn duplicate_process(pid: u32, access: u32) -> impl Iterator<Item = Handle> {
    find_handle(7, access).filter_map(move |h| unsafe {
        if h.pid() < 5 {
            return None;
        }
        let p = Process::open(h.pid(), Some(PROCESS_DUP_HANDLE)).ok()?;
        // println!("Handle {:x} Access {:x} Pid {}", h.HandleValue, h.GrantedAccess, h.pid());
        let target = p
            .duplicate_handle(HANDLE(h.HandleValue as _), GetCurrentProcess())
            .ok()?;
        if target.is_invalid() || pid != GetProcessId(target) {
            None
        } else {
            Some(Handle::from_raw_handle(target))
        }
    })
}
