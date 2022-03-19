use super::*;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem;
use core::ops::{Deref, DerefMut};
use winapi::um::debugapi::OutputDebugStringW;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;

use winapi::shared::ntdef::HANDLE;
use winapi::shared::{minwindef::*, ntdef::*};
use winapi::um::processthreadsapi::*;

#[inline]
pub fn get_current_tid() -> u32 {
    unsafe { GetCurrentThreadId() }
}

pub fn get_proc_address(module: HMODULE, name: impl AsRef<[u8]>) -> FARPROC {
    unsafe { GetProcAddress(module, name.as_ref().as_ptr() as *const i8) }
}

#[inline]
pub fn open_thread(tid: u32, access: u32, inherit: bool) -> Handle {
    unsafe { Handle::from_raw_handle(OpenThread(access, inherit as i32, tid)) }
}

pub fn suspend_thread(tid: u32) -> Handle {
    let handle = open_thread(tid, THREAD_SUSPEND_RESUME, false);
    if handle.is_valid() {
        unsafe {
            SuspendThread(handle.0);
        }
    }
    return handle;
}

#[inline]
pub fn resume_thread(handle: HANDLE) -> u32 {
    unsafe { ResumeThread(handle) }
}

pub fn enable_privilege(name: &str) -> Result<(), String> {
    use winapi::shared::winerror::ERROR_NOT_ALL_ASSIGNED;
    use winapi::um::securitybaseapi::AdjustTokenPrivileges;

    unsafe {
        let mut token: HANDLE = null_mut();
        let mut tp: TOKEN_PRIVILEGES = zeroed();
        let mut luid: LUID = zeroed();

        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token)
            .check_errstr("open")?;

        let token = Handle(token);
        LookupPrivilegeValueW(null(), name.to_unicode_with_null().as_ptr(), &mut luid)
            .check_errstr("lookup")?;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(
            token.0,
            0,
            &mut tp,
            size_of_val(&tp) as u32,
            null_mut(),
            null_mut(),
        )
        .check_errstr("adjust")?;

        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            Err("not all".into())
        } else {
            Ok(())
        }
    }
}

pub fn enable_debug_privilege() -> Result<(), String> {
    enable_privilege(SE_DEBUG_NAME)
}

pub fn output_debug_string<T: AsRef<str>>(s: T) {
    unsafe { OutputDebugStringW(s.as_ref().to_unicode_with_null().as_ptr()) }
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
    })?;
    let result = recver.recv_timeout(timeout).ok();
    if result.is_none() {
        unsafe {
            TerminateThread(th, 1);
        }
    }
    result
}

pub fn msgbox<T: AsRef<str>>(msg: T) {
    unsafe {
        MessageBoxW(
            null_mut(),
            msg.as_ref().to_unicode().as_ptr(),
            "\0\0".as_ptr() as *const u16,
            0u32,
        );
    }
}

pub fn to_dos_path(path: &mut [u16]) -> Option<&[u16]> {
    use winapi::um::fileapi::QueryDosDeviceW;

    let mut buf = [016; 100];
    for d in b'C'..=b'Z' {
        unsafe {
            let mut len = QueryDosDeviceW(
                [d as u16, b':' as u16, 0].as_ptr(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            ) as usize;
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

pub struct Align16<T> {
    _align: u64,
    _data: T,
}

impl<T> Align16<T> {
    pub fn new() -> Self {
        unsafe { core::mem::MaybeUninit::uninit().assume_init() }
    }

    pub fn as_mut(&mut self) -> &mut T {
        unsafe {
            let align_address = transmute::<_, usize>(&self._align);
            if align_address & 0x0F > 0 {
                &mut self._data
            } else {
                transmute(align_address)
            }
        }
    }
}

pub fn register_dll_notification(handler: PLDR_DLL_NOTIFICATION_FUNCTION) -> Result<(), NTSTATUS> {
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
            LdrRegisterDllNotification(0, handler, null_mut(), &mut dll_cookie).check()
        } else {
            Err(STATUS_NOT_FOUND)
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

pub fn get_window(pid: u32) -> Option<HWND> {
    let mut w = null_mut();
    enum_process_window(pid, |hwnd| {
        w = hwnd;
        !w.is_visible()
    });
    if w.is_null() {
        None
    } else {
        Some(w)
    }
}

pub fn duplicate_process(pid: u32, access: u32) -> impl Iterator<Item = Handle> {
    find_handle(7, access).filter_map(move |h| unsafe {
        if h.pid() < 5 {
            return None;
        }
        let p = Handle(OpenProcess(PROCESS_DUP_HANDLE, 0, h.pid()));
        if p.is_null() {
            // error!("OpenProcess {} failed {}", h.pid(), get_last_error_string());
            return None;
        }
        // println!("Handle {:x} Access {:x} Pid {}", h.HandleValue, h.GrantedAccess, h.pid());

        let mut target: HANDLE = null_mut();
        if DuplicateHandle(
            p.0,
            h.HandleValue as HANDLE,
            GetCurrentProcess(),
            &mut target,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        ) == 0
            || target.is_null()
            || pid != GetProcessId(target)
        {
            CloseHandle(target);
            None
        } else {
            Some(Handle::from_raw_handle(target))
        }
    })
}

pub trait IntoThreadProc {
    fn into_thread_fn(self) -> (LPTHREAD_START_ROUTINE, LPVOID);
}

impl<F: FnOnce()> IntoThreadProc for F {
    fn into_thread_fn(self) -> (LPTHREAD_START_ROUTINE, LPVOID) {
        unsafe extern "system" fn wrapper(p: LPVOID) -> u32 {
            let closure: Box<Box<dyn FnOnce()>> = Box::from_raw(transmute(p));
            closure();
            0
        }
        let closure: Box<dyn FnOnce()> = Box::new(self);
        (Some(wrapper), Box::into_raw(Box::new(closure)) as LPVOID)
    }
}

pub fn create_thread(proc: impl IntoThreadProc) -> Option<(HANDLE, u32)> {
    unsafe {
        let mut id: DWORD = 0;
        let (f, p) = proc.into_thread_fn();
        let handle = CreateThread(null_mut(), 0, f, p, 0, &mut id);
        if handle.is_null() {
            None
        } else {
            Some((handle, id))
        }
    }
}
