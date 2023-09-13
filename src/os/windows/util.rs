use super::string::UnicodeUtil;
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
use std::{collections::HashMap, time::Duration};
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
pub fn call_with_timeout<T: 'static>(
    timeout: std::time::Duration,
    callback: impl Fn() -> T + 'static,
) -> Option<T> {
    let event = EventHandle::create(false, false, PCWSTR::null()).ok()?;
    let mut result = None::<T>;

    let resultref = &mut result as *mut Option<T>;
    let eventref = event.as_windows_handle();
    let (th, tid, closure) = ThreadHandle::create_thread_part(move || unsafe {
        resultref.as_mut().unwrap().replace(callback());
        EventHandle::borrow_raw(&eventref).signal().ok();
    })
    .ok()?;

    if ::windows::Win32::Foundation::WAIT_TIMEOUT
        == event.wait_single(Some(timeout.as_millis() as u32))
    {
        th.terminate(1).ok()?;
        None
    } else {
        result
    }
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
            .duplicate_handle_to_current(HANDLE(h.HandleValue as _))
            .ok()?;
        if target.is_invalid() || pid != GetProcessId(*target) {
            None
        } else {
            Some(target)
        }
    })
}

#[derive(Debug, Default)]
pub struct HandleTypeCache {
    pub cache: HashMap<u32, Arc<str>>,
}

impl HandleTypeCache {
    pub fn cache_get(
        &mut self,
        ps: &Process,
        info: &SYSTEM_HANDLE_TABLE_ENTRY_INFO,
    ) -> Option<HandleInfo> {
        let handle = ps
            .duplicate_handle_to_current(HANDLE(info.HandleValue as _))
            .ok()?;
        if handle.is_invalid() {
            return None;
        }

        let type_name = self
            .cache
            .entry(info.ObjectTypeIndex as u32)
            .or_insert_with(|| {
                query_object_type(handle.as_winapi())
                    .map(|t| t.TypeName.to_string())
                    .unwrap_or_default()
                    .into()
            })
            .clone();
        let name = if type_name.as_ref() == "Process" {
            Process { handle }.image_path().unwrap_or_default()
        } else {
            let need_dospath = type_name.as_ref() == "File";
            call_with_timeout(Duration::from_millis(10), move || {
                query_object_name(handle.as_winapi())
                    .ok()
                    .map(|r| {
                        if need_dospath {
                            r.as_slice_with_null()
                                .and_then(|x| unsafe {
                                    #[allow(mutable_transmutes)]
                                    to_dos_path(core::mem::transmute(x)).map(|p| p.to_utf8())
                                })
                                .unwrap_or_else(|| r.to_string())
                        } else {
                            r.to_string()
                        }
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default()
        };
        Some(HandleInfo {
            pid: info.pid(),
            name,
            type_name,
            ty: info.ObjectTypeIndex as u32,
            handle: info.HandleValue as usize,
        })
    }
}

pub fn enum_all_handles<'a>() -> impl Iterator<Item = HandleInfo> + 'a {
    let mut type_cache = HandleTypeCache::default();
    let mut ps_cache = HashMap::<u32, Process>::new();
    system_handle_information().filter_map(move |h| {
        let pid = h.pid();
        if pid < 5 {
            return None;
        }
        let mut ps_handle = ps_cache.get(&pid);
        if ps_handle.is_none() {
            let ph = Process::open(
                pid,
                Some(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION),
            );
            if let Ok(ph) = ph {
                ps_cache.insert(pid, ph);
            }
            ps_handle = ps_cache.get(&pid)
        }
        type_cache.cache_get(ps_handle?, h)
    })
}

#[inline]
pub fn map_or_open(file: HANDLE, path: &str) -> anyhow::Result<memmap2::Mmap> {
    use std::os::windows::io::FromRawHandle;

    if file.is_invalid() {
        Utils::mapfile(path)
    } else {
        unsafe {
            let f = std::fs::File::from_raw_handle(file.0 as _);
            memmap2::Mmap::map(&f).map_err(Into::into)
        }
    }
}
