
use super::*;
use winapi::{
    shared::windef::HHOOK,
    um::libloaderapi::*,
    // um::synchapi::WaitForSingleObject,
};
use core::{ptr, mem::{transmute, size_of}};

pub trait ProcessInject {
    fn prepare_unicode_buf(&self, dll_path: &str) -> Result<usize, String>;
    fn get_remote_export(&self, dll: &str, func: &[u8]) -> Option<(usize, usize)>;
}

impl ProcessInject for Process {
    fn prepare_unicode_buf(&self, dll_path: &str) -> Result<usize, String> {
        let buf = self.virtual_alloc(0, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        (buf > 0).check_errstr("VirtualAllocEx")?;
        let ppath = buf + size_of::<UNICODE_STRING>();
        let us = UNICODE_STRING {
            Length: dll_path.len() as u16,
            MaximumLength: dll_path.len() as u16,
            Buffer: unsafe { transmute(ppath) },
        };
        self.write_wstring(ppath, dll_path).check_errstr("write path")?;
        self.write_value(buf, &us).check_errstr("write path")?;
    
        Ok(buf)
    }

    fn get_remote_export(&self, dll: &str, func: &[u8]) -> Option<(usize, usize)> {
        use winapi::um::libloaderapi::*;

        let mut dll_base = 0;
        for m in self.enum_memory(0) {
            if m.type_ == MEM_IMAGE && self.get_mapped_file_name(m.base).unwrap_or_default().ends_with(dll) {
                dll_base = m.base;
                break;
            }
        }
        if dll_base == 0 { return None; }
        let offset = unsafe {
            let nt = GetModuleHandleW(dll.to_unicode_with_null().as_ptr());
            let func = GetProcAddress(nt, func.as_ptr() as *const i8);
            func.as_ref()?;
            func as usize - nt as usize
        };
        Some((dll_base + offset, dll_base))
    }
}

pub struct RTIJData {
    pub tid: u32,
    pub path_buf: usize,
    pub handle: Handle,
}

pub fn by_remotethread(p: &Process, dll_path: &str) -> Result<RTIJData, String> {
    let m = p.enum_module().find(|m| m.name().eq_ignore_ascii_case("kernel32.dll")).ok_or("kernel32")?;

    unsafe {
        let load_library = if p.is_wow64() {
            use std::fs::File;
            use memmap::Mmap;

            let f = File::open(&m.path()).map_err(|_| "open file")?;
            let mmap = Mmap::map(&f).map_err(|_| "map file")?;
            let pe = crate::pe::parse(&mmap).ok_or("parse pe")?;
            let mut rva = 0;
            for e in pe.exports.iter() {
                if e.name == Some("LoadLibraryW") {
                    rva = e.rva;
                    break;
                }
            }
            if rva == 0 { return Err("LoadLibraryW".into()); }
            m.base() + rva as usize
        } else {
            let k32 = GetModuleHandleA(b"kernel32\0".as_ptr() as *const i8);
            let offset = GetProcAddress(k32, b"LoadLibraryW\0".as_ptr() as *const i8) as usize - k32 as usize;
            m.base() + offset
        };
        let buf = p.virtual_alloc(0, dll_path.len() * 2, MEM_COMMIT, PAGE_READWRITE);
        (buf > 0).check_errstr("VirtualAllocEx")?;
        p.write_wstring(buf, dll_path).check_errstr("write path")?;

        let mut tid = 0u32;
        let h = Handle::from_raw_handle(CreateRemoteThreadEx(
            p.handle.0, ptr::null_mut(), 0usize, transmute(load_library),
            buf as LPVOID, 0u32, ptr::null_mut(), &mut tid
        ));
        h.success().check_errstr("CreateRemoteThreadEx")?;
        // WaitForSingleObject(*h, INFINITE);
        // p.virtual_free(buf);
        Ok(RTIJData { tid, path_buf: buf, handle: h })
    }
}

pub fn by_windowhook(hwnd: HWND, dll_path: &str, func: &str) -> Result<HHOOK, String> {
    unsafe {
        let tid = GetWindowThreadProcessId(hwnd, ptr::null_mut());
        if tid == 0 { return Err("thread not found".into()); }

        let hmod = LoadLibraryExW(
            dll_path.to_unicode_with_null().as_ptr(),
            ptr::null_mut(), 1
        ).check_errstr("LoadLibraryExW")?;

        let hook_proc = GetProcAddress(hmod, {
            let mut func = func.to_unicode().to_ansi(0);
            func.push(0); func
        }.as_ptr() as *const i8).check_errstr("GetProcAddress")?;

        let hook = SetWindowsHookExA(
            WH_GETMESSAGE,
            transmute(hook_proc),
            hmod, tid
        ).check_errstr("SetWindowsHookExA")?;
        FreeLibrary(hmod);

        SendMessageA(hwnd, WM_NULL, 0, 0);
        winapi::um::winuser::SetForegroundWindow(hwnd);
        return Ok(hook);
    }
}