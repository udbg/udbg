mod ffi;
mod window;

#[cfg(feature = "dbglog")]
pub mod dbglog;
pub mod eng;
pub mod ntdll;
pub mod string;
pub mod symbol;
pub mod udbg;
pub mod util;

pub use self::util::*;
pub use self::window::*;

use alloc::string::String;
use alloc::sync::Arc;
use core::mem::{size_of, size_of_val, transmute, zeroed};
use core::ops::Deref;
use core::ptr::{null, null_mut};
use core::slice::{from_raw_parts, from_raw_parts_mut};

use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use winapi::shared::minwindef::*;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::shared::windef::*;
use winapi::um::handleapi::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::psapi::*;
use winapi::um::tlhelp32::*;
use winapi::um::winbase::*;
use winapi::um::winnt::*;
use winapi::um::winuser::*;

use anyhow::{Error, Result};
use std::io::Error as IoError;

use super::ntdll::*;
use crate::{pid_t, prelude::*};

#[derive(Deref)]
pub struct Handle(HANDLE);

unsafe impl Send for Handle {}

impl Handle {
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.0 != INVALID_HANDLE_VALUE
    }

    #[inline]
    pub fn success(&self) -> bool {
        self.is_valid() && !self.is_null()
    }

    #[inline(always)]
    pub unsafe fn from_raw_handle(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub unsafe fn clone_from_raw(handle: HANDLE) -> Result<Self, IoError> {
        let mut result = null_mut();
        if DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut result,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        ) > 0
        {
            Ok(Self::from_raw_handle(result))
        } else {
            Err(IoError::last_os_error())
        }
    }

    #[inline(always)]
    pub fn clone(&self) -> Result<Self, IoError> {
        unsafe { Self::clone_from_raw(self.0) }
    }
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        Handle::clone(self).expect("clone")
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

type ToolHelperFnPtr<T> = unsafe extern "system" fn(HANDLE, *mut T) -> BOOL;

pub struct ToolHelperIter<T: Copy> {
    count: u32,
    handle: Handle,
    data: T,
    first: ToolHelperFnPtr<T>,
    next: ToolHelperFnPtr<T>,
}

impl<T: Copy> ToolHelperIter<T> {
    fn new(
        handle: HANDLE,
        data: T,
        first: ToolHelperFnPtr<T>,
        next: ToolHelperFnPtr<T>,
    ) -> ToolHelperIter<T> {
        // assert!(handle != INVALID_HANDLE_VALUE);
        let handle = unsafe { Handle::from_raw_handle(handle) };
        ToolHelperIter {
            handle,
            count: 0,
            data,
            first,
            next,
        }
    }

    fn next_item(&mut self) -> bool {
        let success = unsafe {
            if self.count > 0 {
                (self.next)(*self.handle, &mut self.data) > 0
            } else {
                (self.first)(*self.handle, &mut self.data) > 0
            }
        };
        self.count += 1;
        return success;
    }
}

impl<T: Copy> Iterator for ToolHelperIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.next_item() {
            Some(self.data)
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MemoryPage {
    pub base: usize,
    pub alloc_base: usize,
    pub size: usize,
    pub type_: u32,
    pub state: u32,
    pub protect: u32,
    pub alloc_protect: u32,
}

impl crate::range::RangeValue for MemoryPage {
    #[inline]
    fn as_range(&self) -> core::ops::Range<usize> {
        self.base..self.base + self.size
    }
}

impl MemoryPage {
    pub fn from_mbi(mbi: &MEMORY_BASIC_INFORMATION) -> MemoryPage {
        MemoryPage {
            base: mbi.BaseAddress as usize,
            alloc_base: mbi.AllocationBase as usize,
            size: mbi.RegionSize,
            type_: mbi.Type,
            state: mbi.State,
            protect: mbi.Protect,
            alloc_protect: mbi.AllocationProtect,
        }
    }

    #[inline]
    pub fn is_commit(&self) -> bool {
        self.state & MEM_COMMIT > 0
    }

    #[inline]
    pub fn is_reserve(&self) -> bool {
        self.state & MEM_RESERVE > 0
    }

    #[inline]
    pub fn is_free(&self) -> bool {
        self.state & MEM_FREE > 0
    }

    #[inline]
    pub fn is_private(&self) -> bool {
        self.type_ & MEM_PRIVATE > 0
    }

    pub fn is_executable(&self) -> bool {
        self.protect & 0xF0 > 0
    }
    pub fn is_writable(&self) -> bool {
        self.protect & 0xCC > 0
    }
    pub fn is_readonly(&self) -> bool {
        self.protect == PAGE_READONLY
    }

    pub fn protect(&self) -> String {
        let guard = self.protect & PAGE_GUARD > 0;
        let mut result = match self.protect & !PAGE_GUARD {
            PAGE_NOACCESS => "-----",
            PAGE_READONLY => "-R---",
            PAGE_READWRITE => "-RW--",
            PAGE_WRITECOPY => "-RWC-",
            PAGE_EXECUTE => "E----",
            PAGE_EXECUTE_READ => "ER---",
            PAGE_EXECUTE_READWRITE => "ERW--",
            PAGE_EXECUTE_WRITECOPY => "ERWC-",
            _ => "?????",
        }
        .to_string();
        if guard {
            unsafe {
                result.as_bytes_mut()[4] = b'G';
            }
        }
        result
    }

    pub fn type_(&self) -> &'static str {
        match self.type_ {
            MEM_PRIVATE => "PRV",
            MEM_IMAGE => "IMG",
            MEM_MAPPED => "MAP",
            _ => "",
        }
    }
}

#[extend::ext(name = ThreadInfo)]
pub impl THREADENTRY32 {
    #[inline]
    fn pid(&self) -> u32 {
        self.th32OwnerProcessID
    }
    #[inline]
    fn tid(&self) -> u32 {
        self.th32ThreadID
    }
}

pub fn enum_thread() -> ToolHelperIter<THREADENTRY32> {
    unsafe {
        let mut te32: THREADENTRY32 = zeroed();
        te32.dwSize = size_of_val(&te32) as u32;
        ToolHelperIter::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).into(),
            te32,
            Thread32First,
            Thread32Next,
        )
    }
}

#[extend::ext(name = ModuleInfo)]
pub impl MODULEENTRY32W {
    #[inline(always)]
    fn name(self) -> String {
        self.szModule.as_ref().to_utf8()
    }
    #[inline(always)]
    fn path(self) -> String {
        self.szExePath.as_ref().to_utf8()
    }
    #[inline(always)]
    fn base(self) -> usize {
        self.modBaseAddr as usize
    }
    #[inline(always)]
    fn size(self) -> usize {
        self.modBaseSize as usize
    }
    #[inline(always)]
    fn id(self) -> u32 {
        self.th32ModuleID
    }
}

impl crate::range::RangeValue for MODULEENTRY32W {
    fn as_range(&self) -> core::ops::Range<usize> {
        self.base()..self.base() + self.size()
    }
}

pub trait ProcessInfo: Deref<Target = PROCESSENTRY32W> + Sized {
    #[inline]
    fn pid(self) -> u32 {
        self.th32ProcessID
    }
    #[inline]
    fn name(self) -> String {
        self.szExeFile.as_ref().to_utf8()
    }
}
impl ProcessInfo for &PROCESSENTRY32W {}

pub fn enum_process() -> ToolHelperIter<PROCESSENTRY32W> {
    unsafe {
        let mut pe32: PROCESSENTRY32W = zeroed();
        pe32.dwSize = size_of_val(&pe32) as u32;
        ToolHelperIter::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0),
            pe32,
            Process32FirstW,
            Process32NextW,
        )
    }
}

#[inline]
pub fn enum_process_filter_name(name: &str) -> impl Iterator<Item = PROCESSENTRY32W> + '_ {
    enum_process().filter(move |p| p.name().eq_ignore_ascii_case(name))
}

pub fn get_thread_context(tid: u32, context: &mut CONTEXT, flags: u32) -> bool {
    let handle = open_thread(tid, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, false);
    unsafe {
        context.ContextFlags = flags;
        SuspendThread(handle.0);
        let r = GetThreadContext(handle.0, context);
        ResumeThread(handle.0);
        return r > 0;
    }
}

pub fn enum_module(pid: u32) -> ToolHelperIter<MODULEENTRY32W> {
    unsafe {
        let mut te32: MODULEENTRY32W = zeroed();
        te32.dwSize = size_of_val(&te32) as u32;
        ToolHelperIter::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid),
            te32,
            Module32FirstW,
            Module32NextW,
        )
    }
}

pub trait UnicodeUtil {
    fn size(&self) -> u16;
    fn max_size(&self) -> u16;
    fn to_string(&self) -> String;
    fn as_slice(&self) -> Option<&[u16]>;
    fn as_mut_slice(&mut self) -> Option<&mut [u16]>;
    fn as_slice_with_null(&self) -> Option<&[u16]>;
}

impl UnicodeUtil for UNICODE_STRING {
    fn size(&self) -> u16 {
        self.Length
    }
    fn max_size(&self) -> u16 {
        self.MaximumLength
    }

    fn to_string(&self) -> String {
        unsafe { from_raw_parts(self.Buffer, self.Length as usize).to_utf8() }
    }

    fn as_mut_slice(&mut self) -> Option<&mut [u16]> {
        unsafe {
            if self.Buffer.is_null() {
                return None;
            }
            Some(from_raw_parts_mut(self.Buffer, self.size() as usize))
        }
    }

    fn as_slice(&self) -> Option<&[u16]> {
        if self.Buffer.is_null() {
            return None;
        }
        Some(unsafe { from_raw_parts(self.Buffer, self.size() as usize) })
    }

    fn as_slice_with_null(&self) -> Option<&[u16]> {
        if self.Buffer.is_null() {
            return None;
        }
        Some(unsafe { from_raw_parts(self.Buffer, self.size() as usize + 1) })
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub record: u64,
    pub address: u64,
    pub param_num: u32,
    pub params: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
}

impl ExceptionRecord {
    pub fn copy(&mut self, r: &EXCEPTION_RECORD) {
        self.code = r.ExceptionCode;
        self.flags = r.ExceptionFlags;
        self.record = r.ExceptionRecord as u64;
        self.address = r.ExceptionAddress as u64;
        self.param_num = r.NumberParameters;
        for i in 0..r.NumberParameters as usize {
            self.params[i] = r.ExceptionInformation[i] as u64;
        }
    }
}

pub const SIZE_OF_CALL: usize = 5;

pub fn read_process_memory(handle: HANDLE, address: usize, data: &mut [u8]) -> usize {
    let mut readed = 0usize;
    let address = address as LPVOID;
    let pdata = data.as_mut_ptr() as LPVOID;
    unsafe {
        if ReadProcessMemory(handle, address, pdata, data.len(), &mut readed) > 0 {
            readed
        } else {
            0usize
        }
    }
}

pub fn write_process_memory(handle: HANDLE, address: usize, data: &[u8]) -> usize {
    let mut written = 0usize;
    let mut old_protect = 0u32;
    let mut new_protect = 0u32;
    let address = address as LPVOID;
    unsafe {
        VirtualProtectEx(
            handle,
            address,
            data.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        let result = WriteProcessMemory(
            handle,
            address,
            data.as_ptr() as LPVOID,
            data.len(),
            &mut written,
        );
        VirtualProtectEx(handle, address, data.len(), old_protect, &mut new_protect);
        if result > 0 {
            written
        } else {
            0usize
        }
    }
}

#[derive(Clone)]
pub struct Process {
    pub handle: Handle,
}

pub struct MemoryIter<'p> {
    pub process: &'p Process,
    pub address: usize,
}

impl MemoryIter<'_> {
    pub fn next_commit(&mut self) -> Option<MemoryPage> {
        while let Some(m) = self.next() {
            if m.is_commit() {
                return Some(m);
            }
        }
        return None;
    }
}

impl Iterator for MemoryIter<'_> {
    type Item = MemoryPage;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.process.virtual_query(self.address);
        if let Some(m) = result.as_ref() {
            self.address += m.size;
        }
        return result;
    }
}

impl ReadMemory for Process {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let r = read_process_memory(*self.handle, addr, data);
        if r > 0 {
            Some(&mut data[..r])
        } else {
            None
        }
    }
}

impl WriteMemory for Process {
    fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        let r = self.write_memory(address, data);
        if r > 0 {
            Some(r)
        } else {
            None
        }
    }
}

impl Process {
    pub fn open(pid: u32, access: Option<u32>) -> Option<Process> {
        unsafe {
            let handle = OpenProcess(access.unwrap_or(PROCESS_ALL_ACCESS), 0, pid);
            if handle.is_null() {
                None
            } else {
                Process::from_handle(Handle::from_raw_handle(handle))
            }
        }
    }

    pub fn duplicate_from_other_process(pid: u32, access: u32) -> Result<Process> {
        let handle = duplicate_process(pid, access)
            .next()
            .ok_or(Error::msg("dup not found"))?;
        Self::from_handle(handle).ok_or_else(|| IoError::last_os_error().into())
    }

    pub fn from_name(name: &str, access: Option<u32>) -> Result<Process> {
        let pid = enum_process_filter_name(name)
            .next()
            .ok_or(Error::msg("name not found"))?
            .pid();
        Self::open(pid, access).ok_or_else(|| IoError::last_os_error().into())
    }

    pub fn from_handle(handle: Handle) -> Option<Process> {
        unsafe {
            let pid = GetProcessId(*handle);
            if pid == 0 {
                return None;
            }

            return Some(Process { handle });
        }
    }

    pub fn current() -> Process {
        unsafe { Self::from_handle(Handle::from_raw_handle(GetCurrentProcess())).unwrap() }
    }

    pub fn basic_information(&self) -> Option<PROCESS_BASIC_INFORMATION> {
        query_process(*self.handle, ProcessInfoClass::BasicInformation, None)
    }

    pub fn pid(&self) -> u32 {
        unsafe { GetProcessId(*self.handle) }
    }

    pub fn peb(&self) -> Option<usize> {
        self.basic_information().map(|i| i.PebBaseAddress as usize)
    }

    /// https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
    pub fn is_wow64(&self) -> bool {
        use winapi::um::wow64apiset::IsWow64Process;
        let mut result: BOOL = 0;
        unsafe {
            IsWow64Process(*self.handle, &mut result);
        };
        return result != 0;
    }

    pub fn get_module_name(&self, module: u64) -> Result<String> {
        unsafe {
            let mut name = [0 as u16; MAX_PATH];
            if GetModuleBaseNameW(
                *self.handle,
                module as HMODULE,
                name.as_mut_ptr(),
                MAX_PATH as u32,
            ) > 0
            {
                Ok(name.as_ref().to_utf8())
            } else {
                Err(IoError::last_os_error().into())
            }
        }
    }

    // TODO: [bug] wow64进程下32位dll取到的是64位的路径
    #[deprecated]
    pub fn get_module_path(&self, module: usize) -> Option<String> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH];
            if GetModuleFileNameExW(
                *self.handle,
                module as HMODULE,
                path.as_mut_ptr(),
                MAX_PATH as u32,
            ) > 0
            {
                Some(path.as_ref().to_utf8())
            } else {
                None
            }
        }
    }

    /// use EnumProcessModulesEx
    pub fn get_module_list(&self, flag: u32) -> Option<Vec<usize>> {
        unsafe {
            let mut len = 0u32;
            EnumProcessModulesEx(self.handle.0, null_mut(), 0, &mut len, flag);
            let mut result = vec![0usize; len as usize];
            if len > 0 {
                if EnumProcessModulesEx(
                    self.handle.0,
                    transmute(result.as_mut_ptr()),
                    result.len() as u32,
                    &mut len,
                    flag,
                ) > 0
                {
                    return Some(result.into_iter().filter(|&m| m > 0).collect());
                }
            }
            None
        }
    }

    /// use GetModuleInformation
    pub fn get_module_info(&self, base: usize) -> Option<MODULEINFO> {
        unsafe {
            let mut result: MODULEINFO = zeroed();
            if GetModuleInformation(
                self.handle.0,
                transmute(base),
                &mut result,
                size_of::<MODULEINFO>() as u32,
            ) > 0
            {
                return Some(result);
            }
            None
        }
    }

    pub fn duplicate_handle(&self, src_handle: HANDLE, dst_ps: HANDLE) -> Option<HANDLE> {
        let mut handle: HANDLE = null_mut();
        unsafe {
            if 0 != DuplicateHandle(
                self.handle.0,
                src_handle,
                dst_ps,
                &mut handle,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            ) && !handle.is_null()
            {
                Some(handle)
            } else {
                None
            }
        }
    }

    #[inline]
    pub fn enum_thread<'a>(&'a self) -> impl Iterator<Item = THREADENTRY32> + 'a {
        let pid = self.pid();
        enum_thread().filter(move |x| x.pid() == pid)
    }

    #[inline]
    pub fn enum_module(&self) -> ToolHelperIter<MODULEENTRY32W> {
        enum_module(self.pid())
    }

    /// Wrapper of QueryFullProcessImageNameW
    pub fn image_path(&self) -> Option<String> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH];
            let mut size = path.len() as u32;
            if QueryFullProcessImageNameW(*self.handle, 0, path.as_mut_ptr(), &mut size) > 0 {
                Some(path.as_ref().to_utf8())
            } else {
                None
            }
        }
    }

    pub fn cmdline(&self) -> Option<String> {
        use ntapi::ntpebteb::PEB;
        use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
        use ntapi::FIELD_OFFSET;

        self.peb()
            .and_then(|peb| {
                self.read_value::<usize>(peb as usize + FIELD_OFFSET!(PEB, ProcessParameters))
            })
            .and_then(|p| {
                self.read_unicode_string(
                    p + FIELD_OFFSET!(RTL_USER_PROCESS_PARAMETERS, CommandLine),
                )
            })
    }

    pub fn protect_memory(&self, address: usize, size: usize, attr: u32) -> Option<u32> {
        unsafe {
            let mut oldattr = 0u32;
            let r = VirtualProtectEx(*self.handle, address as LPVOID, size, attr, &mut oldattr);
            if r > 0 {
                Some(oldattr)
            } else {
                None
            }
        }
    }

    #[inline]
    pub fn write_memory(&self, address: usize, data: &[u8]) -> usize {
        write_process_memory(*self.handle, address, data)
    }

    pub fn write_code(&self, address: usize, data: &[u8]) -> Result<usize, IoError> {
        let r = write_process_memory(*self.handle, address, data);
        if unsafe { FlushInstructionCache(*self.handle, address as LPCVOID, data.len()) > 0 } {
            Ok(r)
        } else {
            Err(IoError::last_os_error())
        }
    }

    pub fn enum_memory(&self, address: usize) -> MemoryIter {
        MemoryIter {
            process: self,
            address,
        }
    }

    pub fn virtual_alloc(&self, address: usize, size: usize, mem_type: u32, protect: u32) -> usize {
        unsafe { VirtualAllocEx(*self.handle, address as LPVOID, size, mem_type, protect) as usize }
    }

    pub fn virtual_free(&self, address: usize) -> bool {
        unsafe { VirtualFreeEx(*self.handle, address as LPVOID, 0, MEM_RELEASE) > 0 }
    }

    pub fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
            match VirtualQueryEx(*self.handle, address as LPVOID, &mut mbi, size_of_val(&mbi)) {
                0 => None,
                _ => Some(MemoryPage::from_mbi(&mbi)),
            }
        }
    }

    #[inline]
    pub fn terminate(&self) -> bool {
        unsafe { TerminateProcess(*self.handle, 0) > 0 }
    }

    pub fn get_exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        unsafe {
            if GetExitCodeProcess(*self.handle, &mut code) > 0 {
                Some(code)
            } else {
                None
            }
        }
    }

    // https://docs.microsoft.com/zh-cn/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
    pub fn get_mapped_file_name(&self, address: usize) -> Option<String> {
        unsafe {
            let mut buf = [0u16; 300];
            let len = GetMappedFileNameW(
                *self.handle,
                address as LPVOID,
                buf.as_mut_ptr(),
                buf.len() as u32,
            );
            if len > 0 {
                util::to_dos_path(&mut buf)
                    .map(|s| s.to_utf8())
                    .or_else(|| Some(buf.as_ref().to_utf8()))
            } else {
                None
            }
        }
    }
}

#[inline(always)]
fn set_bit(n: &mut reg_t, x: usize, set: bool) {
    if set {
        *n |= 1 << x;
    } else {
        *n &= !(1 << x);
    }
}

#[inline(always)]
fn test_bit(n: reg_t, x: usize) -> bool {
    n & (1 << x) > 0
}

#[inline(always)]
fn set_bit2(n: &mut reg_t, x: usize, v: reg_t) {
    *n &= !(0b11 << x);
    *n |= v << x;
}

const L0: usize = 0;
const G0: usize = 1;
const L1: usize = 2;
const G1: usize = 3;
const L2: usize = 4;
const G2: usize = 5;
const L3: usize = 5;
const G3: usize = 7;
const L_ENABLE: usize = 8;
const G_ENABLE: usize = 9;
const RW0: usize = 16;
const LEN0: usize = 18;
const RW1: usize = 20;
const LEN1: usize = 22;
const RW2: usize = 24;
const LEN2: usize = 26;
const RW3: usize = 28;
const LEN3: usize = 30;

pub trait ReadMemUtilWin: ReadMemoryUtil {
    fn read_ansi(&self, address: usize, max: impl Into<Option<usize>>) -> Option<String> {
        let r = self.read_cstring(address, max)?;
        Some(r.to_unicode().to_utf8())
    }

    fn read_utf8_or_ansi(&self, address: usize, max: impl Into<Option<usize>>) -> Option<String> {
        let r = self.read_cstring(address, max)?;
        match core::str::from_utf8(&r) {
            Ok(_) => String::from_utf8(r).ok(),
            Err(_) => Some(r.to_unicode().to_utf8()),
        }
    }

    fn read_wstring(&self, address: usize, max: impl Into<Option<usize>>) -> Option<String> {
        let result = self.read_util(
            address,
            |&x| x < b' ' as u16 && x != 9 && x != 10 && x != 13,
            max.into().unwrap_or(1000),
        );
        if result.len() == 0 {
            return None;
        }
        Some(result.to_utf8())
    }

    fn read_unicode_string(&self, address: usize) -> Option<String> {
        self.read_value::<UNICODE_STRING>(address)
            .and_then(|u| self.read_wstring(u.Buffer as usize, u.Length as usize / 2))
    }

    fn read_nt_header(&self, mod_base: usize) -> Option<(IMAGE_NT_HEADERS, usize)> {
        let dos: IMAGE_DOS_HEADER = self.read_value(mod_base)?;
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }
        let nt: IMAGE_NT_HEADERS = self.read_value(mod_base + dos.e_lfanew as usize)?;
        if nt.Signature != IMAGE_NT_SIGNATURE {
            return None;
        }
        Some((nt, dos.e_lfanew as usize))
    }
}

impl<T: ReadMemoryUtil + ?Sized> ReadMemUtilWin for T {}

const PROC_THREAD_ATTRIBUTE_NUMBER: usize = 0x0000FFFF;
const PROC_THREAD_ATTRIBUTE_THREAD: usize = 0x00010000;
const PROC_THREAD_ATTRIBUTE_INPUT: usize = 0x00020000;
const PROC_THREAD_ATTRIBUTE_ADDITIVE: usize = 0x00040000;

const fn ProcThreadAttributeValue(
    Number: usize,
    Thread: usize,
    Input: usize,
    Additive: usize,
) -> usize {
    ((Number) & PROC_THREAD_ATTRIBUTE_NUMBER)
        | (if Thread != 0 {
            PROC_THREAD_ATTRIBUTE_THREAD
        } else {
            0
        })
        | (if Input != 0 {
            PROC_THREAD_ATTRIBUTE_INPUT
        } else {
            0
        })
        | (if Additive != 0 {
            PROC_THREAD_ATTRIBUTE_ADDITIVE
        } else {
            0
        })
}

pub fn create_debug_process(
    path: &str,
    cwd: Option<&str>,
    args: &[&str],
    pi: &mut PROCESS_INFORMATION,
    ppid: Option<pid_t>,
) -> UDbgResult<Process> {
    unsafe {
        let mut cmdline = path.trim().to_string();
        if cmdline.find(char::is_whitespace).is_some() {
            cmdline = format!("\"{}\"", cmdline);
        }
        if !args.is_empty() {
            cmdline += " ";
            cmdline += &args.join(" ");
        }
        let cwd = cwd.map(|v| v.to_wide());
        let cwd = cwd.as_ref().map(|r| r.as_ptr()).unwrap_or(null());

        const DEFAULT_OPTION: u32 = /*DEBUG_ONLY_THIS_PROCESS*/
            DEBUG_PROCESS | CREATE_NEW_CONSOLE;
        let mut create_process = |opt: u32, si: LPSTARTUPINFOW| {
            CreateProcessW(
                null_mut(),
                cmdline.to_wide().as_mut_ptr(),
                null_mut(),
                null_mut(),
                FALSE,
                DEFAULT_OPTION | opt,
                null_mut(),
                cwd,
                si,
                pi,
            )
        };
        let r = if let Some(ppid) = ppid {
            let mut si: STARTUPINFOEXW = core::mem::zeroed();
            si.StartupInfo.cb = size_of_val(&si) as u32;

            let mut psize = 0;
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut psize);
            let mut pa = BufferType::<PROC_THREAD_ATTRIBUTE_LIST>::with_size(psize);
            let mut handle = OpenProcess(PROCESS_CREATE_PROCESS, 0, ppid);
            handle.as_ref().ok_or("ppid open failed")?;

            InitializeProcThreadAttributeList(pa.as_mut_ptr(), 1, 0, &mut psize);
            let ProcThreadAttributeParentProcess = 0;
            let PROC_THREAD_ATTRIBUTE_PARENT_PROCESS =
                ProcThreadAttributeValue(ProcThreadAttributeParentProcess, 0, 1, 0);
            if UpdateProcThreadAttribute(
                pa.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                transmute(&mut handle),
                size_of_val(&handle),
                null_mut(),
                null_mut(),
            ) == 0
            {
                return Err("set ppid falied".into());
            }
            si.lpAttributeList = pa.as_mut_ptr();

            let r = create_process(EXTENDED_STARTUPINFO_PRESENT, transmute(&mut si));
            DeleteProcThreadAttributeList(pa.as_mut_ptr());
            r
        } else {
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = size_of_val(&si) as u32;
            create_process(0, &mut si)
        };
        if r == 0 {
            return Err(UDbgError::system());
        }
        Ok(Process::from_handle(Handle::from_raw_handle(pi.hProcess)).check_errstr("get pid")?)
    }
}
