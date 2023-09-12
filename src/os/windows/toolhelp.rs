use std::mem::size_of_val;

use windows::Win32::{Foundation::HANDLE, System::Diagnostics::ToolHelp::*};

use crate::string::ToMbstr;

use super::Handle;

pub type ToolHelperFnPtr<T> = unsafe fn(HANDLE, *mut T) -> windows::core::Result<()>;

pub struct ToolHelperIter<T: Copy> {
    count: u32,
    handle: Handle,
    data: T,
    first: ToolHelperFnPtr<T>,
    next: ToolHelperFnPtr<T>,
}

impl<T: Copy> ToolHelperIter<T> {
    pub fn new(
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

    pub fn next_item(&mut self) -> bool {
        let success = unsafe {
            if self.count > 0 {
                (self.next)(*self.handle, &mut self.data).is_ok()
            } else {
                (self.first)(*self.handle, &mut self.data).is_ok()
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

pub trait ProcessExt: core::ops::Deref<Target = PROCESSENTRY32W> + Sized {
    #[inline]
    fn pid(self) -> u32 {
        self.th32ProcessID
    }
    #[inline]
    fn name(self) -> String {
        self.szExeFile.as_ref().to_utf8()
    }
}
impl ProcessExt for &PROCESSENTRY32W {}

pub fn enum_process() -> windows::core::Result<ToolHelperIter<PROCESSENTRY32W>> {
    unsafe {
        let mut pe32: PROCESSENTRY32W = core::mem::zeroed();
        pe32.dwSize = size_of_val(&pe32) as u32;
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map(|ts| ToolHelperIter::new(ts, pe32, Process32FirstW, Process32NextW))
    }
}

pub fn enum_module(pid: u32) -> windows::core::Result<ToolHelperIter<MODULEENTRY32W>> {
    unsafe {
        let mut te32: MODULEENTRY32W = core::mem::zeroed();
        te32.dwSize = size_of_val(&te32) as u32;
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
            .map(|ts| ToolHelperIter::new(ts, te32, Module32FirstW, Module32NextW))
    }
}

pub fn enum_thread() -> windows::core::Result<ToolHelperIter<THREADENTRY32>> {
    unsafe {
        let mut te32: THREADENTRY32 = core::mem::zeroed();
        te32.dwSize = size_of_val(&te32) as u32;
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map(|ts| ToolHelperIter::new(ts, te32, Thread32First, Thread32Next))
    }
}
