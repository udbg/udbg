mod handle;
mod process;
#[cfg(test)]
mod test;
mod thread;
mod toolhelp;
mod udbg;
mod util;

#[cfg(feature = "dbgeng")]
pub mod dbgeng;
pub mod event;
pub mod ntdll;
pub mod string;
pub mod symbol;

pub use self::handle::*;
pub use self::process::*;
pub use self::thread::*;
pub use self::toolhelp::*;
pub use self::udbg::*;
pub use self::util::*;

// see https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority#return-value
pub type priority_t = i32;
pub type pid_t = u32;

use alloc::string::String;
use alloc::sync::Arc;
use anyhow::{Context, Result};
use core::mem::{size_of_val, transmute, zeroed};
use core::ptr::{null, null_mut};
use failed_result::LastError;
// use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use winapi::um::{
    processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST,
    winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE},
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{NTSTATUS, UNICODE_STRING},
        System::{
            Diagnostics::Debug::EXCEPTION_RECORD, SystemServices::*, Threading::*,
            WindowsProgramming::*,
        },
    },
};

use crate::prelude::*;
use ntdll::*;

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ExceptionRecord {
    pub code: i32,
    pub flags: u32,
    pub record: u64,
    pub address: u64,
    pub param_num: u32,
    pub params: [u64; EXCEPTION_MAXIMUM_PARAMETERS as usize],
}

impl ExceptionRecord {
    pub fn code_status(&self) -> NTSTATUS {
        NTSTATUS(self.code)
    }

    pub fn copy(&mut self, r: &EXCEPTION_RECORD) {
        self.code = r.ExceptionCode.0;
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

impl ReadValue<String> for UNICODE_STRING {
    fn read_value<R: ReadMemoryUtils + ?Sized>(r: &R, address: usize) -> Option<String> {
        r.read_copy::<UNICODE_STRING>(address)
            .and_then(|u| r.read_wstring(u.Buffer.0 as usize, u.Length as usize / 2))
    }
}

impl ReadValue for IMAGE_DOS_HEADER {
    fn read_value<R: ReadMemoryUtils + ?Sized>(r: &R, address: usize) -> Option<Self> {
        let dos = r.read_copy::<Self>(address)?;
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }
        Some(dos)
    }
}

impl ReadValue for IMAGE_NT_HEADERS {
    fn read_value<R: ReadMemoryUtils + ?Sized>(r: &R, address: usize) -> Option<Self> {
        let nt = r.read_copy::<Self>(address)?;
        if nt.Signature != IMAGE_NT_SIGNATURE {
            return None;
        }
        Some(nt)
    }
}

pub trait ReadMemUtilsWin: ReadMemoryUtils {
    fn read_ansi(&self, address: usize, max: impl Into<Option<usize>>) -> Option<String> {
        let r = self.read_cstring(address, max)?;
        Some(r.to_unicode().to_utf8())
    }

    // read a C string, if it is not a valid utf8 string, try convert from ANSI encoding
    fn read_utf8_or_ansi(&self, address: usize, max: impl Into<Option<usize>>) -> Option<String> {
        let r = self.read_cstring(address, max)?;
        match String::from_utf8(r) {
            Ok(res) => Some(res),
            Err(err) => Some(err.as_bytes().to_unicode().to_utf8()),
        }
    }

    fn read_nt_header(&self, mod_base: usize) -> Option<(IMAGE_NT_HEADERS, usize)> {
        let dos = self.read_value::<IMAGE_DOS_HEADER>(mod_base)?;
        let nt = self.read_value::<IMAGE_NT_HEADERS>(mod_base + dos.e_lfanew as usize)?;
        Some((nt, dos.e_lfanew as usize))
    }
}

impl<T: ReadMemoryUtils + ?Sized> ReadMemUtilsWin for T {}

pub const fn ProcThreadAttributeValue(number: u32, thread: u32, input: u32, additive: u32) -> u32 {
    ((number) & PROC_THREAD_ATTRIBUTE_NUMBER)
        | (if thread != 0 {
            PROC_THREAD_ATTRIBUTE_THREAD
        } else {
            0
        })
        | (if input != 0 {
            PROC_THREAD_ATTRIBUTE_INPUT
        } else {
            0
        })
        | (if additive != 0 {
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
    ppid: Option<u32>,
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

        let DEFAULT_OPTION = DEBUG_PROCESS | CREATE_NEW_CONSOLE /*DEBUG_ONLY_THIS_PROCESS*/;
        let mut create_process = |opt: PROCESS_CREATION_FLAGS, si: *const STARTUPINFOW| {
            CreateProcessW(
                None,
                windows::core::PWSTR(cmdline.to_wide().as_mut_ptr()),
                None,
                None,
                false,
                DEFAULT_OPTION | opt,
                None,
                PCWSTR(cwd),
                si,
                pi,
            )
        };
        if let Some(ppid) = ppid {
            let mut si: STARTUPINFOEXW = core::mem::zeroed();
            si.StartupInfo.cb = size_of_val(&si) as u32;

            let mut psize = 0;
            InitializeProcThreadAttributeList(Default::default(), 1, 0, &mut psize);
            let mut pa = BufferType::<PROC_THREAD_ATTRIBUTE_LIST>::with_size(psize);
            let mut handle =
                OpenProcess(PROCESS_CREATE_PROCESS, false, ppid).context("open ppid")?;

            let ppa = LPPROC_THREAD_ATTRIBUTE_LIST(pa.as_mut_ptr().cast());
            InitializeProcThreadAttributeList(ppa, 1, 0, &mut psize);
            const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize =
                ProcThreadAttributeValue(0, 0, 1, 0) as usize;
            UpdateProcThreadAttribute(
                ppa,
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                Some(&mut handle as *mut _ as _),
                size_of_val(&handle),
                None,
                None,
            )
            .context("set ppid")?;

            si.lpAttributeList = ppa;
            let result = create_process(EXTENDED_STARTUPINFO_PRESENT, transmute(&mut si));
            DeleteProcThreadAttributeList(ppa);
            result
        } else {
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = size_of_val(&si) as u32;
            create_process(Default::default(), &mut si)
        }?;
        Ok(Process::from_handle(Handle::from_raw_handle(pi.hProcess)).last_error()?)
    }
}
