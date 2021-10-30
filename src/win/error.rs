
use winapi::{
    shared::minwindef::*,
    um::{winbase::*, errhandlingapi::GetLastError},
};
use alloc::string::*;
use crate::strutil::*;

#[inline]
pub fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

#[inline]
pub fn get_error_string(e: u32) -> String {
    use core::ptr::null_mut;

    unsafe {
        let mut buf = [0 as u16; MAX_PATH as usize];
        if FormatMessageW(
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
            null_mut(), e, 0, buf.as_mut_ptr(),
            buf.len() as u32, null_mut()
        ) != 0 {
            let e = buf.iter().position(|&x|
                x == 0 || x == b'\r' as u16 || x == b'\n' as u16
            ).unwrap_or(buf.len());
            buf[..e].as_ref().to_utf8()
        } else { "<UNKNOWN>".to_string() }
    }
}