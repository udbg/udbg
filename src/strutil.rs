
#[cfg(windows)]
pub use crate::win::string::*;

use std::ffi::{OsStr, CString};

pub trait ToUnicode {
    fn to_unicode(&self) -> Vec<u16>;
    fn to_unicode_with_null(&self) -> Vec<u16> {
        let mut result = self.to_unicode();
        result.push(0);
        result.truncate(result.len() - 1);
        result
    }
}

impl<T: AsRef<str>> ToUnicode for T {
    fn to_unicode(&self) -> Vec<u16> {
        self.as_ref().encode_utf16().collect::<Vec<_>>()
    }
}

pub trait StrLen {
    fn strlen(&self) -> usize;
}

impl StrLen for &[u16] {
    fn strlen(&self) -> usize {
        match self.iter().position(|&x| x == 0) {
            None => self.len(),
            Some(x) => x,
        }
    }
}

pub trait StringUtil {
    #[cfg(windows)]
    fn to_wide(&self) -> Vec<u16>;
    #[cfg(windows)]
    fn to_ansi(&self, codepage: u32) -> Vec<u8>;
    fn to_cstring(&self) -> Vec<u8>;
}

impl StringUtil for str {
    #[cfg(windows)]
    fn to_wide(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        let mut r: Vec<u16> = OsStr::new(self).encode_wide().collect();
        r.push(0u16); return r;
    }

    fn to_cstring(&self) -> Vec<u8> {
        CString::new(self).unwrap().into_bytes_with_nul()
    }

    #[cfg(windows)]
    fn to_ansi(&self, codepage: u32) -> Vec<u8> {
        self.to_unicode().to_ansi(codepage)
    }
}