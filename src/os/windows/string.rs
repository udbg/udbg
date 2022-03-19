use core::marker::PhantomData;
use core::{mem, ptr};

use crate::string::*;
use ntapi::ntrtl::RtlInitUnicodeString;
use std::ffi::OsString;
use std::os::windows::prelude::*;

use winapi::{shared::ntdef::*, um::stringapiset::*};

pub trait ToMbstr {
    fn to_utf8(&self) -> String;
    fn to_ansi(&self, codepage: u32) -> Vec<u8>;
}

pub fn unicode_to_mbstr(codepage: u32, s: &[u16]) -> Vec<u8> {
    let len = s.iter().position(|&x| x == 0).unwrap_or(s.len());
    unsafe {
        let len = WideCharToMultiByte(
            codepage,
            0,
            s.as_ptr(),
            len as i32,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let mut buf = vec![0u8; len as usize];
        WideCharToMultiByte(
            codepage,
            0,
            s.as_ptr(),
            s.len() as i32,
            buf.as_mut_ptr() as LPSTR,
            len,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        return buf;
    }
}

pub fn mbstr_to_unicode(codepage: u32, s: &[i8]) -> Vec<u16> {
    let len = s.iter().position(|&x| x == 0).unwrap_or(s.len());
    unsafe {
        let len = MultiByteToWideChar(codepage, 0, s.as_ptr(), len as i32, ptr::null_mut(), 0);
        let mut buf = vec![0u16; len as usize];
        MultiByteToWideChar(
            codepage,
            0,
            s.as_ptr(),
            s.len() as i32,
            buf.as_mut_ptr(),
            len,
        );
        return buf;
    }
}

impl<T: AsRef<[u16]>> ToMbstr for T {
    // fn to_utf8(&self) -> String {
    //     unsafe {
    //         String::from_utf8_unchecked(unicode_to_mbstr(CP_UTF8, self.as_ref()))
    //     }
    // }

    fn to_utf8(&self) -> String {
        String::from_utf16_lossy(self.as_ref().strslice())
    }

    fn to_ansi(&self, codepage: u32) -> Vec<u8> {
        unicode_to_mbstr(codepage, self.as_ref())
    }
}

#[inline]
pub fn ansi_to_unicode(s: impl AsRef<[u8]>, codepage: u32) -> Vec<u16> {
    unsafe { mbstr_to_unicode(codepage, mem::transmute::<_, &[i8]>(s.as_ref())) }
}

macro_rules! impl_unicode {
    ($t:ty) => {
        impl ToUnicode for $t {
            fn to_unicode(&self) -> Vec<u16> {
                unsafe { mbstr_to_unicode(0, mem::transmute::<_, &[i8]>(self)) }
            }
        }
    };
}
impl_unicode!([i8]);
impl_unicode!([u8]);

pub trait UnicodeUtil {
    fn len(&self) -> usize;
    fn capacity(&self) -> usize;
    fn as_slice(&self) -> Option<&[u16]>;
    fn as_slice_with_null(&self) -> Option<&[u16]>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn to_string(&self) -> String {
        String::from_utf16_lossy(self.as_slice().unwrap_or(&[]))
    }
}

impl UnicodeUtil for UNICODE_STRING {
    fn len(&self) -> usize {
        self.Length as usize / 2
    }
    fn capacity(&self) -> usize {
        self.MaximumLength as usize / 2
    }
    fn as_slice(&self) -> Option<&[u16]> {
        if self.Buffer.is_null() {
            return None;
        }
        Some(unsafe { core::slice::from_raw_parts(self.Buffer, self.len()) })
    }
    fn as_slice_with_null(&self) -> Option<&[u16]> {
        if self.Buffer.is_null() {
            return None;
        }
        Some(unsafe { core::slice::from_raw_parts(self.Buffer, self.len() + 1) })
    }
}

#[derive(Deref, DerefMut)]
pub struct UniStr<'a>(
    #[deref]
    #[deref_mut]
    UNICODE_STRING,
    PhantomData<&'a ()>,
);

impl UniStr<'_> {
    // from slice directly
    #[inline]
    pub fn from_slice<'a>(slice: &'a [u16]) -> UniStr<'a> {
        UniStr(
            UNICODE_STRING {
                Length: slice.len() as u16 * 2,
                MaximumLength: slice.len() as u16 * 2,
                Buffer: slice.as_ptr() as *mut u16,
            },
            PhantomData,
        )
    }

    pub fn as_mut_ptr(&mut self) -> PUNICODE_STRING {
        &mut self.0
    }
}

impl<'a> From<&'a [u16]> for UniStr<'a> {
    fn from(slice: &[u16]) -> Self {
        unsafe {
            let mut result = core::mem::zeroed();
            RtlInitUnicodeString(&mut result, slice.as_ref().as_ptr());
            UniStr(result, PhantomData)
        }
    }
}

impl From<PCWCHAR> for UniStr<'_> {
    fn from(p: PCWCHAR) -> Self {
        unsafe {
            let mut result = core::mem::zeroed();
            RtlInitUnicodeString(&mut result, p);
            UniStr(result, PhantomData)
        }
    }
}

pub trait FromWide {
    fn from_wide(wstr: &[u16]) -> Self
    where
        Self: Sized;
    fn from_wide_ptr(p: *const u16) -> Self
    where
        Self: Sized;
}

impl FromWide for String {
    fn from_wide(wstr: &[u16]) -> Self {
        OsString::from_wide(wstr).to_str().unwrap_or("").into()
    }

    fn from_wide_ptr(p: *const u16) -> Self {
        if p.is_null() {
            return "".into();
        }
        unsafe {
            let r = std::slice::from_raw_parts(p, usize::MAX);
            String::from_wide(&r[..r.iter().position(|&v| v == 0).unwrap_or(r.len())])
        }
    }
}

pub struct UnicodeString(pub UNICODE_STRING, pub Vec<u16>);

impl From<&str> for UnicodeString {
    fn from(v: &str) -> Self {
        v.to_unicode_with_null().into()
    }
}

impl From<Vec<u16>> for UnicodeString {
    fn from(v: Vec<u16>) -> Self {
        let us = UniStr::from_slice(v.as_slice()).0;
        Self(us, v)
    }
}
