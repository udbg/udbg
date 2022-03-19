use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::mem::size_of;
use core::slice::{from_raw_parts, from_raw_parts_mut};
use std::io::{BufRead, BufReader, Result as IoResult};
use std::path::Path;

use memmap::Mmap;

pub fn mapfile(path: &str) -> Option<Mmap> {
    std::fs::File::open(path)
        .and_then(|f| unsafe { Mmap::map(&f) })
        .ok()
}

pub fn file_lines<P: AsRef<Path>>(path: P) -> IoResult<impl Iterator<Item = String>> {
    Ok(BufReader::new(std::fs::File::open(path)?)
        .lines()
        .map(|line| line.unwrap_or_default()))
}

pub trait AsByteArray {
    fn as_byte_array(&self) -> &[u8];
}

impl<T: Sized> AsByteArray for T {
    fn as_byte_array(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const T as *const u8, size_of::<T>()) }
    }
}

impl<T: Sized> AsByteArray for [T] {
    fn as_byte_array(&self) -> &[u8] {
        unsafe {
            from_raw_parts(
                self.as_ptr() as *const T as *const u8,
                size_of::<T>() * self.len(),
            )
        }
    }
}

pub trait AsByteArrayMut {
    fn as_mut_byte_array(&mut self) -> &mut [u8];
}

impl<T: Sized> AsByteArrayMut for T {
    fn as_mut_byte_array(&mut self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self as *mut T as *mut u8, size_of::<T>()) }
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#[macro_export]
macro_rules! sc_asm {
    ($asm:expr) => {
        core::arch::asm!($asm)
    };
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[macro_export]
macro_rules! sc_asm {
    ($asm:expr) => {
        core::arch::asm!($asm)
    };
}

#[macro_export]
macro_rules! shellcode {
    ($($asm:expr)*) => {
        unsafe {
            // #[naked]
            unsafe fn shellcode() {
                core::arch::asm!($($asm,)*);
                core::arch::asm!(".byte 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF");
            }
            let buf = std::slice::from_raw_parts(shellcode as *const u8, 0x10000);
            let len = buf.windows(8).position(|w| w == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
            core::slice::from_raw_parts(shellcode as *const u8, len)
        }
    };
}

bitflags! {
    pub struct UFlags: u32 {
        const NONE = 0b00000000;
        const UNDEC_TYPE = 1 << 0;
        const UNDEC_RETN = 1 << 1;
        const UNDEC_NAME_ONLY = 1 << 2;

        const DISASM_RAW = 1 << 8;
        const DISASM_SYMBOL = 1 << 9;
        // const DISASM_SYMBOL = 1 << 3;

        const SHOW_OUTPUT = 1 << 16;
    }
}

impl Default for UFlags {
    fn default() -> Self {
        Self::SHOW_OUTPUT | Self::UNDEC_NAME_ONLY
    }
}

#[cfg(windows)]
pub fn undecorate_symbol(sym: &str, flags: UFlags) -> Option<String> {
    use msvc_demangler::*;

    let mut sym_flags = DemangleFlags::COMPLETE;
    if flags.contains(UFlags::UNDEC_NAME_ONLY) {
        sym_flags = DemangleFlags::NAME_ONLY;
    } else {
        // if flags & UFLAG_UNDEC_TYPE == 0 { sym_flags |= DemangleFlags::NO_ARGUMENTS; }
        if !flags.contains(UFlags::UNDEC_RETN) {
            sym_flags |= DemangleFlags::NO_FUNCTION_RETURNS;
        }
    }

    demangle(sym, sym_flags).ok()
}

/// Convert a reference to Weak<T>, please ensure the reference is from Arc<T>
pub unsafe fn to_weak<T: ?Sized>(t: &T) -> Weak<T> {
    let t = Arc::from_raw(t);
    let result = Arc::downgrade(&t);
    Arc::into_raw(t);
    result
}

#[cfg(not(windows))]
pub fn undecorate_symbol(sym: &str, flags: UFlags) -> Option<String> {
    use cpp_demangle::{DemangleOptions, Symbol};
    Symbol::new(sym).ok().and_then(|s| {
        let mut opts = DemangleOptions::new();
        if flags.contains(UFlags::UNDEC_TYPE) {
            opts = opts.no_params();
        }
        if flags.contains(UFlags::UNDEC_RETN) {
            opts = opts.no_return_type();
        }
        s.demangle(&opts).ok()
    })
}
