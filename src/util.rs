
use core::fmt;
use core::num::ParseIntError;
use core::mem::size_of;
use alloc::boxed::Box;
use alloc::string::String;
use core::slice::{from_raw_parts, from_raw_parts_mut};

pub trait AsByteArray {
    fn as_byte_array(&self) -> &[u8];
}

impl<T: Sized> AsByteArray for T {
    fn as_byte_array(&self) -> &[u8] {
        unsafe {
            from_raw_parts(self as *const T as *const u8, size_of::<T>())
        }
    }
}

impl<T: Sized> AsByteArray for [T] {
    fn as_byte_array(&self) -> &[u8] {
        unsafe {
            from_raw_parts(self.as_ptr() as *const T as *const u8, size_of::<T>() * self.len())
        }
    }
}

pub trait AsByteArrayMut {
    fn as_mut_byte_array(&mut self) -> &mut [u8];
}

impl<T: Sized> AsByteArrayMut for T {
    fn as_mut_byte_array(&mut self) -> &mut [u8] {
        unsafe {
            from_raw_parts_mut(self as *mut T as *mut u8, size_of::<T>())
        }
    }
}

pub fn parse_hex(mut s: &str) -> Result<u64, ParseIntError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        s = &s[2..];
    }
    u64::from_str_radix(s, 16)
}

pub struct HexBuf<'a>(pub &'a [u8]);

impl fmt::Display for HexBuf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Alignment;

        #[inline]
        fn write_hex(f: &mut fmt::Formatter<'_>, b: &[u8]) {
            for &x in b.iter() { write!(f, "{:02x}", x); }
        }
        match f.align() {
            Some(a) => {
                let n = f.width().map(|w| w as isize - self.0.len() as isize * 2).unwrap_or(0);
                let fill = f.fill();
                let is_left = match a { Alignment::Left => true, _ => false };
                if n > 0 && !is_left {
                    for _ in 0..n { write!(f, "{}", fill); }
                }
                write_hex(f, self.0);
                if n > 0 && is_left {
                    for _ in 0..n { write!(f, "{}", fill); }
                }
            }
            None => write_hex(f, self.0),
        }
        Ok(())
    }
}

#[inline(always)]
pub fn hex_string(data: &[u8]) -> String {
    format!("{}", HexBuf(data))
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#[macro_export]
macro_rules! sc_asm {
    ($asm:expr) => { core::arch::asm!($asm) };
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[macro_export]
macro_rules! sc_asm {
    ($asm:expr) => { core::arch::asm!($asm) };
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

use memmap::Mmap;

pub fn mapfile(path: &str) -> Option<Mmap> {
    std::fs::File::open(path).and_then(|f| unsafe { Mmap::map(&f) }).ok()
}

pub struct BinCode {
    meta: Box<[i16]>,
}

impl BinCode {
    pub fn new(pat: &[i16]) -> Self {
        Self {meta: pat.into()}
    }

    pub fn search_position(&self, data: &[u8], backward: bool) -> Option<usize> {
        let pat = &self.meta;
        if backward {
            let mut i = data.len().checked_sub(self.meta.len())? as isize;
            while i >= 0 {
                let mut j = 0usize;
                while j < pat.len() {
                    let p = pat[j];
                    let d = *data.get(i as usize + j)? as i16;
                    if p < 0 || p == d { j += 1; }
                    else { break; }
                }
                if j == pat.len() { return Some(i as _); }
                i -= 1;
            }
        } else {
            let mut i = 0usize;
            while i < data.len() {
                let mut j = 0usize;
                while j < pat.len() {
                    let p = pat[j];
                    let d = *data.get(i + j)? as i16;
                    if p < 0 || p == d { j += 1; }
                    else { break; }
                }
                if j == pat.len() { return Some(i); }
                i += 1;
            }
        }
        None
    }

    pub fn search(&self, data: &[u8], backward: bool) -> Option<*const u8> {
        unsafe {
            Some(data.as_ptr().offset(self.search_position(data, backward)? as isize))
        }
    }
}

#[macro_export]
macro_rules! sig_ {
    (() -> ($($right:literal)*)) => {
        &[$($right,)*]
    };
    (($byte:literal $($left:tt)*) -> ($($right:literal)*)) => {
        sig_!(($($left)*) -> ($($right)* $byte) )
    };
    ((?? $($left:tt)*) -> ($($right:literal)*)) => {
        sig_!(($($left)*) -> ($($right)* -1) )
    };
}

#[macro_export]
macro_rules! sig {
    ($($token:tt)*) => { sig_!(($($token)*) -> ()) };
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
        if !flags.contains(UFlags::UNDEC_RETN) { sym_flags |= DemangleFlags::NO_FUNCTION_RETURNS; }
    }

    demangle(sym, sym_flags).ok()
}

#[cfg(not(windows))]
pub fn undecorate_symbol(sym: &str, flags: UFlags) -> Option<String> {
    use cpp_demangle::{Symbol, DemangleOptions};
    Symbol::new(sym).ok().and_then(|s| {
        let mut opts = DemangleOptions::new();
        if flags.contains(UFlags::UNDEC_TYPE) { opts = opts.no_params(); }
        if flags.contains(UFlags::UNDEC_RETN) { opts = opts.no_return_type(); }
        s.demangle(&opts).ok()
    })
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct PsInfo {
    pub pid: crate::pid_t,
    pub wow64: bool,
    pub name: String,
    pub path: String,
    pub cmdline: String,
}

#[cfg(windows)]
pub fn enum_psinfo() -> Box<dyn Iterator<Item=PsInfo>> {
    use crate::*;
    use winapi::um::winnt::*;

    Box::new(enum_process().map(|p| {
        let pid = p.pid();
        let mut result = PsInfo {
            pid, name: p.name(), wow64: false,
            // window: get_window(pid).map(|w| w.get_text()).unwrap_or(String::new()),
            path: String::new(),
            cmdline: String::new(),
        };
        Process::open(pid, Some(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)).map(|p| {
            result.wow64 = p.is_wow64();
            p.image_path().map(|path| result.path = path);
            p.cmdline().map(|cmd| result.cmdline = cmd);
        });
        result
    }))
}

#[cfg(not(windows))]
pub fn enum_psinfo() -> Box<dyn Iterator<Item=PsInfo>> {
    use crate::process::*;
    Box::new(enum_pid().map(|pid| {
        PsInfo {
            pid, wow64: false,
            name: process_name(pid).unwrap_or(String::new()),
            path: process_path(pid).unwrap_or(String::new()),
            cmdline: process_cmdline(pid).join(" "),
        }
    }))
}