#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/61437564?s=200&v=4")]
#![feature(trait_alias)]
#![feature(once_cell)]
#![feature(ptr_metadata)]
#![feature(min_specialization)]
#![feature(stmt_expr_attributes)]
#![feature(const_ptr_offset_from)]
#![feature(associated_type_defaults)]
#![allow(rustdoc::bare_urls)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate derive_more;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate log;
#[macro_use]
extern crate cstrptr;

pub mod breakpoint;
pub mod elf;
pub mod error;
pub mod event;
pub mod lua;
pub mod memory;
pub mod minidump;
pub mod os;
pub mod pdbfile;
pub mod pe;
pub mod prelude;
pub mod range;
pub mod register;
pub mod shell;
pub mod string;
pub mod symbol;
pub mod target;

/// Constants for current environment
pub mod consts {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub const MAX_INSN_SIZE: usize = 16;

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub const MAX_INSN_SIZE: usize = 4;

    pub const ARCH_X86: u32 = 0;
    pub const ARCH_X64: u32 = 1;
    pub const ARCH_ARM: u32 = 2;
    pub const ARCH_ARM64: u32 = 3;

    #[cfg(target_arch = "x86_64")]
    pub const UDBG_ARCH: u32 = ARCH_X64;
    #[cfg(target_arch = "x86")]
    pub const UDBG_ARCH: u32 = ARCH_X86;
    #[cfg(target_arch = "arm")]
    pub const UDBG_ARCH: u32 = ARCH_ARM;
    #[cfg(target_arch = "aarch64")]
    pub const UDBG_ARCH: u32 = ARCH_ARM64;

    pub const IS_ARCH_ARM: bool = cfg!(target_arch = "arm");
    pub const IS_ARCH_ARM64: bool = cfg!(target_arch = "aarch64");
    pub const IS_ARM: bool = IS_ARCH_ARM || IS_ARCH_ARM64;
    pub const IS_ARCH_X86: bool = cfg!(target_arch = "x86");
    pub const IS_ARCH_X64: bool = cfg!(target_arch = "x86_64");
    pub const IS_X86: bool = IS_ARCH_X86 || IS_ARCH_X64;
}

/// Fragmented utilities
pub mod util {
    use memmap2::Mmap;

    use alloc::sync::{Arc, Weak};
    use std::io::{BufRead, BufReader, Result as IoResult};
    use std::path::Path;

    /// Fragmented utilities code
    pub struct Utils;

    impl Utils {
        pub fn mapfile(path: &str) -> anyhow::Result<Mmap> {
            std::fs::File::open(path)
                .and_then(|f| unsafe { Mmap::map(&f) })
                .map_err(Into::into)
        }

        pub fn file_lines<P: AsRef<Path>>(path: P) -> IoResult<impl Iterator<Item = String>> {
            Ok(BufReader::new(std::fs::File::open(path)?)
                .lines()
                .map(|line| line.unwrap_or_default()))
        }

        /// Convert a reference to Weak<T>, please ensure the reference is from Arc<T>
        pub unsafe fn to_weak<T: ?Sized>(t: &T) -> Weak<T> {
            let t = Arc::from_raw(t);
            let result = Arc::downgrade(&t);
            Arc::into_raw(t);
            result
        }
    }
}
