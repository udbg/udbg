#![feature(trait_alias)]
#![feature(min_specialization)]
#![feature(associated_type_defaults)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(deprecated)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub extern crate iced_x86;
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
extern crate ctor;
#[macro_use]
extern crate cstrptr;

pub mod breakpoint;
pub mod elf;
pub mod error;
pub mod event;
pub mod memory;
pub mod pdbfile;
pub mod pe;
pub mod prelude;
pub mod range;
pub mod regs;
pub mod shell;
pub mod strutil;
pub mod symbol;
pub mod target;
pub mod util;

cfg_if! {
    if #[cfg(target_os="macos")] {
        pub mod mac;
        pub use mac as nix;
    } else if #[cfg(not(windows))] {
        pub mod nix;
    }
}

cfg_if! {
    if #[cfg(windows)] {
        pub mod win;
        pub type pid_t = u32;
        pub use self::win::{self as os, *};
    } else {
        pub use std::os::unix::raw::pid_t;
        pub use self::nix::{self as os, comm::*, *};
    }
}

cfg_if! {
    if #[cfg(target_os="macos")] {
        pub type tid_t = u64;
    } else {
        pub type tid_t = pid_t;
    }
}

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
