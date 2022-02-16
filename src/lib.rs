#![feature(vec_into_raw_parts)]
#![feature(get_mut_unchecked)]
#![feature(untagged_unions)]
#![feature(trait_alias)]
#![feature(naked_functions)]
#![feature(proc_macro_hygiene)]
#![feature(associated_type_defaults)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(deprecated)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub extern crate iced_x86;
#[macro_use] extern crate alloc;
#[macro_use] extern crate cfg_if;
#[macro_use] extern crate bitflags;
#[macro_use] extern crate derive_more;
#[macro_use] extern crate serde;
#[macro_use] extern crate log;
#[macro_use] extern crate ctor;
#[macro_use] extern crate cstrptr;

pub mod pe;
pub mod elf;
pub mod text;
pub mod sym;
pub mod regs;
pub mod util;
pub mod range;
pub mod err;
pub mod mem;
pub mod error;
pub mod strutil;

#[cfg(feature="udbg")]
pub mod udbg;
#[cfg(feature="udbg")]
pub use udbg::*;

#[cfg(feature="csutil")]
pub mod csutil;

pub use err::*;
pub use mem::*;
pub use util::*;
pub use strutil::*;

cfg_if! {
    if #[cfg(windows)] {
        pub mod win;
        pub use crate::win::*;
    } else {
        pub mod nix;
        pub use crate::nix::*;
    }
}

use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[cfg(windows)]
use winapi::{
    shared::minwindef::*,
    um::{
        winnt::*,
        winbase::*,
        minwinbase::LPTHREAD_START_ROUTINE,
    }
};

pub type tid_t = pid_t;

#[cfg(any(target_arch="x86", target_arch="x86_64"))]
pub const MAX_INSN_SIZE: usize = 16;

#[cfg(any(target_arch="arm", target_arch="aarch64"))]
pub const MAX_INSN_SIZE: usize = 4;

#[cfg(target_pointer_width = "64")]
pub type reg_t = u64;
#[cfg(target_pointer_width = "32")]
pub type reg_t = u32;

pub struct CommonModule {
    pub base: usize,
    pub size: usize,
}

pub trait HKitModule {
    fn comm(&self) -> &CommonModule;
    fn name(&self) -> Arc<str>;
    fn path(&self) -> Arc<str>;
}

#[derive(Serialize, Deserialize)]
pub struct SymbolInfo {
    pub module: Arc<str>,
    pub symbol: Arc<str>,
    pub offset: usize,
    pub mod_base: usize,
}

impl SymbolInfo {
    pub fn to_string(&self, addr: usize) -> String {
        if self.symbol.len() > 0 {
            if self.offset == 0 {
                format!("{}!{}", self.module, self.symbol)
            } else {
                format!("{}!{}+{:x}", self.module, self.symbol, self.offset)
            }
        } else if self.module.len() > 0 {
            if addr == self.mod_base {
                self.module.to_string()
            } else {
                format!("{}+{:x}", self.module, addr - self.mod_base)
            }
        } else { format!("{:x}", addr) }
    }
}

pub const ARCH_X86: u32 = 0;
pub const ARCH_X64: u32 = 1;
pub const ARCH_ARM: u32 = 2;
pub const ARCH_ARM64: u32 = 3;

pub const IS_ARCH_ARM: bool = cfg!(target_arch = "arm");
pub const IS_ARCH_ARM64: bool = cfg!(target_arch = "aarch64");
pub const IS_ARM: bool = IS_ARCH_ARM || IS_ARCH_ARM64;
pub const IS_ARCH_X86: bool = cfg!(target_arch = "x86");
pub const IS_ARCH_X64: bool = cfg!(target_arch = "x86_64");
pub const IS_X86: bool = IS_ARCH_X86 || IS_ARCH_X64;