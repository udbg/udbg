
use std::path::{Path, PathBuf};
use parking_lot::RwLock;
use std::convert::TryFrom;
use std::collections::HashMap;
use std::fs::{File, read_dir, read_link};
use core::mem::{transmute, size_of_val, size_of};

use libc::*;
use crate::{*, text::*, regs::*};
use ::nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};

pub mod util;
pub mod udbg;
pub mod process;
pub mod thread;
pub mod ptrace;

pub use self::thread::*;
pub use self::ptrace::*;
pub use self::process::*;

#[cfg(target_arch = "arm")]
#[derive(Copy, Clone)]
pub struct user_regs_struct {   // pt_regs: https://android.googlesource.com/platform/external/kernel-headers/+/froyo/original/asm-arm/ptrace.h
    pub regs: [reg_t; 18],
}

#[cfg(target_arch = "aarch64")]
use std::fmt;

#[cfg(target_arch = "aarch64")]
#[derive(Copy, Clone)]
pub struct user_regs_struct {   // user_pt_regs
    pub regs: [reg_t; 31],
    pub sp: reg_t,
    pub pc: reg_t,
    pub pstate: reg_t,
}

#[cfg(target_arch = "aarch64")]
impl fmt::Display for user_regs_struct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{\n");
        for i in 0..self.regs.len() {
            write!(f, "  r{}\t{:x}\n", i, self.regs[i]);
        }
        write!(f, "}}")
    }
}

#[cfg(target_arch = "arm")] #[macro_export]
macro_rules! arm_lr { ($regs:ident) => { $regs.regs[14] }; }
#[cfg(target_arch = "aarch64")] #[macro_export]
macro_rules! arm_lr { ($regs:ident) => { $regs.regs[30] }; }

#[cfg(target_arch = "arm")] #[macro_export]
macro_rules! arm_sp { ($regs:ident) => { $regs.regs[13] }; }
#[cfg(target_arch = "aarch64")] #[macro_export]
macro_rules! arm_sp { ($regs:ident) => { $regs.sp }; }

#[cfg(target_arch = "arm")] #[macro_export]
macro_rules! arm_pc { ($regs:ident) => { $regs.regs[15] }; }
#[cfg(target_arch = "aarch64")] #[macro_export]
macro_rules! arm_pc { ($regs:ident) => { $regs.pc }; }

#[cfg(target_arch = "aarch64")]
impl AbstractRegs for user_regs_struct {
    fn ip(&mut self) -> &mut reg_t { &mut self.pc }
    fn sp(&mut self) -> &mut reg_t { &mut self.sp }
}

pub struct PidIter(Option<std::fs::ReadDir>);

impl Iterator for PidIter {
    type Item = pid_t;
    fn next(&mut self) -> Option<pid_t> {
        while let Some(e) = self.0.as_mut()?.next() {
            let e = match e { Ok(e) => e, Err(_) => continue, };
            if let Ok(pid) = pid_t::from_str_radix(&e.file_name().into_string().unwrap(), 10) {
                return Some(pid);
            }
        }
        None
    }
}

pub fn enum_pid() -> PidIter {
    PidIter(Some(std::fs::read_dir("/proc").unwrap()))
}

#[cfg(target_arch = "x86_64")]
impl AbstractRegs for user_regs_struct {
    fn ip(&mut self) -> &mut reg_t { &mut self.rip }
    fn sp(&mut self) -> &mut reg_t { &mut self.rsp }
}

#[cfg(target_arch = "x86")]
impl AbstractRegs for user_regs_struct {
    fn ip(&mut self) -> &mut reg_t { &mut self.eip }
    fn sp(&mut self) -> &mut reg_t { &mut self.esp }
}

// TODO:
pub fn is_32(pid: pid_t) -> bool { false }

pub fn is_32bit_file(path: impl AsRef<Path>) -> bool {
    // TODO:
    false
}

pub fn get_exception_name(code: u32) -> String {
    format!("{:?}", match Signal::try_from(code as i32) {
        Ok(s) => s, Err(_) => return String::new(),
    })
}