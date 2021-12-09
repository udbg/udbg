
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::convert::TryFrom;
use std::io::prelude::*;
use std::collections::HashMap;
use std::io::{self, Seek, SeekFrom};
use std::fs::{File, read_dir, read_link};
use core::mem::{transmute, size_of_val, size_of};

pub use libc::*;
use crate::{*, text::*, regs::*};
use ::nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};

pub type pid_t = i32;

pub mod util;
pub mod thread;
pub mod ptrace;
pub mod process;

pub use self::util::*;
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

pub struct MemoryIter(LineReader<File>);

impl Iterator for MemoryIter {
    type Item = MemoryPage;
    fn next(&mut self) -> Option<Self::Item> {
        let line = self.0.next()?;
        let mut line = LineParser::new(line.as_ref());
        let base = line.till('-').unwrap();
        let base = usize::from_str_radix(base, 16).unwrap();
        line.skip_count(1);
        let end = usize::from_str_radix(line.next().unwrap(), 16).unwrap();
        let size = end - base;
        let prot = line.next().unwrap();
        for i in 0..3 { line.next(); }
        let usage: Arc<str> = line.rest().trim().into();

        let mut result = MemoryPage { base, size, usage, prot: [0; 4] };
        result.prot.copy_from_slice(prot.as_bytes());
        Some(result)
    }
}

#[derive(Deref)]
pub struct Module {
    #[deref]
    pub comm: CommonModule,
    pub name: Arc<str>,
    pub path: Arc<str>,
}

impl HKitModule for Module {
    fn comm(&self) -> &CommonModule { &self.comm }
    fn name(&self) -> Arc<str> { self.name.clone() }
    fn path(&self) -> Arc<str> { self.path.clone() }
}

pub struct ModuleIter<'a> {
    f: LineReader<File>,
    p: &'a Process,
    cached: bool,
    base: usize,
    size: usize,
    usage: Arc<str>,
}

pub const ELF_SIG: [u8; 4] = [127, b'E', b'L', b'F'];

impl ModuleIter<'_> {
    fn next_line(&mut self) -> bool {
        let line = match self.f.next() { Some(r) => r, None => return false, };
        let mut line = LineParser::new(line.as_ref());
        let base = line.till('-').unwrap();
        self.base = usize::from_str_radix(base, 16).expect("page base");
        line.skip_count(1);
        let end = usize::from_str_radix(line.next().unwrap(), 16).expect("page end");
        self.size = end - self.base;
        let _prot = line.next().unwrap().to_string();
        for _i in 0..3 { line.next(); }
        self.usage = line.rest().trim().into();
        return true;
    }

    fn next_module(&mut self) -> Option<Module> {
        loop {
            if !self.cached {
                self.cached = self.next_line();
                if !self.cached { return None; }
            }

            let mut sig = [0u8; 4];
            if self.usage.len() > 0 && self.p.read(self.base, &mut sig).is_some() && ELF_SIG == sig {
                // Moudle Begin
                let base = self.base;
                let path = self.usage.clone();
                let mut size = self.size;
                let name: Arc<str> = Path::new(path.as_ref()).file_name()
                                .and_then(|v| v.to_str())
                                .unwrap_or("").into();
                loop {
                    self.cached = self.next_line();
                    if !self.cached || self.usage != path { break; }
                    size += self.size;
                }
                return Some(Module { comm: CommonModule {base, size}, name, path });
            } else { self.cached = false; }
        }
    }
}

impl<'a> Iterator for ModuleIter<'a> {
    type Item = Module;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(r) = self.next_module() {
            if r.path.as_ref() == "[vdso]" { continue; }
            return Some(r);
        }
        None
    }
}

// pub fn ptrace_peektext(tid: pid_t, address: usize) -> Option<usize> {
//     unsafe { ptrace(PTRACE_PEEKTEXT, tid, address, 0) == 0 }
// }

// https://github.com/innogames/android-ndk/blob/master/platforms/android-9/arch-arm/usr/include/asm/ptrace.h
const NT_PRSTATUS: i32 = 1;
cfg_if! {
    if #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
        const PTRACE_GETREGS: i32 = 12;
        const PTRACE_SETREGS: i32 = 13;
        const PTRACE_GETREGSET: i32 = 0x4204;
        const PTRACE_SETREGSET: i32 = 0x4205;
    }
}
pub fn ptrace_getregs(tid: pid_t, regs: &mut user_regs_struct) -> bool {
    unsafe {
        let mut io = iovec {
            iov_len: size_of_val(regs),
            iov_base: transmute(regs as *mut user_regs_struct),
            // iov_len: 18 * 4,
        };
        if ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &mut io) >= 0 {
            return true;
        }
        ptrace(PTRACE_GETREGS, tid, 0, regs) >= 0
    }
}

pub fn ptrace_setregs(tid: pid_t, regs: &user_regs_struct) -> bool {
    unsafe {
        let mut io = iovec {
            iov_base: transmute(regs),
            iov_len: size_of_val(regs),
        };
        if ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &mut io) >= 0 {
            return true;
        }
        return ptrace(PTRACE_SETREGS, tid, 0, regs) >= 0;
    }
}

pub fn ptrace_write(pid: pid_t, address: usize, data: &[u8]) {
    const SSIZE: usize = size_of::<usize>();
    unsafe {
        for i in (0..data.len()).step_by(SSIZE) {
            let val = *((data.as_ptr() as usize + i) as *const usize);
            ptrace(PTRACE_POKEDATA, pid, address + i, val);
        }
        let align_len = data.len() - data.len() % SSIZE;
        if align_len < data.len() {
            let rest = &data[align_len..];
            let mut val = ptrace(PTRACE_PEEKDATA, pid, address + align_len, 0).to_ne_bytes();
            for i in 0..data.len() % SSIZE { val[i] = rest[i]; }
            ptrace(PTRACE_POKEDATA, pid, address + align_len, usize::from_ne_bytes(val));
        }
    }
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

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryPage {
    pub base: usize,
    pub size: usize,
    pub prot: [u8; 4],
    pub usage: Arc<str>,
}

impl MemoryPage {
    #[inline]
    pub fn is_commit(&self) -> bool { true }

    #[inline]
    pub fn is_reserve(&self) -> bool { false }

    #[inline]
    pub fn is_free(&self) -> bool { false }

    #[inline]
    pub fn is_private(&self) -> bool { self.prot[3] == b'p' }

    #[inline]
    pub fn is_shared(&self) -> bool { self.prot[3] == b's' }

    pub fn is_executable(&self) -> bool { self.prot[2] == b'x' }
    pub fn is_writable(&self) -> bool { self.prot[1] == b'w' }
    pub fn is_readonly(&self) -> bool {
        self.prot[0] == b'r' && !self.is_writable() && !self.is_executable()
    }

    pub fn protect(&self) -> &str {
        std::str::from_utf8(&self.prot).unwrap_or("")
    }

    pub fn type_str(&self) -> &'static str {
        if self.is_private() { "PRV" } else if self.is_shared() { "SHR" } else { "" }
    }
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

pub fn this_process() -> &'static Process {
    static mut P: Option<Process> = None;

    unsafe { P.get_or_insert_with(|| Process::current()) }
}