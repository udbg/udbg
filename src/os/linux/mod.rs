use super::unix::{udbg::TraceBuf, *};
use crate::os::tid_t;
use crate::prelude::*;
use crate::register::*;
use anyhow::Context;
use libc::*;
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::{ptrace, wait::*};
use nix::unistd::Pid;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{read_dir, read_link, File};
use std::io::Result as IoResult;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const WAIT_PID_FLAG: fn() -> WaitPidFlag = || WaitPidFlag::__WALL | WaitPidFlag::WUNTRACED;

// pub mod comm;
mod process;
mod udbg;
pub mod util;

// pub use self::comm::*;
pub use self::process::*;
pub use self::udbg::*;

// #[cfg(target_arch = "arm")]
// #[derive(Copy, Clone)]
// pub struct user_regs_struct {
//     // pt_regs: https://android.googlesource.com/platform/external/kernel-headers/+/froyo/original/asm-arm/ptrace.h
//     pub regs: [reg_t; 18],
// }

// #[cfg(target_arch = "aarch64")]
// use std::fmt;

// #[cfg(target_arch = "aarch64")]
// #[derive(Copy, Clone)]
// pub struct user_regs_struct {
//     // user_pt_regs
//     pub regs: [reg_t; 31],
//     pub sp: reg_t,
//     pub pc: reg_t,
//     pub pstate: reg_t,
// }

// #[cfg(target_arch = "aarch64")]
// impl fmt::Display for user_regs_struct {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{{\n");
//         for i in 0..self.regs.len() {
//             write!(f, "  r{}\t{:x}\n", i, self.regs[i]);
//         }
//         write!(f, "}}")
//     }
// }

pub struct PidIter(Option<std::fs::ReadDir>);

impl Iterator for PidIter {
    type Item = pid_t;
    fn next(&mut self) -> Option<pid_t> {
        while let Some(e) = self.0.as_mut()?.next() {
            let e = match e {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Ok(pid) = pid_t::from_str_radix(&e.file_name().into_string().unwrap(), 10) {
                return Some(pid);
            }
        }
        None
    }
}

pub fn enum_pid() -> PidIter {
    PidIter(std::fs::read_dir("/proc").ok())
}

pub fn get_exception_name(code: u32) -> String {
    format!(
        "{:?}",
        match Signal::try_from(code as i32) {
            Ok(s) => s,
            Err(_) => return String::new(),
        }
    )
}

pub fn ptrace_write(pid: pid_t, address: usize, data: &[u8]) {
    const SSIZE: usize = core::mem::size_of::<usize>();
    unsafe {
        for i in (0..data.len()).step_by(SSIZE) {
            let val = *((data.as_ptr() as usize + i) as *const usize);
            ptrace(PTRACE_POKEDATA, pid, address + i, val);
        }
        let align_len = data.len() - data.len() % SSIZE;
        if align_len < data.len() {
            let rest = &data[align_len..];
            let mut val = ptrace(PTRACE_PEEKDATA, pid, address + align_len, 0).to_ne_bytes();
            for i in 0..data.len() % SSIZE {
                val[i] = rest[i];
            }
            ptrace(
                PTRACE_POKEDATA,
                pid,
                address + align_len,
                usize::from_ne_bytes(val),
            );
        }
    }
}

pub fn ptrace_attach_wait(tid: pid_t, opt: c_int) -> nix::Result<WaitStatus> {
    ptrace::attach(Pid::from_raw(tid))?;
    let status = nix::sys::wait::waitpid(
        Pid::from_raw(tid),
        Some(WaitPidFlag::from_bits_truncate(opt)),
    )?;
    Ok(status)
}

impl ProcessInfo {
    pub fn enumerate() -> Box<dyn Iterator<Item = Self>> {
        Box::new(enum_pid().map(|pid| Self {
            pid,
            wow64: false,
            name: process_name(pid).unwrap_or(String::new()),
            path: process_path(pid).unwrap_or(String::new()),
            cmdline: process_cmdline(pid).join(" "),
        }))
    }
}

pub fn ptrace_peekuser(pid: i32, offset: usize) -> nix::Result<c_long> {
    Errno::result(unsafe { libc::ptrace(PTRACE_PEEKUSER, Pid::from_raw(pid), offset) })
}

pub fn ptrace_pokeuser(pid: i32, offset: usize, val: c_long) -> nix::Result<c_long> {
    Errno::result(unsafe { libc::ptrace(PTRACE_POKEUSER, Pid::from_raw(pid), offset, val) })
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod arch_util {
    use super::*;

    pub type user_regs = libc::user;

    const OFFSET_DR: usize = memoffset::offset_of!(libc::user, u_debugreg);
    const DEBUGREG_PTR: *const reg_t = OFFSET_DR as _;

    #[extend::ext]
    impl libc::user {
        fn peek_dr(&mut self, pid: i32, i: usize) -> nix::Result<c_long> {
            ptrace_peekuser(pid, unsafe { DEBUGREG_PTR.add(i) } as usize)
        }

        fn peek_dregs(&mut self, pid: i32) -> UDbgResult<()> {
            for i in 0..self.u_debugreg.len() {
                self.u_debugreg[i] = ptrace_peekuser(pid, unsafe { DEBUGREG_PTR.add(i) } as usize)
                    .with_context(|| format!("peek dr[{i}]"))?
                    as _;
            }
            Ok(())
        }

        fn poke_regs(&self, pid: i32) {
            for i in (0..self.u_debugreg.len()).filter(|&i| i < 4 || i > 5) {
                ptrace_pokeuser(
                    pid,
                    unsafe { DEBUGREG_PTR.add(i) as usize },
                    self.u_debugreg[i] as _,
                )
                .log_error_with(|err| format!("poke dr[{i}]: {err:?}"));
            }
        }
    }

    impl HWBPRegs for libc::user {
        fn eflags(&mut self) -> &mut u32 {
            unsafe { core::mem::transmute(&mut self.regs.eflags) }
        }

        fn dr(&self, i: usize) -> reg_t {
            self.u_debugreg[i]
        }

        fn set_dr(&mut self, i: usize, v: reg_t) {
            self.u_debugreg[i] = v;
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl AbstractRegs for user_regs_struct {
        fn ip(&mut self) -> &mut reg_t {
            &mut self.rip
        }
        fn sp(&mut self) -> &mut reg_t {
            &mut self.rsp
        }
    }

    #[cfg(target_arch = "x86")]
    impl AbstractRegs for user_regs_struct {
        fn ip(&mut self) -> &mut reg_t {
            &mut self.eip
        }
        fn sp(&mut self) -> &mut reg_t {
            &mut self.esp
        }
    }

    impl AbstractRegs for libc::user {
        fn ip(&mut self) -> &mut Self::REG {
            self.regs.ip()
        }

        fn sp(&mut self) -> &mut Self::REG {
            self.regs.sp()
        }
    }

    impl TraceBuf<'_> {
        pub fn update_regs(&mut self, tid: pid_t) {
            ptrace::getregs(Pid::from_raw(tid))
                .log_error("getregs")
                .map(|regs| {
                    self.user.regs = regs;
                    self.regs_dirty = true;
                });
        }

        pub fn write_regs(&self, tid: tid_t) {
            ptrace::setregs(Pid::from_raw(tid), self.user.regs);
        }
    }

    impl CommonAdaptor {
        pub fn enable_hwbp_for_thread(
            &self,
            tid: tid_t,
            info: HwbpInfo,
            enable: bool,
        ) -> UDbgResult<bool> {
            unsafe {
                let mut user: libc::user = core::mem::zeroed();
                user.peek_dregs(tid)?;

                let i = info.index as usize;
                if enable {
                    user.u_debugreg[i] = self.dbg_reg[i].get() as _;
                    user.set_bp(self.dbg_reg[i].get(), i, info.rw, info.len);
                } else {
                    user.unset_bp(i);
                }

                user.poke_regs(tid);
            }

            Ok(true)
        }

        pub fn get_hwbp(&self, tb: &mut TraceBuf) -> Option<Arc<Breakpoint>> {
            let dr6 = tb
                .user
                .peek_dr(self.base.event_tid.get(), 6)
                .log_error("peek dr6")?;
            self.get_bp_(if dr6 & 0x01 > 0 {
                -1
            } else if dr6 & 0x02 > 0 {
                -2
            } else if dr6 & 0x04 > 0 {
                -3
            } else if dr6 & 0x08 > 0 {
                -4
            } else {
                return None;
            })
        }
    }

    pub fn call_remote(pid: pid_t, fp: usize, ret: usize, args: &[reg_t]) -> anyhow::Result<reg_t> {
        unimplemented!();
    }
}

#[cfg(any(target_arch = "aarch64"))]
mod arch_util {
    use super::*;
    use core::mem::*;

    // https://github.com/innogames/android-ndk/blob/master/platforms/android-9/arch-arm/usr/include/asm/ptrace.h
    pub const NT_PRSTATUS: i32 = 1;

    pub const PTRACE_GETREGS: i32 = 12;
    pub const PTRACE_SETREGS: i32 = 13;

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct user_hwdebug_state {
        pub dbg_info: u32,
        pub pad: u32,
        pub dbg_regs: [user_hwdebug_state__bindgen_ty_1; 16usize],
    }
    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct user_hwdebug_state__bindgen_ty_1 {
        pub addr: u64,
        pub ctrl: u32,
        pub pad: u32,
    }

    #[cfg(target_arch = "aarch64")]
    impl AbstractRegs for user_regs_struct {
        fn ip(&mut self) -> &mut reg_t {
            &mut self.pc
        }
        fn sp(&mut self) -> &mut reg_t {
            &mut self.sp
        }

        fn lr(&mut self) -> &mut Self::REG {
            &mut self.regs[30]
        }
    }

    #[cfg(target_arch = "arm")]
    impl AbstractRegs for user_regs_struct {
        fn ip(&mut self) -> &mut reg_t {
            &mut self.pc
        }
        fn sp(&mut self) -> &mut reg_t {
            &mut self.sp
        }

        fn lr(&mut self) -> &mut Self::REG {
            &mut self.regs[14]
        }
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct user_regs {
        pub regs: user_regs_struct,
        pub hwdebug: user_hwdebug_state,
    }

    impl TraceBuf<'_> {
        pub fn update_regs(&mut self, tid: pid_t) {
            ptrace_getregs(tid, &mut self.user.regs)
                .log_error("getregs")
                .map(|_| {
                    self.regs_dirty = true;
                });
        }

        pub fn write_regs(&self, tid: tid_t) {
            ptrace_setregs(tid, &self.user.regs);
        }
    }

    impl CommonAdaptor {
        pub fn enable_hwbp_for_thread(
            &self,
            tid: tid_t,
            info: HwbpInfo,
            enable: bool,
        ) -> UDbgResult<bool> {
            Err(UDbgError::NotSupport)
        }

        pub fn get_hwbp(&self, tb: &mut TraceBuf) -> Option<Arc<Breakpoint>> {
            None
        }
    }

    pub fn ptrace_getregs(tid: pid_t, regs: &mut user_regs_struct) -> nix::Result<libc::c_long> {
        unsafe {
            let mut io = iovec {
                iov_len: size_of_val(regs),
                iov_base: transmute(regs as *mut user_regs_struct),
                // iov_len: 18 * 4,
            };
            Errno::result(ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &mut io))
                .or_else(|_| Errno::result(ptrace(PTRACE_GETREGS, tid, 0, regs)))
        }
    }

    pub fn ptrace_setregs(tid: pid_t, regs: &user_regs_struct) -> nix::Result<libc::c_long> {
        unsafe {
            let mut io = iovec {
                iov_base: transmute(regs),
                iov_len: size_of_val(regs),
            };
            Errno::result(ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &mut io))
                .or_else(|_| Errno::result(ptrace(PTRACE_SETREGS, tid, 0, regs)))
        }
    }

    pub fn call_remote(pid: pid_t, fp: usize, ret: usize, args: &[reg_t]) -> anyhow::Result<reg_t> {
        #[cfg(target_arch = "arm")]
        const REGS_ARG_NUM: usize = 4;
        #[cfg(target_arch = "aarch64")]
        const REGS_ARG_NUM: usize = 6;

        unsafe {
            let mut regs: user_regs_struct = core::mem::zeroed();
            ptrace_getregs(pid, &mut regs).context("getregs")?;
            let bak = regs;
            for i in 0..REGS_ARG_NUM.min(args.len()) {
                regs.regs[i] = args[i];
            }
            if args.len() > REGS_ARG_NUM {
                let stack_num = args.len() - REGS_ARG_NUM;
                *regs.sp() -= (size_of::<reg_t>() * stack_num) as reg_t;
                ptrace_write(pid, *regs.sp() as _, args[REGS_ARG_NUM..].as_byte_array());
            }

            *regs.lr() = ret as reg_t;
            *regs.ip() = fp as reg_t;

            ptrace_setregs(pid, &regs).context("setregs")?;
            ptrace::cont(Pid::from_raw(pid), None);

            libc::waitpid(pid, core::ptr::null_mut(), WUNTRACED);
            ptrace_getregs(pid, &mut regs);
            ptrace_setregs(pid, &bak).context("setregs")?;

            Ok(regs.regs[0])
        }
    }
}

pub use self::arch_util::*;
