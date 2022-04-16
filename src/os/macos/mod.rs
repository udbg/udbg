pub mod ffi;
mod process;
#[cfg(test)]
mod test;
mod udbg;

pub use process::*;
pub use udbg::*;

pub type priority_t = i32;

use crate::prelude::*;
use crate::register::{regid::*, *};
use libc::*;

#[cfg(target_arch = "x86_64")]
mod arch {
    pub use mach2::structs::x86_thread_state64_t as user_regs_t;

    impl UDbgRegs for user_regs_struct {
        fn get_reg(&self, id: u32) -> Option<CpuReg> {
            let c = self;
            Some(CpuReg::Int(match id {
                X86_REG_RAX => c.__rax,
                X86_REG_RBX => c.__rbx,
                X86_REG_RCX => c.__rcx,
                X86_REG_RDX => c.__rdx,
                X86_REG_RBP => c.__rbp,
                X86_REG_RSI => c.__rsi,
                X86_REG_RDI => c.__rdi,
                X86_REG_R8 => c.__r8,
                X86_REG_R9 => c.__r9,
                X86_REG_R10 => c.__r10,
                X86_REG_R11 => c.__r11,
                X86_REG_R12 => c.__r12,
                X86_REG_R13 => c.__r13,
                X86_REG_R14 => c.__r14,
                X86_REG_R15 => c.__r15,
                X86_REG_RSP | COMM_REG_SP => c.__rsp,
                X86_REG_RIP | COMM_REG_PC => c.__rip,
                X86_REG_EFLAGS => c.__rflags,
                _ => return None,
            } as usize))
        }

        fn set_reg(&mut self, id: u32, val: CpuReg) {
            let c = self;
            match id {
                X86_REG_RAX => c.__rax = val.into(),
                X86_REG_RBX => c.__rbx = val.into(),
                X86_REG_RCX => c.__rcx = val.into(),
                X86_REG_RDX => c.__rdx = val.into(),
                X86_REG_RBP => c.__rbp = val.into(),
                X86_REG_RSI => c.__rsi = val.into(),
                X86_REG_RDI => c.__rdi = val.into(),
                X86_REG_R8 => c.__r8 = val.into(),
                X86_REG_R9 => c.__r9 = val.into(),
                X86_REG_R10 => c.__r10 = val.into(),
                X86_REG_R11 => c.__r11 = val.into(),
                X86_REG_R12 => c.__r12 = val.into(),
                X86_REG_R13 => c.__r13 = val.into(),
                X86_REG_R14 => c.__r14 = val.into(),
                X86_REG_R15 => c.__r15 = val.into(),
                X86_REG_RSP | COMM_REG_SP => c.__rsp = val.into(),
                X86_REG_RIP | COMM_REG_PC => c.__rip = val.into(),
                X86_REG_EFLAGS => c.__rflags = val.into(),
                _ => {}
            };
        }

        fn to_regs(&self) -> RegType {
            RegType::X64(X64Regs {
                rax: self.__rax,
                rbx: self.__rbx,
                rcx: self.__rcx,
                rdx: self.__rdx,
                rbp: self.__rbp,
                rsp: self.__rsp,
                rsi: self.__rsi,
                rdi: self.__rdi,
                r8: self.__r8,
                r9: self.__r9,
                r10: self.__r10,
                r11: self.__r11,
                r12: self.__r12,
                r13: self.__r13,
                r14: self.__r14,
                r15: self.__r15,
                rip: self.__rip,
                cs: self.__cs as _,
                ds: 0 as _,
                es: 0 as _,
                fs: self.__fs as _,
                gs: self.__gs as _,
                ss: 0 as _,
                rflags: self.__rflags as reg_t,
            })
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::*;

    pub use libc::__darwin_arm_thread_state64 as user_regs_struct;

    impl UDbgRegs for user_regs_struct {
        fn get_reg(&self, id: u32) -> Option<CpuReg> {
            let c = self;
            Some(CpuReg::Int(match id {
                ARM_REG_PC | COMM_REG_PC => c.__pc,
                ARM_REG_SP | ARM64_REG_SP | COMM_REG_SP => c.__sp,
                ARM64_REG_X0..=ARM64_REG_X28 => c.__x[(id - ARM64_REG_X0) as usize],
                ARM64_REG_FP => c.__fp,
                ARM64_REG_LR => c.__lr,
                _ => return None,
            } as usize))
        }

        fn set_reg(&mut self, id: u32, val: CpuReg) {
            let c = self;
            match id {
                ARM_REG_PC | COMM_REG_PC => c.__pc = val.into(),
                ARM_REG_SP | ARM64_REG_SP | COMM_REG_SP => c.__sp = val.into(),
                ARM64_REG_X0..=ARM64_REG_X28 => c.__x[(id - ARM64_REG_X0) as usize] = val.into(),
                ARM64_REG_FP => c.__fp = val.into(),
                ARM64_REG_LR => c.__lr = val.into(),
                _ => {}
            };
        }

        fn to_regs(&self) -> RegType {
            RegType::Arm64(Arm64Regs {
                regs: self.__x,
                fp: self.__fp,
                lr: self.__lr,
                sp: self.__sp,
                pc: self.__pc,
                pstate: self.__cpsr as _,
            })
        }
    }

    impl CommonAdaptor {
        pub fn enable_hwbp_for_thread(
            &self,
            tid: tid_t,
            _bp: &Breakpoint,
            info: HwbpInfo,
            enable: bool,
        ) -> UDbgResult<bool> {
            todo!();
        }

        // pub fn get_hwbp(&self, tb: &mut TraceBuf) -> Option<Arc<Breakpoint>> {
        //     let dr6 = tb
        //         .user
        //         .peek_dr(self.base.event_tid.get(), 6)
        //         .log_error("peek dr6")?;
        //     self.get_bp_(if dr6 & 0x01 > 0 {
        //         -1
        //     } else if dr6 & 0x02 > 0 {
        //         -2
        //     } else if dr6 & 0x04 > 0 {
        //         -3
        //     } else if dr6 & 0x08 > 0 {
        //         -4
        //     } else {
        //         return None;
        //     })
        // }
    }
}

pub use self::arch::*;

pub struct user_regs {
    pub regs: user_regs_struct,
}

pub struct FFIArray<T, S = u32> {
    pub ptr: *mut T,
    pub cnt: S,
}

impl<T, S: Default> Default for FFIArray<T, S> {
    fn default() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            cnt: Default::default(),
        }
    }
}

impl<T> FFIArray<T, u32> {
    pub fn as_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.cnt as _) }
    }
}

impl<T> FFIArray<T, usize> {
    pub fn as_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.cnt as _) }
    }
}
