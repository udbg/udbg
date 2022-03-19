//!
//! Traits and types for CPU registers
//!

#[cfg(target_pointer_width = "64")]
pub type reg_t = u64;
#[cfg(target_pointer_width = "32")]
pub type reg_t = u32;

pub const RW_EXECUTE: reg_t = 0;
pub const RW_WRITE: reg_t = 1;
pub const RW_ACCESS: reg_t = 3;

pub const LEN_1: reg_t = 0;
pub const LEN_2: reg_t = 1;
pub const LEN_4: reg_t = 3;
pub const LEN_8: reg_t = 2;

pub const EFLAGS_TF: u32 = 0x100;
pub const EFLAGS_RF: u32 = 0x10000;

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct X64Regs {
    pub rax: reg_t,
    pub rbx: reg_t,
    pub rcx: reg_t,
    pub rdx: reg_t,
    pub rbp: reg_t,
    pub rsp: reg_t,
    pub rsi: reg_t,
    pub rdi: reg_t,

    pub r8: reg_t,
    pub r9: reg_t,
    pub r10: reg_t,
    pub r11: reg_t,
    pub r12: reg_t,
    pub r13: reg_t,
    pub r14: reg_t,
    pub r15: reg_t,

    pub rip: reg_t,
    pub rflags: reg_t,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct X86Regs {
    pub eax: reg_t,
    pub ebx: reg_t,
    pub ecx: reg_t,
    pub edx: reg_t,
    pub ebp: reg_t,
    pub esp: reg_t,
    pub esi: reg_t,
    pub edi: reg_t,
    pub eip: reg_t,
    pub eflags: reg_t,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ArmRegs {
    pub r0: reg_t,
    pub r1: reg_t,
    pub r2: reg_t,
    pub r3: reg_t,
    pub r4: reg_t,
    pub r5: reg_t,
    pub r6: reg_t,
    pub r7: reg_t,
    pub r8: reg_t,
    pub r9: reg_t,
    pub r10: reg_t,
    pub r11: reg_t,
    pub r12: reg_t,
    pub r13: reg_t,
    pub r14: reg_t,
    pub r15: reg_t,
}

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Arm64Regs {
    pub regs: [reg_t; 31],
    pub sp: reg_t,
    pub pc: reg_t,
    pub pstate: reg_t,
}

pub trait AbstractRegs {
    type REG: FromUsize + Copy = reg_t;

    fn ip(&mut self) -> &mut Self::REG;
    fn sp(&mut self) -> &mut Self::REG;
}

impl AbstractRegs for X86Regs {
    fn ip(&mut self) -> &mut reg_t {
        &mut self.eip
    }
    fn sp(&mut self) -> &mut reg_t {
        &mut self.esp
    }
}

impl AbstractRegs for X64Regs {
    fn ip(&mut self) -> &mut reg_t {
        &mut self.rip
    }
    fn sp(&mut self) -> &mut reg_t {
        &mut self.rsp
    }
}

impl AbstractRegs for ArmRegs {
    fn ip(&mut self) -> &mut reg_t {
        &mut self.r15
    }
    fn sp(&mut self) -> &mut reg_t {
        &mut self.r13
    }
}

impl AbstractRegs for Arm64Regs {
    fn ip(&mut self) -> &mut reg_t {
        &mut self.pc
    }
    fn sp(&mut self) -> &mut reg_t {
        &mut self.sp
    }
}

use core::mem::transmute;

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(windows)]
use winapi::um::winnt::{CONTEXT, WOW64_CONTEXT};

// regid from capstone-rs
pub mod regid {
    pub const X86_REG_INVALID: u32 = 0;
    pub const X86_REG_AH: u32 = 1;
    pub const X86_REG_AL: u32 = 2;
    pub const X86_REG_AX: u32 = 3;
    pub const X86_REG_BH: u32 = 4;
    pub const X86_REG_BL: u32 = 5;
    pub const X86_REG_BP: u32 = 6;
    pub const X86_REG_BPL: u32 = 7;
    pub const X86_REG_BX: u32 = 8;
    pub const X86_REG_CH: u32 = 9;
    pub const X86_REG_CL: u32 = 10;
    pub const X86_REG_CS: u32 = 11;
    pub const X86_REG_CX: u32 = 12;
    pub const X86_REG_DH: u32 = 13;
    pub const X86_REG_DI: u32 = 14;
    pub const X86_REG_DIL: u32 = 15;
    pub const X86_REG_DL: u32 = 16;
    pub const X86_REG_DS: u32 = 17;
    pub const X86_REG_DX: u32 = 18;
    pub const X86_REG_EAX: u32 = 19;
    pub const X86_REG_EBP: u32 = 20;
    pub const X86_REG_EBX: u32 = 21;
    pub const X86_REG_ECX: u32 = 22;
    pub const X86_REG_EDI: u32 = 23;
    pub const X86_REG_EDX: u32 = 24;
    pub const X86_REG_EFLAGS: u32 = 25;
    pub const X86_REG_EIP: u32 = 26;
    pub const X86_REG_EIZ: u32 = 27;
    pub const X86_REG_ES: u32 = 28;
    pub const X86_REG_ESI: u32 = 29;
    pub const X86_REG_ESP: u32 = 30;
    pub const X86_REG_FPSW: u32 = 31;
    pub const X86_REG_FS: u32 = 32;
    pub const X86_REG_GS: u32 = 33;
    pub const X86_REG_IP: u32 = 34;
    pub const X86_REG_RAX: u32 = 35;
    pub const X86_REG_RBP: u32 = 36;
    pub const X86_REG_RBX: u32 = 37;
    pub const X86_REG_RCX: u32 = 38;
    pub const X86_REG_RDI: u32 = 39;
    pub const X86_REG_RDX: u32 = 40;
    pub const X86_REG_RIP: u32 = 41;
    pub const X86_REG_RIZ: u32 = 42;
    pub const X86_REG_RSI: u32 = 43;
    pub const X86_REG_RSP: u32 = 44;
    pub const X86_REG_SI: u32 = 45;
    pub const X86_REG_SIL: u32 = 46;
    pub const X86_REG_SP: u32 = 47;
    pub const X86_REG_SPL: u32 = 48;
    pub const X86_REG_SS: u32 = 49;
    pub const X86_REG_CR0: u32 = 50;
    pub const X86_REG_CR1: u32 = 51;
    pub const X86_REG_CR2: u32 = 52;
    pub const X86_REG_CR3: u32 = 53;
    pub const X86_REG_CR4: u32 = 54;
    pub const X86_REG_CR5: u32 = 55;
    pub const X86_REG_CR6: u32 = 56;
    pub const X86_REG_CR7: u32 = 57;
    pub const X86_REG_CR8: u32 = 58;
    pub const X86_REG_CR9: u32 = 59;
    pub const X86_REG_CR10: u32 = 60;
    pub const X86_REG_CR11: u32 = 61;
    pub const X86_REG_CR12: u32 = 62;
    pub const X86_REG_CR13: u32 = 63;
    pub const X86_REG_CR14: u32 = 64;
    pub const X86_REG_CR15: u32 = 65;
    pub const X86_REG_DR0: u32 = 66;
    pub const X86_REG_DR1: u32 = 67;
    pub const X86_REG_DR2: u32 = 68;
    pub const X86_REG_DR3: u32 = 69;
    pub const X86_REG_DR4: u32 = 70;
    pub const X86_REG_DR5: u32 = 71;
    pub const X86_REG_DR6: u32 = 72;
    pub const X86_REG_DR7: u32 = 73;
    pub const X86_REG_DR8: u32 = 74;
    pub const X86_REG_DR9: u32 = 75;
    pub const X86_REG_DR10: u32 = 76;
    pub const X86_REG_DR11: u32 = 77;
    pub const X86_REG_DR12: u32 = 78;
    pub const X86_REG_DR13: u32 = 79;
    pub const X86_REG_DR14: u32 = 80;
    pub const X86_REG_DR15: u32 = 81;
    pub const X86_REG_FP0: u32 = 82;
    pub const X86_REG_FP1: u32 = 83;
    pub const X86_REG_FP2: u32 = 84;
    pub const X86_REG_FP3: u32 = 85;
    pub const X86_REG_FP4: u32 = 86;
    pub const X86_REG_FP5: u32 = 87;
    pub const X86_REG_FP6: u32 = 88;
    pub const X86_REG_FP7: u32 = 89;
    pub const X86_REG_K0: u32 = 90;
    pub const X86_REG_K1: u32 = 91;
    pub const X86_REG_K2: u32 = 92;
    pub const X86_REG_K3: u32 = 93;
    pub const X86_REG_K4: u32 = 94;
    pub const X86_REG_K5: u32 = 95;
    pub const X86_REG_K6: u32 = 96;
    pub const X86_REG_K7: u32 = 97;
    pub const X86_REG_MM0: u32 = 98;
    pub const X86_REG_MM1: u32 = 99;
    pub const X86_REG_MM2: u32 = 100;
    pub const X86_REG_MM3: u32 = 101;
    pub const X86_REG_MM4: u32 = 102;
    pub const X86_REG_MM5: u32 = 103;
    pub const X86_REG_MM6: u32 = 104;
    pub const X86_REG_MM7: u32 = 105;
    pub const X86_REG_R8: u32 = 106;
    pub const X86_REG_R9: u32 = 107;
    pub const X86_REG_R10: u32 = 108;
    pub const X86_REG_R11: u32 = 109;
    pub const X86_REG_R12: u32 = 110;
    pub const X86_REG_R13: u32 = 111;
    pub const X86_REG_R14: u32 = 112;
    pub const X86_REG_R15: u32 = 113;
    pub const X86_REG_ST0: u32 = 114;
    pub const X86_REG_ST1: u32 = 115;
    pub const X86_REG_ST2: u32 = 116;
    pub const X86_REG_ST3: u32 = 117;
    pub const X86_REG_ST4: u32 = 118;
    pub const X86_REG_ST5: u32 = 119;
    pub const X86_REG_ST6: u32 = 120;
    pub const X86_REG_ST7: u32 = 121;
    pub const X86_REG_XMM0: u32 = 122;
    pub const X86_REG_XMM1: u32 = 123;
    pub const X86_REG_XMM2: u32 = 124;
    pub const X86_REG_XMM3: u32 = 125;
    pub const X86_REG_XMM4: u32 = 126;
    pub const X86_REG_XMM5: u32 = 127;
    pub const X86_REG_XMM6: u32 = 128;
    pub const X86_REG_XMM7: u32 = 129;
    pub const X86_REG_XMM8: u32 = 130;
    pub const X86_REG_XMM9: u32 = 131;
    pub const X86_REG_XMM10: u32 = 132;
    pub const X86_REG_XMM11: u32 = 133;
    pub const X86_REG_XMM12: u32 = 134;
    pub const X86_REG_XMM13: u32 = 135;
    pub const X86_REG_XMM14: u32 = 136;
    pub const X86_REG_XMM15: u32 = 137;
    pub const X86_REG_XMM16: u32 = 138;
    pub const X86_REG_XMM17: u32 = 139;
    pub const X86_REG_XMM18: u32 = 140;
    pub const X86_REG_XMM19: u32 = 141;
    pub const X86_REG_XMM20: u32 = 142;
    pub const X86_REG_XMM21: u32 = 143;
    pub const X86_REG_XMM22: u32 = 144;
    pub const X86_REG_XMM23: u32 = 145;
    pub const X86_REG_XMM24: u32 = 146;
    pub const X86_REG_XMM25: u32 = 147;
    pub const X86_REG_XMM26: u32 = 148;
    pub const X86_REG_XMM27: u32 = 149;
    pub const X86_REG_XMM28: u32 = 150;
    pub const X86_REG_XMM29: u32 = 151;
    pub const X86_REG_XMM30: u32 = 152;
    pub const X86_REG_XMM31: u32 = 153;
    pub const X86_REG_YMM0: u32 = 154;
    pub const X86_REG_YMM1: u32 = 155;
    pub const X86_REG_YMM2: u32 = 156;
    pub const X86_REG_YMM3: u32 = 157;
    pub const X86_REG_YMM4: u32 = 158;
    pub const X86_REG_YMM5: u32 = 159;
    pub const X86_REG_YMM6: u32 = 160;
    pub const X86_REG_YMM7: u32 = 161;
    pub const X86_REG_YMM8: u32 = 162;
    pub const X86_REG_YMM9: u32 = 163;
    pub const X86_REG_YMM10: u32 = 164;
    pub const X86_REG_YMM11: u32 = 165;
    pub const X86_REG_YMM12: u32 = 166;
    pub const X86_REG_YMM13: u32 = 167;
    pub const X86_REG_YMM14: u32 = 168;
    pub const X86_REG_YMM15: u32 = 169;
    pub const X86_REG_YMM16: u32 = 170;
    pub const X86_REG_YMM17: u32 = 171;
    pub const X86_REG_YMM18: u32 = 172;
    pub const X86_REG_YMM19: u32 = 173;
    pub const X86_REG_YMM20: u32 = 174;
    pub const X86_REG_YMM21: u32 = 175;
    pub const X86_REG_YMM22: u32 = 176;
    pub const X86_REG_YMM23: u32 = 177;
    pub const X86_REG_YMM24: u32 = 178;
    pub const X86_REG_YMM25: u32 = 179;
    pub const X86_REG_YMM26: u32 = 180;
    pub const X86_REG_YMM27: u32 = 181;
    pub const X86_REG_YMM28: u32 = 182;
    pub const X86_REG_YMM29: u32 = 183;
    pub const X86_REG_YMM30: u32 = 184;
    pub const X86_REG_YMM31: u32 = 185;
    pub const X86_REG_ZMM0: u32 = 186;
    pub const X86_REG_ZMM1: u32 = 187;
    pub const X86_REG_ZMM2: u32 = 188;
    pub const X86_REG_ZMM3: u32 = 189;
    pub const X86_REG_ZMM4: u32 = 190;
    pub const X86_REG_ZMM5: u32 = 191;
    pub const X86_REG_ZMM6: u32 = 192;
    pub const X86_REG_ZMM7: u32 = 193;
    pub const X86_REG_ZMM8: u32 = 194;
    pub const X86_REG_ZMM9: u32 = 195;
    pub const X86_REG_ZMM10: u32 = 196;
    pub const X86_REG_ZMM11: u32 = 197;
    pub const X86_REG_ZMM12: u32 = 198;
    pub const X86_REG_ZMM13: u32 = 199;
    pub const X86_REG_ZMM14: u32 = 200;
    pub const X86_REG_ZMM15: u32 = 201;
    pub const X86_REG_ZMM16: u32 = 202;
    pub const X86_REG_ZMM17: u32 = 203;
    pub const X86_REG_ZMM18: u32 = 204;
    pub const X86_REG_ZMM19: u32 = 205;
    pub const X86_REG_ZMM20: u32 = 206;
    pub const X86_REG_ZMM21: u32 = 207;
    pub const X86_REG_ZMM22: u32 = 208;
    pub const X86_REG_ZMM23: u32 = 209;
    pub const X86_REG_ZMM24: u32 = 210;
    pub const X86_REG_ZMM25: u32 = 211;
    pub const X86_REG_ZMM26: u32 = 212;
    pub const X86_REG_ZMM27: u32 = 213;
    pub const X86_REG_ZMM28: u32 = 214;
    pub const X86_REG_ZMM29: u32 = 215;
    pub const X86_REG_ZMM30: u32 = 216;
    pub const X86_REG_ZMM31: u32 = 217;
    pub const X86_REG_R8B: u32 = 218;
    pub const X86_REG_R9B: u32 = 219;
    pub const X86_REG_R10B: u32 = 220;
    pub const X86_REG_R11B: u32 = 221;
    pub const X86_REG_R12B: u32 = 222;
    pub const X86_REG_R13B: u32 = 223;
    pub const X86_REG_R14B: u32 = 224;
    pub const X86_REG_R15B: u32 = 225;
    pub const X86_REG_R8D: u32 = 226;
    pub const X86_REG_R9D: u32 = 227;
    pub const X86_REG_R10D: u32 = 228;
    pub const X86_REG_R11D: u32 = 229;
    pub const X86_REG_R12D: u32 = 230;
    pub const X86_REG_R13D: u32 = 231;
    pub const X86_REG_R14D: u32 = 232;
    pub const X86_REG_R15D: u32 = 233;
    pub const X86_REG_R8W: u32 = 234;
    pub const X86_REG_R9W: u32 = 235;
    pub const X86_REG_R10W: u32 = 236;
    pub const X86_REG_R11W: u32 = 237;
    pub const X86_REG_R12W: u32 = 238;
    pub const X86_REG_R13W: u32 = 239;
    pub const X86_REG_R14W: u32 = 240;
    pub const X86_REG_R15W: u32 = 241;
    pub const X86_REG_BND0: u32 = 242;
    pub const X86_REG_BND1: u32 = 243;
    pub const X86_REG_BND2: u32 = 244;
    pub const X86_REG_BND3: u32 = 245;
    pub const X86_REG_ENDING: u32 = 246;

    pub const ARM_REG_INVALID: u32 = 0;
    pub const ARM_REG_APSR: u32 = 1;
    pub const ARM_REG_APSR_NZCV: u32 = 2;
    pub const ARM_REG_CPSR: u32 = 3;
    pub const ARM_REG_FPEXC: u32 = 4;
    pub const ARM_REG_FPINST: u32 = 5;
    pub const ARM_REG_FPSCR: u32 = 6;
    pub const ARM_REG_FPSCR_NZCV: u32 = 7;
    pub const ARM_REG_FPSID: u32 = 8;
    pub const ARM_REG_ITSTATE: u32 = 9;
    pub const ARM_REG_LR: u32 = 10;
    pub const ARM_REG_PC: u32 = 11;
    pub const ARM_REG_SP: u32 = 12;
    pub const ARM_REG_SPSR: u32 = 13;
    pub const ARM_REG_D0: u32 = 14;
    pub const ARM_REG_D1: u32 = 15;
    pub const ARM_REG_D2: u32 = 16;
    pub const ARM_REG_D3: u32 = 17;
    pub const ARM_REG_D4: u32 = 18;
    pub const ARM_REG_D5: u32 = 19;
    pub const ARM_REG_D6: u32 = 20;
    pub const ARM_REG_D7: u32 = 21;
    pub const ARM_REG_D8: u32 = 22;
    pub const ARM_REG_D9: u32 = 23;
    pub const ARM_REG_D10: u32 = 24;
    pub const ARM_REG_D11: u32 = 25;
    pub const ARM_REG_D12: u32 = 26;
    pub const ARM_REG_D13: u32 = 27;
    pub const ARM_REG_D14: u32 = 28;
    pub const ARM_REG_D15: u32 = 29;
    pub const ARM_REG_D16: u32 = 30;
    pub const ARM_REG_D17: u32 = 31;
    pub const ARM_REG_D18: u32 = 32;
    pub const ARM_REG_D19: u32 = 33;
    pub const ARM_REG_D20: u32 = 34;
    pub const ARM_REG_D21: u32 = 35;
    pub const ARM_REG_D22: u32 = 36;
    pub const ARM_REG_D23: u32 = 37;
    pub const ARM_REG_D24: u32 = 38;
    pub const ARM_REG_D25: u32 = 39;
    pub const ARM_REG_D26: u32 = 40;
    pub const ARM_REG_D27: u32 = 41;
    pub const ARM_REG_D28: u32 = 42;
    pub const ARM_REG_D29: u32 = 43;
    pub const ARM_REG_D30: u32 = 44;
    pub const ARM_REG_D31: u32 = 45;
    pub const ARM_REG_FPINST2: u32 = 46;
    pub const ARM_REG_MVFR0: u32 = 47;
    pub const ARM_REG_MVFR1: u32 = 48;
    pub const ARM_REG_MVFR2: u32 = 49;
    pub const ARM_REG_Q0: u32 = 50;
    pub const ARM_REG_Q1: u32 = 51;
    pub const ARM_REG_Q2: u32 = 52;
    pub const ARM_REG_Q3: u32 = 53;
    pub const ARM_REG_Q4: u32 = 54;
    pub const ARM_REG_Q5: u32 = 55;
    pub const ARM_REG_Q6: u32 = 56;
    pub const ARM_REG_Q7: u32 = 57;
    pub const ARM_REG_Q8: u32 = 58;
    pub const ARM_REG_Q9: u32 = 59;
    pub const ARM_REG_Q10: u32 = 60;
    pub const ARM_REG_Q11: u32 = 61;
    pub const ARM_REG_Q12: u32 = 62;
    pub const ARM_REG_Q13: u32 = 63;
    pub const ARM_REG_Q14: u32 = 64;
    pub const ARM_REG_Q15: u32 = 65;
    pub const ARM_REG_R0: u32 = 66;
    pub const ARM_REG_R1: u32 = 67;
    pub const ARM_REG_R2: u32 = 68;
    pub const ARM_REG_R3: u32 = 69;
    pub const ARM_REG_R4: u32 = 70;
    pub const ARM_REG_R5: u32 = 71;
    pub const ARM_REG_R6: u32 = 72;
    pub const ARM_REG_R7: u32 = 73;
    pub const ARM_REG_R8: u32 = 74;
    pub const ARM_REG_R9: u32 = 75;
    pub const ARM_REG_R10: u32 = 76;
    pub const ARM_REG_R11: u32 = 77;
    pub const ARM_REG_R12: u32 = 78;
    pub const ARM_REG_S0: u32 = 79;
    pub const ARM_REG_S1: u32 = 80;
    pub const ARM_REG_S2: u32 = 81;
    pub const ARM_REG_S3: u32 = 82;
    pub const ARM_REG_S4: u32 = 83;
    pub const ARM_REG_S5: u32 = 84;
    pub const ARM_REG_S6: u32 = 85;
    pub const ARM_REG_S7: u32 = 86;
    pub const ARM_REG_S8: u32 = 87;
    pub const ARM_REG_S9: u32 = 88;
    pub const ARM_REG_S10: u32 = 89;
    pub const ARM_REG_S11: u32 = 90;
    pub const ARM_REG_S12: u32 = 91;
    pub const ARM_REG_S13: u32 = 92;
    pub const ARM_REG_S14: u32 = 93;
    pub const ARM_REG_S15: u32 = 94;
    pub const ARM_REG_S16: u32 = 95;
    pub const ARM_REG_S17: u32 = 96;
    pub const ARM_REG_S18: u32 = 97;
    pub const ARM_REG_S19: u32 = 98;
    pub const ARM_REG_S20: u32 = 99;
    pub const ARM_REG_S21: u32 = 100;
    pub const ARM_REG_S22: u32 = 101;
    pub const ARM_REG_S23: u32 = 102;
    pub const ARM_REG_S24: u32 = 103;
    pub const ARM_REG_S25: u32 = 104;
    pub const ARM_REG_S26: u32 = 105;
    pub const ARM_REG_S27: u32 = 106;
    pub const ARM_REG_S28: u32 = 107;
    pub const ARM_REG_S29: u32 = 108;
    pub const ARM_REG_S30: u32 = 109;
    pub const ARM_REG_S31: u32 = 110;
    pub const ARM_REG_ENDING: u32 = 111;
    pub const ARM_REG_R13: u32 = 12;
    pub const ARM_REG_R14: u32 = 10;
    pub const ARM_REG_R15: u32 = 11;
    pub const ARM_REG_SB: u32 = 75;
    pub const ARM_REG_SL: u32 = 76;
    pub const ARM_REG_FP: u32 = 77;
    pub const ARM_REG_IP: u32 = 78;
}

pub const COMM_REG_SP: u32 = 0x10001;
pub const COMM_REG_PC: u32 = 0x10002;

use regid::*;

#[derive(Copy, Clone)]
pub enum CpuReg {
    Int(usize),
    Flt(f64),
}

impl serde::Serialize for CpuReg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Int(val) => serializer.serialize_u64(*val as _),
            Self::Flt(val) => serializer.serialize_f64(*val),
        }
    }
}

impl CpuReg {
    #[inline]
    pub fn as_int(&self) -> usize {
        match *self {
            Self::Int(n) => n,
            Self::Flt(n) => n as usize,
        }
    }

    #[inline]
    pub fn as_flt(&self) -> f64 {
        match *self {
            Self::Int(n) => n as f64,
            Self::Flt(n) => n,
        }
    }
}

impl From<usize> for CpuReg {
    fn from(v: usize) -> Self {
        Self::Int(v)
    }
}

impl From<f64> for CpuReg {
    fn from(v: f64) -> Self {
        Self::Flt(v)
    }
}

impl Into<u64> for CpuReg {
    #[inline]
    fn into(self) -> u64 {
        self.as_int() as u64
    }
}

impl Into<u32> for CpuReg {
    #[inline]
    fn into(self) -> u32 {
        self.as_int() as u32
    }
}

impl Into<usize> for CpuReg {
    #[inline]
    fn into(self) -> usize {
        self.as_int()
    }
}

pub trait FromUsize {
    fn from_usize(v: usize) -> Self;
    fn to_usize(&self) -> usize;
}

impl FromUsize for u32 {
    fn from_usize(v: usize) -> Self {
        v as Self
    }
    fn to_usize(&self) -> usize {
        *self as usize
    }
}

impl FromUsize for u64 {
    fn from_usize(v: usize) -> Self {
        v as Self
    }
    fn to_usize(&self) -> usize {
        *self as usize
    }
}

#[cfg(windows)]
mod plat {
    use super::*;
    use core::slice::{from_raw_parts, from_raw_parts_mut};

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub type CONTEXT32 = WOW64_CONTEXT;
    #[cfg(target_arch = "x86")]
    pub type CONTEXT32 = CONTEXT;

    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
    #[cfg(target_arch = "x86_64")]
    impl AbstractRegs for CONTEXT {
        type REG = u64;

        #[inline]
        fn ip(&mut self) -> &mut Self::REG {
            &mut self.Rip
        }
        #[inline]
        fn sp(&mut self) -> &mut Self::REG {
            &mut self.Rsp
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl AbstractRegs for CONTEXT {
        type REG = u64;

        #[inline]
        fn ip(&mut self) -> &mut Self::REG {
            &mut self.Pc
        }
        #[inline]
        fn sp(&mut self) -> &mut Self::REG {
            &mut self.Sp
        }
    }

    impl AbstractRegs for CONTEXT32 {
        type REG = u32;

        #[inline]
        fn ip(&mut self) -> &mut Self::REG {
            &mut self.Eip
        }
        #[inline]
        fn sp(&mut self) -> &mut Self::REG {
            &mut self.Esp
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl UDbgRegs for CONTEXT {
        fn get_reg(&self, id: u32) -> Option<CpuReg> {
            let c = self;
            Some(CpuReg::Int(match id {
                X86_REG_RAX => c.Rax,
                X86_REG_RBX => c.Rbx,
                X86_REG_RCX => c.Rcx,
                X86_REG_RDX => c.Rdx,
                X86_REG_RBP => c.Rbp,
                X86_REG_RSI => c.Rsi,
                X86_REG_RDI => c.Rdi,
                X86_REG_R8..=X86_REG_R15 => unsafe {
                    let i = (id - X86_REG_R8) as usize;
                    from_raw_parts(&c.R8, 8)[i]
                },
                X86_REG_DR0 => c.Dr0,
                X86_REG_DR1 => c.Dr1,
                X86_REG_DR2 => c.Dr2,
                X86_REG_DR3 => c.Dr3,
                X86_REG_DR6 => c.Dr6,
                X86_REG_DR7 => c.Dr7,
                X86_REG_RSP | COMM_REG_SP => c.Rsp,
                X86_REG_RIP | COMM_REG_PC => c.Rip,
                X86_REG_EFLAGS => c.EFlags as u64,
                X86_REG_MM0..=X86_REG_MM7 => unsafe {
                    let i = (id - X86_REG_MM0) as usize;
                    let mut f = [0.0; 4];
                    _mm_storeu_ps(
                        f.as_mut_ptr(),
                        transmute(from_raw_parts(&mutable(c).u.s_mut().Xmm0, 100)[i]),
                    );
                    return CpuReg::Flt(f[0] as f64).into();
                },
                X86_REG_XMM0..=X86_REG_XMM15 => unsafe {
                    let i = (id - X86_REG_XMM0) as usize;
                    let mut f = [0.0; 2];
                    _mm_storeu_pd(
                        f.as_mut_ptr(),
                        transmute(from_raw_parts(&mutable(c).u.s_mut().Xmm0, 100)[i]),
                    );
                    return CpuReg::Flt(f[0]).into();
                },
                _ => return None,
            } as usize))
        }

        fn set_reg(&mut self, id: u32, val: CpuReg) {
            let c = self;
            match id {
                X86_REG_RAX => c.Rax = val.into(),
                X86_REG_RBX => c.Rbx = val.into(),
                X86_REG_RCX => c.Rcx = val.into(),
                X86_REG_RDX => c.Rdx = val.into(),
                X86_REG_RBP => c.Rbp = val.into(),
                X86_REG_RSI => c.Rsi = val.into(),
                X86_REG_RDI => c.Rdi = val.into(),
                X86_REG_R8 => c.R8 = val.into(),
                X86_REG_R9 => c.R9 = val.into(),
                X86_REG_R10 => c.R10 = val.into(),
                X86_REG_R11 => c.R11 = val.into(),
                X86_REG_R12 => c.R12 = val.into(),
                X86_REG_R13 => c.R13 = val.into(),
                X86_REG_R14 => c.R14 = val.into(),
                X86_REG_R15 => c.R15 = val.into(),
                X86_REG_RSP | COMM_REG_SP => c.Rsp = val.into(),
                X86_REG_RIP | COMM_REG_PC => c.Rip = val.into(),
                X86_REG_EFLAGS => c.EFlags = val.into(),
                X86_REG_MM0..=X86_REG_MM7 => unsafe {
                    let i = (id - X86_REG_MM0) as usize;
                    from_raw_parts_mut(&mut c.u.s_mut().Xmm0, 100)[i] =
                        transmute(_mm_set1_ps(val.as_flt() as f32));
                },
                X86_REG_XMM0..=X86_REG_XMM15 => unsafe {
                    let i = (id - X86_REG_XMM0) as usize;
                    from_raw_parts_mut(&mut c.u.s_mut().Xmm0, 100)[i] =
                        transmute(_mm_set1_pd(val.as_flt()));
                },
                _ => {}
            };
        }

        fn get(&self, reg_t: &str) -> Option<CpuReg> {
            if reg_t.starts_with("mm") {
                // float
                return usize::from_str_radix(&reg_t[3..], 10)
                    .map(|o| unsafe {
                        let c = transmute::<_, &mut CONTEXT>(transmute::<_, usize>(self));
                        let mut f = [0.0; 4];
                        _mm_storeu_ps(
                            f.as_mut_ptr(),
                            transmute(from_raw_parts(&c.u.s_mut().Xmm0, 100)[o]),
                        );
                        CpuReg::Flt(f[0] as f64)
                    })
                    .ok();
            }
            if reg_t.starts_with("xmm") {
                // double
                return usize::from_str_radix(&reg_t[3..], 10)
                    .map(|o| unsafe {
                        let c = transmute::<_, &mut CONTEXT>(transmute::<_, usize>(self));
                        let mut f = [0.0; 2];
                        _mm_storeu_pd(
                            f.as_mut_ptr(),
                            transmute(from_raw_parts(&c.u.s_mut().Xmm0, 100)[o]),
                        );
                        CpuReg::Flt(f[0])
                    })
                    .ok();
            }
            Some(CpuReg::Int(match reg_t {
                "rax" => self.Rax,
                "rbx" => self.Rbx,
                "rcx" => self.Rcx,
                "rdx" => self.Rdx,
                "rbp" => self.Rbp,
                "rsp" | "_sp" => self.Rsp,
                "rsi" => self.Rsi,
                "rdi" => self.Rdi,
                "r8" => self.R8,
                "r9" => self.R9,
                "r10" => self.R10,
                "r11" => self.R11,
                "r12" => self.R12,
                "r13" => self.R13,
                "r14" => self.R14,
                "r15" => self.R15,
                "rip" | "_pc" => self.Rip,
                "rflags" => self.EFlags as u64,
                _ => return None,
            } as usize))
        }

        fn set(&mut self, name: &str, val: CpuReg) {
            if name.starts_with("mm") {
                // float
                usize::from_str_radix(&name[3..], 10).map(|o| unsafe {
                    from_raw_parts_mut(&mut self.u.s_mut().Xmm0, 100)[o] =
                        transmute(_mm_set1_ps(val.as_flt() as f32));
                });
            }
            if name.starts_with("xmm") {
                // double
                usize::from_str_radix(&name[3..], 10).map(|o| unsafe {
                    from_raw_parts_mut(&mut self.u.s_mut().Xmm0, 100)[o] =
                        transmute(_mm_set1_pd(val.as_flt()));
                });
            }
            let val = val.as_int() as u64;
            match name {
                "rax" => self.Rax = val,
                "rbx" => self.Rbx = val,
                "rcx" => self.Rcx = val,
                "rdx" => self.Rdx = val,
                "rbp" => self.Rbp = val,
                "rsp" | "_sp" => self.Rsp = val,
                "rsi" => self.Rsi = val,
                "rdi" => self.Rdi = val,
                "r8" => self.R8 = val,
                "r9" => self.R9 = val,
                "r10" => self.R10 = val,
                "r11" => self.R11 = val,
                "r12" => self.R12 = val,
                "r13" => self.R13 = val,
                "r14" => self.R14 = val,
                "r15" => self.R15 = val,
                "rip" | "_pc" => self.Rip = val,
                "rflags" => self.EFlags = val as u32,
                _ => {}
            };
        }

        fn to_regs(&self) -> RegType {
            RegType::X64(context_to_regs(self))
        }

        fn as_raw(&self) -> Option<&CONTEXT> {
            Some(self)
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl UDbgRegs for CONTEXT {
        fn get_reg(&self, id: u32) -> Option<CpuReg> {
            let c = self;
            Some(CpuReg::Int(match id {
                ARM_REG_PC => c.Pc,
                ARM_REG_SP | COMM_REG_SP => c.Sp,
                // TODO:
                _ => return None,
            } as usize))
        }

        fn set_reg(&mut self, id: u32, val: CpuReg) {
            // TODO:
        }

        fn to_regs(&self) -> RegType {
            #[cfg(target_arch = "aarch64")]
            {
                RegType::Arm64(context_to_regs(self))
            }
        }
    }

    impl UDbgRegs for CONTEXT32 {
        fn get_reg(&self, id: u32) -> Option<CpuReg> {
            let c = self;
            Some(CpuReg::Int(match id {
                X86_REG_EAX => c.Eax,
                X86_REG_EBX => c.Ebx,
                X86_REG_ECX => c.Ecx,
                X86_REG_EDX => c.Edx,
                X86_REG_EBP => c.Ebp,
                X86_REG_ESI => c.Esi,
                X86_REG_EDI => c.Edi,
                X86_REG_DR0 => c.Dr0,
                X86_REG_DR1 => c.Dr1,
                X86_REG_DR2 => c.Dr2,
                X86_REG_DR3 => c.Dr3,
                X86_REG_DR6 => c.Dr6,
                X86_REG_DR7 => c.Dr7,
                X86_REG_ESP | COMM_REG_SP => c.Esp,
                X86_REG_EIP | COMM_REG_PC => c.Eip,
                X86_REG_EFLAGS => c.EFlags,
                _ => return None,
            } as usize))
        }

        fn get(&self, reg_t: &str) -> Option<CpuReg> {
            Some(CpuReg::Int(match reg_t {
                "eax" => self.Eax,
                "ebx" => self.Ebx,
                "ecx" => self.Ecx,
                "edx" => self.Edx,
                "ebp" => self.Ebp,
                "esp" | "_sp" => self.Esp,
                "esi" => self.Esi,
                "edi" => self.Edi,
                "eip" | "_pc" => self.Eip,
                "eflags" => self.EFlags,
                _ => return None,
            } as usize))
        }

        fn set_reg(&mut self, id: u32, val: CpuReg) {
            let c = self;
            match id {
                X86_REG_EAX => c.Eax = val.into(),
                X86_REG_EBX => c.Ebx = val.into(),
                X86_REG_ECX => c.Ecx = val.into(),
                X86_REG_EDX => c.Edx = val.into(),
                X86_REG_EBP => c.Ebp = val.into(),
                X86_REG_ESI => c.Esi = val.into(),
                X86_REG_EDI => c.Edi = val.into(),
                X86_REG_ESP | COMM_REG_SP => c.Esp = val.into(),
                X86_REG_EIP | COMM_REG_PC => c.Eip = val.into(),
                X86_REG_EFLAGS => c.EFlags = val.into(),
                _ => {}
            };
        }

        fn to_regs(&self) -> RegType {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            {
                RegType::X86(context_to_regs32(self))
            }
            #[cfg(target_arch = "x86")]
            {
                RegType::X86(context_to_regs(self))
            }
        }

        #[cfg(target_arch = "x86_64")]
        fn as_wow64(&self) -> Option<&WOW64_CONTEXT> {
            Some(self)
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn context_to_regs(c: &CONTEXT) -> Registers {
        Registers {
            rax: c.Rax,
            rbx: c.Rbx,
            rcx: c.Rcx,
            rdx: c.Rdx,
            rbp: c.Rbp,
            rsp: c.Rsp,
            rsi: c.Rsi,
            rdi: c.Rdi,
            r8: c.R8,
            r9: c.R9,
            r10: c.R10,
            r11: c.R11,
            r12: c.R12,
            r13: c.R13,
            r14: c.R14,
            r15: c.R15,
            rip: c.Rip,
            rflags: c.EFlags as u64,
            cs: c.SegCs,
            ds: c.SegDs,
            es: c.SegEs,
            fs: c.SegFs,
            gs: c.SegGs,
            ss: c.SegSs,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn context_to_regs(c: &CONTEXT) -> Registers {
        Registers {
            regs: unsafe { core::mem::transmute(c.u) },
            sp: c.Sp,
            pc: c.Pc,
            // TODO:
            pstate: c.Cpsr as _,
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn context_to_regs32(c: &WOW64_CONTEXT) -> X86Regs {
        X86Regs {
            eax: c.Eax as _,
            ebx: c.Ebx as _,
            ecx: c.Ecx as _,
            edx: c.Edx as _,
            ebp: c.Ebp as _,
            esp: c.Esp as _,
            esi: c.Esi as _,
            edi: c.Edi as _,
            eip: c.Eip as _,
            eflags: c.EFlags as _,
            cs: c.SegCs as u16,
            ds: c.SegDs as u16,
            es: c.SegEs as u16,
            fs: c.SegFs as u16,
            gs: c.SegGs as u16,
            ss: c.SegSs as u16,
        }
    }

    #[cfg(target_arch = "x86")]
    pub fn context_to_regs(c: &CONTEXT) -> Registers {
        Registers {
            eax: c.Eax,
            ebx: c.Ebx,
            ecx: c.Ecx,
            edx: c.Edx,
            ebp: c.Ebp,
            esp: c.Esp,
            esi: c.Esi,
            edi: c.Edi,
            eip: c.Eip,
            eflags: c.EFlags as u32,
            cs: c.SegCs as u16,
            ds: c.SegDs as u16,
            es: c.SegEs as u16,
            fs: c.SegFs as u16,
            gs: c.SegGs as u16,
            ss: c.SegSs as u16,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod plat {
    use super::*;
    #[cfg(target_arch = "aarch64")]
    use crate::nix::user_regs_struct;
    #[cfg(target_arch = "x86_64")]
    use libc::user_regs_struct;

    #[cfg(target_arch = "x86_64")]
    impl UDbgRegs for user_regs_struct {
        fn get_reg(&self, id: u32) -> Option<CpuReg> {
            let c = self;
            Some(CpuReg::Int(match id {
                X86_REG_RAX => c.rax,
                X86_REG_RBX => c.rbx,
                X86_REG_RCX => c.rcx,
                X86_REG_RDX => c.rdx,
                X86_REG_RBP => c.rbp,
                X86_REG_RSI => c.rsi,
                X86_REG_RDI => c.rdi,
                X86_REG_R8 => c.r8,
                X86_REG_R9 => c.r9,
                X86_REG_R10 => c.r10,
                X86_REG_R11 => c.r11,
                X86_REG_R12 => c.r12,
                X86_REG_R13 => c.r13,
                X86_REG_R14 => c.r14,
                X86_REG_R15 => c.r15,
                X86_REG_RSP | COMM_REG_SP => c.rsp,
                X86_REG_RIP | COMM_REG_PC => c.rip,
                X86_REG_EFLAGS => c.eflags as u64,
                _ => return None,
            } as usize))
        }

        fn set_reg(&mut self, id: u32, val: CpuReg) {
            let c = self;
            match id {
                X86_REG_RAX => c.rax = val.into(),
                X86_REG_RBX => c.rbx = val.into(),
                X86_REG_RCX => c.rcx = val.into(),
                X86_REG_RDX => c.rdx = val.into(),
                X86_REG_RBP => c.rbp = val.into(),
                X86_REG_RSI => c.rsi = val.into(),
                X86_REG_RDI => c.rdi = val.into(),
                X86_REG_R8 => c.r8 = val.into(),
                X86_REG_R9 => c.r9 = val.into(),
                X86_REG_R10 => c.r10 = val.into(),
                X86_REG_R11 => c.r11 = val.into(),
                X86_REG_R12 => c.r12 = val.into(),
                X86_REG_R13 => c.r13 = val.into(),
                X86_REG_R14 => c.r14 = val.into(),
                X86_REG_R15 => c.r15 = val.into(),
                X86_REG_RSP | COMM_REG_SP => c.rsp = val.into(),
                X86_REG_RIP | COMM_REG_PC => c.rip = val.into(),
                X86_REG_EFLAGS => c.eflags = val.into(),
                _ => {}
            };
        }

        fn to_regs(&self) -> RegType {
            RegType::X64(context_to_regs(self))
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl UDbgRegs for user_regs_struct {
        fn get_reg(&self, id: u32) -> Option<CpuReg> {
            let c = self;
            Some(CpuReg::Int(match id {
                ARM_REG_SP | COMM_REG_SP => c.sp,
                ARM_REG_PC | COMM_REG_PC => c.pc,
                ARM_REG_S0..=ARM_REG_S31 => c.regs[(id - ARM_REG_S0) as usize],
                _ => return None,
            } as usize))
        }

        fn set_reg(&mut self, id: u32, val: CpuReg) {
            let c = self;
            match id {
                ARM_REG_SP | COMM_REG_SP => c.sp = val.into(),
                ARM_REG_PC | COMM_REG_PC => c.pc = val.into(),
                ARM_REG_S0..=ARM_REG_S31 => c.regs[(id - ARM_REG_S0) as usize] = val.into(),
                _ => {}
            };
        }

        fn to_regs(&self) -> RegType {
            RegType::Arm64(context_to_regs(self))
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn context_to_regs(regs: &user_regs_struct) -> Registers {
        Registers {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rbp: regs.rbp,
            rsp: regs.rsp,
            rsi: regs.rsi,
            rdi: regs.rdi,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            cs: regs.cs as _,
            ds: regs.ds as _,
            es: regs.es as _,
            fs: regs.fs as _,
            gs: regs.gs as _,
            ss: regs.ss as _,
            rflags: regs.eflags as reg_t,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn context_to_regs(regs: &user_regs_struct) -> Registers {
        unsafe { core::mem::transmute_copy(regs) }
    }
}

#[cfg(target_os = "macos")]
mod plat {}

pub use self::plat::*;

#[inline]
unsafe fn mutable<T: Sized>(t: &T) -> &mut T {
    transmute(transmute::<_, usize>(t))
}

cfg_if! {
    if #[cfg(target_arch = "x86")] {
        pub type Registers = X86Regs;
    } else if #[cfg(target_arch = "x86_64")] {
        pub type Registers = X64Regs;
    } else if #[cfg(target_arch = "arm")] {
        pub type Registers = ArmRegs;
    } else if #[cfg(target_arch = "aarch64")] {
        pub type Registers = Arm64Regs;
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Registers32 {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebp: u32,
    pub esp: u32,
    pub esi: u32,
    pub edi: u32,
    pub eip: u32,
    pub eflags: u32,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

#[cfg(target_arch = "aarch64")]
#[derive(Copy, Clone)]
pub struct Registers32 {
    // pt_regs: https://android.googlesource.com/platform/external/kernel-headers/+/froyo/original/asm-arm/ptrace.h
    pub regs: [reg_t; 18],
}

#[cfg(target_arch = "x86")]
pub type Registers32 = Registers;

pub enum RegType {
    X86(X86Regs),
    X64(X64Regs),
    Arm(ArmRegs),
    Arm64(Arm64Regs),
}

pub trait UDbgRegs: crate::memory::AsByteArray {
    fn get_reg(&self, id: u32) -> Option<CpuReg>;
    fn set_reg(&mut self, id: u32, val: CpuReg);

    fn get(&self, name: &str) -> Option<CpuReg> {
        get_regid(name).and_then(|id| self.get_reg(id))
    }
    fn set(&mut self, name: &str, val: CpuReg) {
        get_regid(name).map(|id| self.set_reg(id, val));
    }

    fn to_regs(&self) -> RegType;

    #[cfg(windows)]
    fn as_raw(&self) -> Option<&CONTEXT> {
        None
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    fn as_wow64(&self) -> Option<&WOW64_CONTEXT> {
        None
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_regid(r: &str) -> Option<u32> {
    Some(match r {
        "rax" => X86_REG_RAX,
        "rbx" => X86_REG_RBX,
        "rcx" => X86_REG_RCX,
        "rdx" => X86_REG_RDX,
        "rbp" => X86_REG_RBP,
        "rsp" => X86_REG_RSP,
        "rsi" => X86_REG_RSI,
        "rdi" => X86_REG_RDI,
        "r8" => X86_REG_R8,
        "r9" => X86_REG_R9,
        "r10" => X86_REG_R10,
        "r11" => X86_REG_R11,
        "r12" => X86_REG_R12,
        "r13" => X86_REG_R13,
        "r14" => X86_REG_R14,
        "r15" => X86_REG_R15,
        "rip" => X86_REG_RIP,
        "eax" => X86_REG_EAX,
        "ebx" => X86_REG_EBX,
        "ecx" => X86_REG_ECX,
        "edx" => X86_REG_EDX,
        "ebp" => X86_REG_EBP,
        "esp" => X86_REG_ESP,
        "esi" => X86_REG_ESI,
        "edi" => X86_REG_EDI,
        "eip" => X86_REG_EIP,
        "_pc" => COMM_REG_PC,
        "_sp" => COMM_REG_SP,
        "eflags" => X86_REG_EFLAGS,
        _ => {
            if r.starts_with("xmm") {
                u32::from_str_radix(&r[3..], 10)
                    .map(|i| X86_REG_XMM0 + i)
                    .ok()?
            } else if r.starts_with("mm") {
                u32::from_str_radix(&r[2..], 10)
                    .map(|i| X86_REG_MM0 + i)
                    .ok()?
            } else if r.starts_with("dr") {
                u32::from_str_radix(&r[2..], 10)
                    .map(|i| X86_REG_DR0 + i)
                    .ok()?
            } else {
                return None;
            }
        }
    })
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn get_regid(r: &str) -> Option<u32> {
    Some(match r {
        "apsr" => ARM_REG_APSR,
        "apsr_nzcv" => ARM_REG_APSR_NZCV,
        "cpsr" => ARM_REG_CPSR,
        "fpexc" => ARM_REG_FPEXC,
        "fpinst" => ARM_REG_FPINST,
        "fpscr" => ARM_REG_FPSCR,
        "fpscr_nzcv" => ARM_REG_FPSCR_NZCV,
        "fpsid" => ARM_REG_FPSID,
        "itstate" => ARM_REG_ITSTATE,
        "lr" => ARM_REG_LR,
        "pc" => ARM_REG_PC,
        "sp" => ARM_REG_SP,
        "_pc" => COMM_REG_PC,
        "_sp" => COMM_REG_SP,
        "spsr" => ARM_REG_SPSR,
        "d0" => ARM_REG_D0,
        "d1" => ARM_REG_D1,
        "d2" => ARM_REG_D2,
        "d3" => ARM_REG_D3,
        "d4" => ARM_REG_D4,
        "d5" => ARM_REG_D5,
        "d6" => ARM_REG_D6,
        "d7" => ARM_REG_D7,
        "d8" => ARM_REG_D8,
        "d9" => ARM_REG_D9,
        "d10" => ARM_REG_D10,
        "d11" => ARM_REG_D11,
        "d12" => ARM_REG_D12,
        "d13" => ARM_REG_D13,
        "d14" => ARM_REG_D14,
        "d15" => ARM_REG_D15,
        "d16" => ARM_REG_D16,
        "d17" => ARM_REG_D17,
        "d18" => ARM_REG_D18,
        "d19" => ARM_REG_D19,
        "d20" => ARM_REG_D20,
        "d21" => ARM_REG_D21,
        "d22" => ARM_REG_D22,
        "d23" => ARM_REG_D23,
        "d24" => ARM_REG_D24,
        "d25" => ARM_REG_D25,
        "d26" => ARM_REG_D26,
        "d27" => ARM_REG_D27,
        "d28" => ARM_REG_D28,
        "d29" => ARM_REG_D29,
        "d30" => ARM_REG_D30,
        "d31" => ARM_REG_D31,
        "fpinst2" => ARM_REG_FPINST2,
        "mvfr0" => ARM_REG_MVFR0,
        "mvfr1" => ARM_REG_MVFR1,
        "mvfr2" => ARM_REG_MVFR2,
        "q0" => ARM_REG_Q0,
        "q1" => ARM_REG_Q1,
        "q2" => ARM_REG_Q2,
        "q3" => ARM_REG_Q3,
        "q4" => ARM_REG_Q4,
        "q5" => ARM_REG_Q5,
        "q6" => ARM_REG_Q6,
        "q7" => ARM_REG_Q7,
        "q8" => ARM_REG_Q8,
        "q9" => ARM_REG_Q9,
        "q10" => ARM_REG_Q10,
        "q11" => ARM_REG_Q11,
        "q12" => ARM_REG_Q12,
        "q13" => ARM_REG_Q13,
        "q14" => ARM_REG_Q14,
        "q15" => ARM_REG_Q15,
        "r0" => ARM_REG_R0,
        "r1" => ARM_REG_R1,
        "r2" => ARM_REG_R2,
        "r3" => ARM_REG_R3,
        "r4" => ARM_REG_R4,
        "r5" => ARM_REG_R5,
        "r6" => ARM_REG_R6,
        "r7" => ARM_REG_R7,
        "r8" => ARM_REG_R8,
        "r9" => ARM_REG_R9,
        "r10" => ARM_REG_R10,
        "r11" => ARM_REG_R11,
        "r12" => ARM_REG_R12,
        "s0" => ARM_REG_S0,
        "s1" => ARM_REG_S1,
        "s2" => ARM_REG_S2,
        "s3" => ARM_REG_S3,
        "s4" => ARM_REG_S4,
        "s5" => ARM_REG_S5,
        "s6" => ARM_REG_S6,
        "s7" => ARM_REG_S7,
        "s8" => ARM_REG_S8,
        "s9" => ARM_REG_S9,
        "x10" => ARM_REG_S10,
        "x11" => ARM_REG_S11,
        "x12" => ARM_REG_S12,
        "x13" => ARM_REG_S13,
        "x14" => ARM_REG_S14,
        "x15" => ARM_REG_S15,
        "x16" => ARM_REG_S16,
        "x17" => ARM_REG_S17,
        "x18" => ARM_REG_S18,
        "x19" => ARM_REG_S19,
        "x20" => ARM_REG_S20,
        "x21" => ARM_REG_S21,
        "x22" => ARM_REG_S22,
        "x23" => ARM_REG_S23,
        "x24" => ARM_REG_S24,
        "x25" => ARM_REG_S25,
        "x26" => ARM_REG_S26,
        "x27" => ARM_REG_S27,
        "x28" => ARM_REG_S28,
        "x29" => ARM_REG_S29,
        "x30" => ARM_REG_S30,
        "x31" => ARM_REG_S31,
        "ending" => ARM_REG_ENDING,
        "r13" => ARM_REG_R13,
        "r14" => ARM_REG_R14,
        "r15" => ARM_REG_R15,
        "sb" => ARM_REG_SB,
        "sl" => ARM_REG_SL,
        "fp" => ARM_REG_FP,
        "ip" => ARM_REG_IP,
        _ => return None,
    })
}
