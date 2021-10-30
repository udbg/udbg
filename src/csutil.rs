
pub use capstone::prelude::*;
pub use capstone::{Insn, Instructions};
pub use capstone::arch::{
    ArchOperand,
    x86::X86OpMem,
    x86::X86OperandType,
    arm::ArmOperandType,
    arm64::Arm64OperandType,
};

#[derive(Copy, Clone)]
pub struct SimpleOpMem {
    pub segment: RegId,
    pub base: RegId,
    pub index: RegId,
    pub disp: i64,
    pub base_reg: RegIdInt,
}

impl From<X86OpMem> for SimpleOpMem {
    fn from(m: X86OpMem) -> Self {
        Self {
            segment: m.segment(),
            base: m.base(),
            index: m.index(),
            disp: m.disp(),
            base_reg: m.base().0,
        }
    }
}

impl SimpleOpMem {
    pub fn to_abs(&self, i: &Insn) -> Option<usize> {
        use capstone::arch::x86::X86Reg::*;

        if self.base_reg as u32 == X86_REG_RIP {
            Some((i.address() as i64 + i.bytes().len() as i64 + self.disp) as usize)
        } else if self.base_reg == 0 {
            Some(self.disp as usize)
        } else { None }
    }
}

pub enum SimpleOperand {
    None,
    Imm(usize),
    Reg(RegId),
    Mem(SimpleOpMem),
}

pub fn simplify_operand(dis: &Insn, op: &ArchOperand) -> SimpleOperand {
    match op {
        ArchOperand::X86Operand(o) => match o.op_type {
            X86OperandType::Mem(m) => {
                // 解析内存操作数引用的真实地址
                SimpleOperand::Mem(m.into())
            }
            X86OperandType::Imm(i) => SimpleOperand::Imm(i as usize),
            X86OperandType::Reg(r) => SimpleOperand::Reg(r),
            _ => SimpleOperand::None,
        }
        ArchOperand::ArmOperand(o) => match o.op_type {
            // ArmOperandType::Mem(m) => {
            //     // 解析内存操作数引用的真实地址
            //     let disp = m.disp() as usize;
            //     // println!("disp {:x}", disp);
            //     if m.base() == RegId(X86_REG_RIP as RegIdInt) {
            //         let addr = dis.address() as usize + dis.bytes().len() + disp;
            //         self.read_value::<usize>(addr).unwrap_or(0)
            //     } else { 0 }
            // }
            ArmOperandType::Imm(i) => SimpleOperand::Imm(i as usize),
            ArmOperandType::Reg(r) => SimpleOperand::Reg(r),
            _ => SimpleOperand::None,
        }
        ArchOperand::Arm64Operand(o) => match o.op_type {
            Arm64OperandType::Imm(i) => SimpleOperand::Imm(i as usize),
            Arm64OperandType::Reg(r) => SimpleOperand::Reg(r),
            _ => SimpleOperand::None,
        }
        _ => SimpleOperand::None,
    }
}

pub trait CsUtil {
    fn get_absolute_address(&self, dis: &Insn, i_operand: usize) -> SimpleOperand;
}

impl CsUtil for Capstone {
    fn get_absolute_address(&self, dis: &Insn, i_operand: usize) -> SimpleOperand {
        self.insn_detail(dis).ok().and_then(|d| Some(
            simplify_operand(dis, d.arch_detail().operands().get(i_operand)?)
        )).unwrap_or(SimpleOperand::None)
    }
}

pub fn create_thumb_cs() -> Capstone {
    // https://docs.rs/capstone/0.6.0/capstone/arch/arm/enum.ArchMode.html
    let mut result = Capstone::new().arm()
        .mode(arch::arm::ArchMode::Thumb)
        .syntax(arch::arm::ArchSyntax::NoRegName)
        .detail(true).build()
        .expect("Failed to create Capstone object");
    result.set_skipdata(true);
    result
}

pub fn create_arm() -> Capstone {
    // https://docs.rs/capstone/0.6.0/capstone/arch/arm/enum.ArchMode.html
    let mut result = Capstone::new().arm()
        .mode(arch::arm::ArchMode::Arm)
        .syntax(arch::arm::ArchSyntax::NoRegName)
        .detail(true).build()
        .expect("Failed to create Capstone object");
    result.set_skipdata(true);
    result
}

pub fn create_arm64() -> Capstone {
    // https://docs.rs/capstone/0.6.0/capstone/arch/arm/enum.ArchMode.html
    let mut result = Capstone::new().arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true).build()
        .expect("Failed to create Capstone object");
    result.set_skipdata(true);
    result
}

pub fn create_x86() -> Capstone {
    let mut result = Capstone::new().x86()
        .mode(arch::x86::ArchMode::Mode32)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true).build()
        .expect("Failed to create Capstone object");
    result.set_skipdata(true);
    result
}

pub fn create_x64() -> Capstone {
    let mut result = Capstone::new().x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true).build()
        .expect("Failed to create Capstone object");
    result.set_skipdata(true);
    return result;
}

#[cfg(target_arch = "x86")]
pub use create_x86 as create_cs;
#[cfg(target_arch = "x86_64")]
pub use create_x64 as create_cs;
#[cfg(target_arch = "arm")]
pub use create_arm as create_cs;
#[cfg(target_arch = "aarch64")]
pub use create_arm64 as create_cs;