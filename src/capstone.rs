//! Capstone's utilities for udbg

use crate::prelude::*;

use capstone::arch::{
    arm::ArmOperandType, arm64::Arm64OperandType, x86::X86OpMem, x86::X86OperandType, ArchOperand,
};
use capstone::prelude::*;
use capstone::{Insn, Instructions};
use std::lazy::SyncLazy;

cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        const MIN_INSN_SIZE: usize = 16;
    } else {
        const MIN_INSN_SIZE: usize = 4;
    }
}

pub struct CachedCapstone {
    pub x86: Capstone,
    pub x64: Capstone,
    pub arm: Capstone,
    pub arm64: Capstone,
}

unsafe impl Send for CachedCapstone {}
unsafe impl Sync for CachedCapstone {}

pub static CS: SyncLazy<CachedCapstone> = SyncLazy::new(|| {
    let mut arm = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .syntax(arch::arm::ArchSyntax::NoRegName)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");
    arm.set_skipdata(true);

    let mut arm64 = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");
    arm64.set_skipdata(true);

    let mut x86 = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode32)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");
    x86.set_skipdata(true);

    let mut x64 = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");
    x64.set_skipdata(true);

    CachedCapstone {
        x86,
        x64,
        arm,
        arm64,
    }
});

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
    pub fn absolute_address(&self, i: &Insn) -> Option<usize> {
        use capstone::arch::x86::X86Reg::*;

        if self.base_reg as u32 == X86_REG_RIP {
            Some((i.address() as i64 + i.bytes().len() as i64 + self.disp) as usize)
        } else if self.base_reg == 0 {
            Some(self.disp as usize)
        } else {
            None
        }
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
        },
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
        },
        ArchOperand::Arm64Operand(o) => match o.op_type {
            Arm64OperandType::Imm(i) => SimpleOperand::Imm(i as usize),
            Arm64OperandType::Reg(r) => SimpleOperand::Reg(r),
            _ => SimpleOperand::None,
        },
        _ => SimpleOperand::None,
    }
}

#[extend::ext(pub)]
impl Capstone {
    fn get_absolute_address(&self, dis: &Insn, i_operand: usize) -> SimpleOperand {
        self.insn_detail(dis)
            .ok()
            .and_then(|d| {
                Some(simplify_operand(
                    dis,
                    d.arch_detail().operands().get(i_operand)?,
                ))
            })
            .unwrap_or(SimpleOperand::None)
    }
}

impl dyn UDbgTarget {
    pub fn operand_symbol_string(&self, i: &Insn, o: &SimpleOperand) -> Option<String> {
        let get_symbol_string = <dyn UDbgTarget as TargetUtil>::get_symbol_string;

        match o {
            SimpleOperand::Mem(m) => {
                let addr = m.absolute_address(i)?;
                let a = self.read_ptr(addr);
                match a
                    .and_then(|a| get_symbol_string(self, a))
                    .map(|s| format!("&{}", s))
                {
                    Some(s) => Some(s),
                    None => get_symbol_string(self, addr),
                }
            }
            SimpleOperand::Imm(a) => get_symbol_string(self, *a),
            _ => None,
        }
    }

    pub fn operand_detail_string(&self, i: &Insn, o: &SimpleOperand) -> String {
        use SimpleOperand::*;
        match *o {
            Mem(m) => m
                .absolute_address(i)
                .map(|a| {
                    let mut s = format!("[{:x}]", a);
                    if let Some(sym) = self.operand_symbol_string(i, &o) {
                        s.push_str(" => [");
                        s.push_str(&sym);
                        s.push_str("]");
                    }
                    s
                })
                .unwrap_or_default(),
            Imm(a) => {
                let mut s = format!("{:x}", a);
                if let Some(sym) = self.operand_symbol_string(i, &o) {
                    s.push_str(" => ");
                    s.push_str(&sym);
                }
                s
            }
            Reg(r) => self.select_cs(0).reg_name(r).expect("register name"),
            _ => String::new(),
        }
    }

    pub fn select_cs(&self, address: usize) -> &Capstone {
        // if IS_ARM && address & 1 > 0 { return &self.thumb; }
        let cs = &CS;
        match self.base().context_arch.get() {
            ARCH_ARM => &cs.arm,
            ARCH_ARM64 => &cs.arm64,
            ARCH_X86 => &cs.x86,
            ARCH_X64 => &cs.x64,
            _ => unreachable!(),
        }
    }

    pub fn disasm<'a>(
        &self,
        cs: &'a Capstone,
        address: usize,
    ) -> Result<Instructions<'a>, Vec<u8>> {
        let mut buf = vec![0u8; MIN_INSN_SIZE];

        let b = self.read_memory(address, &mut buf).ok_or(vec![])?;
        if b.len() > 0 {
            self.get_bp_by_address(address).and_then(|bp| {
                bp.origin_bytes().map(|o| {
                    if b.len() >= o.len() {
                        (&mut b[..o.len()]).copy_from_slice(o);
                    }
                })
            });
            cs.disasm_count(b, address as u64, 1)
                .map_err(|_| b.to_vec())
        } else {
            Err(vec![])
        }
    }
}
