
use cfg_if::*;
use crate::tid_t;

pub type BpID = isize;

#[derive(Copy, Clone, Debug)]
pub enum HwbpType {
    Execute = 0,
    Write = 1,
    Access = 3,
}

#[derive(Copy, Clone, Debug)]
pub enum BpType {
    Soft,
    Table,
    Hwbp(HwbpType, u8),
}

impl ToString for BpType {
    fn to_string(&self) -> String {
        match self {
            Self::Soft => "soft".into(),
            Self::Table => "table".into(),
            Self::Hwbp(t, l) => {
                format!("hwbp:{}{}", match t {
                    HwbpType::Execute => "e",
                    HwbpType::Write => "w",
                    HwbpType::Access => "a",
                }, ["1", "2", "8", "4"][*l as usize])
            }
        }
    }
}

impl Into<u8> for HwbpType {
    fn into(self) -> u8 {
        match self {
            HwbpType::Execute => 0,
            HwbpType::Write => 1,
            HwbpType::Access => 3,
        }
    }
}

impl From<u8> for HwbpType {
    fn from(b: u8) -> Self {
        match b {
            0 => HwbpType::Execute,
            1 => HwbpType::Write,
            3 => HwbpType::Access,
            _ => unreachable!(),
        }
    }
}

impl Into<u8> for HwbpLen { fn into(self) -> u8 { self as u8 } }

#[derive(Copy, Clone)]
pub enum HwbpLen {
    L1 = 0,
    L2 = 1,
    L4 = 3,
    L8 = 2,
}

impl HwbpLen {
    pub fn to_int(self) -> u32 {
        match self {
            Self::L1 => 1,
            Self::L2 => 2,
            Self::L4 => 4,
            Self::L8 => 8,
        }
    }
}

pub struct BpOpt {
    pub address: usize,
    pub rw: Option<HwbpType>,
    pub len: Option<HwbpLen>,
    pub table: bool,                // table type bp
    pub temp: bool,
    pub enable: bool,
    pub tid: Option<tid_t>,
}

impl BpOpt {
    pub fn int3(address: usize) -> Self {
        Self { address, temp: false, enable: true, tid: None, rw: None, len: None, table: false }
    }

    pub fn temp(mut self, b: bool) -> Self {
        self.temp = b; self
    }

    pub fn enable(mut self, b: bool) -> Self {
        self.enable = b; self
    }

    pub fn thread(mut self, tid: tid_t) -> Self {
        self.tid = Some(tid); self
    }
}

#[derive(Clone, Copy)]
pub struct HwbpInfo {
    pub rw: u8,
    pub len: u8,
    pub index: u8
}

cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[derive(Copy, Clone)]
        pub enum InnerBpType {
            Soft(BpInsn),
            Hard(HwbpInfo),
            Table {index: isize, origin: usize},
        }
        pub type BpInsn = [u8; 1];
        pub const BP_INSN: BpInsn = [0xCC];
    } else if #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
        #[derive(Copy, Clone)]
        pub enum InnerBpType {
            Soft(BpInsn),
            Hard(HwbpInfo),
            Table {index: isize, origin: usize},
        }
        pub type BpInsn = [u8; 4];
        pub const BP_INSN: BpInsn = [0xF0, 0x01, 0xF0, 0xE7];
    }
}