//!
//! Breakpoint types
//!

use std::{
    cell::Cell,
    sync::{Arc, Weak},
};

use crate::{error::*, os::tid_t, register::*, target::UDbgAdaptor};
use cfg_if::*;

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

impl BpType {
    #[inline]
    pub fn is_hard(&self) -> bool {
        if let Self::Hwbp(_, _) = self {
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn is_soft(&self) -> bool {
        if let Self::Soft = self {
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn is_table(&self) -> bool {
        if let Self::Table = self {
            true
        } else {
            false
        }
    }
}

impl ToString for BpType {
    fn to_string(&self) -> String {
        match self {
            Self::Soft => "soft".into(),
            Self::Table => "table".into(),
            Self::Hwbp(t, l) => {
                format!(
                    "hwbp:{}{}",
                    match t {
                        HwbpType::Execute => "e",
                        HwbpType::Write => "w",
                        HwbpType::Access => "a",
                    },
                    ["1", "2", "8", "4"][*l as usize]
                )
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

impl Into<u8> for HwbpLen {
    fn into(self) -> u8 {
        self as u8
    }
}

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
    pub table: bool, // table type bp
    pub temp: bool,
    pub enable: bool,
    pub tid: Option<tid_t>,
}

impl From<usize> for BpOpt {
    fn from(address: usize) -> Self {
        Self::int3(address)
    }
}

impl From<(usize, HwbpType)> for BpOpt {
    fn from((address, ty): (usize, HwbpType)) -> Self {
        Self::hwbp(address, ty, None)
    }
}

impl BpOpt {
    pub fn int3(address: usize) -> Self {
        Self {
            address,
            temp: false,
            enable: true,
            tid: None,
            rw: None,
            len: None,
            table: false,
        }
    }

    pub fn hwbp(address: usize, ty: HwbpType, len: Option<HwbpLen>) -> Self {
        Self {
            address,
            temp: false,
            enable: true,
            tid: None,
            rw: ty.into(),
            len,
            table: false,
        }
    }

    pub fn temp(mut self, b: bool) -> Self {
        self.temp = b;
        self
    }

    pub fn enable(mut self, b: bool) -> Self {
        self.enable = b;
        self
    }

    pub fn thread(mut self, tid: tid_t) -> Self {
        self.tid = Some(tid);
        self
    }

    pub fn len(mut self, len: HwbpLen) -> Self {
        self.len = len.into();
        self
    }
}

#[derive(Clone, Copy)]
pub struct HwbpInfo {
    pub rw: u8,
    pub len: u8,
    pub index: u8,
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
        pub const BP_INSN: &BpInsn = &[0xCC];
    } else if #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
        #[derive(Copy, Clone)]
        pub enum InnerBpType {
            Soft(BpInsn),
            Hard(HwbpInfo),
            Table {index: isize, origin: usize},
        }
        pub type BpInsn = [u8; 4];
        pub const BP_INSN: &BpInsn = &[0x00, 0x00, 0x3E, 0xD4];
    }
}

pub trait UDbgBreakpoint {
    fn get_id(&self) -> BpID;
    fn address(&self) -> usize;
    fn enabled(&self) -> bool;
    fn get_type(&self) -> BpType;
    /// count of this breakpoint hitted
    fn hit_count(&self) -> usize;
    /// set count of the to be used,
    /// when hit_count() > this count, bp will be delete
    fn set_count(&self, count: usize);
    /// set the which can hit the bp. if tid == 0, all thread used
    fn set_hit_thread(&self, tid: tid_t);
    /// current tid setted by set_hit_thread()
    fn hit_tid(&self) -> tid_t;
    /// original bytes written by software breakpoint
    fn origin_bytes<'a>(&'a self) -> Option<&'a [u8]>;

    fn enable(&self, enable: bool) -> UDbgResult<()>;
    fn remove(&self) -> UDbgResult<()>;
}

#[derive(Clone)]
pub struct Breakpoint {
    pub address: usize,
    pub enabled: Cell<bool>,
    pub temp: Cell<bool>,
    pub bp_type: InnerBpType,
    pub hit_count: Cell<usize>,
    pub hit_tid: Option<tid_t>,

    pub target: Weak<dyn UDbgAdaptor>,
    pub common: *const crate::os::CommonAdaptor,
}

impl Breakpoint {
    pub fn get_hwbp_len(&self) -> Option<usize> {
        if let InnerBpType::Hard(info) = self.bp_type {
            Some(match info.len as reg_t {
                LEN_1 => 1,
                LEN_2 => 2,
                LEN_4 => 4,
                LEN_8 => 8,
                _ => 0,
            })
        } else {
            None
        }
    }

    #[inline]
    pub fn is_hard(&self) -> bool {
        self.get_type().is_hard()
    }

    #[inline]
    pub fn is_soft(&self) -> bool {
        self.get_type().is_soft()
    }

    #[inline]
    pub fn is_table(&self) -> bool {
        self.get_type().is_table()
    }

    #[inline]
    pub fn hard_index(&self) -> Option<usize> {
        if let InnerBpType::Hard(info) = self.bp_type {
            Some(info.index as usize)
        } else {
            None
        }
    }
}

impl UDbgBreakpoint for Breakpoint {
    fn get_id(&self) -> BpID {
        self.address as BpID
    }
    fn address(&self) -> usize {
        self.address
    }
    fn enabled(&self) -> bool {
        self.enabled.get()
    }
    fn get_type(&self) -> BpType {
        match self.bp_type {
            InnerBpType::Soft { .. } => BpType::Soft,
            InnerBpType::Table { .. } => BpType::Table,
            InnerBpType::Hard(info) => BpType::Hwbp(info.rw.into(), info.len),
        }
    }
    /// count of this breakpoint hitted
    fn hit_count(&self) -> usize {
        self.hit_count.get()
    }
    /// set count of the to be used,
    /// when hit_count() > this count, bp will be delete
    fn set_count(&self, count: usize) {}
    /// set the which can hit the bp. if tid == 0, all thread used
    fn set_hit_thread(&self, tid: tid_t) {}
    /// current tid setted by set_hit_thread()
    fn hit_tid(&self) -> tid_t {
        0
    }

    fn origin_bytes<'a>(&'a self) -> Option<&'a [u8]> {
        if let InnerBpType::Soft(raw) = &self.bp_type {
            Some(raw)
        } else {
            None
        }
    }

    fn enable(&self, enable: bool) -> UDbgResult<()> {
        let t = self.target.upgrade().ok_or(UDbgError::NoTarget)?;
        unsafe {
            let common = self.common.as_ref().unwrap();
            common.enable_breadpoint(t.as_ref(), self, enable)?;
            Ok(())
        }
    }

    fn remove(&self) -> UDbgResult<()> {
        let t = self.target.upgrade().ok_or(UDbgError::NoTarget)?;
        unsafe {
            let common = self.common.as_ref().unwrap();
            self.enable(false);
            common.remove_breakpoint(t.as_ref(), self);
            Ok(())
        }
    }
}

pub trait BreakpointManager {
    fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<dyn UDbgBreakpoint>> {
        Err(UDbgError::NotSupport)
    }
    fn get_bp(&self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + '_>> {
        None
    }
    fn get_bp_by_address(&self, a: usize) -> Option<Arc<dyn UDbgBreakpoint + '_>> {
        self.get_bp(a as BpID)
    }
    fn get_bp_list(&self) -> Vec<BpID> {
        vec![]
    }
    fn get_breakpoints(&self) -> Vec<Arc<dyn UDbgBreakpoint + '_>> {
        self.get_bp_list()
            .into_iter()
            .filter_map(|id| self.get_bp(id))
            .collect()
    }
}
