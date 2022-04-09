//! OS-specific functionality

use std::{cell::Cell, sync::Arc};

use crate::prelude::*;

cfg_if! {
    if #[cfg(any(target_os="linux", target_os="android"))] {
        pub mod linux;
        pub use self::linux::*;
    }
}

cfg_if! {
    if #[cfg(target_os="macos")] {
        pub mod macos;
        pub use self::macos::*;
    }
}

cfg_if! {
    if #[cfg(windows)] {
        pub mod windows;
        pub type pid_t = u32;
        pub use self::windows::{WinModule as OsModule, *};
    } else {
        pub mod unix;
        pub type pid_t = libc::pid_t;
        pub use self::unix::{NixModule as OsModule, *};
    }
}

cfg_if! {
    if #[cfg(target_os="macos")] {
        pub type tid_t = u64;
    } else {
        pub type tid_t = pid_t;
    }
}

impl CommonAdaptor {
    pub fn add_int3_bp(&self, this: &dyn UDbgAdaptor, opt: &BpOpt) -> UDbgResult<Arc<Breakpoint>> {
        // int3 breakpoint
        if let Some(raw_byte) = this.read_value::<BpInsn>(opt.address) {
            let bp = Arc::new(Breakpoint {
                address: opt.address,
                enabled: Cell::new(false),
                temp: Cell::new(opt.temp),
                hit_tid: opt.tid,
                hit_count: Cell::new(0),
                bp_type: InnerBpType::Soft(raw_byte),

                target: unsafe { Utils::to_weak(this) },
                common: self,
            });
            if opt.enable {
                self.enable_breadpoint(this, &bp, true)?;
            }
            self.bp_map.write().insert(bp.get_id(), bp.clone());
            Ok(bp)
        } else {
            Err(UDbgError::InvalidAddress)
        }
    }

    pub fn add_bp(&self, this: &dyn UDbgAdaptor, opt: &BpOpt) -> UDbgResult<Arc<Breakpoint>> {
        self.base.check_opened()?;
        if self.bp_exists(opt.address as BpID) {
            return Err(UDbgError::BpExists);
        }

        let bp = if let Some(rw) = opt.rw {
            // hardware breakpoint
            if let Some(index) = self.get_hwbp_index() {
                let bp = Arc::new(Breakpoint {
                    address: opt.address,
                    enabled: Cell::new(false),
                    temp: Cell::new(opt.temp),
                    hit_count: Cell::new(0),
                    hit_tid: opt.tid,
                    bp_type: InnerBpType::Hard(HwbpInfo {
                        rw: rw.into(),
                        index: index as u8,
                        len: opt.len.unwrap_or(HwbpLen::L1).into(),
                    }),

                    target: unsafe { Utils::to_weak(this) },
                    common: self,
                });
                self.set_hwbp(index, opt.address);
                // hardware breakpoint
                self.bp_map.write().insert(-(index as BpID + 1), bp.clone());
                Ok(bp)
            } else {
                Err(UDbgError::HWBPSlotMiss)
            }
        } else if opt.table {
            // table breakpoint
            let origin = this.read_ptr(opt.address).ok_or("read origin failed")?;
            let index = self.find_table_bp_index().ok_or("no more table index")?;
            let bp = Arc::new(Breakpoint {
                address: opt.address,
                enabled: Cell::new(false),
                temp: Cell::new(opt.temp),
                hit_count: Cell::new(0),
                hit_tid: opt.tid,
                bp_type: InnerBpType::Table { index, origin },

                target: unsafe { Utils::to_weak(this) },
                common: self,
            });
            self.bp_map.write().insert(index, bp.clone());
            Ok(bp)
        } else {
            self.add_int3_bp(this, opt)
        }?;
        let bpid = bp.get_id();
        self.bp_map.write().insert(bpid, bp.clone());

        if opt.enable {
            self.enable_breadpoint(this, &bp, true)
                .log_error("enable bp falied");
        }
        Ok(bp)
    }

    pub fn enable_breadpoint(
        &self,
        dbg: &dyn UDbgAdaptor,
        bp: &Breakpoint,
        enable: bool,
    ) -> UDbgResult<bool> {
        match bp.bp_type {
            InnerBpType::Soft(raw_byte) => {
                let written = if enable {
                    dbg.write_memory(bp.address, &[0xCC])
                } else {
                    dbg.write_memory(bp.address, &raw_byte)
                }
                .unwrap_or_default();
                // println!("enable softbp @{:x} {} {:?}", bp.address, enable, written);
                if written > 0 {
                    dbg.flush_cache(bp.address, written)?;
                    bp.enabled.set(enable);
                    Ok(enable)
                } else {
                    Err(UDbgError::MemoryError)
                }
            }
            InnerBpType::Table { index, origin } => {
                let r = if enable {
                    dbg.write_ptr(bp.address, index as usize)
                } else {
                    dbg.write_ptr(bp.address, origin)
                };
                if r.is_some() {
                    bp.enabled.set(enable);
                    Ok(enable)
                } else {
                    Err(UDbgError::MemoryError)
                }
            }
            InnerBpType::Hard(info) => self.enable_hwbp(dbg, bp, info, enable),
        }
    }

    pub fn enable_bp(
        &self,
        dbg: &dyn UDbgAdaptor,
        id: BpID,
        enable: bool,
    ) -> Result<bool, UDbgError> {
        if let Some(bp) = self.bp_map.read().get(&id) {
            self.enable_breadpoint(dbg, bp, enable)
        } else {
            Err(UDbgError::NotFound)
        }
    }

    pub fn remove_breakpoint(&self, this: &dyn UDbgAdaptor, bp: &Breakpoint) {
        let mut hard_id = 0;
        let mut table_index = None;
        self.enable_breadpoint(this, &bp, false)
            .log_error("disable bp falied");
        if self.bp_map.write().remove(&bp.get_id()).is_some() {
            match bp.bp_type {
                InnerBpType::Hard(info) => {
                    self.set_hwbp(info.index as usize, 0);
                    hard_id = -(info.index as BpID + 1);
                }
                InnerBpType::Table { index, .. } => {
                    table_index = Some(index);
                }
                _ => {}
            }
        }
        // delete hardware breakpoint
        if hard_id < 0 {
            self.bp_map.write().remove(&hard_id);
        }
        // delete table breakpoint
        table_index.map(|i| self.bp_map.write().remove(&i));
    }
}

impl<T> BreakpointManager for T
where
    T: core::ops::Deref<Target = CommonAdaptor> + UDbgAdaptor,
{
    default fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<dyn UDbgBreakpoint>> {
        Ok(self.deref().add_bp(self, &opt)?)
    }

    default fn get_bp(&self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + '_>> {
        Some(self.deref().bp_map.read().get(&id)?.clone())
    }

    default fn get_bp_list(&self) -> Vec<BpID> {
        self.deref().get_bp_list()
    }
}
