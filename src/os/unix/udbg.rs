use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use libc::*;
use nix::sys::ptrace;
use nix::sys::signal::Signal;

use crate::{
    os::{user_regs, StandardAdaptor},
    prelude::*,
};

pub struct TraceBuf<'a> {
    pub callback: *mut UDbgCallback<'a>,
    pub target: Arc<StandardAdaptor>,
    pub user: user_regs,
    pub regs_dirty: bool,
    pub si: siginfo_t,
}

impl TraceBuf<'_> {
    #[inline]
    pub fn call(&mut self, event: UEvent) -> UserReply {
        unsafe { (self.callback.as_mut().unwrap())(self, event) }
    }

    // pub fn set_regs(&self) -> UDbgResult<()> {
    //     ptrace::setregs(Pid::from_raw(self.base.event_tid.get()), unsafe {
    //         *self.regs.get()
    //     })
    //     .context("")?;
    //     Ok(())
    // }
}

impl TraceContext for TraceBuf<'_> {
    // #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    fn register(&mut self) -> Option<&mut dyn UDbgRegs> {
        Some(&mut self.user.regs)
    }

    // #[cfg(any(target_arch = "aarch64"))]
    // fn register(&mut self) -> Option<&mut dyn UDbgRegs> {
    //     Some(&mut self.user)
    // }

    fn target(&self) -> Arc<dyn UDbgTarget> {
        self.target.clone()
    }
}

pub type HandleResult = Option<Signal>;

pub trait EventHandler {
    /// fetch a debug event
    fn fetch(&mut self, buf: &mut TraceBuf) -> Option<()>;
    /// handle the debug event
    fn handle(&mut self, buf: &mut TraceBuf) -> Option<HandleResult>;
    /// continue debug event
    fn cont(&mut self, _: HandleResult, buf: &mut TraceBuf);
}
