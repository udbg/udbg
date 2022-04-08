use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use libc::*;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::{sys::ptrace, unistd::Pid};

use crate::os::CommonAdaptor;
use crate::{
    os::{self, pid_t, tid_t, StandardAdaptor, WAIT_PID_FLAG},
    prelude::*,
};

impl StandardAdaptor {
    pub fn create(path: &str, args: &[&str]) -> UDbgResult<Arc<Self>> {
        unsafe {
            match libc::fork() {
                0 => {
                    use std::ffi::CString;
                    ptrace::traceme();
                    let path = CString::new(path).unwrap();
                    let args = args
                        .iter()
                        .map(|&arg| CString::new(arg).unwrap())
                        .collect::<Vec<_>>();
                    let mut argv = args.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
                    argv.insert(0, path.as_ptr());
                    argv.push(core::ptr::null());
                    libc::execvp(path.as_ptr().cast(), argv.as_ptr());
                    unreachable!();
                }
                -1 => Err(UDbgError::system()),
                pid => {
                    waitpid(None, Some(WAIT_PID_FLAG())).context("waitpid")?;
                    let ps = Process::from_pid(pid)?;
                    let this = Self(CommonAdaptor::new(ps));
                    this.base().status.set(UDbgStatus::Attached);
                    this.insert_thread(pid);
                    Ok(Arc::new(this))
                }
            }
        }
    }
}

pub struct TraceBuf<'a> {
    pub callback: *mut UDbgCallback<'a>,
    pub target: Arc<StandardAdaptor>,
    pub user: libc::user,
    pub regs_dirty: bool,
}

impl TraceBuf<'_> {
    #[inline]
    pub fn call(&mut self, event: UEvent) -> UserReply {
        unsafe { (self.callback.as_mut().unwrap())(self, event) }
    }

    pub fn update_regs(&mut self, tid: pid_t) {
        ptrace::getregs(Pid::from_raw(tid))
            .log_error("getregs")
            .map(|regs| {
                self.user.regs = regs;
                self.regs_dirty = true;
            });
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
    fn register(&mut self) -> Option<&mut dyn UDbgRegs> {
        Some(&mut self.user.regs)
    }

    fn target(&self) -> Arc<dyn UDbgAdaptor> {
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

pub struct DefaultEngine {
    targets: Vec<Arc<StandardAdaptor>>,
    status: WaitStatus,
    inited: bool,
    cloned_tids: HashSet<tid_t>,
    tid: tid_t,
}

impl Default for DefaultEngine {
    fn default() -> Self {
        Self {
            targets: Default::default(),
            status: WaitStatus::StillAlive,
            inited: false,
            tid: 0,
            cloned_tids: Default::default(),
        }
    }
}

impl EventHandler for DefaultEngine {
    fn fetch(&mut self, buf: &mut TraceBuf) -> Option<()> {
        self.status = waitpid(None, Some(WAIT_PID_FLAG())).ok()?;
        info!("[status] {:?}", self.status);

        self.tid = self
            .status
            .pid()
            .map(|p| p.as_raw() as tid_t)
            .unwrap_or_default();

        let target = self
            .targets
            .iter()
            .find(|&t| self.tid == t.pid() as tid_t || t.threads.read().contains(&self.tid))
            .cloned();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            buf.target = target
                .or_else(|| {
                    self.targets
                        .iter()
                        .find(|&t| procfs::process::Task::new(t.process.pid, self.tid).is_ok())
                        .cloned()
                })
                .expect("not traced target");
        }
        #[cfg(any(target_os = "macos"))]
        {
            buf.target = target.expect("not traced target");
        }

        buf.target.base.event_tid.set(self.tid as _);
        Some(())
    }

    fn handle(&mut self, buf: &mut TraceBuf) -> Option<HandleResult> {
        let status = self.status.clone();
        let this = buf.target.clone();
        let tid = self.tid;

        Some(match status {
            WaitStatus::Stopped(_, sig) => loop {
                buf.update_regs(tid);
                match sig {
                    // maybe thread created (by ptrace_attach or ptrace_interrupt) (in PTRACE_EVENT_CLONE)
                    // maybe kill by SIGSTOP
                    Signal::SIGSTOP => {
                        if matches!(
                            this.base().status.get(),
                            UDbgStatus::Idle | UDbgStatus::Opened
                        ) {
                            this.base().status.set(UDbgStatus::Attached);
                        }
                        if this.threads.read().get(&tid).is_none() {
                            buf.call(UEvent::ThreadCreate(tid));
                            this.insert_thread(tid);
                            break None;
                        }
                        if self.cloned_tids.remove(&tid) {
                            buf.call(UEvent::ThreadCreate(tid));
                            break None;
                        }
                    }
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Signal::SIGTRAP | Signal::SIGILL => {
                        let si = ptrace::getsiginfo(Pid::from_raw(tid)).expect("siginfo");
                        if this
                            .handle_breakpoint(this.as_ref(), self, buf, &si)
                            .log_error("handle trap")
                            .is_some()
                        {
                            break None;
                        }
                    }
                    _ => {}
                }
                buf.call(UEvent::Exception {
                    first: true,
                    code: sig as _,
                });
                break Some(sig);
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            WaitStatus::PtraceEvent(_, sig, code) => {
                match code {
                    PTRACE_EVENT_STOP => {
                        this.insert_thread(tid);
                    }
                    PTRACE_EVENT_CLONE => {
                        let mut new_tid: tid_t = 0;
                        os::ptrace_getevtmsg(tid, &mut new_tid);
                        buf.call(UEvent::ThreadCreate(new_tid));
                        // trace new thread
                        ptrace::attach(Pid::from_raw(new_tid));
                        // set trace options for new thread
                        this.insert_thread(new_tid);

                        self.cloned_tids.insert(new_tid);
                    }
                    PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK => {
                        let mut new_pid: pid_t = 0;
                        os::ptrace_getevtmsg(tid, &mut new_pid);
                        StandardAdaptor::open(new_pid)
                            .log_error("open child")
                            .map(|t| self.targets.push(t));
                    }
                    PTRACE_EVENT_EXEC => {
                        buf.call(UEvent::ProcessCreate);
                    }
                    _ => {}
                }
                None
            }
            // exited with exception
            WaitStatus::Signaled(_, sig, coredump) => {
                buf.call(UEvent::Exception {
                    first: false,
                    code: sig as _,
                });
                if !matches!(sig, Signal::SIGSTOP) {
                    this.remove_thread(tid, -1, buf);
                }
                Some(sig)
            }
            // exited normally
            WaitStatus::Exited(_, code) => {
                this.remove_thread(tid, code, buf);
                if this.threads.read().is_empty() {
                    self.targets.retain(|t| !Arc::ptr_eq(t, &this));
                }
                if self.targets.is_empty() {
                    return None;
                }
                None
            }
            _ => unreachable!("status: {status:?}"),
        })
    }

    fn cont(&mut self, sig: HandleResult, buf: &mut TraceBuf) {
        let this = buf.target.clone();
        if this.detaching.get() {
            for bp in this.get_breakpoints() {
                bp.remove();
            }
            for &tid in this.threads.read().iter() {
                if let Err(err) = ptrace::detach(Pid::from_raw(tid as _), None) {
                    udbg_ui().error(format!("ptrace_detach({tid}) failed: {err:?}"));
                }
            }
        }
        let tid = Pid::from_raw(self.tid as _);
        if buf.regs_dirty {
            buf.regs_dirty = false;
            ptrace::setregs(tid, buf.user.regs);
        }
        ptrace::cont(tid, sig);
    }
}

impl UDbgEngine for DefaultEngine {
    fn open(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(StandardAdaptor::open(pid)?)
    }

    #[cfg(target_os = "linux")]
    fn attach(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        let this = StandardAdaptor::open(pid)?;
        // attach each of threads
        for tid in this.process.enum_thread() {
            ptrace::attach(Pid::from_raw(tid)).context("attach")?;
            // this.threads.write().insert(tid);
            this.insert_thread(tid);
        }
        self.targets.push(this.clone());
        Ok(this)
    }

    #[cfg(target_os = "macos")]
    fn attach(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Err(UDbgError::NotSupport)
    }

    fn create(
        &mut self,
        path: &str,
        cwd: Option<&str>,
        args: &[&str],
    ) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        let result = StandardAdaptor::create(path, args)?;
        self.targets.push(result.clone());
        self.tid = result.pid();
        Ok(result)
    }

    fn event_loop<'a>(&mut self, callback: &mut UDbgCallback<'a>) -> UDbgResult<()> {
        #[cfg(target_os = "linux")]
        self.targets.iter().for_each(|t| {
            t.update_module();
            t.update_memory_page();
        });

        let mut buf = TraceBuf {
            callback,
            user: unsafe { core::mem::zeroed() },
            regs_dirty: false,
            target: self
                .targets
                .iter()
                .next()
                .map(Clone::clone)
                .expect("no attached target"),
        };

        buf.call(UEvent::InitBp);
        self.cont(None, &mut buf);

        while let Some(s) = self.fetch(&mut buf).and_then(|_| self.handle(&mut buf)) {
            self.cont(s, &mut buf);
        }

        Ok(())
    }
}
