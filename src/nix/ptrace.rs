
use libc::*;
use nix::{sys::wait::{WaitStatus, WaitPidFlag}, unistd::Pid};

pub fn waitpid(tid: pid_t, opt: c_int) -> Option<(pid_t, c_int)> {
    let mut status: c_int = 0;
    unsafe {
        // http://man7.org/linux/man-pages/man2/waitpid.2.html
        let tid = libc::waitpid(tid, &mut status, opt);
        if tid < 0 { None } else { Some((tid, status)) }
    }
}

pub fn ptrace_step(pid: pid_t) -> bool {
    unsafe { ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == 0 }
}

pub fn ptrace_cont(pid: pid_t, sig: c_int) -> bool {
    unsafe { ptrace(PTRACE_CONT, pid, 0, sig) == 0 }
}

pub fn ptrace_attach(tid: pid_t) -> bool {
    unsafe { ptrace(PTRACE_ATTACH, tid, 0, 0) == 0 }
}

pub fn ptrace_attach_wait(tid: pid_t, opt: c_int) -> Option<(pid_t, WaitStatus)> {
    if !ptrace_attach(tid) { return None; }
    let status = nix::sys::wait::waitpid(Some(Pid::from_raw(tid)), Some(WaitPidFlag::from_bits_truncate(opt))).ok()?;
    Some((status.pid()?.as_raw(), status))
}

pub fn ptrace_detach(tid: pid_t) -> bool {
    unsafe { ptrace(PTRACE_DETACH, tid, 0, 0) == 0 }
}

pub fn ptrace_setopt(tid: pid_t, opt: i32) -> bool {
    unsafe { ptrace(PTRACE_SETOPTIONS, tid, 0, opt) != -1 }
}