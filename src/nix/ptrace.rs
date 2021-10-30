
use libc::*;

// https://docs.rs/nix/0.16.1/nix/sys/wait/enum.WaitStatus.html
#[derive(Copy, Clone, Debug)]
pub enum WaitStatus {
    Exit(c_int),
    Stop(c_int),
    Signal(c_int),
    Clone(pid_t),
    Exec,
    Continue,
}

pub fn waitpid(tid: pid_t, opt: c_int) -> Result<(pid_t, WaitStatus), ()> {
    let mut status: c_int = 0;
    unsafe {
        // http://man7.org/linux/man-pages/man2/waitpid.2.html
        let tid = libc::waitpid(tid, &mut status, opt);
        Ok(if WIFEXITED(status) {
            (tid, WaitStatus::Exit(WEXITSTATUS(status)))
        } else if WIFSIGNALED(status) {
            (tid, WaitStatus::Signal(WTERMSIG(status)))
        } else if WIFSTOPPED(status) {
            let extra = (status >> 16) & 0xffff;
            (tid, match extra {
                PTRACE_EVENT_CLONE => {
                    let new_tid: pid_t = 0;
                    if ptrace(PTRACE_GETEVENTMSG, tid, 0, &new_tid) < 0 {
                        // error!("PTRACE_GETEVENTMSG Failed");
                    }
                    WaitStatus::Clone(new_tid)
                }
                PTRACE_EVENT_EXEC => {
                    WaitStatus::Exec
                }
                _ => WaitStatus::Stop(WSTOPSIG(status)),
            })
        } else if WIFCONTINUED(status) {
            (tid, WaitStatus::Continue)
        } else { return Err(()); })
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

pub fn ptrace_attach_wait(tid: pid_t, opt: c_int) -> Result<(pid_t, WaitStatus), ()> {
    if !ptrace_attach(tid) { return Err(()); }
    waitpid(tid, opt)
}

pub fn ptrace_detach(tid: pid_t) -> bool {
    unsafe { ptrace(PTRACE_DETACH, tid, 0, 0) == 0 }
}

pub fn ptrace_setopt(tid: pid_t, opt: i32) -> bool {
    unsafe { ptrace(PTRACE_SETOPTIONS, tid, 0, opt) != -1 }
}