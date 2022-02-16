
use text_io::scan;
use super::pid_t;
use crate::text::*;
use alloc::string::String;

#[derive(Clone, Default)]
pub struct ThreadStat {
    pub tid: pid_t,
    pub name: String,
    pub state: char,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub tpgid: i32,
    pub flags: u32,
    pub minflt: u64,
    pub cminflt: u64,
    pub majflt: u64,
    pub cmajflt: u64,
    pub utime: u64,
    pub stime: u64,
    pub cutime: u64,
    pub cstime: u64,
    pub priority: i64,
    pub nice: i64,
    pub num_threads: u64,
    pub itrealvalue: u64,
    pub starttime: u64,
    pub vsize: u64,
    pub rss: u64,
    pub rsslim: u64,
    pub startcode: u64,
    pub endcode: u64,
    pub startstack: u64,
    pub kstkesp: u64,
    pub kstkeip: u64,
    pub signal: u64,
    pub blocked: u64,
    pub sigignore: u64,
    pub sigcatch: u64,
    pub wchan: u64,
    pub nswap: u64,
    pub cnswap: u64,
    pub exit_signal: i64,
    pub processor: u64,
    pub rt_priority: u64,
    pub policy: u64,
}

impl ThreadStat {
    pub fn from(pid: pid_t, tid: pid_t) -> Option<Self> {
        let line = read_lines(format!("/proc/{}/task/{}/stat", pid, tid)).ok()?.next()?;
        let mut result = Self::default();
        scan!(line.bytes() => "{} ({}) {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            result.tid, result.name, result.state, result.ppid, result.pgrp, result.session,
            result.tty_nr, result.tpgid, result.flags, result.minflt, result.cminflt, result.majflt,
            result.cmajflt, result.utime, result.stime, result.cutime, result.cstime, result.priority,
            result.nice, result.num_threads, result.itrealvalue, result.starttime, result.vsize,
            result.rss, result.rsslim, result.startcode, result.endcode, result.startstack, result.kstkesp,
            result.kstkeip, result.signal, result.blocked, result.sigignore, result.sigcatch, result.wchan,
            result.nswap, result.cnswap, result.exit_signal, result.processor, result.rt_priority, result.policy
        );
        Some(result)
    }

    pub fn state(&self) -> String {
        match self.state {
            'R' => format!("{} (Running)", self.state),
            'S' => format!("{} (Sleeping)", self.state),
            'D' => format!("{} (Disk Sleep)", self.state),
            'T' => format!("{} (Stopped)", self.state),
            't' => format!("{} (Tracing Stop)", self.state),
            'Z' => format!("{} (Zombie)", self.state),
            'X' | 'x' => format!("{} (Dead)", self.state),
            'W' => format!("{} (Waking/Paging)", self.state),
            'K' => format!("{} (Wakekill)", self.state),
            'P' => format!("{} (Parked)", self.state),
            s => format!("[{}]", s),
        }
    }
}
