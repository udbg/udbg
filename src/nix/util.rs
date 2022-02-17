
use std::fs;
use std::ffi::*;

use crate::elf;
use crate::nix::*;

pub fn is_selinux_enabled() -> bool {
    unsafe {
        String::from_utf8_unchecked(fs::read("/proc/filesystems").unwrap()).find("selinuxfs").is_some()
    }
}

pub fn disable_selinux() -> bool {
    let mut se_dir = String::new();
    for line in read_lines("/proc/mounts").unwrap() {
        let line = line.split(' ').collect::<Vec<_>>();
        if line.get(0) == Some(&"selinuxfs") {
            se_dir = line[1].to_string();
        }
    }
    if se_dir.is_empty() { return false; }

    fs::write(format!("{}/enforce", se_dir), b"0").is_ok()
}

#[derive(Debug)]
pub enum InjectError {
    LibNotFound(&'static str),
    FuncNotFound(&'static str),
    DlOpenFailed(String),
    MmapFailed,
    DisableSeLinux,
    AttachFailed,
    WriteFailed,
    Else(String),
}

impl From<String> for InjectError {
    #[inline(always)]
    fn from(s: String) -> Self {
        Self::Else(s)
    }
}

pub fn ptrace_inject(p: &Process, libpath: &str) -> Result<(), InjectError> {
    use InjectError::*;

    if is_selinux_enabled() && !disable_selinux() {
        return Err(DisableSeLinux);
    }

    let m = p.enum_module()?.find(|m| m.name.as_ref() == "libc.so").ok_or(LibNotFound("libc.so"))?;
    let map = mapfile(m.path.as_ref()).unwrap();
    let e = elf::parse(&map).unwrap();
    let mmap = m.base + e.get_export("mmap").ok_or(FuncNotFound("mmap"))?.offset();

    let m = p.enum_module()?.find(|m| m.name.as_ref() == "libdl.so").ok_or(LibNotFound("libdl.so"))?;
    let data = fs::read(m.path.as_ref()).unwrap();
    let e = elf::parse(&data).unwrap();
    let dlopen = m.base + e.get_export("dlopen").ok_or(FuncNotFound("dlopen"))?.offset();

    ptrace_attach_wait(p.pid, WUNTRACED).ok_or(AttachFailed)?;
    let result = (|| {
        let libpath = fs::canonicalize(libpath).unwrap();
        let libpath = libpath.to_str().unwrap();
        let mut libpath = libpath.as_bytes().to_vec();
        libpath.push(0);
        let buf = call_remote(p.pid, mmap, 0, &[
            0, libpath.len() as reg_t, (PROT_READ | PROT_WRITE) as reg_t, (MAP_PRIVATE | MAP_ANONYMOUS) as reg_t, 0, 0
        ]) as i64;
        if buf <= 0 { return Err(MmapFailed); }
        ptrace_write(p.pid, buf as usize, &libpath);

        let vndk = p.enum_module()?.find(|m| m.name.as_ref() == "libRS.so").ok_or(LibNotFound("libRS.so"))?.base;
        let h = call_remote(p.pid, dlopen, vndk, &[buf as reg_t, (RTLD_NOW | RTLD_LOCAL) as reg_t]);
        if h == 0 {
            let dlerror = m.base + e.get_export("dlerror").ok_or(FuncNotFound("dlerror"))?.offset();
            let err = call_remote(p.pid, dlerror, 0, &[]);
            return Err(DlOpenFailed(p.read_utf8(err as usize, None).unwrap_or("".into())));
        }
        Ok(())
    })();
    ptrace_detach(p.pid); result
}

#[cfg(not(target_arch = "aarch64"))]
pub fn call_remote(pid: pid_t, fp: usize, ret: usize, args: &[reg_t]) -> reg_t {
    todo!()
}

#[cfg(target_arch = "aarch64")]
pub fn call_remote(pid: pid_t, fp: usize, ret: usize, args: &[reg_t]) -> reg_t {
    #[cfg(target_arch = "arm")] const REGS_ARG_NUM: usize = 4;
    #[cfg(target_arch = "aarch64")] const REGS_ARG_NUM: usize = 6;

    unsafe {
        let mut regs: user_regs_struct = std::mem::zeroed();
        ptrace_getregs(pid, &mut regs);
        let bak = regs;
        for i in 0..REGS_ARG_NUM.min(args.len()) {
            regs.regs[i] = args[i];
        }
        if args.len() > REGS_ARG_NUM {
            let stack_num = args.len() - REGS_ARG_NUM;
            arm_sp!(regs) -= (size_of::<reg_t>() * stack_num) as reg_t;
            ptrace_write(pid, arm_sp!(regs) as usize, args[REGS_ARG_NUM..].as_byte_array());
        }

        arm_lr!(regs) = ret as reg_t;
        arm_pc!(regs) = fp as reg_t;

        assert!(ptrace_setregs(pid, &regs));
        ptrace_cont(pid, 0);
    
        ptrace::waitpid(pid, WUNTRACED);
        ptrace_getregs(pid, &mut regs);
        assert!(ptrace_setregs(pid, &bak));

        regs.regs[0]
    }
}

pub fn memfd_create(name: &CStr, flags: c_int) -> Option<fs::File> {
    use std::os::unix::io::*;

    unsafe {
        let r = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0);
        if r > 0 { Some(File::from_raw_fd(r as RawFd)) } else { None }
    }
}

// pub fn ptrace_peektext(tid: pid_t, address: usize) -> Option<usize> {
//     unsafe { ptrace(PTRACE_PEEKTEXT, tid, address, 0) == 0 }
// }

// https://github.com/innogames/android-ndk/blob/master/platforms/android-9/arch-arm/usr/include/asm/ptrace.h
const NT_PRSTATUS: i32 = 1;
cfg_if! {
    if #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
        const PTRACE_GETREGS: i32 = 12;
        const PTRACE_SETREGS: i32 = 13;
        const PTRACE_GETREGSET: i32 = 0x4204;
        const PTRACE_SETREGSET: i32 = 0x4205;
    }
}
pub fn ptrace_getregs(tid: pid_t, regs: &mut user_regs_struct) -> bool {
    unsafe {
        let mut io = iovec {
            iov_len: size_of_val(regs),
            iov_base: transmute(regs as *mut user_regs_struct),
            // iov_len: 18 * 4,
        };
        if ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &mut io) >= 0 {
            return true;
        }
        ptrace(PTRACE_GETREGS, tid, 0, regs) >= 0
    }
}

pub fn ptrace_setregs(tid: pid_t, regs: &user_regs_struct) -> bool {
    unsafe {
        let mut io = iovec {
            iov_base: transmute(regs),
            iov_len: size_of_val(regs),
        };
        if ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &mut io) >= 0 {
            return true;
        }
        return ptrace(PTRACE_SETREGS, tid, 0, regs) >= 0;
    }
}

pub fn ptrace_write(pid: pid_t, address: usize, data: &[u8]) {
    const SSIZE: usize = size_of::<usize>();
    unsafe {
        for i in (0..data.len()).step_by(SSIZE) {
            let val = *((data.as_ptr() as usize + i) as *const usize);
            ptrace(PTRACE_POKEDATA, pid, address + i, val);
        }
        let align_len = data.len() - data.len() % SSIZE;
        if align_len < data.len() {
            let rest = &data[align_len..];
            let mut val = ptrace(PTRACE_PEEKDATA, pid, address + align_len, 0).to_ne_bytes();
            for i in 0..data.len() % SSIZE { val[i] = rest[i]; }
            ptrace(PTRACE_POKEDATA, pid, address + align_len, usize::from_ne_bytes(val));
        }
    }
}
