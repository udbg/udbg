use super::*;
use crate::elf;
use std::{ffi::CStr, fs};

pub fn is_selinux_enabled() -> bool {
    String::from_utf8(fs::read("/proc/filesystems").unwrap_or_default())
        .unwrap_or_default()
        .find("selinuxfs")
        .is_some()
}

pub fn disable_selinux() -> anyhow::Result<()> {
    let se_dir = Utils::file_lines("/proc/mounts")?
        .filter_map(|line| {
            let line = line.split(' ').collect::<Vec<_>>();
            if line.get(0)? == &"selinuxfs" {
                Some(line[1].to_string())
            } else {
                None
            }
        })
        .next()
        .context("selinuxfs")?;
    fs::write(format!("{se_dir}/enforce"), b"0")?;
    Ok(())
}

pub fn ptrace_inject(p: &Process, libpath: &str) -> anyhow::Result<()> {
    if is_selinux_enabled() {
        disable_selinux().context("selinux")?;
    }

    let m = p
        .enum_module()?
        .find(|m| m.name.as_ref() == "libc.so")
        .context("libc.so")?;
    let map = Utils::mapfile(m.path.as_ref()).context("mapfile")?;
    let e = elf::ElfHelper::parse(&map).context("elf")?;
    let mmap = m.base + e.get_export("mmap").context("mmap")?.offset();

    let m = p
        .enum_module()?
        .find(|m| m.name.as_ref() == "libdl.so")
        .context("libdl.so")?;
    let data = fs::read(m.path.as_ref())?;
    let e = elf::ElfHelper::parse(&data).context("elf")?;
    let dlopen = m.base + e.get_export("dlopen").context("dlopen")?.offset();

    ptrace_attach_wait(p.pid, WUNTRACED).context("attach wait")?;
    let result = (|| {
        let libpath = fs::canonicalize(libpath).unwrap();
        let libpath = libpath.to_string_lossy();
        let mut libpath = libpath.as_bytes().to_vec();
        libpath.push(0);
        let buf = call_remote(
            p.pid,
            mmap,
            0,
            &[
                0,
                libpath.len() as reg_t,
                (PROT_READ | PROT_WRITE) as reg_t,
                (MAP_PRIVATE | MAP_ANONYMOUS) as reg_t,
                0,
                0,
            ],
        )
        .context("call mmap")?;
        ptrace_write(p.pid, buf as usize, &libpath);

        let vndk = p
            .enum_module()?
            .find(|m| m.name.as_ref() == "libRS.so")
            .context("libRS.so")?
            .base;
        let h = call_remote(
            p.pid,
            dlopen,
            vndk,
            &[buf as reg_t, (RTLD_NOW | RTLD_LOCAL) as reg_t],
        )
        .context("call dlopen")?;
        if h == 0 {
            let dlerror = m.base + e.get_export("dlerror").context("dlerror")?.offset();
            let err = call_remote(p.pid, dlerror, 0, &[]).unwrap_or(0);
            return Err(anyhow::Error::msg(
                p.read_utf8(err as usize, None).unwrap_or_default(),
            ));
        }
        Ok(())
    })();
    ptrace::detach(Pid::from_raw(p.pid), None)?;
    result
}

pub fn memfd_create(name: &CStr, flags: c_int) -> Option<fs::File> {
    use std::os::unix::io::*;

    unsafe {
        let r = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0);
        if r > 0 {
            Some(File::from_raw_fd(r as RawFd))
        } else {
            None
        }
    }
}

// pub fn ptrace_peektext(tid: pid_t, address: usize) -> Option<usize> {
//     unsafe { ptrace(PTRACE_PEEKTEXT, tid, address, 0) == 0 }
// }
