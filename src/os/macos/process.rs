use super::ffi::*;
use super::*;

use crate::os::tid_t;

use core::mem::size_of;
use mach2::mach_types::thread_act_t;
use mach2::task::{task_resume, task_suspend, task_threads};
use mach2::task_info::*;
use mach2::thread_act::{thread_resume, thread_suspend};
use mach2::vm::*;
use mach2::vm_region::*;
use mach2::vm_types::mach_vm_size_t;
use nix::errno::Errno;
use std::io::Error as IoErr;
use std::io::Result as IoResult;
use std::sync::Arc;

pub struct Process {
    pub pid: pid_t,
    pub task: mach_port_t,
}

impl ReadMemory for Process {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        unsafe {
            let mut nread = 0;
            if mach_vm_read_overwrite(
                self.task,
                addr as _,
                data.len() as _,
                data.as_mut_ptr() as _,
                &mut nread,
            ) == KERN_SUCCESS
            {
                Some(&mut data[..nread as usize])
            } else {
                None
            }
        }
    }
}

impl WriteMemory for Process {
    fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        unsafe {
            if mach_vm_write(self.task, address as _, data.as_ptr() as _, data.len() as _)
                == KERN_SUCCESS
            {
                Some(data.len())
            } else {
                None
            }
        }
    }
}

impl TargetMemory for Process {
    fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        Ok(Box::new(Process::enum_memory(self)))
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        Process::virtual_query(self, address as _)
    }

    fn collect_memory_info(&self) -> Vec<MemoryPage> {
        // mach_vm_region_recurse(target_task, address, size, nesting_depth, info, infoCnt)
        self.enum_memory().collect()
    }
}

impl<T> TargetMemory for T
where
    T: AsRef<Process> + ReadMemory + WriteMemory,
{
    default fn enum_memory(&self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + '_>> {
        TargetMemory::enum_memory(self.as_ref())
    }

    default fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        TargetMemory::virtual_query(self.as_ref(), address)
    }

    default fn collect_memory_info(&self) -> Vec<MemoryPage> {
        self.as_ref().collect_memory_info()
    }
}

impl<T> TargetControl for T
where
    T: AsRef<Process>,
{
    /// detach from debugging target
    fn detach(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    /// interrupt the target running
    fn breakk(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    /// kill target
    fn kill(&self) -> UDbgResult<()> {
        unsafe {
            kill(self.as_ref().pid, SIGKILL);
            Ok(())
        }
    }
    /// suspend target
    fn suspend(&self) -> UDbgResult<()> {
        self.as_ref().suspend();
        Ok(())
    }
    /// resume target
    fn resume(&self) -> UDbgResult<()> {
        self.as_ref().resume();
        Ok(())
    }
}

impl Process {
    pub fn enum_pid() -> nix::Result<impl Iterator<Item = pid_t>> {
        unsafe {
            let count = Errno::result(libc::proc_listallpids(::std::ptr::null_mut(), 0))?;
            let mut pids: Vec<pid_t> = Vec::with_capacity(count as usize);
            pids.set_len(count as usize);

            let count = count * core::mem::size_of::<pid_t>() as i32;
            let x = Errno::result(libc::proc_listallpids(pids.as_mut_ptr().cast(), count))?;
            pids.set_len(x as usize);
            Ok(pids.into_iter())
        }
    }

    pub fn current() -> Self {
        Self::from_pid(std::process::id() as _).unwrap()
    }

    pub fn from_pid(pid: pid_t) -> UDbgResult<Self> {
        unsafe {
            let mut task = 0;
            let r = task_for_pid(mach_task_self(), pid, &mut task);
            UDbgError::from_kern_return(r)?;

            Ok(Self { pid, task })
        }
    }

    pub fn pid(&self) -> pid_t {
        self.pid
    }

    pub fn image_path(&self) -> nix::Result<String> {
        Self::pid_path(self.pid)
    }

    pub fn pid_path(pid: pid_t) -> nix::Result<String> {
        unsafe {
            let mut buffer: Vec<u8> = Vec::with_capacity(libc::PROC_PIDPATHINFO_MAXSIZE as _);
            let len = Errno::result(libc::proc_pidpath(
                pid,
                buffer.as_mut_ptr() as *mut _,
                libc::PROC_PIDPATHINFO_MAXSIZE as _,
            ))?;
            buffer.set_len(len as _);
            Ok(String::from_utf8_lossy(&buffer).into())
        }
    }

    pub fn pid_name(pid: pid_t) -> nix::Result<String> {
        unsafe {
            let mut buffer: Vec<u8> =
                Vec::with_capacity(libc::PROC_PIDPATHINFO_MAXSIZE as usize / 2);
            let len = Errno::result(libc::proc_name(
                pid,
                buffer.as_mut_ptr() as *mut _,
                buffer.capacity() as _,
            ))?;
            buffer.set_len(len as _);
            Ok(String::from_utf8_lossy(&buffer).into())
        }
    }

    pub fn regionfilename(pid: i32, address: u64) -> nix::Result<String> {
        let mut buf: Vec<u8> = Vec::with_capacity(libc::PROC_PIDPATHINFO_MAXSIZE as usize - 1);
        let buffer_size = buf.capacity() as u32;
        let ret: i32;

        unsafe {
            Errno::result(proc_regionfilename(
                pid,
                address,
                buf.as_mut_ptr().cast(),
                buffer_size,
            ))?;
            Ok(String::from_utf8_lossy(&buf).into())
        }
    }

    pub fn pid_cmdline(pid: pid_t) -> Vec<String> {
        let mut size = get_arg_max();
        let mut proc_args = Vec::with_capacity(size);
        unsafe {
            let ptr: *mut u8 = proc_args.as_mut_slice().as_mut_ptr();
            let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as _];
            /*
             * /---------------\ 0x00000000
             * | ::::::::::::: |
             * |---------------| <-- Beginning of data returned by sysctl() is here.
             * | argc          |
             * |---------------|
             * | exec_path     |
             * |---------------|
             * | 0             |
             * |---------------|
             * | arg[0]        |
             * |---------------|
             * | 0             |
             * |---------------|
             * | arg[n]        |
             * |---------------|
             * | 0             |
             * |---------------|
             * | env[0]        |
             * |---------------|
             * | 0             |
             * |---------------|
             * | env[n]        |
             * |---------------|
             * | ::::::::::::: |
             * |---------------| <-- Top of stack.
             * :               :
             * :               :
             * \---------------/ 0xffffffff
             */
            if libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                ptr.cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == -1
            {
                return vec![];
            }
            let argc = *ptr.cast::<c_int>();
            let intsize = core::mem::size_of::<c_int>();
            let buf = core::slice::from_raw_parts(ptr.add(intsize), size - intsize);
            buf.split(|&b| b == b'\0')
                .skip(1)
                .take(argc as _)
                .map(|x| String::from_utf8_unchecked(x.to_vec()))
                .collect()
        }
    }

    pub fn pid_fds(pid: pid_t) -> UDbgResult<impl Iterator<Item = HandleInfo>> {
        use ::libproc::libproc::bsd_info::BSDInfo;
        use ::libproc::libproc::file_info::*;
        use ::libproc::libproc::net_info::*;
        use ::libproc::libproc::proc_pid::*;

        impl Default for vnode_fdinfowithpath {
            fn default() -> Self {
                unsafe { core::mem::zeroed() }
            }
        }

        impl PIDFDInfo for vnode_fdinfowithpath {
            fn flavor() -> PIDFDInfoFlavor {
                PIDFDInfoFlavor::VNodePathInfo
            }
        }

        // help: https://github.com/aosm/lsof/blob/master/lsof/dialects/darwin/libproc/dfile.c
        let info = pidinfo::<BSDInfo>(pid, 0)?;
        let fds = listpidinfo::<ListFDs>(pid, info.pbi_nfiles as usize)?;
        Ok(fds.into_iter().map(move |fd| {
            let ty = fd.proc_fdtype.into();
            let type_name = format!("{ty:?}");
            let name = match ty {
                ProcFDType::Socket => {
                    let socket =
                        pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd).expect("pidfdinfo() failed");
                    let proto = match socket.psi.soi_protocol {
                        libc::IPPROTO_TCP => "tcp",
                        libc::IPPROTO_UDP => "udp",
                        libc::IPPROTO_IP => "ip",
                        libc::IPPROTO_IPV6 => "ipv6",
                        libc::IPPROTO_ICMP => "icmp",
                        libc::IPPROTO_ICMPV6 => "icmpv6",
                        _ => "unk",
                    };
                    // let info = socket.psi.soi_proto.pri_tcp;
                    format!("[socket] {proto}")
                }
                // pipe_fdinfo, ...
                // https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX10.8.sdk/usr/include/sys/proc_info.h
                // ProcFDType::Pipe => {}
                ProcFDType::VNode => {
                    let fdp = pidfdinfo::<vnode_fdinfowithpath>(pid, fd.proc_fd).unwrap();
                    let s = fdp.pvip.vip_path.split(|&x| x == 0).next().unwrap();
                    let s = unsafe { std::str::from_utf8_unchecked(core::mem::transmute(s)) };
                    s.to_string()
                }
                fdt => format!("[{fdt:?}]"),
            };
            HandleInfo {
                ty: fd.proc_fdtype,
                handle: fd.proc_fd as _,
                type_name,
                name,
            }
        }))
    }

    pub fn virtual_query(&self, mut address: u64) -> Option<MemoryPage> {
        let mut size: mach_vm_size_t = 0;
        unsafe {
            let mut info: vm_region_basic_info_64 = core::mem::zeroed();
            let mut count = core::mem::size_of::<vm_region_basic_info_64>() as u32;
            let mut object_name: mach_port_t = 0;
            if mach_vm_region(
                self.task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut _ as _,
                &mut count,
                &mut object_name as _,
            ) != KERN_SUCCESS
            {
                return None;
            }

            Some(MemoryPage {
                base: address as _,
                size: size as _,
                protect: u32::from_be_bytes(protection_bits_to_rwx(&info)),
                info: Self::regionfilename(self.pid, address as _)
                    .ok()
                    .map(Into::into),
                ..Default::default()
            })
        }
    }

    pub fn enum_memory<'a>(&'a self) -> impl Iterator<Item = MemoryPage> + 'a {
        let mut addr = 1;
        std::iter::from_fn(move || {
            let m = self.virtual_query(addr)?;
            addr = (m.base + m.size) as _;
            Some(m)
        })
    }

    pub fn read_all_image_info(&self) -> Vec<dyld_image_info> {
        unsafe {
            let mut info: task_dyld_info = core::mem::zeroed();
            let mut count = (size_of::<task_dyld_info>() / size_of::<natural_t>()) as u32;
            if task_info(
                self.task,
                TASK_DYLD_INFO,
                &mut info as *mut _ as _,
                &mut count,
            ) == KERN_SUCCESS
            {
                (|| {
                    let infos =
                        self.read_value::<dyld_all_image_infos>(info.all_image_info_addr as _)?;
                    let mut res = vec![core::mem::zeroed(); infos.infoArrayCount as usize];
                    self.read_to_array::<dyld_image_info>(infos.infoArray as _, &mut res);
                    Some(res)
                })()
            } else {
                None
            }
            .unwrap_or_default()
        }
    }

    pub fn list_module(&self) -> impl Iterator<Item = ModuleData> + '_ {
        self.read_all_image_info().into_iter().map(move |info| {
            let path = self
                .read_utf8(info.imageFilePath as _, PROC_PIDPATHINFO_MAXSIZE as usize)
                .unwrap_or_default();

            let size = self
                .read_value::<mach_header>(info.imageLoadAddress as _)
                .and_then(|header| unsafe {
                    let mut size = size_of::<mach_header>();
                    size += header.sizeofcmds as usize;
                    let mut lc = info.imageLoadAddress.offset(1).cast::<load_command>();
                    for i in 0..header.ncmds {
                        let l = self.read_value::<segment_command>(lc as _)?;
                        if l.cmd == LC_SEGMENT {
                            size += l.vmsize as usize;
                        }
                        lc = lc.cast::<u8>().add(l.cmdsize as _).cast();
                    }
                    Some(size)
                })
                .unwrap_or_default();
            ModuleData {
                base: info.imageLoadAddress as _,
                name: path.rsplit_once("/").unwrap_or_default().1.into(),
                path: path.into(),
                size,
                user_module: false.into(),
                arch: std::env::consts::ARCH,
                entry: 0,
            }
        })
    }

    pub fn suspend(&self) -> nix::Result<()> {
        unsafe {
            Errno::result(task_suspend(self.task))?;
            Ok(())
        }
    }

    pub fn resume(&self) -> nix::Result<()> {
        unsafe {
            Errno::result(task_resume(self.task))?;
            Ok(())
        }
    }

    pub fn list_thread(&self) -> UDbgResult<VmMemory<'_, thread_act_t>> {
        unsafe {
            let mut arr = FFIArray::default();
            let err = task_threads(self.task, &mut arr.ptr, &mut arr.cnt);
            UDbgError::from_kern_return(err)?;
            Ok(VmMemory { ps: self, arr })
        }
    }
}

#[derive(Deref, DerefMut)]
pub struct VmMemory<'a, T> {
    pub ps: &'a Process,
    #[deref]
    #[deref_mut]
    arr: FFIArray<T, u32>,
}

impl<T> Drop for VmMemory<'_, T> {
    #[inline]
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        unsafe {
            vm_deallocate(
                self.ps.task,
                self.ptr as _,
                core::mem::size_of_val(&*self.ptr) * self.cnt as usize,
            );
        }
    }
}

pub struct ThreadAct(pub thread_act_t);

pub trait ThreadActInfo {
    const FLAVOR: i32;
    const COUNT: u32;
}

impl ThreadActInfo for thread_basic_info {
    const FLAVOR: i32 = THREAD_BASIC_INFO;
    const COUNT: u32 = THREAD_BASIC_INFO_COUNT;
}

impl ThreadActInfo for thread_extended_info {
    const FLAVOR: i32 = THREAD_EXTENDED_INFO;
    const COUNT: u32 = THREAD_EXTENDED_INFO_COUNT;
}

impl ThreadActInfo for thread_identifier_info {
    const FLAVOR: i32 = THREAD_IDENTIFIER_INFO;
    const COUNT: u32 = THREAD_IDENTIFIER_INFO_COUNT;
}

impl ThreadAct {
    pub fn id(&self) -> tid_t {
        self.identifier_info()
            .map(|x| x.thread_id)
            .unwrap_or_default()
    }

    pub fn info<T: ThreadActInfo>(&self) -> Result<T, i32> {
        unsafe {
            let mut info: T = core::mem::zeroed();
            let mut size = T::COUNT;
            let err = thread_info(self.0, T::FLAVOR as _, &mut info as *mut _ as _, &mut size);
            if err == KERN_SUCCESS {
                Ok(info)
            } else {
                Err(err)
            }
        }
    }

    #[inline(always)]
    pub fn basic_info(&self) -> Result<thread_basic_info, i32> {
        self.info()
    }

    #[inline(always)]
    pub fn identifier_info(&self) -> Result<thread_identifier_info, i32> {
        self.info()
    }

    #[inline(always)]
    pub fn extended_info(&self) -> Result<thread_extended_info, i32> {
        self.info()
    }

    pub fn suspend(&self) -> Result<(), i32> {
        unsafe {
            let res = thread_suspend(self.0);
            if res == KERN_SUCCESS {
                Ok(())
            } else {
                Err(res)
            }
        }
    }

    pub fn resume(&self) -> Result<(), i32> {
        unsafe {
            let res = thread_resume(self.0);
            if res == KERN_SUCCESS {
                Ok(())
            } else {
                Err(res)
            }
        }
    }
}

#[derive(Deref)]
pub struct MacThread {
    #[deref]
    pub data: ThreadData,
}

impl GetProp for MacThread {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        Ok(serde_value::Value::Unit)
    }
}

impl UDbgThread for MacThread {
    fn name(&self) -> Arc<str> {
        self.handle
            .extended_info()
            .map(|info| unsafe {
                let name = info.pth_name[..].strslice();
                String::from_utf8_lossy(core::mem::transmute(name)).into()
            })
            .unwrap_or_else(|_| "".into())
    }

    fn status(&self) -> Arc<str> {
        self.handle
            .basic_info()
            .map(|info| info.run_state.to_string())
            .unwrap_or_default()
            .into()
    }

    fn priority(&self) -> Option<i32> {
        self.handle
            .extended_info()
            .map(|info| info.pth_priority)
            .ok()
    }

    fn suspend(&self) -> IoResult<i32> {
        self.handle
            .suspend()
            .map(|_| 0)
            .map_err(IoErr::from_raw_os_error)
    }

    fn resume(&self) -> IoResult<u32> {
        self.handle
            .resume()
            .map(|_| 0)
            .map_err(IoErr::from_raw_os_error)
    }

    fn suspend_count(&self) -> usize {
        self.handle
            .basic_info()
            .map(|info| info.suspend_count as usize)
            .unwrap_or_default()
    }
}

fn protection_bits_to_rwx(info: &vm_region_basic_info_64) -> [u8; 4] {
    let p = info.protection;
    [
        if p & VM_PROT_READ > 0 { b'r' } else { b'-' },
        if p & VM_PROT_WRITE > 0 { b'w' } else { b'-' },
        if p & VM_PROT_EXECUTE > 0 { b'x' } else { b'-' },
        if info.shared > 0 { b'-' } else { b'p' },
    ]
}

fn get_arg_max() -> usize {
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut arg_max = 0i32;
    let mut size = core::mem::size_of::<c_int>();
    unsafe {
        if sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            (&mut arg_max) as *mut i32 as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) == -1
        {
            4096 // We default to this value
        } else {
            arg_max as usize
        }
    }
}

impl ProcessInfo {
    pub fn enumerate() -> nix::Result<Box<dyn Iterator<Item = Self>>> {
        Ok(Box::new(Process::enum_pid()?.map(|pid| Self {
            pid,
            wow64: false,
            name: Process::pid_name(pid).unwrap_or_default(),
            path: Process::pid_path(pid).unwrap_or_default(),
            cmdline: Process::pid_cmdline(pid).join(" "),
        })))
    }
}
