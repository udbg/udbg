
use libc::{task_info, *};
use mach::*;
use mach::mach_types::thread_act_t;
use mach::thread_act::thread_resume;
use mach::thread_act::thread_suspend;
use mach::vm::*;
use mach::task::*;
use mach::task_info::TASK_DYLD_INFO;
use mach::task_info::task_dyld_info;
use vm_region::*;

pub use libc::pid_t;
pub use libc::__darwin_arm_thread_state64;

use crate::*;
use crate::sym::ModuleData;

use std::ffi::CStr;
use std::io::Error as IoErr;
use core::mem::size_of;
use std::ops::Deref;
use super::ffi::*;

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
            ) == KERN_SUCCESS {
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
            if mach_vm_write(
                self.task,
                address as _,
                data.as_ptr() as _,
                data.len() as _,
            ) == KERN_SUCCESS {
                Some(data.len())
            } else {
                None
            }
        }
    }
}

impl Process {
    pub fn current() -> Self {
        Self::from_pid(std::process::id() as _).unwrap()
    }

    pub fn from_pid(pid: pid_t) -> UDbgResult<Self> {
        unsafe {
            let mut task = 0;
            let r = task_for_pid(mach_task_self(), pid, &mut task);
            if r != KERN_SUCCESS {
                println!("err: {r}");
                return Err(IoErr::last_os_error().into());
            }

            Ok(Self {pid, task})
        }
    }

    pub fn virtual_query(&self, mut address: u64) -> Option<MemoryPage> {
        let mut size: mach_vm_size_t = 0;
        unsafe {
            let mut info: vm_region_basic_info = core::mem::zeroed();
            let mut count = core::mem::size_of::<vm_region_basic_info_data_64_t>() as u32;
            let mut object_name: mach_port_t = 0;
            if vm::mach_vm_region(
                self.task, &mut address,
                &mut size, VM_REGION_BASIC_INFO,
                &mut info as *mut _ as _,
                &mut count,
                &mut object_name as _,
            ) != KERN_SUCCESS { return None; }

            Some(MemoryPage {
                base: address as _,
                size: size as _,
                prot: protection_bits_to_rwx(&info),
                usage: regionfilename(self.pid, address as _).unwrap_or_default()
            })
        }
    }

    pub fn enum_memory<'a>(&'a self) -> impl Iterator<Item=MemoryPage> + 'a {
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
                &mut count
            ) == KERN_SUCCESS {
                (|| {
                    let infos = self.read_value::<dyld_all_image_infos>(info.all_image_info_addr as _)?;
                    let mut res = vec![core::mem::zeroed(); infos.infoArrayCount as usize];
                    self.read_to_array::<dyld_image_info>(infos.infoArray as _, &mut res);
                    Some(res)
                })()
            } else {
                None
            }.unwrap_or_default()
        }
    }

    pub fn list_module(&self) -> impl Iterator<Item=ModuleData> + '_ {
        self.read_all_image_info().into_iter().map(move |info| {
            let path = self.read_utf8(info.imageFilePath as _, PROC_PIDPATHINFO_MAXSIZE as usize).unwrap_or_default();
            ModuleData {
                base: info.imageLoadAddress as _,
                name: path.rsplit_once("/").unwrap_or_default().1.into(),
                path: path.into(),
                // TODO:
                size: 0x1000,
                user_module: false.into(),
                arch: std::env::consts::ARCH,
                entry: 0,
            }
        })
    }

    pub fn suspend(&self) {
        unsafe {
            task_suspend(self.task);
        }
    }

    pub fn resume(&self) {
        unsafe {
            task_resume(self.task);
        }
    }

    pub fn list_thread(&self) -> Result<ProcessMemory<'_, thread_act_t>, i32> {
        unsafe {
            let mut threads = core::ptr::null_mut();
            let mut count = 0;
            let err = task_threads(
                self.task,
                &mut threads,
                &mut count
            );
            if err == KERN_SUCCESS {
                Ok(ProcessMemory {ps: self, ptr: threads, count: count as _})
            } else {
                Err(err)
            }
        }
    }
}

pub struct ProcessMemory<'a, T> {
    ps: &'a Process,
    ptr: *const T,
    count: usize,
}

impl<T> Deref for ProcessMemory<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe {
            core::slice::from_raw_parts(self.ptr, self.count)
        }
    }    
}

impl<T> Drop for ProcessMemory<'_, T> {
    fn drop(&mut self) {
        unsafe {
            vm_deallocate(self.ps.task, self.ptr as _, core::mem::size_of_val(&*self.ptr) * self.count);
        }
    }
}

pub struct ThreadAct(pub thread_act_t);

pub trait ThreadActInfo {
    const FLAVOR: i32;
    const COUNT: u32;
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
        self.identifier_info().map(|x| x.thread_id).unwrap_or_default()
    }

    pub fn info<T: ThreadActInfo>(&self) -> Result<T, i32> {
        unsafe {
            let mut info: T = core::mem::zeroed();
            let mut size = T::COUNT;
            let err = thread_info(
                self.0,
                T::FLAVOR as _,
                &mut info as *mut _ as _,
                &mut size
            );
            if err == KERN_SUCCESS {
                Ok(info)
            } else {
                Err(err)
            }
        }
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

impl UDbgThread for MacThread {
    fn name(&self) -> Arc<str> {
        self.handle.extended_info().map(|info| unsafe {
            CStr::from_bytes_with_nul_unchecked(
                // core::mem::transmute(info.pth_name.strslice())
                // TODO:
                core::mem::transmute(&info.pth_name[..])
            ).to_string_lossy()
        }).unwrap_or_default().into()
    }

    fn status(&self) -> Arc<str> {
        // thread_
        "".into()
    }

    fn priority(&self) -> Arc<str> {
        // thread_basic_info
        
        // thread_info(self.0, flavor, thread_info_out, thread_info_outCnt)
        "".into()
    }

    fn suspend(&self) -> IoResult<i32> {
        self.handle.suspend().map(|_| 0).map_err(IoErr::from_raw_os_error)
    }

    fn resume(&self) -> IoResult<u32> {
        self.handle.resume().map(|_| 0).map_err(IoErr::from_raw_os_error)
    }

    fn last_error(&self) -> Option<u32> { None }
}

pub trait ModuleInfo: core::ops::Deref<Target=dyld_image_info> + Sized {
    fn size(self) -> usize {
        // FIXME:
        unsafe {
            self.imageLoadAddress.as_ref().map(|header| {
                let mut size = size_of::<mach_header>();
                size += header.sizeofcmds as usize;
                let mut lc = self.imageLoadAddress.offset(1).cast::<load_command>();
                for i in 0..header.ncmds {
                    let l = lc.cast::<segment_command>().as_ref().unwrap();
                    if l.cmd == LC_SEGMENT {
                        size += l.vmsize as usize;
                    }
                    lc = lc.cast::<u8>().add(l.cmdsize as _).cast();
                }
                size
            }).unwrap_or_default()
        }
    }
}
impl ModuleInfo for &dyld_image_info {}

fn protection_bits_to_rwx(info: &vm_region_basic_info) -> [u8; 4] {
    let p = info.protection;
    [
        if p & VM_PROT_READ > 0 { b'r' } else { b'-' },
        if p & VM_PROT_WRITE > 0 { b'w' } else { b'-' },
        if p & VM_PROT_EXECUTE > 0 { b'x' } else { b'-' },
        if info.shared > 0 { b'-' } else { b'p' },
    ]
}

pub fn get_errno_with_message(return_code: i32) -> String {
    let e = errno::errno();
    let code = e.0 as i32;
    format!("return code = {}, errno = {}, message = '{}'", return_code, code, e)
}

pub fn check_errno(ret: i32, buf: &mut Vec<u8>) -> Result<String, String> {
    if ret <= 0 {
        Err(get_errno_with_message(ret))
    } else {
        unsafe {
            buf.set_len(ret as usize);
        }

        match String::from_utf8(buf.to_vec()) {
            Ok(return_value) => Ok(return_value),
            Err(e) => Err(format!("Invalid UTF-8 sequence: {}", e))
        }
    }
}

pub fn regionfilename(pid: i32, address: u64) -> Result<String, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(PROC_PIDPATHINFO_MAXSIZE as usize - 1);
    let buffer_ptr = buf.as_mut_ptr() as *mut c_void;
    let buffer_size = buf.capacity() as u32;
    let ret: i32;

    unsafe {
        ret = proc_regionfilename(pid, address, buffer_ptr, buffer_size);
    };

    check_errno(ret, &mut buf)
}

pub fn enum_pid() -> impl Iterator<Item=pid_t> {
    unsafe {
        let count = libc::proc_listallpids(::std::ptr::null_mut(), 0);
        if count < 1 {
            return vec![].into_iter();
        }
        let mut pids: Vec<pid_t> = Vec::with_capacity(count as usize);
        pids.set_len(count as usize);
        let count = count * core::mem::size_of::<pid_t>() as i32;
        let x = libc::proc_listallpids(pids.as_mut_ptr() as *mut c_void, count);

        if x < 1 || x as usize >= pids.len() {
            return vec![].into_iter();
        } else {
            pids.set_len(x as usize);
            pids.into_iter()
        }
    }
}

pub fn process_name(pid: pid_t) -> Option<String> {
    unsafe {
        let mut buffer: Vec<u8> = Vec::with_capacity(libc::PROC_PIDPATHINFO_MAXSIZE as usize / 2);
        match libc::proc_name(pid,
            buffer.as_mut_ptr() as *mut _,
            buffer.capacity() as _,
        ) {
            x if x > 0 => {
                buffer.set_len(x as _);
                let tmp = String::from_utf8_unchecked(buffer);
                Some(tmp)
            }
            _ => None
        }
    }
}

pub fn process_path(pid: pid_t) -> Option<String> {
    unsafe {
        let mut buffer: Vec<u8> = Vec::with_capacity(libc::PROC_PIDPATHINFO_MAXSIZE as _);
        match libc::proc_pidpath(pid,
            buffer.as_mut_ptr() as *mut _,
            libc::PROC_PIDPATHINFO_MAXSIZE as _,
        ) {
            x if x > 0 => {
                buffer.set_len(x as _);
                let tmp = String::from_utf8_unchecked(buffer);
                Some(tmp)
            }
            _ => None
        }
    }
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

unsafe fn get_unchecked_str(cp: *mut u8, start: *mut u8) -> String {
    let len = cp as usize - start as usize;
    let part = Vec::from_raw_parts(start, len, len);
    let tmp = String::from_utf8_unchecked(part.clone());
    core::mem::forget(part);
    tmp
}

pub fn process_cmdline(pid: pid_t) -> Vec<String> {
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
            ptr as *mut c_void,
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
        buf.split(|&b| b == b'\0').skip(1).take(argc as _).map(|x| String::from_utf8_unchecked(x.to_vec())).collect()
    }
}

pub fn process_fds(pid: pid_t) -> impl Iterator<Item=UiHandle> {
    use ::libproc::libproc::proc_pid::*;
    use ::libproc::libproc::file_info::*;
    use ::libproc::libproc::bsd_info::BSDInfo;
    // use ::libproc::libproc::net_info::*;

    impl Default for vnode_fdinfowithpath {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    impl PIDFDInfo for vnode_fdinfowithpath {
        fn flavor() -> PIDFDInfoFlavor { PIDFDInfoFlavor::VNodePathInfo }
    }

    let info = pidinfo::<BSDInfo>(pid, 0).expect("pidinfo() failed");
    let fds = listpidinfo::<ListFDs>(pid, info.pbi_nfiles as usize).expect("listpidinfo() failed");
    fds.into_iter().map(move |fd| {
        let ty = fd.proc_fdtype.into();
        let type_name = format!("{ty:?}");
        let name = match ty {
            ProcFDType::Socket => {
                // let socket = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd).expect("pidfdinfo() failed");
                // if let SocketInfoKind::Tcp = socket.psi.soi_kind.into() {
                //     unsafe {
                //         let info = socket.psi.soi_proto.pri_tcp;
                //         assert_eq!(socket.psi.soi_protocol, libc::IPPROTO_TCP);
                //         assert_eq!(info.tcpsi_ini.insi_lport as u32, 65535);
                //     }
                // }
                format!("[socket]")
            }
            // ProcFDType::Pipe => {}
            ProcFDType::VNode => {
                let fdp = pidfdinfo::<vnode_fdinfowithpath>(pid, fd.proc_fd).unwrap();
                let s = fdp.pvip.vip_path.split(|&x| x == 0).next().unwrap();
                let s = unsafe { std::str::from_utf8_unchecked(core::mem::transmute(s)) };
                s.to_string()
            }
            _ => {
                "".into()
            }
        };
        UiHandle {
            ty: fd.proc_fdtype,
            handle: fd.proc_fd as _,
            type_name, name
        }
    })
}