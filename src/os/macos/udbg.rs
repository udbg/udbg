use super::*;

use crate::os::unix::{udbg::*, Module};
use crate::prelude::{pid_t, *};

use anyhow::Context;
use goblin::mach::{exports, header, imports, load_command, parse_magic_and_ctx, segment};
use mach2::exception_types::*;
use mach2::mach_port::*;
use mach2::mach_types::exception_handler_array_t;
use mach2::mach_types::exception_handler_t;
use mach2::message::{mach_msg_type_number_t, *};
use mach2::port::MACH_PORT_NULL;
use mach2::port::MACH_PORT_RIGHT_RECEIVE;
use mach2::thread_status::thread_state_flavor_t;
use mach2::thread_status::thread_state_t;
use mach2::thread_status::THREAD_STATE_NONE;
use mach2::traps::{mach_task_self, *};
use mach_o_sys::dyld::x86_thread_state;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;
use parking_lot::RwLock;
use std::cell::{Cell, UnsafeCell};
use std::mem::size_of_val;
use std::slice::from_raw_parts_mut;
use std::{collections::HashSet, sync::Arc};

#[derive(Deref)]
pub struct TargetCommon {
    #[deref]
    _base: CommonBase,
    pub threads: RwLock<HashSet<tid_t>>,
    mem_pages: RwLock<Vec<MemoryPage>>,
    pub detaching: Cell<bool>,
    pub regs: UnsafeCell<x86_thread_state>,
    waiting: Cell<bool>,
}

impl TargetCommon {
    pub fn new(ps: Process) -> Self {
        Self {
            _base: CommonBase::new(ps),
            regs: unsafe { core::mem::zeroed() },
            mem_pages: RwLock::new(Vec::new()),
            threads: RwLock::new(HashSet::new()),
            waiting: Cell::new(false),
            detaching: Cell::new(false),
        }
    }

    fn update_module(&self) -> Result<(), String> {
        for mut m in self.process.list_module() {
            if self.symgr.find_module(m.base).is_some() {
                continue;
            }

            // MachO::parse(bytes, offset)
            (|| -> anyhow::Result<_> {
                use goblin::mach::MachO;
                let header = self
                    .read_value::<mach_header_64, Vec<u8>>(m.base)
                    .unwrap_or_default();
                // info!("header size: {}", header.len());
                if header.is_empty() {
                    anyhow::bail!("read header");
                }

                let map = Utils::mapfile(&m.path).ok();
                if let Some(mach) = map.as_ref().and_then(|data| MachO::parse(&data, 0).ok()) {
                    m.entry = mach.entry as _;
                    m.size = mach.segments.iter().map(|s| s.vmsize).sum::<u64>() as _;
                } else {
                    // let (_, segments) = parse_partial_macho(&header)?;
                    // m.size = segments.iter().map(|s| s.vmsize).sum::<u64>() as _;
                }
                Ok(())
            })()
            .log_warn("parse macho");

            self.symgr.base.write().add(Module {
                data: m,
                loaded: false.into(),
                syms: Default::default(),
            });
        }
        Ok(())
    }

    pub fn enable_hwbp(
        &self,
        dbg: &dyn UDbgTarget,
        bp: &Breakpoint,
        info: HwbpInfo,
        enable: bool,
    ) -> UDbgResult<bool> {
        let mut result = Ok(enable);
        // Set Context for each thread
        for &tid in self.threads.read().iter() {
            if bp.hit_tid.is_some() && bp.hit_tid != Some(tid) {
                continue;
            }
            // Set Debug Register
            result = self.enable_hwbp_for_thread(tid, bp, info, enable);
            if let Err(e) = &result {
                udbg_ui().error(format!("enable_hwbp_for_thread for {} failed {:?}", tid, e));
                // break;
            }
        }
        // TODO: Set Context for current thread, update eflags from user

        if result.is_ok() {
            bp.enabled.set(enable);
        }
        result
    }
}

#[derive(Deref)]
pub struct ProcessTarget(pub TargetCommon);

unsafe impl Send for ProcessTarget {}
unsafe impl Sync for ProcessTarget {}

impl AsRef<Process> for ProcessTarget {
    #[inline]
    fn as_ref(&self) -> &Process {
        &self.process
    }
}

impl AsRef<TargetBase> for ProcessTarget {
    #[inline]
    fn as_ref(&self) -> &TargetBase {
        &self.base
    }
}

impl GetProp for ProcessTarget {}

impl Target for ProcessTarget {
    fn base(&self) -> &TargetBase {
        &self.0.base
    }

    fn process(&self) -> Option<&Process> {
        Some(&self.process)
    }

    fn symbol_manager(&self) -> Option<&dyn TargetSymbol> {
        Some(&self.symgr)
    }

    fn enum_module<'a>(
        &'a self,
    ) -> UDbgResult<Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a>> {
        self.update_module();
        Ok(self.symgr.enum_module())
    }

    fn enum_thread(
        &self,
        _detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>> {
        Ok(Box::new(
            self.process
                .list_thread()?
                .as_slice()
                .to_vec()
                .into_iter()
                .map(|ts| {
                    let handle = ThreadAct(ts);
                    Box::new(MacThread {
                        data: ThreadData {
                            tid: handle.id(),
                            wow64: false,
                            handle,
                        },
                    }) as Box<dyn UDbgThread>
                }),
        ))
    }

    fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<dyn UDbgThread>> {
        Err(UDbgError::NotSupport)
    }

    fn enum_handle<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = HandleInfo> + 'a>> {
        Ok(Box::new(Process::pid_fds(self.process.pid)?))
    }
}

impl UDbgTarget for ProcessTarget {}

impl ProcessTarget {
    pub fn open(pid: pid_t) -> UDbgResult<Arc<Self>> {
        Ok(Self(TargetCommon::new(Process::from_pid(pid)?)).into())
    }

    pub fn create(path: &str, args: &[&str]) -> UDbgResult<Arc<Self>> {
        match unsafe { libc::fork() } {
            0 => unsafe {
                use libc::*;
                use std::ffi::CString;

                ptrace(PT_TRACE_ME, 0, core::ptr::null_mut(), 0);
                // let r = ptrace(PT_SIGEXC, libc::getpid(), core::ptr::null_mut(), 0);
                // println!("PT_SIGEXC: {r}");

                // If our parent is setgid, lets make sure we don't inherit those
                // extra powers due to nepotism.
                if setgid(getgid()) == 0 {
                    // Let the child have its own process group. We need to execute
                    // this call in both the child and parent to avoid a race condition
                    // between the two processes.
                    setpgid(0, 0); // Set the child process group to match its pid

                    // Sleep a bit to before the exec call
                    sleep(1);

                    let path = CString::new(path).unwrap();
                    let args = args
                        .iter()
                        .map(|&arg| CString::new(arg).unwrap())
                        .collect::<Vec<_>>();
                    let mut argv = args.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
                    argv.insert(0, path.as_ptr());
                    argv.push(core::ptr::null());
                    libc::execvp(path.as_ptr().cast(), argv.as_ptr());
                }
                unreachable!();
            },
            -1 => Err(UDbgError::system()),
            pid => unsafe {
                libc::setpgid(pid, pid);
                waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WUNTRACED)).context("waitpid")?;
                let ps = Process::from_pid(pid).context("open")?;
                let this = Self(TargetCommon::new(ps));
                this.base().status.set(UDbgStatus::Attached);
                this.insert_thread(pid as _);
                this.base().event_tid.set(pid as _);
                Ok(Arc::new(this))
            },
        }
    }

    pub fn insert_thread(&self, tid: tid_t) {}
    pub fn remove_thread(&self, id: tid_t, s: i32, tb: &mut TraceBuf) {}

    pub fn update_regs(&self, tid: tid_t) {}

    fn set_exception_port(&self, port: mach_port_t) -> anyhow::Result<()> {
        const EXC_TYPES_COUNT: usize = 14;

        unsafe {
            let mut count: mach_msg_type_number_t = 0;
            let mut masks = [0 as exception_mask_t; EXC_TYPES_COUNT];
            let mut ports = [0 as exception_handler_t; EXC_TYPES_COUNT];
            let mut behaviors = [0 as exception_behavior_t; EXC_TYPES_COUNT];
            let mut flavors = [0 as thread_state_flavor_t; EXC_TYPES_COUNT];
            Errno::result(task_get_exception_ports(
                self.process.task,
                EXC_MASK_ALL,
                masks.as_mut_ptr(),
                &mut count,
                ports.as_mut_ptr(),
                behaviors.as_mut_ptr(),
                flavors.as_mut_ptr(),
            ))
            .context("get ports")?;
            Errno::result(task_set_exception_ports(
                self.process.task,
                EXC_MASK_ALL,
                port,
                (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES) as _,
                THREAD_STATE_NONE,
            ))
            .context("set ports")?;
            Ok(())
        }
    }
}

#[no_mangle]
unsafe extern "C" fn catch_mach_exception_raise(
    exception_port: mach_port_t,
    thread: mach_port_t,
    task: mach_port_t,
    exception: exception_type_t,
    code: mach_exception_data_t,
    codeCnt: mach_msg_type_number_t,
) -> kern_return_t {
    info!("catch_mach_exception_raise({exception_port}, {thread}, {task})");
    let params = from_raw_parts_mut(code, codeCnt as usize);
    info!("  {params:x?}");
    0
}

#[no_mangle]
unsafe extern "C" fn catch_mach_exception_raise_state_identity(
    exception_port: mach_port_t,
    thread: mach_port_t,
    task: mach_port_t,
    exception: exception_type_t,
    code: mach_exception_data_t,
    codeCnt: mach_msg_type_number_t,
    flavor: *mut i32,
    old_state: thread_state_t,
    old_stateCnt: mach_msg_type_number_t,
    new_state: thread_state_t,
    new_stateCnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    info!("catch_mach_exception_raise_state_identity({exception_port}, {thread}, {task})");
    let params = from_raw_parts_mut(code, codeCnt as usize);
    info!("  {params:x?}");
    0
}

#[no_mangle]
unsafe extern "C" fn catch_mach_exception_raise_state(
    exception_port: mach_port_t,
    exception: exception_type_t,
    code: mach_exception_data_t,
    codeCnt: mach_msg_type_number_t,
    flavor: *mut i32,
    old_state: thread_state_t,
    old_stateCnt: mach_msg_type_number_t,
    new_state: thread_state_t,
    new_stateCnt: *mut mach_msg_type_number_t,
) -> kern_return_t {
    info!("catch_mach_exception_raise_state({exception_port}, {exception})");
    let params = from_raw_parts_mut(code, codeCnt as usize);
    info!("  {params:x?}");
    0
}

extern "C" {
    fn mach_exc_server(input: *mut mach_msg_header_t, out: *mut mach_msg_header_t) -> bool;
}

extern "C" {
    pub fn task_get_exception_ports(
        task: task_t,
        exception_mask: exception_mask_t,
        masks: exception_mask_array_t,
        masksCnt: *mut mach_msg_type_number_t,
        old_handlers: exception_handler_array_t,
        old_behaviors: exception_behavior_array_t,
        old_flavors: exception_flavor_array_t,
    ) -> kern_return_t;

    pub fn task_set_exception_ports(
        task: task_t,
        exception_mask: exception_mask_t,
        new_port: mach_port_t,
        behavior: exception_behavior_t,
        new_flavor: thread_state_flavor_t,
    ) -> kern_return_t;
}

#[repr(C)]
struct msg_t {
    head: mach_msg_header_t,
    body: mach_msg_body_t,
    data: [u8; 1024],
}

impl msg_t {
    pub fn len(&self) -> usize {
        size_of_val(self)
    }

    pub fn recv(&mut self, port: u32) -> kern_return_t {
        unsafe {
            mach_msg(
                &mut self.head,
                MACH_RCV_MSG | MACH_RCV_INTERRUPT,
                0,
                self.data.len() as _,
                port,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL,
            )
        }
    }

    pub fn decode(&mut self, msg: &mut mach_msg_header_t) -> bool {
        unsafe { mach_exc_server(&mut self.head, msg) }
    }

    pub fn send(&mut self) -> kern_return_t {
        unsafe {
            mach_msg(
                &mut self.head,
                MACH_SEND_MSG,
                self.head.msgh_size,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL,
            )
        }
    }
}

pub struct MachPort(mach_port_t);

impl MachPort {
    pub fn new(port: mach_port_t) -> MachPort {
        MachPort(port)
    }

    pub fn as_raw(&self) -> mach_port_t {
        self.0
    }
}

impl Drop for MachPort {
    fn drop(&mut self) {
        unsafe {
            mach_port_deallocate(mach_task_self(), self.0);
        }
    }
}

pub struct DefaultEngine {
    pub targets: Vec<Arc<ProcessTarget>>,
    pub inited: bool,
    pub cloned_tids: HashSet<tid_t>,
    pub tid: tid_t,
    excp_port: MachPort,
}

impl Default for DefaultEngine {
    fn default() -> Self {
        Self {
            targets: Default::default(),
            inited: false,
            tid: 0,
            cloned_tids: Default::default(),
            excp_port: Self::new_exception_port().unwrap(),
        }
    }
}

impl DefaultEngine {
    pub fn new_exception_port() -> anyhow::Result<MachPort> {
        unsafe {
            let mut raw_port = 0;
            Errno::result(mach_port_allocate(
                mach_task_self(),
                MACH_PORT_RIGHT_RECEIVE,
                &mut raw_port,
            ))
            .context("allocate")?;
            let port = MachPort::new(raw_port);
            Errno::result(mach_port_insert_right(
                mach_task_self(),
                raw_port,
                raw_port,
                MACH_MSG_TYPE_MAKE_SEND,
            ))
            .context("insert right")?;
            Ok(port)
        }
    }
}

impl UDbgEngine for DefaultEngine {
    fn open(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgTarget>> {
        Ok(ProcessTarget::open(pid)?)
    }

    fn attach(&mut self, pid: pid_t) -> UDbgResult<Arc<dyn UDbgTarget>> {
        let this = ProcessTarget::open(pid)?;
        this.set_exception_port(self.excp_port.0)?;
        self.targets.push(this.clone());
        Ok(this)
    }

    fn create(
        &mut self,
        path: &str,
        cwd: Option<&str>,
        args: &[&str],
    ) -> UDbgResult<Arc<dyn UDbgTarget>> {
        let this = ProcessTarget::create(path, args)?;
        this.set_exception_port(self.excp_port.0)?;
        self.targets.push(this.clone());
        self.tid = this.pid() as _;
        Ok(this)
    }

    fn event_loop<'a>(&mut self, callback: &mut UDbgCallback<'a>) -> UDbgResult<()> {
        let mut buf = TraceBuf {
            callback,
            user: unsafe { core::mem::zeroed() },
            si: unsafe { core::mem::zeroed() },
            regs_dirty: false,
            target: self
                .targets
                .iter()
                .next()
                .map(Clone::clone)
                .context("no attached target")?,
        };

        buf.call(UEvent::InitBp);
        self.targets.iter().for_each(|target| {
            ptrace::cont(Pid::from_raw(target.process.pid), None);
        });

        let mut rmsg: msg_t = unsafe { core::mem::zeroed() };
        let mut smsg: msg_t = unsafe { core::mem::zeroed() };
        while !self.targets.is_empty() {
            let err = rmsg.recv(self.excp_port.as_raw());
            match err {
                MACH_RCV_INTERRUPTED => {
                    warn!("MACH_RCV_INTERRUPTED");
                    continue;
                }
                MACH_RCV_TIMED_OUT => {
                    warn!("MACH_RCV_TIMED_OUT");
                    continue;
                }
                0 => {}
                _ => {
                    warn!("recv err: {err:x}");
                    continue;
                }
            };
            info!("recved");
            if !rmsg.decode(&mut smsg.head) {
                warn!("decode failed");
                break;
            }
            smsg.send();
            info!("sended");
        }

        Ok(())
    }
}

impl ReadValue<Vec<u8>> for mach_header {
    fn read_value<R: ReadMemoryUtils + ?Sized>(r: &R, address: usize) -> Option<Vec<u8>> {
        r.read_copy::<mach_header>(address).map(|header| {
            let mut size = core::mem::size_of::<mach_header>();
            size += header.sizeofcmds as usize;
            r.read_bytes(address, size)
        })
    }
}

impl ReadValue<Vec<u8>> for mach_header_64 {
    fn read_value<R: ReadMemoryUtils + ?Sized>(r: &R, address: usize) -> Option<Vec<u8>> {
        r.read_copy::<mach_header_64>(address).map(|header| {
            let mut size = core::mem::size_of::<mach_header_64>();
            size += header.sizeofcmds as usize;
            r.read_bytes(address, size)
        })
    }
}

use goblin::mach::segment::Segments;
fn parse_partial_macho(bytes: &[u8]) -> goblin::error::Result<(header::Header, Segments)> {
    use goblin::error;
    use scroll::{ctx::SizeWith, Pread};

    let mut offset = 0;
    let (magic, maybe_ctx) = parse_magic_and_ctx(bytes, offset)?;
    let ctx = if let Some(ctx) = maybe_ctx {
        ctx
    } else {
        return Err(error::Error::BadMagic(u64::from(magic)));
    };
    debug!("Ctx: {:?}", ctx);
    let offset = &mut offset;
    let header: header::Header = bytes.pread_with(*offset, ctx)?;
    debug!("Mach-o header: {:?}", header);
    let little_endian = ctx.le.is_little();
    let is_64 = ctx.container.is_big();
    *offset += header::Header::size_with(&ctx.container);
    let ncmds = header.ncmds;

    let sizeofcmds = header.sizeofcmds as usize;
    // a load cmd is at least 2 * 4 bytes, (type, sizeof)
    if ncmds > sizeofcmds / 8 || sizeofcmds > bytes.len() {
        return Err(error::Error::BufferTooShort(ncmds, "load commands"));
    }

    let mut cmds: Vec<load_command::LoadCommand> = Vec::with_capacity(ncmds);
    let mut export_trie = None;
    let mut bind_interpreter = None;
    let mut main_entry_offset = None;
    let mut segments = segment::Segments::new(ctx);
    for i in 0..ncmds {
        let cmd = load_command::LoadCommand::parse(bytes, offset, ctx.le)?;
        debug!("{} - {:?}", i, cmd);
        match cmd.command {
            load_command::CommandVariant::Segment32(command) => {
                // FIXME: we may want to be less strict about failure here, and just return an empty segment to allow parsing to continue?
                segment::Segment::from_32(bytes, &command, cmd.offset, ctx)
                    // .log_warn("parse seg32")
                    .map(|seg| segments.push(seg));
            }
            load_command::CommandVariant::Segment64(command) => {
                segment::Segment::from_64(bytes, &command, cmd.offset, ctx)
                    // .log_error("parse seg64")
                    .map(|seg| segments.push(seg));
            }
            load_command::CommandVariant::Symtab(command) => {
                // symbols = Some(symbols::Symbols::parse(bytes, &command, ctx)?);
            }
            load_command::CommandVariant::LoadDylib(command)
            | load_command::CommandVariant::LoadUpwardDylib(command)
            | load_command::CommandVariant::ReexportDylib(command)
            | load_command::CommandVariant::LoadWeakDylib(command)
            | load_command::CommandVariant::LazyLoadDylib(command) => {}
            load_command::CommandVariant::Rpath(command) => {}
            load_command::CommandVariant::DyldInfo(command)
            | load_command::CommandVariant::DyldInfoOnly(command) => {
                export_trie = Some(exports::ExportTrie::new(bytes, &command));
                bind_interpreter = Some(imports::BindInterpreter::new(bytes, &command));
            }
            load_command::CommandVariant::DyldExportsTrie(command) => {}
            load_command::CommandVariant::Unixthread(command) => {}
            load_command::CommandVariant::Main(command) => {
                // dyld cares only about the first LC_MAIN
                if main_entry_offset.is_none() {
                    main_entry_offset = Some(command.entryoff);
                }
            }
            load_command::CommandVariant::IdDylib(command) => {}
            _ => (),
        }
        cmds.push(cmd)
    }
    Ok((header, segments))
}
