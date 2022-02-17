
use super::{*, process::*};

use std::cell::Cell;
use std::{sync::Arc, collections::HashSet};
use std::collections::HashMap;
use parking_lot::RwLock;

use libc::pid_t;
use crate::{*, sym::*};

pub struct CommonAdaptor {
    base: UDbgBase,
    ps: Process,
    symgr: SymbolManager<NixModule>,
    pub bp_map: RwLock<HashMap<BpID, Arc<Breakpoint>>>,
    threads: RwLock<HashSet<pid_t>>,
    mem_pages: RwLock<Vec<MemoryPage>>,
    detaching: Cell<bool>,
    waiting: Cell<bool>,
}

impl CommonAdaptor {
    fn new(mut base: UDbgBase, ps: Process) -> Self {
        base.pid.set(ps.pid);
        base.image_path = process_path(ps.pid).unwrap_or_default();
        Self {
            base, ps,
            bp_map: RwLock::new(HashMap::new()),
            symgr: SymbolManager::<NixModule>::new("".into()),
            mem_pages: RwLock::new(Vec::new()),
            threads: RwLock::new(HashSet::new()),
            waiting: Cell::new(false), detaching: Cell::new(false),
        }
    }

    // TODO:
    pub fn enable_breadpoint(&self, bp: &Breakpoint, enable: bool) -> UDbgResult<bool> {
        Ok(true)
    }

    fn update_module(&self) -> Result<(), String> {
        for m in self.ps.list_module() {
            if self.symgr.find_module(m.base).is_some() { continue; }
            // let name = self.module_name(&m.name);

            // // TODO: use memory data
            // let mut f = match File::open(m.path.as_ref()) {
            //     Ok(f) => f, Err(_) => {
            //         error!("open module file: {}", m.path);
            //         continue;
            //     }
            // };
            // let mut buf: Header64 = unsafe { std::mem::zeroed() };
            // if f.read_exact(buf.as_mut_byte_array()).is_err() {
            //     error!("read file: {}", m.path);
            //     continue;
            // }
            
            // let arch = match elf::machine_to_arch(buf.e_machine) {
            //     Some(a) => a, None => {
            //         error!("error e_machine: {} {}", buf.e_machine, m.path);
            //         continue;
            //     }
            // };

            // let entry = match arch {
            //     "arm64" | "x86_64" => buf.e_entry as usize,
            //     "x86" | "arm" => unsafe { transmute::<_, &Header32>(&buf).e_entry as usize }
            //     a => { error!("error arch: {}", a); continue; }
            // };

            let base = m.base;
            let path = m.path.clone();
            self.symgr.base.write().add(NixModule {
                data: m,
                loaded: false.into(),
                syms: Default::default(),
            });
            // TODO:
            // self.base.module_load(&path, base);
        }
        Ok(())
    }
}

#[derive(Deref)]
pub struct StandardAdaptor(CommonAdaptor);

unsafe impl Send for StandardAdaptor {}
unsafe impl Sync for StandardAdaptor {}

impl AsRef<Process> for StandardAdaptor {
    #[inline]
    fn as_ref(&self) -> &Process { &self.0.ps }
}

impl AdaptorSpec for StandardAdaptor {}
impl GetProp for StandardAdaptor {}

impl UDbgAdaptor for StandardAdaptor {
    fn base(&self) -> &UDbgBase {
        &self.0.base
    }

    fn get_memory_map(&self) -> Vec<UiMemory> {
        todo!()
    }

    fn enum_thread<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=tid_t>+'a>> {
        todo!()
    }

    fn symbol_manager(&self) -> Option<&dyn UDbgSymMgr> {
        Some(&self.symgr)
    }

    fn get_thread_context(&self, tid: u32) -> Option<regs::Registers> { None }

    fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<dyn UDbgThread>> { Err(UDbgError::NotSupport) }

    fn open_all_thread(&self) -> Vec<Box<dyn UDbgThread>> {
        self.ps.list_thread().map(|ts| ts.iter().map(|&ts| {
            let handle = ThreadAct(ts);
            Box::new(MacThread {
                data: ThreadData {
                    tid: handle.id(),
                    wow64: false,
                    handle,
                }
            }) as Box<dyn UDbgThread>
        }).collect::<Vec<_>>()).unwrap_or_default()
    }

    fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<dyn UDbgBreakpoint>> { Err(UDbgError::NotSupport) }

    fn get_bp<'a>(&'a self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + 'a>> { None }

    fn get_bp_by_address<'a>(&'a self, a: usize) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        self.get_bp(a as BpID)
    }

    fn get_bp_list(&self) -> Vec<BpID> { vec![] }

    fn get_breakpoints<'a>(&'a self) -> Vec<Arc<dyn UDbgBreakpoint + 'a>> {
        self.get_bp_list().into_iter().filter_map(|id| self.get_bp(id)).collect()
    }

    fn enum_handle<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item=UiHandle>+'a>> {
        // self.ps.
        todo!()
    }

    fn get_registers<'a>(&'a self) -> UDbgResult<&'a mut dyn regs::UDbgRegs> {
        Err(UDbgError::NotSupport)
    }

    fn except_param(&self, i: usize) -> Option<usize> { None }

    fn do_cmd(&self, cmd: &str) -> UDbgResult<()> { Err(UDbgError::NotSupport) }

    fn event_loop<'a>(&self, callback: &mut UDbgCallback<'a>) -> UDbgResult<()> {
        if self.base().is_opened() {
            use std::time::Duration;
            while self.base().status.get() != UDbgStatus::Ended {
                std::thread::sleep(Duration::from_millis(10));
            }
            return Ok(());
        }
        Err(UDbgError::NotSupport)
    }
}

impl StandardAdaptor {
    pub fn open(base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<Self>> {
        Ok(Self(CommonAdaptor::new(base, Process::from_pid(pid)?)).into())
    }
}

pub struct DefaultEngine;

impl UDbgEngine for DefaultEngine {
    fn open(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Ok(StandardAdaptor::open(base, pid)?)
    }

    fn attach(&self, base: UDbgBase, pid: pid_t) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Err(UDbgError::NotSupport)
    }
    
    fn create(&self, base: UDbgBase, path: &str, cwd: Option<&str>, args: &[&str]) -> UDbgResult<Arc<dyn UDbgAdaptor>> {
        Err(UDbgError::NotSupport)
    }
}