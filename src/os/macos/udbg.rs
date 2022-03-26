use super::process::*;

use mach_o_sys::dyld::x86_thread_state;
use nix::sys::wait::WaitPidFlag;
use parking_lot::RwLock;
use std::cell::{Cell, UnsafeCell};
use std::collections::HashMap;
use std::{collections::HashSet, sync::Arc};

use crate::os::unix::udbg::TraceBuf;
use crate::os::{pid_t, tid_t, NixModule};
use crate::prelude::*;

pub const WAIT_PID_FLAG: WaitPidFlag = WaitPidFlag::WUNTRACED;

pub struct CommonAdaptor {
    pub base: TargetBase,
    pub ps: Process,
    pub symgr: SymbolManager<NixModule>,
    pub bp_map: RwLock<HashMap<BpID, Arc<Breakpoint>>>,
    pub threads: RwLock<HashSet<tid_t>>,
    mem_pages: RwLock<Vec<MemoryPage>>,
    pub detaching: Cell<bool>,
    pub regs: UnsafeCell<x86_thread_state>,
    waiting: Cell<bool>,
}

impl CommonAdaptor {
    pub fn new(ps: Process) -> Self {
        let mut base = TargetBase::default();
        base.pid.set(ps.pid);
        base.image_path = process_path(ps.pid).unwrap_or_default();
        Self {
            base,
            ps,
            regs: unsafe { core::mem::zeroed() },
            bp_map: RwLock::new(HashMap::new()),
            symgr: SymbolManager::<NixModule>::new("".into()),
            mem_pages: RwLock::new(Vec::new()),
            threads: RwLock::new(HashSet::new()),
            waiting: Cell::new(false),
            detaching: Cell::new(false),
        }
    }

    // TODO:
    pub fn enable_breadpoint(&self, bp: &Breakpoint, enable: bool) -> UDbgResult<bool> {
        Ok(true)
    }

    fn update_module(&self) -> Result<(), String> {
        use anyhow::Context;
        use goblin::mach::MachO;

        for mut m in self.ps.list_module() {
            if self.symgr.find_module(m.base).is_some() {
                continue;
            }

            // MachO::parse(bytes, offset)
            let nm = (|| -> anyhow::Result<_> {
                let data =
                    Utils::mapfile(&m.path).with_context(|| format!("map file: {}", m.path))?;
                let mach = MachO::parse(&data, 0).context("parse macho")?;
                let base = m.base;
                let path = m.path.clone();
                m.entry = mach.entry as _;
                m.size = mach.segments.iter().map(|s| s.cmdsize).sum::<u32>() as _;
                Ok(())
            })();

            nm.map_err(|e| error!("{e:?}"));
            self.symgr.base.write().add(NixModule {
                data: m,
                loaded: false.into(),
                syms: Default::default(),
            });
        }
        Ok(())
    }
}

#[derive(Deref)]
pub struct StandardAdaptor(pub CommonAdaptor);

unsafe impl Send for StandardAdaptor {}
unsafe impl Sync for StandardAdaptor {}

impl AsRef<Process> for StandardAdaptor {
    #[inline]
    fn as_ref(&self) -> &Process {
        &self.0.ps
    }
}

impl GetProp for StandardAdaptor {}

impl BreakpointManager for StandardAdaptor {
    fn add_bp(&self, opt: BpOpt) -> UDbgResult<Arc<dyn UDbgBreakpoint>> {
        Err(UDbgError::NotSupport)
    }

    fn get_bp<'a>(&'a self, id: BpID) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        None
    }

    fn get_bp_by_address<'a>(&'a self, a: usize) -> Option<Arc<dyn UDbgBreakpoint + 'a>> {
        self.get_bp(a as BpID)
    }

    fn get_bp_list(&self) -> Vec<BpID> {
        vec![]
    }

    fn get_breakpoints<'a>(&'a self) -> Vec<Arc<dyn UDbgBreakpoint + 'a>> {
        self.get_bp_list()
            .into_iter()
            .filter_map(|id| self.get_bp(id))
            .collect()
    }
}

impl Target for StandardAdaptor {
    fn base(&self) -> &TargetBase {
        &self.0.base
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
        Ok(Box::new(self.ps.list_thread()?.to_vec().into_iter().map(
            |ts| {
                let handle = ThreadAct(ts);
                Box::new(MacThread {
                    data: ThreadData {
                        tid: handle.id(),
                        wow64: false,
                        handle,
                    },
                }) as Box<dyn UDbgThread>
            },
        )))
    }

    fn open_thread(&self, tid: tid_t) -> UDbgResult<Box<dyn UDbgThread>> {
        Err(UDbgError::NotSupport)
    }

    fn enum_handle<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = HandleInfo> + 'a>> {
        Ok(Box::new(process_fds(self.ps.pid)))
    }
}

impl UDbgAdaptor for StandardAdaptor {
    fn get_registers(&self) -> UDbgResult<&mut dyn UDbgRegs> {
        Err(UDbgError::NotSupport)
    }

    fn except_param(&self, i: usize) -> Option<usize> {
        None
    }
}

impl StandardAdaptor {
    pub fn open(pid: pid_t) -> UDbgResult<Arc<Self>> {
        Ok(Self(CommonAdaptor::new(Process::from_pid(pid)?)).into())
    }

    pub fn insert_thread(&self, tid: tid_t) {}
    pub fn remove_thread(&self, id: tid_t, s: i32, tb: &mut TraceBuf) {}

    pub fn update_regs(&self, tid: tid_t) {}
}

#[test]
fn test() {
    let a = StandardAdaptor::open(std::process::id() as _).unwrap();
    for m in a.enum_module().unwrap() {
        // println!("{}", m.data().path);
    }

    for p in a.collect_memory_info() {
        println!("{}", p.usage);
    }
}
