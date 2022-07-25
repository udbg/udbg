//! [`MiniDumpTarget`] implementation

use crate::{os::priority_t, pe::*, prelude::*, range::RangeValue};

use anyhow::Context;
use memmap2::Mmap;
use minidump::*;
use serde_value::Value as SerdeValue;
use std::{path::Path, sync::Arc};

#[derive(Deref)]
pub struct MiniDumpTarget {
    base: TargetBase,
    #[deref]
    dump: Minidump<'static, Mmap>,
    memory: Vec<MemoryPage>,
}

unsafe impl Send for MiniDumpTarget {}
unsafe impl Sync for MiniDumpTarget {}

impl ReadMemory for MiniDumpTarget {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let mem = self
            .dump
            .get_stream::<MinidumpMemoryList>()
            .context("memory")
            .unwrap();

        let m = mem.memory_at_address(addr as _)?;
        let offset = addr - m.base_address as usize;
        let src = &m.bytes[offset..m.bytes.len().min(offset + data.len())];
        let dst = &mut data[..src.len()];
        dst.copy_from_slice(src);
        Some(dst)
    }
}

impl WriteMemory for MiniDumpTarget {
    fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        None
    }
}

impl From<&MinidumpMemoryInfo<'_>> for MemoryPage {
    fn from(m: &MinidumpMemoryInfo<'_>) -> MemoryPage {
        let range = m.memory_range().unwrap();
        MemoryPage {
            base: range.start as _,
            alloc_base: range.start as _,
            size: (range.end - range.start) as _,
            type_: m.ty.bits(),
            state: m.state.bits(),
            protect: m.protection.bits(),
            alloc_protect: m.allocation_protection.bits(),
            ..Default::default()
        }
    }
}

impl TargetMemory for MiniDumpTarget {
    fn enum_memory(&self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + '_>> {
        Ok(Box::new(self.memory.iter().map(Clone::clone)))
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        RangeValue::binary_search(&self.memory, address).cloned()
    }

    fn collect_memory_info(&self) -> Vec<MemoryPage> {
        self.memory.iter().map(Clone::clone).collect()
    }
}

impl GetProp for MiniDumpTarget {
    fn get_prop(&self, key: &str) -> UDbgResult<SerdeValue> {
        match key {
            _ => Ok(SerdeValue::Unit),
        }
    }
}

impl TargetControl for MiniDumpTarget {
    fn detach(&self) -> UDbgResult<()> {
        self.base.status.set(UDbgStatus::Detaching);
        Ok(())
    }

    fn kill(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
}

impl BreakpointManager for MiniDumpTarget {}

pub struct MiniDumpModule {
    data: ModuleData,
    dump: MinidumpModule,
}

impl From<MinidumpModule> for MiniDumpModule {
    fn from(dump: MinidumpModule) -> Self {
        let name: Arc<str> = dump.name.as_str().into();
        Self {
            data: ModuleData {
                base: dump.raw.base_of_image as _,
                size: dump.raw.size_of_image as _,
                path: name.clone(),
                name,
                arch: std::env::consts::ARCH,
                entry: 0,
                user_module: true.into(),
            },
            dump,
        }
    }
}

impl GetProp for MiniDumpModule {}

impl UDbgModule for MiniDumpModule {
    fn data(&self) -> &ModuleData {
        &self.data
    }

    fn symbol_status(&self) -> SymbolStatus {
        SymbolStatus::Unload
    }
}

impl TargetSymbol for MiniDumpTarget {
    fn find_module(&self, address: usize) -> Option<Arc<dyn UDbgModule>> {
        let modules = self.get_stream::<MinidumpModuleList>().ok()?;
        Some(Arc::new(MiniDumpModule::from(
            modules.module_at_address(address as _)?.clone(),
        )))
    }

    fn get_module(&self, name: &str) -> Option<Arc<dyn UDbgModule>> {
        Some(Arc::new(MiniDumpModule::from(
            self.get_stream::<MinidumpModuleList>()
                .ok()?
                .iter()
                .find(|m| m.name == name)?
                .clone(),
        )))
    }

    fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a> {
        let modules = self
            .get_stream::<MinidumpModuleList>()
            .context("get modules")
            .unwrap();
        let mut i = (0..).into_iter();
        Box::new(core::iter::from_fn(move || {
            Some(
                Arc::new(MiniDumpModule::from(modules.iter().nth(i.next()?)?.clone()))
                    as Arc<dyn UDbgModule>,
            )
        }))
    }

    fn remove(&self, address: usize) {
        todo!()
    }
}

impl Target for MiniDumpTarget {
    fn base(&self) -> &TargetBase {
        &self.base
    }

    /// Executable image path of target
    fn image_path(&self) -> UDbgResult<String> {
        Ok(self
            .dump
            .get_stream::<MinidumpModuleList>()
            .context("module list")?
            .main_module()
            .context("main module")?
            .name
            .clone())
    }

    fn symbol_manager(&self) -> Option<&dyn TargetSymbol> {
        Some(self)
    }

    fn enum_thread(
        &self,
        detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>> {
        let names = self
            .get_stream::<MinidumpThreadNames>()
            .context("get names")?;
        let iter = self
            .get_stream::<MinidumpThreadList>()
            .context("get stream")?
            .threads
            .into_iter()
            .map(move |t| {
                let data = ThreadData {
                    tid: t.raw.thread_id as _,
                    wow64: false,
                    ..unsafe { core::mem::zeroed() }
                };
                Box::new(MiniDumpThread {
                    name: names
                        .get_name(data.tid as _)
                        .unwrap_or_default()
                        .as_ref()
                        .into(),
                    data,
                    dump: unsafe { core::mem::transmute(t) },
                }) as Box<dyn UDbgThread>
            });
        Ok(Box::new(iter))
    }
}

impl UDbgTarget for MiniDumpTarget {}

#[derive(Deref)]
pub struct MiniDumpThread {
    #[deref]
    data: ThreadData,
    name: Arc<str>,
    dump: MinidumpThread<'static>,
}

impl GetProp for MiniDumpThread {}

impl UDbgThread for MiniDumpThread {
    fn name(&self) -> Arc<str> {
        self.name.clone()
    }

    fn status(&self) -> Arc<str> {
        "".into()
    }

    fn priority(&self) -> Option<priority_t> {
        Some(self.dump.raw.priority as _)
    }

    fn suspend_count(&self) -> usize {
        self.dump.raw.suspend_count as _
    }

    #[cfg(windows)]
    fn teb(&self) -> Option<usize> {
        Some(self.dump.raw.teb as _)
    }
}

impl MiniDumpTarget {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let dump = Minidump::read_path(path)?;
        let base = TargetBase::default();

        base.pid.set(
            dump.get_stream::<MinidumpMiscInfo>()
                .ok()
                .and_then(|m| m.raw.process_id().map(Clone::clone))
                .unwrap_or(1) as _,
        );

        let mut memory = if let Some(mem) = dump
            .get_stream::<MinidumpMemoryInfoList>()
            .log_error("get memoryinfo list")
        {
            mem.iter().map(|m| MemoryPage::from(m)).collect()
        } else if let Some(mem) = dump
            .get_stream::<MinidumpMemoryList>()
            .log_error("get memory list")
        {
            mem.iter()
                .map(|m| MemoryPage {
                    base: m.base_address as _,
                    alloc_base: m.base_address as _,
                    size: m.size as _,
                    state: MEM_COMMIT,
                    type_: MEM_PRIVATE,
                    protect: PAGE_READWRITE,
                    alloc_protect: PAGE_READWRITE,
                    ..Default::default()
                })
                .collect()
        } else {
            vec![]
        };
        memory.sort_by_key(|m| m.base);

        for t in dump
            .get_stream::<MinidumpThreadList>()
            .map(|x| x.threads)
            .unwrap_or_default()
        {
            RangeValue::binary_search_mut(&mut memory, t.raw.teb as _).map(|m| {
                m.info.replace(format!("TEB ~{}", t.raw.thread_id).into());
                m.flags |= MemoryFlags::TEB;
            });
            RangeValue::binary_search_mut(&mut memory, t.raw.stack.start_of_memory_range as _).map(
                |m| {
                    m.info.replace(format!("Stack ~{}", t.raw.thread_id).into());
                    m.flags |= MemoryFlags::STACK;
                },
            );
        }

        let mut this = Self {
            base,
            dump,
            memory: vec![],
        };
        for m in Target::enum_module(&this).into_iter().flatten() {
            let md = m.data();
            RangeValue::binary_search_mut(&mut memory, md.base).map(|m| {
                m.info.replace(md.path.clone());
                m.type_ = MEM_IMAGE;
                m.flags |= MemoryFlags::IMAGE;
                // TODO: mark each sections, read nt headers cross-platform
                // let nt = this.read_nt_header(md.base);
                // if let Some((nt, offset)) = nt {
                //     nt.FileHeader.SizeOfOptionalHeader
                // }
            });
        }
        this.memory = memory;
        Ok(this)
    }
}
