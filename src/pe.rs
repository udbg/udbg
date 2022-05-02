//! PE file helper && [`PETarget`] implementation

use crate::prelude::*;
use crate::range::RangeValue;

use anyhow::Context;
use goblin::pe::section_table::*;
use goblin::pe::PE;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::Arc;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;
pub const PAGE_ENCLAVE_THREAD_CONTROL: u32 = 0x80000000;
pub const PAGE_REVERT_TO_FILE_MAP: u32 = 0x80000000;
pub const PAGE_TARGETS_NO_UPDATE: u32 = 0x40000000;
pub const PAGE_TARGETS_INVALID: u32 = 0x40000000;
pub const PAGE_ENCLAVE_UNVALIDATED: u32 = 0x20000000;
pub const PAGE_ENCLAVE_DECOMMIT: u32 = 0x10000000;
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_DECOMMIT: u32 = 0x4000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_FREE: u32 = 0x10000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_RESET: u32 = 0x80000;
pub const MEM_TOP_DOWN: u32 = 0x100000;
pub const MEM_WRITE_WATCH: u32 = 0x200000;
pub const MEM_PHYSICAL: u32 = 0x400000;
pub const MEM_ROTATE: u32 = 0x800000;
pub const MEM_DIFFERENT_IMAGE_BASE_OK: u32 = 0x800000;
pub const MEM_RESET_UNDO: u32 = 0x1000000;
pub const MEM_LARGE_PAGES: u32 = 0x20000000;
pub const MEM_4MB_PAGES: u32 = 0x80000000;
pub const MEM_64K_PAGES: u32 = MEM_LARGE_PAGES | MEM_PHYSICAL;
pub const SEC_64K_PAGES: u32 = 0x00080000;
pub const SEC_FILE: u32 = 0x800000;
pub const SEC_IMAGE: u32 = 0x1000000;
pub const SEC_PROTECTED_IMAGE: u32 = 0x2000000;
pub const SEC_RESERVE: u32 = 0x4000000;
pub const SEC_COMMIT: u32 = 0x8000000;
pub const SEC_NOCACHE: u32 = 0x10000000;
pub const SEC_WRITECOMBINE: u32 = 0x40000000;
pub const SEC_LARGE_PAGES: u32 = 0x80000000;
pub const SEC_IMAGE_NO_EXECUTE: u32 = SEC_IMAGE | SEC_NOCACHE;
pub const MEM_IMAGE: u32 = SEC_IMAGE;

#[derive(Deref)]
pub struct PeHelper<'a>(pub PE<'a>);

impl<'a> PeHelper<'a> {
    pub fn get_pdb_path(&self) -> Option<&'a CStr> {
        self.debug_data
            .and_then(|d| d.codeview_pdb70_debug_info)
            .map(|d| unsafe { CStr::from_ptr(d.filename.as_ptr() as *const c_char) })
    }

    #[rustfmt::skip]
    pub fn get_pdb_signature(&self) -> Option<String> {
        self.debug_data
            .and_then(|d| d.codeview_pdb70_debug_info)
            .map(|d| unsafe {
                let (d1, d2, d3, d4): (u32, u16, u16, [u8; 8]) = std::mem::transmute(d.signature);
                format!(
                    "{:08X}{:04X}{:04X}{}{:X}",
                    d1, d2, d3, hex::encode_upper(&d4), d.age
                )
            })
    }

    pub fn section_by_rva(&self, rva: usize) -> Option<&SectionTable> {
        RangeValue::binary_search(&self.sections, rva)
    }

    pub fn rva_to_offset(&self, rva: usize) -> Option<usize> {
        let s = self.section_by_rva(rva)?;
        Some((rva as u32 - s.virtual_address + s.pointer_to_raw_data) as usize)
    }

    pub fn get_tls_dir_rva(&self) -> Option<usize> {
        self.header
            .optional_header?
            .data_directories
            .get_tls_table()
            .map(|d| d.virtual_address as usize)
    }

    pub fn get_arch(&self) -> Option<&'static str> {
        Self::arch_name(self.header.coff_header.machine)
    }

    pub fn parse(data: &'a [u8]) -> anyhow::Result<Self> {
        Ok(Self(PE::parse(data)?))
    }

    pub fn arch_name(m: u16) -> Option<&'static str> {
        use goblin::pe::header::*;
        Some(match m {
            COFF_MACHINE_X86_64 => "x86_64",
            COFF_MACHINE_X86 => "x86",
            COFF_MACHINE_ARM => "arm",
            COFF_MACHINE_ARM64 => "arm64",
            _ => return None,
        })
    }

    pub fn exported_symbols(&self) -> SymbolMap {
        let mut result = SymbolMap::default();
        for e in self.exports.iter() {
            let len = self
                .exception_data
                .as_ref()
                .and_then(|x| x.find_function(e.rva as u32).ok())
                .and_then(|f| f.map(|f| f.end_address - f.begin_address))
                .unwrap_or(SYM_NOLEN);
            result.insert(
                e.rva,
                Symbol {
                    name: e.name.unwrap_or_default().into(),
                    type_id: 0,
                    len,
                    offset: e.rva as u32,
                    flags: (SymbolFlags::FUNCTION | SymbolFlags::EXPORT).bits(),
                },
            );
        }
        result
    }
}

pub struct PEModule {
    pub data: ModuleData,
    pub syms: SymbolsData,
    helper: PeHelper<'static>,
    map: memmap2::Mmap,
    pages: Vec<MemoryPage>,
}

impl PEModule {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        unsafe {
            let path = path.as_ref();
            let pathstr = &path.to_string_lossy();
            let map = crate::util::Utils::mapfile(pathstr)?;
            let helper = PeHelper::parse(core::mem::transmute(map.as_ref()))?;
            let opt = helper
                .header
                .optional_header
                .as_ref()
                .context("optional header")?;
            let data = ModuleData {
                user_module: false.into(),
                base: helper.image_base,
                size: opt.windows_fields.size_of_image as _,
                entry: opt.standard_fields.address_of_entry_point as _,
                arch: helper.get_arch().unwrap_or_default(),
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into(),
                path: pathstr.as_ref().into(),
            };

            let sec = helper.sections.first().unwrap();
            let mut pages = vec![MemoryPage {
                alloc_base: data.base,
                base: data.base,
                size: sec.virtual_address as _,
                type_: MEM_IMAGE,
                state: MEM_COMMIT,
                protect: PAGE_READONLY,
                alloc_protect: PAGE_READONLY,
                info: Some(data.path.clone()),
                flags: MemoryFlags::IMAGE,
            }];
            pages.extend(helper.sections.iter().map(|sec| {
                let base = sec.virtual_address as usize + data.base;
                let ch = sec.characteristics;
                let protect = if IMAGE_SCN_MEM_EXECUTE & ch != 0 {
                    if IMAGE_SCN_MEM_WRITE & ch != 0 {
                        PAGE_EXECUTE_READWRITE
                    } else {
                        PAGE_EXECUTE_READ
                    }
                } else {
                    if IMAGE_SCN_MEM_WRITE & ch != 0 {
                        PAGE_READWRITE
                    } else {
                        PAGE_READONLY
                    }
                };
                MemoryPage {
                    alloc_base: base,
                    alloc_protect: protect,
                    base,
                    protect,
                    size: sec.virtual_size as _,
                    type_: MEM_COMMIT,
                    state: MEM_COMMIT,
                    info: Some(sec.name().unwrap_or_default().into()),
                    flags: MemoryFlags::IMAGE,
                }
            }));

            Ok(Self {
                syms: helper.symbols_data(pathstr),
                helper,
                map,
                data,
                pages,
            })
        }
    }

    pub fn helper(&self) -> &PeHelper<'_> {
        &self.helper
    }
}

impl GetProp for PEModule {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        Ok(serde_value::Value::Unit)
    }
}

impl UDbgModule for PEModule {
    fn data(&self) -> &ModuleData {
        &self.data
    }

    fn symbols_data(&self) -> Option<&SymbolsData> {
        Some(&self.syms)
    }

    // TODO:
    fn symbol_status(&self) -> SymbolStatus {
        SymbolStatus::Unload
    }
}

pub struct PETarget {
    base: TargetBase,
    symgr: SymbolManager<PEModule>,
}

unsafe impl Send for PETarget {}
unsafe impl Sync for PETarget {}

impl PETarget {
    pub fn new<P: AsRef<Path>>(path: P) -> UDbgResult<Self> {
        let module = PEModule::new(path.as_ref())?;
        let base = TargetBase::default();
        base.pid.set(1);
        // base.arch
        let symgr = SymbolManager::default();
        symgr.base.write().list.push(module.into());
        Ok(Self { base, symgr })
    }

    pub fn module(&self, addr: usize) -> Option<Arc<PEModule>> {
        SymbolManager::find_module(&self.symgr, addr)
    }
}

impl RangeValue for SectionTable {
    fn as_range(&self) -> std::ops::Range<usize> {
        let addr = self.virtual_address as _;
        let size = self.virtual_size as usize;
        addr..addr + size
    }
}

impl ReadMemory for PETarget {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let pe = self.module(addr)?;
        let rva = addr - pe.data.base;
        let i = pe.pages.binary_search_by(|x| x.cmp(rva)).ok()?;
        let page = pe.pages.get(i)?;
        let (offset, size) = if i > 0 {
            let sec = pe.helper.section_by_rva(rva)?;
            // TODO: section fill by zero
            let offset = (rva as u32 - sec.virtual_address + sec.pointer_to_raw_data) as usize;
            (offset, sec.virtual_size as usize - rva)
        } else {
            (0, page.size - rva)
        };
        let slice = &pe.map.as_ref()[offset..];
        let len = data.len().min(size);
        let res = &mut data[..len];
        res.copy_from_slice(&slice[..len]);
        Some(res)
    }
}

impl WriteMemory for PETarget {
    fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        None
    }
}

impl TargetMemory for PETarget {
    fn enum_memory(&self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + '_>> {
        let modules = self.symgr.base.read().list.clone();
        Ok(Box::new(
            modules
                .into_iter()
                .map(|pe| pe.pages.clone().into_iter())
                .flatten(),
        ))
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        let pe = self.module(address)?;
        RangeValue::binary_search(&pe.pages, address - pe.data.base).cloned()
    }

    fn collect_memory_info(&self) -> Vec<MemoryPage> {
        let modules = self.symgr.base.read().list.clone();
        modules
            .iter()
            .map(|pe| pe.pages.iter().map(Clone::clone))
            .flatten()
            .collect()
    }
}

impl TargetControl for PETarget {
    fn detach(&self) -> UDbgResult<()> {
        self.base.status.set(UDbgStatus::Detaching);
        Ok(())
    }

    fn kill(&self) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
}

impl Target for PETarget {
    fn base(&self) -> &TargetBase {
        &self.base
    }

    fn enum_thread(
        &self,
        detail: bool,
    ) -> UDbgResult<Box<dyn Iterator<Item = Box<dyn UDbgThread>> + '_>> {
        Ok(Box::new(core::iter::empty()))
    }

    fn symbol_manager(&self) -> Option<&dyn TargetSymbol> {
        Some(&self.symgr)
    }
}

impl GetProp for PETarget {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        Ok(serde_value::Value::Unit)
    }
}

impl BreakpointManager for PETarget {}

impl UDbgTarget for PETarget {}
