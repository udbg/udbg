//! PE file helper

use crate::prelude::*;
use crate::range::RangeValue;

use anyhow::Context;
use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use std::ffi::CStr;
use std::os::raw::c_char;

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
}

impl PEModule {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        unsafe {
            let map = crate::util::Utils::mapfile(path)?;
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
                name: std::path::Path::new(path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into(),
                path: path.into(),
            };
            Ok(Self {
                syms: helper.symbols_data(path),
                helper,
                map,
                data,
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
    modules: Vec<PEModule>,
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
        let pe = RangeValue::binary_search(&self.modules, addr)?;
        let rva = addr - pe.data.base;
        let sec = pe.helper.section_by_rva(rva)?;
        // TODO: section fill by zero
        let offset = (rva as u32 - sec.virtual_address + sec.pointer_to_raw_data) as usize;
        let slice = &pe.map.as_ref()[offset..];
        let len = data.len().min(slice.len());
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
        todo!()
    }

    fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        todo!()
    }

    fn collect_memory_info(&self) -> Vec<MemoryPageInfo> {
        todo!()
    }
}
