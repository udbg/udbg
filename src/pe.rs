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

    pub fn get_pdb_signature(&self) -> Option<String> {
        self.debug_data
            .and_then(|d| d.codeview_pdb70_debug_info)
            .map(|d| unsafe {
                let g = std::mem::transmute::<_, &guid::GUID>(&d.signature);
                format!(
                    "{:08X}{:04X}{:04X}{}{:X}",
                    g.data1(),
                    g.data2(),
                    g.data3(),
                    hex::encode_upper(&g.data4()),
                    d.age
                )
            })
    }

    pub fn rva_to_offset(&self, rva: usize) -> Option<usize> {
        let rva = rva as u32;
        let s = self
            .sections
            .iter()
            .find(|r| rva >= r.virtual_address && rva < r.virtual_address + r.virtual_size)?;
        Some((rva - s.virtual_address + s.pointer_to_raw_data) as usize)
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

    pub fn parse(data: &'a [u8]) -> Option<Self> {
        PE::parse(data).ok().map(|pe| Self(pe))
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
}
