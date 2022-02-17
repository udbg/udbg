
use std::ffi::CStr;
use std::os::raw::c_char;
use goblin::pe::PE;

#[derive(Deref)]
pub struct PeHelper<'a>(pub PE<'a>);

impl<'a> PeHelper<'a> {
    pub fn get_pdb_path(&self) -> Option<&'a CStr> {
        self.debug_data.and_then(|d| d.codeview_pdb70_debug_info)
                       .map(|d| unsafe { CStr::from_ptr(d.filename.as_ptr() as *const c_char) })
    }

    pub fn get_pdb_signature(&self) -> Option<String> {
        use crate::util::HexBuf;

        self.debug_data.and_then(|d| d.codeview_pdb70_debug_info).map(|d| unsafe {
            let g = std::mem::transmute::<_, &guid::GUID>(&d.signature);
            format!("{:08X}{:04X}{:04X}{}{:X}", g.data1(), g.data2(), g.data3(), HexBuf(&g.data4()), d.age)
        })
    }

    pub fn rva_to_offset(&self, rva: usize) -> Option<usize> {
        let rva = rva as u32;
        let s = self.sections.iter().find(|r| rva >= r.virtual_address && rva < r.virtual_address + r.virtual_size)?;
        Some((rva - s.virtual_address + s.pointer_to_raw_data) as usize)
    }

    pub fn get_tls_dir_rva(&self) -> Option<usize> {
        self.header.optional_header?.data_directories.get_tls_table().map(|d| d.virtual_address as usize)
    }

    pub fn get_arch(&self) -> &'static str { machine_to_arch(self.header.coff_header.machine) }
}

pub fn parse(data: &[u8]) -> Option<PeHelper> {
    PE::parse(data).ok().map(|pe| PeHelper(pe))
}

pub fn machine_to_arch(m: u16) -> &'static str {
    use goblin::pe::header::*;
    match m {
        COFF_MACHINE_X86_64 => "x86_64",
        COFF_MACHINE_X86 => "x86",
        COFF_MACHINE_ARM => "arm",
        COFF_MACHINE_ARM64 => "arm64", _ => "",
    }
}