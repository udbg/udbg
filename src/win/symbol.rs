
use alloc::string::String;
use winapi::um::dbghelp::*;
use winapi::shared::minwindef::BOOL;

use crate::SymbolInfo;
use super::*;

use anyhow::Result;
use core::ptr::{null_mut, null};
use core::mem::{transmute, size_of, size_of_val, zeroed};
use core::slice::from_raw_parts;
use std::io::Error;

// https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-undecoratesymbolnamew
pub fn undecorate_symbol(sym: &str) -> Option<String> {
    unsafe {
        let mut buf = [0u16; 1000];
        if UnDecorateSymbolNameW(
            sym.to_unicode().as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            UNDNAME_NAME_ONLY) > 0
        { Some(buf.as_ref().to_utf8()) } else { None }
    }
}

pub trait SymbolApi {
    fn sym_init(&self, search_path: Option<&str>, invade: bool) -> Result<()>;
    fn sym_clean(&self);
    fn sym_load_module(&self, module_path: &str, base: u64, size: u32, flags: u32) -> Result<()>;
    // fn sym_add_symbol(&self, base: usize, name: &str, address: usize) -> bool;

    fn get_address_by_symbol(&self, symbol: &str) -> Result<usize>;
    fn get_symbol_by_address(&self, address: usize) -> Option<SymbolInfo>;
}

impl SymbolApi for Process {
    fn sym_init(&self, search_path: Option<&str>, invade: bool) -> Result<()> {
        unsafe {
            let search_path = search_path.map(|s| s.to_unicode());
            let search_path = match search_path { None => null(), Some(s) => s.as_ptr() };
            if SymInitializeW(*self.handle, search_path, invade as BOOL) > 0 {
                Ok(())
            } else { Err(Error::last_os_error().into()) }
        }
    }

    fn sym_clean(&self) { unsafe { SymCleanup(*self.handle); } }

    fn sym_load_module(&self, module_path: &str, base: u64, size: u32, flags: u32) -> Result<()> {
        const SPLIT1: u16 = b'\\' as u16;
        const SPLIT2: u16 = b'/' as u16;

        let path = module_path.to_unicode();
        unsafe {
            let name = match path.rsplit(|c| *c == SPLIT1 || *c == SPLIT2).next() {
                Some(n) => n.as_ptr(), None => path.as_ptr(),
            };
            if SymLoadModuleExW(*self.handle, null_mut(), path.as_ptr(), name, base, size, null_mut(), flags) > 0 {
                Ok(())
            } else { Err(Error::last_os_error().into()) }
        }
    }

    // fn sym_add_symbol(&self, base: usize, name: &str, address: usize) -> bool {
    //     unsafe { SymAddSymbolW(*self.handle, base, name.to_unicode().as_ptr(), address, 0, 0) > 0 }
    // }

    fn get_address_by_symbol(&self, symbol: &str) -> Result<usize> {
        unsafe {
            let mut buf = [0u8; size_of::<SYMBOL_INFOW>() + MAX_SYM_NAME * 2];
            let mut si: *mut SYMBOL_INFOW = transmute(buf.as_mut_ptr());
            (*si).SizeOfStruct = buf.len() as u32;
            (*si).MaxNameLen = MAX_SYM_NAME as u32;

            if SymFromNameW(*self.handle, symbol.to_unicode().as_ptr(), si) > 0 {
                Ok((*si).Address as usize)
            } else {
                let symbol = symbol.to_lowercase();
                for m in self.enum_module() {
                    let name = m.name().to_lowercase();
                    if name == symbol { return Ok(m.base()); }

                    let can_trim = name.ends_with(".dll") || name.ends_with(".exe");
                    if can_trim && name.len() > 4 && &name[..name.len() - 4] == symbol {
                        return Ok(m.base());
                    }
                }
                Err(Error::last_os_error().into())
            }
        }
    }

    fn get_symbol_by_address(&self, address: usize) -> Option<SymbolInfo> {
        unsafe {
            let mut buf = [0u8; size_of::<SYMBOL_INFOW>() + MAX_SYM_NAME * 2];
            let mut si: *mut SYMBOL_INFOW = transmute(buf.as_mut_ptr());
            (*si).SizeOfStruct = size_of::<SYMBOL_INFOW>() as u32;
            (*si).MaxNameLen = MAX_SYM_NAME as u32;

            let mut dis = 0 as u64;
            let mut im: IMAGEHLP_MODULEW64 = zeroed();
            im.SizeOfStruct = size_of_val(&im) as u32;
            SymGetModuleInfoW64(*self.handle, address as u64, &mut im);
            let module_name = im.ModuleName.to_utf8().into();

            if SymFromAddrW(*self.handle, address as u64, &mut dis, si) > 0 {
                let s = from_raw_parts((*si).Name.as_ptr(), (*si).NameLen as usize);
                Some(SymbolInfo {
                    module: module_name,
                    symbol: s.to_utf8().into(),
                    offset: dis as usize,
                    mod_base: im.BaseOfImage as usize,
                })
            } else if !module_name.is_empty() {
                Some(SymbolInfo {
                    module: module_name,
                    symbol: "".into(),
                    offset: 0,
                    mod_base: im.BaseOfImage as usize,
                })
            } else { None }
        }
    }
}