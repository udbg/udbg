//! Practical wrappers for windows dbghelp

use alloc::string::String;
use windows::{
    core::w,
    Win32::{
        Foundation::{BOOL, HANDLE},
        System::Diagnostics::Debug::*,
    },
};

use super::*;
use crate::symbol::SymbolInfo;

use anyhow::Result;
use core::mem::{size_of, size_of_val, transmute, zeroed};
use core::ptr::null;
use core::slice::from_raw_parts;
use std::{ffi::c_void, io::Error};

pub fn sym_get_options() -> u32 {
    unsafe { SymGetOptions() }
}

pub fn sym_set_options(option: u32) -> u32 {
    unsafe { SymSetOptions(option) }
}

// https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-undecoratesymbolnamew
pub fn undecorate_symbol(sym: &str) -> Option<String> {
    unsafe {
        let mut buf = [0u16; 1000];
        let sym = sym.to_unicode();
        if UnDecorateSymbolNameW(PCWSTR(sym.as_ptr()), &mut buf, UNDNAME_NAME_ONLY) > 0 {
            Some(buf.as_ref().to_utf8())
        } else {
            None
        }
    }
}

impl Process {
    pub fn sym_init(&self, search_path: Option<&str>, invade: bool) -> windows::core::Result<()> {
        unsafe {
            let search_path = search_path.map(|s| s.to_unicode());
            let search_path = match search_path {
                None => null(),
                Some(s) => s.as_ptr(),
            };
            SymInitializeW(*self.handle, PCWSTR(search_path), invade)
        }
    }

    pub fn sym_clean(&self) {
        unsafe {
            SymCleanup(*self.handle).ok();
        }
    }

    pub fn sym_load_module(
        &self,
        module_path: &str,
        base: u64,
        size: u32,
        flags: SYM_LOAD_FLAGS,
    ) -> Result<()> {
        const SPLIT1: u16 = b'\\' as u16;
        const SPLIT2: u16 = b'/' as u16;

        let path = module_path.to_unicode();
        unsafe {
            let name = match path.rsplit(|c| *c == SPLIT1 || *c == SPLIT2).next() {
                Some(n) => n.as_ptr(),
                None => path.as_ptr(),
            };
            if SymLoadModuleExW(
                *self.handle,
                HANDLE::default(),
                PCWSTR(path.as_ptr()),
                PCWSTR(name),
                base,
                size,
                None,
                flags,
            ) > 0
            {
                Ok(())
            } else {
                Err(Error::last_os_error().into())
            }
        }
    }

    // pub fn sym_add_symbol(&self, base: usize, name: &str, address: usize) -> bool {
    //     unsafe { SymAddSymbolW(*self.handle, base, name.to_unicode().as_ptr(), address, 0, 0) > 0 }
    // }

    pub fn get_address_by_symbol(&self, symbol: &str) -> Result<usize> {
        unsafe {
            let mut buf = [0u8; size_of::<SYMBOL_INFOW>() + MAX_SYM_NAME as usize * 2];
            let si = buf.as_mut_ptr().cast::<SYMBOL_INFOW>().as_mut().unwrap();
            si.SizeOfStruct = buf.len() as u32;
            si.MaxNameLen = MAX_SYM_NAME;

            let name = symbol.to_unicode();
            if SymFromNameW(*self.handle, PCWSTR(name.as_ptr()), si).is_ok() {
                Ok(si.Address as usize)
            } else {
                let symbol = symbol.to_lowercase();
                for m in self.enum_module()? {
                    let name = m.name().to_lowercase();
                    if name == symbol {
                        return Ok(m.base());
                    }

                    let can_trim = name.ends_with(".dll") || name.ends_with(".exe");
                    if can_trim && name.len() > 4 && &name[..name.len() - 4] == symbol {
                        return Ok(m.base());
                    }
                }
                Err(Error::last_os_error().into())
            }
        }
    }

    pub fn get_symbol_by_address(&self, address: usize) -> Option<SymbolInfo> {
        unsafe {
            let mut buf = [0u8; size_of::<SYMBOL_INFOW>() + MAX_SYM_NAME as usize * 2];
            let si = buf.as_mut_ptr().cast::<SYMBOL_INFOW>().as_mut().unwrap();
            si.SizeOfStruct = buf.len() as u32;
            si.MaxNameLen = MAX_SYM_NAME;

            let mut dis = 0 as u64;
            let mut im: IMAGEHLP_MODULEW64 = zeroed();
            im.SizeOfStruct = size_of_val(&im) as u32;
            SymGetModuleInfoW64(*self.handle, address as u64, &mut im);
            let module_name = im.ModuleName.to_utf8().into();

            if SymFromAddrW(*self.handle, address as u64, Some(&mut dis), si).is_ok() {
                let s = from_raw_parts(si.Name.as_ptr(), si.NameLen as usize);
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
            } else {
                None
            }
        }
    }

    pub fn enum_symbols(
        &self,
        module: usize,
        callback: &dyn FnMut(usize, Arc<str>) -> bool,
    ) -> bool {
        // const SYMENUM_OPTIONS_DEFAULT: u32 = 1;
        unsafe extern "system" fn enum_proc(
            si: *const SYMBOL_INFOW,
            _size: u32,
            arg: *const c_void,
        ) -> BOOL {
            let si = &*si;
            let callback: *mut &'static mut dyn FnMut(usize, Arc<str>) -> bool = transmute(arg);
            let name: Arc<str> = from_raw_parts(si.Name.as_ptr(), si.NameLen as usize)
                .to_utf8()
                .into();
            BOOL((*callback)(si.Address as usize, name) as _)
        }
        unsafe {
            SymEnumSymbolsW(
                *self.handle,
                module as u64,
                w!("*"),
                Some(enum_proc),
                Some(transmute(&callback)),
            )
            .is_ok()
        }
    }
}

impl Symbol {
    pub fn undecorate(sym: &str, flags: UDbgFlags) -> Option<String> {
        use msvc_demangler::*;

        let mut sym_flags = DemangleFlags::COMPLETE;
        if flags.contains(UDbgFlags::UNDEC_NAME_ONLY) {
            sym_flags = DemangleFlags::NAME_ONLY;
        } else {
            // if flags & UFLAG_UNDEC_TYPE == 0 { sym_flags |= DemangleFlags::NO_ARGUMENTS; }
            if !flags.contains(UDbgFlags::UNDEC_RETN) {
                sym_flags |= DemangleFlags::NO_FUNCTION_RETURNS;
            }
        }

        demangle(sym, sym_flags).ok()
    }
}
