use crate::prelude::*;

use core::cell::Cell;
use std::sync::Arc;

pub mod udbg;

pub use libc::pid_t;

impl Symbol {
    pub fn undecorate(sym: &str, flags: UDbgFlags) -> Option<String> {
        use cpp_demangle::{DemangleOptions, Symbol};
        Symbol::new(sym).ok().and_then(|s| {
            let mut opts = DemangleOptions::new();
            if flags.contains(UDbgFlags::UNDEC_TYPE) {
                opts = opts.no_params();
            }
            if flags.contains(UDbgFlags::UNDEC_RETN) {
                opts = opts.no_return_type();
            }
            s.demangle(&opts).ok()
        })
    }
}

pub struct Module {
    pub data: ModuleData,
    pub syms: SymbolsData,
    pub loaded: Cell<bool>,
}

impl Module {
    // fn check_loaded(&self) {
    //     if self.loaded.get() { return; }
    //     let mut s = self.syms.write();
    //     self.loaded.set(true);
    //     match s.load(&self.data.path) {
    //         Ok(_) => {
    //         }
    //         Err(e) => {
    //             error!("{}", e);
    //         }
    //     }
    // }
}

impl GetProp for Module {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        Ok(serde_value::Value::Unit)
    }
}

impl UDbgModule for Module {
    fn data(&self) -> &ModuleData {
        &self.data
    }

    fn symbol_status(&self) -> SymbolStatus {
        if self.syms.pdb.read().is_some() {
            SymbolStatus::Loaded
        } else {
            SymbolStatus::Unload
        }
    }
    fn add_symbol(&self, offset: usize, name: &str) -> UDbgResult<()> {
        self.syms.add_symbol(offset, name)
    }
    fn find_symbol(&self, offset: usize, max_offset: usize) -> Option<Symbol> {
        self.syms.find_symbol(offset, max_offset)
    }
    fn get_symbol(&self, name: &str) -> Option<Symbol> {
        self.syms.get_symbol(name)
    }
    fn symbol_file(&self) -> Option<Arc<dyn SymbolFile>> {
        self.syms.pdb.read().clone()
    }

    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item = Symbol>>> {
        Ok(Box::new(self.syms.enum_symbol(pat)?.into_iter()))
    }
    fn get_exports(&self) -> Option<Vec<Symbol>> {
        Some(self.syms.exports.iter().map(|i| i.1.clone()).collect())
    }

    // TODO: dwarf
    // fn load_symbol_file(&self, path: &str) -> UDbgResult<()> {
    //     // self.syms.write().load_from_pdb(path)?; Ok(())
    //     Ok(())
    // }
}
