use super::process::Process;
use crate::prelude::*;
use core::{cell::Cell, fmt};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryPage {
    pub base: usize,
    pub size: usize,
    pub prot: [u8; 4],
    pub usage: String,
}

impl fmt::Debug for MemoryPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryPage")
            .field("base", &format!("0x{:x}", self.base))
            .field("size", &format!("0x{:x}", self.size))
            .field("prot", &unsafe {
                String::from_utf8_unchecked(self.prot.to_vec())
            })
            .field("usage", &self.usage)
            .finish()
    }
}

impl MemoryPage {
    #[inline]
    pub fn is_commit(&self) -> bool {
        true
    }

    #[inline]
    pub fn is_reserve(&self) -> bool {
        false
    }

    #[inline]
    pub fn is_free(&self) -> bool {
        false
    }

    #[inline]
    pub fn is_private(&self) -> bool {
        self.prot[3] == b'p'
    }

    #[inline]
    pub fn is_shared(&self) -> bool {
        self.prot[3] == b's'
    }

    pub fn is_executable(&self) -> bool {
        self.prot[2] == b'x'
    }
    pub fn is_writable(&self) -> bool {
        self.prot[1] == b'w'
    }
    pub fn is_readonly(&self) -> bool {
        self.prot[0] == b'r' && !self.is_writable() && !self.is_executable()
    }

    pub fn protect(&self) -> &str {
        std::str::from_utf8(&self.prot).unwrap_or("")
    }

    pub fn type_str(&self) -> &'static str {
        if self.is_private() {
            "PRV"
        } else if self.is_shared() {
            "SHR"
        } else {
            ""
        }
    }
}

pub struct NixModule {
    /// 模块基本信息
    pub data: ModuleData,
    /// 模块符号信息
    pub syms: SymbolsData,
    /// 是否已尝试过加载模块符号
    pub loaded: Cell<bool>,
}

impl NixModule {
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

impl GetProp for NixModule {
    fn get_prop(&self, key: &str) -> UDbgResult<serde_value::Value> {
        Ok(serde_value::Value::Unit)
    }
}

impl UDbgModule for NixModule {
    fn data(&self) -> &ModuleData {
        &self.data
    }
    // fn is_32(&self) -> bool { IS_ARCH_X64 || IS_ARCH_ARM64 }
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
    // fn load_symbol_file(&self, path: &str) -> UDbgResult<()> {
    //     // self.syms.write().load_from_pdb(path)?; Ok(())
    //     Ok(())  // TODO:
    // }
}

impl<T: AsRef<Process>> ReadMemory for T {
    default fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        self.as_ref().read_memory(addr, data)
    }
}

impl<T: AsRef<Process>> WriteMemory for T {
    default fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        self.as_ref().write_memory(address, data)
    }
}

impl<T: AsRef<Process>> TargetMemory for T {
    default fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        Ok(Box::new(self.as_ref().enum_memory()))
    }

    default fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        self.as_ref().virtual_query(address as _)
    }

    default fn virtual_alloc(&self, address: usize, size: usize, ty: &str) -> UDbgResult<usize> {
        todo!()
    }

    default fn virtual_free(&self, address: usize) {}
}

impl<T: AsRef<Process>> TargetControl for T {
    fn detach(&self) -> UDbgResult<()> {
        todo!()
    }

    fn kill(&self) -> UDbgResult<()> {
        todo!()
    }

    fn breakk(&self) -> UDbgResult<()> {
        todo!()
    }

    fn suspend(&self) -> UDbgResult<()> {
        self.as_ref().suspend();
        Ok(())
    }

    fn resume(&self) -> UDbgResult<()> {
        self.as_ref().resume();
        Ok(())
    }
}
