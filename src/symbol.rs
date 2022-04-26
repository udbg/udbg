//!
//! Utilities for dealing symbols implements by udbg which is platform independently
//!

use crate::{
    consts::*, error::*, pe::PeHelper, prelude::GetProp, range::RangeValue, shell::udbg_ui,
};

use core::cell::Cell;
use parking_lot::RwLock;
use spin::RwLock as SpinRW;
use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(windows)]
use unicase::UniCase;
#[cfg(windows)]
type ModKey = UniCase<Arc<str>>;
#[cfg(not(windows))]
type ModKey = Arc<str>;

bitflags! {
    pub struct SymbolFlags: u32 {
        const NONE = 0;

        const FUNCTION = 1 << 0;
        const IMPORT = 1 << 1;
        const EXPORT = 1 << 2;
    }
}

pub const SYM_NOLEN: u32 = u32::max_value();

pub const TTY_BASIC: u32 = 1;
pub const TTY_UNION: u32 = 2;
pub const TTY_ENUM: u32 = 3;
pub const TTY_CLASS: u32 = 4;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TypeKind {
    Primitive {
        pointer: bool,
    },
    Class {
        fields: Option<u32>,
        vtable: Option<u32>,
        derive: Option<u32>,
        size: u16,
    },
    Nested,
    Union,
    Enum,
    Array {
        tid: u32,
        dimensions: Vec<u32>,
    },
    Bitfield {
        tid: u32,
        len: u8,
        pos: u8,
    },
    Pointer {
        tid: u32,
    },
    Proc {
        args_tid: u32,
        return_tid: u32,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TypeInfo {
    pub id: u32,
    pub name: String,
    pub kind: TypeKind,
}

impl TypeInfo {
    pub fn tty(t: u32) -> &'static str {
        match t {
            TTY_BASIC => "basic",
            TTY_UNION => "union",
            TTY_ENUM => "enum",
            TTY_CLASS => "class",
            _ => "",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub type_id: u32,
    pub offset: u32,
    pub name: String,
}

/// 抽象的符号文件类:
/// * 全局符号(变量)偏移、类型等信息
/// * 符号信息，结构体偏移等
pub trait SymbolFile {
    fn path(&self) -> &str;
    fn global(&self) -> anyhow::Result<Arc<SymbolMap>>;

    fn find_type(&self, name: &str) -> Vec<TypeInfo> {
        vec![]
    }
    fn get_type(&self, id: u32) -> Option<TypeInfo> {
        None
    }
    fn get_field(&self, id: u32, index: usize) -> Option<FieldInfo> {
        None
    }
    fn find_field(&self, id: u32, name: &str) -> Option<FieldInfo> {
        let mut i = 0;
        while let Some(f) = self.get_field(id, i) {
            if f.name.starts_with(name) {
                return Some(f);
            }
            i += 1;
        }
        None
    }
    fn get_field_list(&self, id: u32) -> Vec<FieldInfo> {
        let mut result = vec![];
        let mut i = 0;
        while let Some(f) = self.get_field(id, i) {
            result.push(f);
            i += 1;
        }
        result
    }
}

/// symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub offset: u32,
    pub len: u32,
    pub type_id: u32,
    pub flags: u32,
    pub name: Arc<str>,
}

impl crate::range::RangeValue for Symbol {
    fn as_range(&self) -> core::ops::Range<usize> {
        (self.offset as usize)..(self.len + self.offset) as usize
    }
}

/// symbol information with module
#[derive(Serialize, Deserialize)]
pub struct SymbolInfo {
    pub module: Arc<str>,
    pub symbol: Arc<str>,
    pub offset: usize,
    pub mod_base: usize,
}

impl SymbolInfo {
    pub fn to_string(&self, addr: usize) -> String {
        if self.symbol.len() > 0 {
            if self.offset == 0 {
                format!("{}!{}", self.module, self.symbol)
            } else {
                format!("{}!{}+{:x}", self.module, self.symbol, self.offset)
            }
        } else if self.module.len() > 0 {
            if addr == self.mod_base {
                self.module.to_string()
            } else {
                format!("{}+{:x}", self.module, addr - self.mod_base)
            }
        } else {
            format!("{:x}", addr)
        }
    }
}

#[derive(Debug)]
pub struct ModuleData {
    pub base: usize,
    pub size: usize,
    pub name: Arc<str>,
    pub path: Arc<str>,
    pub arch: &'static str,
    /// RVA(windows)/offset of the module
    pub entry: usize,
    pub user_module: Cell<bool>,
}

impl ModuleData {
    pub fn entry_point(&self) -> usize {
        self.base + self.entry
    }
}

#[derive(Deref, DerefMut, Default)]
pub struct SymbolMap(pub BTreeMap<usize, Symbol>);

impl SymbolMap {
    pub fn find_symbol(&self, moffset: usize, max_offset: usize) -> Option<Symbol> {
        (if max_offset == 0 {
            self.get(&moffset)
        } else {
            self.range(0..=moffset).last().map(|(_, v)| v)
        })
        .map(Symbol::clone)
    }

    pub fn add_symbol(&mut self, offset: usize, name: &str) -> UDbgResult<()> {
        self.insert(
            offset,
            Symbol {
                offset: offset as u32,
                name: name.into(),
                type_id: 0,
                len: SYM_NOLEN,
                flags: 0,
            },
        );
        Ok(())
    }

    pub fn get_symbol(&self, name: &str) -> Option<Symbol> {
        self.iter()
            .find(|(_, s)| name == s.name.as_ref())
            .map(|(_, v)| v.clone())
    }
}

/// Represents the symbols in a module
#[derive(Default)]
pub struct SymbolsData {
    /// symbols user added
    pub user_syms: RwLock<SymbolMap>,
    /// symbols from module export
    pub exports: SymbolMap,
    /// PDB Signature
    pub pdb_sig: Box<str>,
    /// PDB file name
    pub pdb_name: Box<str>,
    pub pdb: SpinRW<Option<Arc<dyn SymbolFile>>>,
}

impl SymbolsData {
    pub fn add_symbol(&self, offset: usize, name: &str) -> UDbgResult<()> {
        self.user_syms.write().add_symbol(offset, name)
    }

    pub fn find_symbol(&self, offset: usize, max_offset: usize) -> Option<Symbol> {
        self.user_syms
            .read()
            .find_symbol(offset, max_offset)
            .or_else(|| {
                self.pdb
                    .read()
                    .as_ref()
                    .and_then(|p| p.global().ok())
                    .and_then(|s| s.find_symbol(offset, max_offset))
            })
            .or_else(|| self.exports.find_symbol(offset, max_offset))
    }

    pub fn get_symbol(&self, name: &str) -> Option<Symbol> {
        self.user_syms
            .read()
            .get_symbol(name)
            .or_else(|| {
                self.pdb
                    .read()
                    .as_ref()
                    .and_then(|p| p.global().ok())
                    .and_then(|s| s.get_symbol(name))
            })
            .or_else(|| self.exports.get_symbol(name))
    }

    pub fn enum_symbol<'a>(&'a self, pat: Option<&str>) -> UDbgResult<Vec<Symbol>> {
        let global = self.pdb.read().as_ref().and_then(|p| p.global().ok());
        let user_syms = self.user_syms.read();
        let iter = user_syms
            .iter()
            .chain(global.iter().map(|s| s.iter()).flatten())
            .chain(self.exports.iter());
        let pattern =
            glob::Pattern::new(pat.unwrap_or("*")).map_err(|e| format!("pattern: {:?}", e))?;
        let options = glob::MatchOptions {
            case_sensitive: false,
            ..Default::default()
        };
        Ok(iter
            .filter_map(|(_, s)| {
                if pattern.matches_with(s.name.as_ref(), options) {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect())
    }
}

#[cfg(all(windows, any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use winapi::um::winnt::RUNTIME_FUNCTION;
#[cfg(all(windows, target_arch = "x86"))]
pub struct RUNTIME_FUNCTION {
    pub BeginAddress: winapi::shared::minwindef::DWORD,
    pub EndAddress: winapi::shared::minwindef::DWORD,
    pub u: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolStatus {
    Unload,
    Failed,
    Loaded,
}

/// Represents a module in target, which has symbols
pub trait UDbgModule: GetProp {
    fn data(&self) -> &ModuleData;
    fn is_32(&self) -> bool {
        IS_ARCH_X64 || IS_ARCH_ARM64
    }

    fn symbols_data(&self) -> Option<&SymbolsData> {
        None
    }

    fn symbol_status(&self) -> SymbolStatus;

    fn add_symbol(&self, offset: usize, name: &str) -> UDbgResult<()> {
        self.symbols_data()
            .map(|syms| syms.add_symbol(offset, name))
            .unwrap_or(Err(UDbgError::NotSupport))
    }

    fn find_symbol(&self, offset: usize, max_offset: usize) -> Option<Symbol> {
        self.symbols_data()?.find_symbol(offset, max_offset)
    }

    #[cfg(windows)]
    fn runtime_function(&self) -> Option<&[RUNTIME_FUNCTION]> {
        None
    }
    #[cfg(windows)]
    fn find_function(&self, offset: usize) -> Option<&RUNTIME_FUNCTION> {
        let funcs = self.runtime_function()?;
        let offset = offset as u32;
        let i = funcs
            .binary_search_by(|f| {
                use std::cmp::Ordering;
                #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
                let end = f.EndAddress;
                #[cfg(any(target_arch = "aarch64"))]
                let end = f.BeginAddress + f.FunctionLength();
                if offset >= f.BeginAddress && offset < end {
                    Ordering::Equal
                } else if offset < f.BeginAddress {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            })
            .ok()?;
        funcs.get(i)
    }

    /// get symbol info by name
    fn get_symbol(&self, name: &str) -> Option<Symbol> {
        self.symbols_data()?.get_symbol(name)
    }

    /// get the symbol file of this module
    fn symbol_file(&self) -> Option<Arc<dyn SymbolFile>> {
        self.symbols_data()?.pdb.read().clone()
    }

    /// specific a symbol file for this module
    fn load_symbol_file(&self, path: Option<&str>) -> UDbgResult<()> {
        if let Some(syms) = self.symbols_data() {
            *syms.pdb.write() = Some(match path {
                // TODO:
                #[cfg(windows)]
                Some(path) => Arc::new(crate::pdbfile::PDBData::load(path, None)?),
                #[cfg(not(windows))]
                Some(_) => return Err(UDbgError::NotSupport),
                None => return Err(UDbgError::NotFound),
            });
            Ok(())
        } else {
            Err(UDbgError::NotSupport)
        }
    }

    /// enumerate symbols by optional wildcard
    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item = Symbol> + '_>> {
        if let Some(syms) = self.symbols_data() {
            Ok(Box::new(syms.enum_symbol(pat)?.into_iter()))
        } else {
            Err(UDbgError::NotSupport)
        }
    }

    /// get all exported symbols
    fn get_exports(&self) -> Option<Vec<Symbol>> {
        Some(
            self.symbols_data()?
                .exports
                .iter()
                .map(|i| i.1.clone())
                .collect(),
        )
    }
}

impl<T: UDbgModule + Sized> RangeValue for T {
    default fn as_range(&self) -> std::ops::Range<usize> {
        let data = self.data();
        data.base..data.base + data.size
    }
}

/// Represents a symbol manager for debug target
pub trait TargetSymbol {
    /// find a symbol module by a address in the module range
    fn find_module(&self, address: usize) -> Option<Arc<dyn UDbgModule>>;

    /// get module by the module name
    fn get_module(&self, name: &str) -> Option<Arc<dyn UDbgModule>>;

    /// enumerate all modules in target
    fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a>;

    /// enumerate symbols in target with optional wildcard
    fn enum_symbol<'a>(
        &'a self,
        pat: Option<&str>,
    ) -> UDbgResult<Box<dyn Iterator<Item = Symbol> + 'a>> {
        Err(UDbgError::NotSupport)
    }

    /// remove a module
    fn remove(&self, address: usize);

    #[cfg(windows)]
    fn check_load_module(
        &self,
        read: &dyn crate::memory::ReadMemory,
        base: usize,
        size: usize,
        path: &str,
        file: winapi::um::winnt::HANDLE,
    ) -> bool {
        false
    }
}

/// A builtin symbol manager, which can
/// * get a module by a address or name
/// * get symbol info of specific address, includes module name, offset, etc.
#[derive(Default)]
pub struct ModuleManager<T: UDbgModule> {
    pub list: Vec<Arc<T>>,
    map: BTreeMap<ModKey, Arc<T>>,
}

impl<T: UDbgModule> ModuleManager<T> {
    pub fn new() -> Self {
        Self {
            list: Default::default(),
            map: Default::default(),
        }
    }

    /// 添加一个模块（模块加载时，也可用于手动添加一个自定义模块）
    pub fn add(&mut self, m: T) {
        let m = Arc::new(m);
        let d = m.data();
        self.map.insert(d.name.clone().into(), m.clone());
        #[cfg(windows)]
        {
            if let Some(p) = d.name.rfind('.') {
                let name: Arc<str> = d.name[..p].into();
                self.map.insert(name.into(), m.clone());
            }
        }
        self.list.push(m);
        self.list.sort_by(|a, b| a.data().base.cmp(&b.data().base));
    }

    /// 移除一个模块（模块卸载时）
    pub fn remove(&mut self, address: usize) {
        self.find_module(address).map(|m| {
            let p = self.list.iter().position(|v| Arc::ptr_eq(v, &m));
            if let Some(i) = p {
                self.list.remove(i);
            }
            let mut torm = Vec::new();
            self.map.iter().for_each(|(k, v)| {
                if Arc::ptr_eq(v, &m) {
                    torm.push(k.clone());
                }
            });
            torm.iter().for_each(|k| {
                #[cfg(not(windows))]
                let k = k.as_ref();
                self.map.remove(k);
            });
        });
    }

    #[cfg(not(windows))]
    pub fn contains(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    pub fn find_module(&self, address: usize) -> Option<Arc<T>> {
        use std::cmp::Ordering;
        let list = &self.list;
        list.binary_search_by(|mm| {
            let m = mm.data();
            if address >= m.base && address < (m.base + m.size) {
                Ordering::Equal
            } else if address < m.base {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        })
        .ok()
        .and_then(|i| list.get(i).map(Arc::clone))
    }

    pub fn get_module(&self, name: &str) -> Option<Arc<T>> {
        #[cfg(windows)]
        let name: ModKey = UniCase::new(name.into());
        #[cfg(windows)]
        let name = &name;
        self.map.get(name).map(Clone::clone)
    }

    // pub fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item=Arc<dyn UDbgModule + 'a>> + 'a> {
    //     Box::new(self.list.clone().into_iter().map(|m| {
    //         let r: Arc<dyn UDbgModule + 'a> = m; r
    //     }))
    // }

    #[inline]
    pub fn exists(&self, address: usize) -> bool {
        self.find_module(address).is_some()
    }

    pub fn get_symbol_info(&self, addr: usize, max_offset: usize) -> Option<SymbolInfo> {
        self.find_module(addr).and_then(|mm| {
            let m = mm.data();
            let moffset = addr - m.base;
            mm.find_symbol(moffset, max_offset).and_then(|s| {
                let offset = moffset - s.offset as usize;
                if max_offset == 0 && offset != 0 {
                    return None;
                }
                if s.len != SYM_NOLEN && offset > s.len as usize {
                    return Some(SymbolInfo {
                        mod_base: m.base,
                        offset: moffset,
                        module: m.name.clone(),
                        symbol: "".into(),
                    });
                }
                let symbol = s.name.clone();
                Some(SymbolInfo {
                    mod_base: m.base,
                    offset,
                    module: m.name.clone(),
                    symbol,
                })
            })
        })
    }
}

pub struct SymbolManager<T: UDbgModule> {
    pub base: RwLock<ModuleManager<T>>,
    pub symcache: Arc<str>,
    pub is_wow64: Cell<bool>,
}

impl<T: UDbgModule> Default for SymbolManager<T> {
    fn default() -> Self {
        let symcache = udbg_ui()
            .base()
            .symcache
            .as_ref()
            .map(|s| s.to_string_lossy().into())
            .unwrap_or_else(|| "".into());
        Self::new(symcache)
    }
}

impl<T: UDbgModule> SymbolManager<T> {
    pub fn new(symcache: Arc<str>) -> Self {
        Self {
            symcache,
            is_wow64: Cell::new(false),
            base: RwLock::new(ModuleManager::<T>::new()),
        }
    }

    pub fn find_module(&self, address: usize) -> Option<Arc<T>> {
        self.base.try_read()?.find_module(address)
    }

    pub fn get_module(&self, name: &str) -> Option<Arc<T>> {
        self.base.try_read()?.get_module(name)
    }

    pub fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a> {
        match self.base.try_read() {
            Some(sm) => Box::new(
                sm.list
                    .clone()
                    .into_iter()
                    .map(|m| m as Arc<dyn UDbgModule + 'a>),
            ),
            None => Box::new(vec![].into_iter()),
        }
    }
}

impl<T: UDbgModule + 'static> TargetSymbol for SymbolManager<T> {
    default fn find_module(&self, address: usize) -> Option<Arc<dyn UDbgModule>> {
        Some(Self::find_module(self, address)?)
    }

    default fn get_module(&self, name: &str) -> Option<Arc<dyn UDbgModule>> {
        Some(Self::get_module(self, name)?)
    }

    default fn enum_module<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = Arc<dyn UDbgModule + 'a>> + 'a> {
        Self::enum_module(self)
    }

    default fn remove(&self, address: usize) {
        self.base.write().remove(address)
    }

    #[cfg(windows)]
    default fn check_load_module(
        &self,
        read: &dyn crate::memory::ReadMemory,
        base: usize,
        size: usize,
        path: &str,
        file: winapi::um::winnt::HANDLE,
    ) -> bool {
        false
    }
}

impl PeHelper<'_> {
    #[cfg(windows)]
    pub fn runtime_functions(&self) -> Vec<RUNTIME_FUNCTION> {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            self.exception_data
                .iter()
                .map(|e| e.functions())
                .flatten()
                .filter_map(|x| x.ok())
                .map(|x| unsafe { core::mem::transmute::<_, RUNTIME_FUNCTION>(x) })
                .collect()
        }

        #[cfg(any(target_arch = "aarch64"))]
        {
            vec![]
        }
    }

    pub fn symbols_data(&self, path: &str) -> SymbolsData {
        let pdb_sig = self
            .get_pdb_signature()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let pdb_name = self
            .debug_data
            .and_then(|d| d.codeview_pdb70_debug_info)
            .and_then(|d| std::str::from_utf8(&d.filename).ok())
            .unwrap_or_default()
            .trim_matches(|c: char| c.is_whitespace() || c == '\0')
            .to_string();
        let pdb = self
            .find_pdb(path)
            // .map_err(|err| ui.warn(format!("load pdb for {}: {err:?}", data.name)))
            .ok()
            .map(|p| p as Arc<dyn SymbolFile>);

        SymbolsData {
            pdb: pdb.into(),
            user_syms: Default::default(),
            exports: self.exported_symbols(),
            pdb_name: pdb_name.into(),
            pdb_sig: pdb_sig.into(),
        }
    }
}
