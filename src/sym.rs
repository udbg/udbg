
use serde::{Serialize, Deserialize};

use core::cell::Cell;
use std::sync::Arc;
use parking_lot::RwLock;
use spin::RwLock as SpinRW;
use std::collections::BTreeMap;

use crate::{*, error::*};

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
#[serde(rename_all="lowercase")]
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
    fn global(&self) -> Result<Arc<Syms>, String>;

    fn find_type(&self, name: &str) -> Vec<TypeInfo> { vec![] }
    fn get_type(&self, id: u32) -> Option<TypeInfo> { None }
    fn get_field(&self, id: u32, index: usize) -> Option<FieldInfo> { None }
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

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Debug)]
pub struct ModuleData {
    pub base: usize,
    pub size: usize,
    pub name: Arc<str>,
    pub path: Arc<str>,
    pub arch: &'static str,
    pub entry: usize,
    pub user_module: Cell<bool>,
}

pub type Syms = BTreeMap<usize, Symbol>;

pub fn find_symbol(symbols: &Syms, moffset: usize, max_offset: usize) -> Option<Symbol> {
    (if max_offset == 0 {
        symbols.get(&moffset)
    } else {
        symbols.range(0..=moffset).last().map(|(_, v)| v)
    }).map(Symbol::clone)
}

pub fn add_symbol(symbols: &mut Syms, offset: usize, name: &str) -> UDbgResult<()> {
    symbols.insert(offset, Symbol {
        offset: offset as u32, name: name.into(),
        type_id: 0, len: SYM_NOLEN, flags: 0
    });
    Ok(())
}

pub fn get_symbol(symbols: &Syms, name: &str) -> Option<Symbol> {
    symbols.iter().find(|(_, s)| name == s.name.as_ref()).map(|(_, v)| v.clone())
}

/// 代表一个模块内的符号数据
/// * 三种符号来源：导出表、符号文件、用户自定义
/// * 可动态添加自定义符号
#[derive(Default)]
pub struct SymbolsData {
    pub user_syms: RwLock<Syms>,
    pub exports: Syms,
    /// PDB Signature
    pub pdb_sig: Box<str>,
    /// PDB file name
    pub pdb_name: Box<str>,
    pub pdb: SpinRW<Option<Arc<dyn SymbolFile>>>,
}

impl SymbolsData {
    pub fn add_symbol(&self, offset: usize, name: &str) -> UDbgResult<()> {
        add_symbol(&mut self.user_syms.write(), offset, name)
    }

    pub fn find_symbol(&self, offset: usize, max_offset: usize) -> Option<Symbol> {
        find_symbol(&self.user_syms.read(), offset, max_offset).or_else(||
            self.pdb.read().as_ref().and_then(|p| p.global().ok()).and_then(|s| find_symbol(&s, offset, max_offset))
        ).or_else(|| find_symbol(&self.exports, offset, max_offset))
    }

    pub fn get_symbol(&self, name: &str) -> Option<Symbol> {
        get_symbol(&self.user_syms.read(), name).or_else(||
            self.pdb.read().as_ref().and_then(|p| p.global().ok()).and_then(|s| get_symbol(&s, name))
        ).or_else(|| get_symbol(&self.exports, name))
    }

    pub fn enum_symbol<'a>(&'a self, pat: Option<&str>) -> UDbgResult<Vec<Symbol>> {
        let global = self.pdb.read().as_ref().and_then(|p| p.global().ok());
        let user_syms = self.user_syms.read();
        let iter = user_syms.iter().chain(
            global.iter().map(|s| s.iter()).flatten()
        ).chain(self.exports.iter());
        let pattern = glob::Pattern::new(pat.unwrap_or("*")).map_err(|e| format!("pattern: {:?}", e))?;
        let options = glob::MatchOptions {case_sensitive: false, ..Default::default()};
        Ok(iter.filter_map(|(_, s)| {
            if pattern.matches_with(s.name.as_ref(), options) {
                Some(s.clone())
            } else { None }
        }).collect())
    }
}

#[cfg(all(windows, target_arch="x86_64"))]
pub use winapi::um::winnt::RUNTIME_FUNCTION;
#[cfg(all(windows, target_arch="x86"))]
pub struct RUNTIME_FUNCTION {
    pub BeginAddress: DWORD,
    pub EndAddress: DWORD,
    pub u: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolStatus {
    Unload,
    Failed,
    Loaded,
}

pub trait UDbgModule {
    fn data(&self) -> &sym::ModuleData;
    fn is_32(&self) -> bool { IS_ARCH_X64 || IS_ARCH_ARM64 }
    fn symbol_status(&self) -> SymbolStatus;
    fn add_symbol(&self, offset: usize, name: &str) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    fn find_symbol(&self, offset: usize, max_offset: usize) -> Option<sym::Symbol> {
        None
    }
    #[cfg(windows)]
    fn runtime_function(&self) -> Option<&[RUNTIME_FUNCTION]> { None }
    #[cfg(windows)]
    fn find_function(&self, offset: usize) -> Option<&RUNTIME_FUNCTION> {
        let funcs = self.runtime_function()?;
        let offset = offset as u32;
        let i = funcs.binary_search_by(|f| {
            use std::cmp::Ordering;
            #[cfg(any(target_arch="x86_64", target_arch="x86"))]
            let end = f.EndAddress;
            #[cfg(any(target_arch="aarch64"))]
            let end = f.BeginAddress + f.FunctionLength();
            if offset >= f.BeginAddress && offset < end {
                Ordering::Equal
            } else if offset < f.BeginAddress {
                Ordering::Greater
            } else { Ordering::Less }
        }).ok()?;
        funcs.get(i)
    }
    fn get_symbol(&self, name: &str) -> Option<sym::Symbol> { None }
    fn symbol_file(&self) -> Option<Arc<dyn sym::SymbolFile>> { None }
    fn load_symbol_file(&self, path: Option<&str>) -> UDbgResult<()> {
        Err(UDbgError::NotSupport)
    }
    fn enum_symbol(&self, pat: Option<&str>) -> UDbgResult<Box<dyn Iterator<Item=sym::Symbol>>> {
        Err(UDbgError::NotSupport)
    }
    fn get_exports(&self) -> Option<Vec<sym::Symbol>> { None }
}

/// 一个目标的模块符号管理器，几个主要功能：
/// * 通过地址、名称来定位模块
/// * 获取指定地址的符号信息（模块、偏移等）
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
        #[cfg(windows)] {
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
            if let Some(i) = p { self.list.remove(i); }
            let mut torm = Vec::new();
            self.map.iter()
                .for_each(|(k, v)| if Arc::ptr_eq(v, &m) { torm.push(k.clone()); });
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
            } else { Ordering::Less }
        }).ok().and_then(|i| list.get(i).map(Arc::clone))
    }

    pub fn get_module(&self, name: &str) -> Option<Arc<T>> {
        #[cfg(windows)]
        let name: ModKey = UniCase::new(name.into());
        #[cfg(windows)] let name = &name;
        self.map.get(name).map(Clone::clone)
    }

    // pub fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item=Arc<dyn UDbgModule + 'a>> + 'a> {
    //     Box::new(self.list.clone().into_iter().map(|m| {
    //         let r: Arc<dyn UDbgModule + 'a> = m; r
    //     }))
    // }

    #[inline]
    pub fn exists(&self, address: usize) -> bool { self.find_module(address).is_some() }

    pub fn get_symbol_info(&self, addr: usize, max_offset: usize) -> Option<SymbolInfo> {
        self.find_module(addr).and_then(|mm| {
            let m = mm.data();
            let moffset = addr - m.base;
            mm.find_symbol(moffset, max_offset).and_then(|s| {
                let offset = moffset - s.offset as usize;
                if max_offset == 0 && offset != 0 { return None; }
                if s.len != SYM_NOLEN && offset > s.len as usize {
                    return Some(SymbolInfo {
                        mod_base: m.base, offset: moffset, module: m.name.clone(), symbol: "".into()
                    });
                }
                let symbol = s.name.clone();
                // let symbol = crate::undec_sym(symbol.as_ref()).map(|v| v.into()).unwrap_or(symbol);
                Some(SymbolInfo {mod_base: m.base, offset, module: m.name.clone(), symbol})
            })
        })
    }
}

pub struct SymbolManager<T: UDbgModule> {
    pub base: RwLock<ModuleManager<T>>,
    pub symcache: Arc<str>,
    pub is_wow64: Cell<bool>,
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

    pub fn enum_module<'a>(&'a self) -> Box<dyn Iterator<Item=Arc<dyn UDbgModule + 'a>> + 'a> {
        match self.base.try_read() {
            Some(sm) => Box::new(
                sm.list.clone().into_iter().map(|m| m as Arc<dyn UDbgModule + 'a>)
            ),
            None => Box::new(vec![].into_iter()),
        }
    }
}