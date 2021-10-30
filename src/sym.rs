
use serde::{Serialize, Deserialize};

use core::cell::Cell;
use std::sync::Arc;
use std::collections::BTreeMap;

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
        tid: Option<u32>,
        base: Option<u32>,
        size: u16,
    },
    Nested,
    Union,
    Enum,
    Array {
        tid: u32,
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

    fn type_info(&self, name: &str) -> Option<TypeInfo> { None }
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