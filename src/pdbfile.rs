//!
//! Utilities for accessing symbols in pdb file
//!

use anyhow::Context;
use pdb::{FallibleIterator, ItemIter, MemberType, SymbolData, TypeData, TypeIndex, PDB};

use spin::Mutex;
use std::sync::Arc;
use std::{fs::File, io::ErrorKind};

use crate::{pe, prelude::*, shell::udbg_ui};

fn to_field_info(m: MemberType) -> FieldInfo {
    FieldInfo {
        offset: m.offset as u32,
        type_id: m.field_type.0,
        name: m.name.to_string().into(),
    }
}

pub struct PdbFile {
    // use box to ensure the reference in `finder` unchange
    db: Box<PDB<'static, File>>,
    ti: pdb::TypeInformation<'static>,
    finder: pdb::ItemFinder<'static, pdb::TypeIndex>,
}

impl PdbFile {
    pub fn load(path: &str, pe: Option<&pe::PeHelper>) -> anyhow::Result<Self> {
        let mut db = Box::new(
            pdb::PDB::open(File::open(path).with_context(|| format!("open file {path}"))?)
                .with_context(|| format!("open pdb {path}"))?,
        );
        let pi = db.pdb_information().context("PDBInformation")?;
        if let Some(pe) = pe {
            if !pe
                .debug_data
                .and_then(|d| d.codeview_pdb70_debug_info)
                .map(|d| unsafe {
                    let (g1, g2, g3, g4): (u32, u16, u16, [u8; 8]) =
                        core::mem::transmute(d.signature);
                    let (d1, d2, d3, d4) = pi.guid.as_fields();
                    g1 == d1 && g2 == d2 && g3 == d3 && &g4 == d4
                })
                .unwrap_or(true)
            {
                anyhow::bail!("Signature not matched");
            }
        }

        let ti = db.type_information().context("ItemInformation")?;
        let pti: *const _ = &ti;
        unsafe {
            let finder = pti.as_ref().unwrap().finder();
            // let ii = db.id_information().context("IdInformation")?;
            Ok(Self {
                db,
                ti,
                finder: core::mem::transmute(finder),
            })
        }
    }

    pub fn global(&mut self) -> anyhow::Result<SymbolMap> {
        let pdb = &mut self.db;
        let address_map = pdb.address_map().context("address_map failed")?;
        let dbi = pdb
            .debug_information()
            .context("debug_information failed")?;
        let mut modules = dbi.modules().context("get modules failed")?;

        let mut result = SymbolMap::default();
        let mut push_symbol = |sym: SymbolData| {
            match sym {
                SymbolData::Public(p) => {
                    let rva = p.offset.to_rva(&address_map).unwrap_or_default().0;
                    // println!("0x{:x} {}", rva, p.name);
                    let mut flags = SymbolFlags::NONE;
                    if p.function {
                        flags |= SymbolFlags::FUNCTION;
                    }
                    result.entry(rva as usize).or_insert_with(|| Symbol {
                        offset: rva,
                        name: p.name.to_string().into(),
                        type_id: 0,
                        flags: flags.bits(),
                        len: SYM_NOLEN,
                    });
                }
                SymbolData::Procedure(p) => {
                    let rva = p.offset.to_rva(&address_map).unwrap_or_default().0;
                    // println!("Proc: {} {} {:x} {:x}", p.name.to_string(), p.global, rva, p.len);
                    result.entry(rva as usize).or_insert_with(|| Symbol {
                        offset: rva,
                        name: p.name.to_string().into(),
                        type_id: p.type_index.0,
                        flags: SymbolFlags::FUNCTION.bits(),
                        len: p.len,
                    });
                }
                SymbolData::Data(p) => {
                    // if let Err(_) = std::panic::catch_unwind(|| {
                    let rva = p.offset.to_rva(&address_map).unwrap_or_default().0;
                    result.entry(rva as usize).or_insert_with(|| Symbol {
                        offset: rva,
                        name: p.name.to_string().into(),
                        flags: SymbolFlags::NONE.bits(),
                        len: 0,
                        type_id: p.type_index.0,
                    });
                    // }) { error!("push_symbol error"); }
                }
                _ => {}
            }
        };
        while let Ok(Some(module)) = modules.next() {
            if let Ok(Some(i)) = pdb.module_info(&module) {
                if let Ok(mut syms) = i.symbols() {
                    while let Ok(Some(symbol)) = syms.next() {
                        symbol.parse().map(|sym| push_symbol(sym)).ok();
                    }
                } else {
                    error!("get symbols failed: {}", module.module_name());
                }
            }
            // println!("module name: {}, object file name: {}", module.module_name(), module.object_file_name());
        }

        let symbol_table = pdb.global_symbols().context("global_symbols failed")?;
        let mut symbols = symbol_table.iter();
        while let Ok(Some(symbol)) = symbols.next() {
            symbol.parse().map(|sym| push_symbol(sym)).ok();
        }
        Ok(result)
    }

    pub fn td2ti(&mut self, id: u32, data: TypeData, name: Option<&str>) -> Option<TypeInfo> {
        let (tn, kind) = match data {
            TypeData::Procedure(p) => (
                "".into(),
                TypeKind::Proc {
                    args_tid: p.argument_list.0,
                    return_tid: p.return_type.map(|i| i.0).unwrap_or_default(),
                },
            ),
            TypeData::Class(cls) => {
                // if cls.fields.is_none() { return None; }
                (
                    cls.name.to_string(),
                    TypeKind::Class {
                        fields: cls.fields.map(|x| x.0),
                        vtable: cls.vtable_shape.map(|x| x.0),
                        derive: cls.derived_from.map(|x| x.0),
                        size: cls.size as _,
                    },
                )
            }
            TypeData::Nested(n) => (n.name.to_string(), TypeKind::Nested),
            // TypeData::BaseClass(cls) => {
            //     ("BaseClass".into(), TypeKind::Class {tid: cls.base_class.0.into(), vtable: None, size: 0})
            // }
            TypeData::Array(a) => (
                "".into(),
                TypeKind::Array {
                    tid: a.element_type.0,
                    dimensions: a.dimensions.clone(),
                },
            ),
            TypeData::Bitfield(b) => (
                "".into(),
                TypeKind::Bitfield {
                    tid: b.underlying_type.0,
                    len: b.length,
                    pos: b.position,
                },
            ),
            TypeData::Union(cls) => (cls.name.to_string(), TypeKind::Union),
            // TypeData::Enumerate(cls) => {
            //     (cls.name.to_string(), TypeKind::Enum)
            // }
            TypeData::Enumeration(cls) => (cls.name.to_string(), TypeKind::Enum),
            TypeData::Pointer(pt) => (
                "".into(),
                TypeKind::Pointer {
                    tid: pt.underlying_type.0,
                },
            ),
            TypeData::Primitive(p) => (
                format!("{:?}", p.kind).into(),
                TypeKind::Primitive {
                    pointer: p.indirection.is_some(),
                },
            ),
            TypeData::Modifier(m) => {
                if name.is_none() {
                    let id = m.underlying_type.0;
                    let x = self.find_type(id).and_then(|x| x.parse().ok())?;
                    return self.td2ti(id, x, None);
                } else {
                    return None;
                }
            }
            _ => return None,
        };
        if let Some(pattern) = name.and_then(|n| glob::Pattern::new(n).ok()) {
            let options = glob::MatchOptions {
                case_sensitive: true,
                ..Default::default()
            };
            if !pattern.matches_with(&tn, options) {
                return None;
            }
        }
        Some(TypeInfo {
            id,
            name: tn.into(),
            kind,
        })
    }

    pub fn get_type(&mut self, id: u32) -> Option<TypeInfo> {
        let x = self.find_type(id)?.parse().ok()?;
        self.td2ti(id, x, None)
    }

    pub fn find_type_info(&mut self, name: &str) -> Vec<TypeInfo> {
        let mut type_iter: ItemIter<'static, TypeIndex> =
            unsafe { core::mem::transmute(self.ti.iter()) };
        let mut cache = vec![];
        while let Some(typ) = type_iter.next().ok().flatten() {
            self.finder.update(&type_iter);
            let id = typ.index().0;
            if let Some(r) = typ
                .parse()
                .ok()
                .and_then(|ty| self.td2ti(id, ty, Some(name)))
            {
                let canbreak = match &r.kind {
                    TypeKind::Class { fields, .. } => fields.is_some(),
                    _ => true,
                };
                cache.push(r);
                if canbreak {
                    break;
                }
            }
        }
        cache
    }

    pub fn find_type(&mut self, id: u32) -> Option<pdb::Item<'static, TypeIndex>> {
        self.finder.find(id.into()).ok().or_else(|| {
            let mut type_iter: ItemIter<'static, TypeIndex> =
                unsafe { core::mem::transmute(self.ti.iter()) };
            while let Some(item) = type_iter.next().ok()? {
                self.finder.update(&type_iter);
                if item.index().0 == id {
                    return Some(item);
                }
            }
            None
        })
    }

    pub fn field_list(&mut self, type_id: u32) -> Option<pdb::FieldList> {
        let id = match self.find_type(type_id)?.parse().ok()? {
            TypeData::Class(cls) => cls.fields,
            TypeData::Enumeration(cls) => Some(cls.fields),
            TypeData::FieldList(data) => return Some(data),
            _ => None,
        };
        match self.find_type(id?.0)?.parse().ok()? {
            TypeData::FieldList(data) => Some(data),
            _ => {
                // println!("find field list or parse failed");
                None
            }
        }
    }

    pub fn get_field_list(&mut self, type_id: u32) -> Vec<FieldInfo> {
        let mut result = vec![];
        if let Some(fl) = self.field_list(type_id) {
            for field in fl.fields {
                match field {
                    TypeData::Member(m) => {
                        result.push(to_field_info(m));
                    }
                    TypeData::Enumerate(cls) => {
                        result.push(FieldInfo {
                            type_id: 0,
                            offset: 0,
                            name: cls.name.to_string().into(),
                        });
                    }
                    _ => continue,
                }
            }
        }
        result
    }

    pub fn find_field(&mut self, id: u32, name: &str) -> Result<FieldInfo, String> {
        for field in self.field_list(id).ok_or("no field list")?.fields {
            match field {
                TypeData::Member(m) => {
                    if m.name.to_string() == name {
                        return Ok(to_field_info(m));
                    }
                }
                _ => continue,
            }
        }
        Err("".into())
    }

    pub fn get_field(&mut self, id: u32, index: usize) -> Option<FieldInfo> {
        match self.field_list(id)?.fields.get(index)? {
            TypeData::Member(m) => Some(to_field_info(m.clone())),
            _ => None,
        }
    }
}

pub struct PDBData {
    pub file: Mutex<PdbFile>,
    pub path: Arc<str>,
    pub global: Mutex<Option<Arc<SymbolMap>>>,
}

impl PDBData {
    pub fn load(path: &str, pe: Option<&pe::PeHelper>) -> anyhow::Result<PDBData> {
        Ok(Self {
            file: PdbFile::load(path, pe)?.into(),
            path: path.into(),
            global: None.into(),
        })
    }
}

impl SymbolFile for PDBData {
    fn path(&self) -> &str {
        self.path.as_ref()
    }

    fn find_type(&self, name: &str) -> Vec<TypeInfo> {
        self.file.lock().find_type_info(name)
    }

    fn get_type(&self, tid: u32) -> Option<TypeInfo> {
        self.file.lock().get_type(tid)
    }

    fn get_field_list(&self, tid: u32) -> Vec<FieldInfo> {
        self.file.lock().get_field_list(tid)
    }

    fn get_field(&self, tid: u32, index: usize) -> Option<FieldInfo> {
        self.file.lock().get_field(tid, index)
    }

    fn find_field(&self, id: u32, name: &str) -> Option<FieldInfo> {
        self.file.lock().find_field(id, name).ok()
    }

    fn global(&self) -> anyhow::Result<Arc<SymbolMap>> {
        let result = self.global.lock().clone();
        match result {
            Some(r) => Ok(r.clone()),
            None => {
                let r = Arc::new(self.file.lock().global()?);
                *self.global.lock() = r.clone().into();
                Ok(r)
            }
        }
    }
}

impl pe::PeHelper<'_> {
    pub fn find_pdb(&self, path: &str) -> anyhow::Result<Arc<PDBData>> {
        use std::path::Path;

        let fullpath = Path::new(path);
        let pdbpath = self.get_pdb_path().and_then(|p| p.to_str().ok());
        let mut paths = vec![];

        if let Some(pdbpath) = pdbpath {
            let pdbpath = Path::new(pdbpath);
            let pdbname = pdbpath.file_name().context("pdbname")?;
            // 1. the pdb's full path
            if pdbpath.is_absolute() {
                paths.push(pdbpath.to_path_buf());
            }
            // 2. dir(module) + pdb's name
            paths.push(fullpath.with_file_name(pdbname));
            // 3. the cached pdb path
            udbg_ui().base().symcache.as_ref().map(|cache| {
                if let Some(pdb_sig) = self.get_pdb_signature() {
                    paths.push(cache.join(pdbname).join(pdb_sig).join(pdbname));
                }
            });
        }
        // 4. the same pdb path to dll
        paths.push(fullpath.with_extension("pdb"));

        let mut err = None;
        for p in paths.iter() {
            if p.exists() {
                match PDBData::load(&p.to_string_lossy(), self.into()) {
                    Ok(pdb) => return Ok(pdb.into()),
                    Err(e) => err = Some(e),
                }
            }
        }

        Err(err
            .map(Into::into)
            .unwrap_or_else(|| std::io::Error::from(ErrorKind::NotFound).into()))
    }
}

impl SymbolsData {
    pub fn load_from_pdb(&self, path: &str) -> anyhow::Result<SymbolMap> {
        let mut pdb = PdbFile::load(path, None)?;
        pdb.global()
    }
}
