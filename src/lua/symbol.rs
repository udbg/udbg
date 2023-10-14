use super::*;

impl UserData for Symbol {
    const TYPE_NAME: &'static str = "UDbgSymbol";

    fn getter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields.add_field_get("name", |_, this: &Self| this.name.as_ref())?;
        fields.set_closure("offset", |this: &Self| this.offset)?;
        fields.set_closure("len", |this: &Self| this.len)?;
        fields.set_closure("flags", |this: &Self| this.flags)?;
        fields.add_field_get("uname", |s: &LuaState, this: &Self| {
            if let Some(n) = Symbol::undecorate(&this.name, Default::default()) {
                s.new_val(n)
            } else {
                s.new_val(this.name.as_ref())
            }
        })?;
        fields.set_closure("typeId", |s: &LuaState, this: &Self| {
            (this.type_id > 0).then_some(this.type_id)
        })?;

        Ok(())
    }

    fn methods(methods: UserdataRegistry<Self>) -> LuaResult<()> {
        Ok(())
    }
}

impl ToLuaMulti for FieldInfo {
    fn push_multi(self, s: &LuaState) -> LuaResult<usize> {
        (self.type_id, self.offset, self.name.as_str()).push_multi(s)
    }
}

#[derive(Deref)]
pub struct ArcSymbolFile(pub Arc<dyn SymbolFile>);

impl UserData for ArcSymbolFile {
    const TYPE_NAME: &'static str = "SymbolFile*";

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        #[cfg(windows)]
        mt.set_closure("open", |path: &str| {
            crate::pdbfile::PDBData::load(path, None).map(|r| ArcSymbolFile(Arc::new(r)))
        })?;
        mt.add_method("path", |_, this, ()| this.path())?;
        mt.set_closure("getType", |this: &Self, id: u32| {
            this.get_type(id).map(SerdeValue)
        })?;
        mt.set_closure("findType", |this: &Self, name: &str| {
            SerdeValue(this.find_type(name))
        })?;
        mt.set_closure("getField", |this: &Self, type_id: u32, val: LuaValue| {
            match val {
                LuaValue::String(name) => {
                    this.find_field(type_id, name.to_str().unwrap_or_default())
                }
                LuaValue::Integer(i) => this.get_field(type_id, i as usize),
                _ => {
                    // Err("integer|string").lua_result()?;
                    None
                }
            }
            .ok_or(())
        })?;
        mt.set_closure("enumField", |this: &Self, type_id: u32| {
            StaticIter::from(this.get_field_list(type_id).into_iter().map(|x| x))
        })?;

        Ok(())
    }
}
