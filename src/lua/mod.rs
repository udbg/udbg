//! lua bindings for udbg

use crate::{
    os::{pid_t, tid_t},
    prelude::*,
    register::CpuReg,
};
use ezlua::{ffi::lua_Integer, marker::*, prelude::*, serde::SerdeValue};
use std::{cell::RefCell, sync::Arc};

pub struct ReturnAll;

impl ToLuaMulti for ReturnAll {
    fn push_multi(self, s: &LuaState) -> LuaResult<usize> {
        Ok((s.stack_top() - s.base) as _)
    }
}

pub const STACK_BUFFER_SIZE: usize = 2000;

pub const INIT_BP: lua_Integer = 1;
pub const BREAKPOINT: lua_Integer = 2;
pub const PROCESS_CREATE: lua_Integer = 3;
pub const PROCESS_EXIT: lua_Integer = 4;
pub const THREAD_CREATE: lua_Integer = 5;
pub const THREAD_EXIT: lua_Integer = 6;
pub const MODULE_LOAD: lua_Integer = 7;
pub const MODULE_UNLOAD: lua_Integer = 8;
pub const EXCEPTION: lua_Integer = 9;
pub const STEP: lua_Integer = 10;

pub fn init(s: &LuaState, t: &ValRef) -> LuaResult<()> {
    t.set("SymbolFile", s.register_usertype::<ArcSymbolFile>()?)?;
    t.set("UDbgTarget", s.register_usertype::<ArcTarget>()?)?;
    t.set("UDbgBreakpoint", s.register_usertype::<ArcBreakpoint>()?)?;
    t.set("Engine", s.register_usertype::<BoxEngine>()?)?;

    let sf = s.new_table_with_size(0, 4)?;
    {
        use SymbolFlags as SF;

        t.set("FUNCTION", SF::FUNCTION.bits())?;
        t.set("IMPORT", SF::IMPORT.bits())?;
        t.set("EXPORT", SF::EXPORT.bits())?;
    }
    t.set("SymbolFlags", sf)?;

    let regid = s.new_table_with_size(0, 4)?;
    {
        regid.set("x86", init_regid_x86(s)?)?;
        regid.set("arm", init_regid_arm(s)?)?;
        regid.set("aarch64", init_regid_aarch64(s)?)?;
    }
    t.set("regid", regid)?;

    let event = s.new_table_with_size(0, 8)?;
    {
        event.set("INIT_BP", INIT_BP)?;
        event.set("BREAKPOINT", BREAKPOINT)?;
        event.set("PROCESS_CREATE", PROCESS_CREATE)?;
        event.set("PROCESS_EXIT", PROCESS_EXIT)?;
        event.set("THREAD_CREATE", THREAD_CREATE)?;
        event.set("THREAD_EXIT", THREAD_EXIT)?;
        event.set("MODULE_LOAD", MODULE_LOAD)?;
        event.set("MODULE_UNLOAD", MODULE_UNLOAD)?;
        event.set("EXCEPTION", EXCEPTION)?;
        event.set("STEP", STEP)?;
    }
    t.set("Event", event)?;

    Ok(())
}

pub fn read_pack<R: ReadMemory + ?Sized>(
    s: &LuaState,
    d: &R,
    a: usize,
    pack: &[u8],
    psize: Option<usize>,
) -> Result<(), &'static str> {
    use ezlua::luaapi::UnsafeLuaApi;

    let mut iter = pack.iter();

    let read_ptr = |addr| match psize {
        Some(4) => d.read_value::<u32>(addr).map(|p| p as usize),
        Some(8) => d.read_value::<u64>(addr).map(|p| p as usize),
        _ => d.read_value::<usize>(addr),
    };

    let psize = psize.unwrap_or(core::mem::size_of::<usize>());
    let mut address = a;
    let mut ahead = None;
    while let Some(b) = ahead.take().or_else(|| iter.next()) {
        let mut c = *b;
        let mut isptr = false;
        let mut addr = address;
        if c == b'*' {
            c = *iter.next().ok_or("expect *item")?;
            isptr = true;
            addr = read_ptr(addr).ok_or("read ptr")?;
        }
        let size = if addr != 0 {
            match c {
                b'i' => {
                    let b = iter.next().ok_or("expect integer")?;
                    match b {
                        b'1' => s.push(d.read_value::<i8>(addr)),
                        b'2' => s.push(d.read_value::<i16>(addr)),
                        b'4' => s.push(d.read_value::<i32>(addr)),
                        b'8' => s.push(d.read_value::<i64>(addr)),
                        _ => return Err("invalid integer"),
                    };
                    (b - b'0') as usize
                }
                b'I' => {
                    let b = iter.next().ok_or("expect integer")?;
                    match b {
                        b'1' => s.push(d.read_value::<u8>(addr)),
                        b'2' => s.push(d.read_value::<u16>(addr)),
                        b'4' => s.push(d.read_value::<u32>(addr)),
                        b'8' => s.push(d.read_value::<u64>(addr)),
                        _ => return Err("invalid integer"),
                    };
                    (b - b'0') as usize
                }
                b'f' => {
                    s.push(d.read_value::<f32>(addr));
                    4
                }
                b'd' => {
                    s.push(d.read_value::<f64>(addr));
                    8
                }
                b'T' => {
                    s.push(read_ptr(addr));
                    psize
                }
                b'z' => {
                    let text = d.read_cstring(addr, None);
                    if text.is_none() && isptr {
                        s.push_nil();
                        0
                    } else {
                        let text = text.ok_or("read string")?;
                        s.push(text.as_slice());
                        text.len() + 1
                    }
                }
                #[cfg(windows)]
                b'w' => {
                    let w = d.read_wstring(addr, None);
                    if w.is_none() && isptr {
                        s.push_nil();
                        0
                    } else {
                        let w = w.ok_or("read wstring")?;
                        s.push(w.as_str());
                        (w.len() + 1) * 2
                    }
                }
                b's' => {
                    let b = iter.next().ok_or("expect integer")?;
                    let len = match b {
                        b'1' => d.read_value::<u8>(addr).map(|n| n as usize),
                        b'2' => d.read_value::<u16>(addr).map(|n| n as usize),
                        b'4' => d.read_value::<u32>(addr).map(|n| n as usize),
                        b'8' => d.read_value::<u64>(addr).map(|n| n as usize),
                        _ => return Err("invalid integer"),
                    }
                    .ok_or("read integer")?;
                    let r = d.read_bytes(addr + (b - b'0') as usize, len);
                    s.push(r.as_slice());
                    (b - b'0') as usize + r.len()
                }
                b'c' => {
                    let mut len = 0;
                    while let Some(b) = iter.next() {
                        if !b.is_ascii_digit() {
                            ahead = Some(b);
                            break;
                        }
                        len = len * 10 + (*b - b'0') as usize;
                    }
                    let r = d.read_bytes(addr + (b - b'0') as usize, len);
                    s.push(r.as_slice());
                    r.len()
                }
                _ => return Err("invalid type"),
            }
        } else {
            s.push_nil();
            0
        };
        if isptr {
            address += psize;
        } else {
            address += size;
        }
    }
    Ok(())
}

impl ToLua for CpuReg {
    #[inline(always)]
    fn to_lua<'a>(self, s: &'a LuaState) -> LuaResult<ValRef<'a>> {
        match self {
            CpuReg::Int(n) => n.to_lua(s),
            CpuReg::Flt(n) => n.to_lua(s),
        }
    }
}

impl UserData for MemoryPage {
    const TYPE_NAME: &'static str = "MemoryPage";

    fn getter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields.set_closure("alloc_base", |this: &Self| this.alloc_base)?;
        fields.set_closure("alloc_protect", |this: &Self| this.alloc_protect)?;
        fields.set_closure("base", |this: &Self| this.base)?;
        fields.set_closure("size", |this: &Self| this.size)?;
        fields.set_closure("executable", |this: &Self| this.is_executable())?;
        fields.set_closure("writable", |this: &Self| this.is_writable())?;
        fields.set_closure("readonly", |this: &Self| this.is_readonly())?;
        fields.set_closure("private", |this: &Self| this.is_private())?;
        fields.set_closure("commited", |this: &Self| this.is_commit())?;
        fields.set_closure("protect", |this: &Self| this.protect)?;
        fields.set_closure("type", |this: &Self| this.type_)?;
        fields.set_closure("state", |this: &Self| this.state)?;
        fields.set_closure("info", |this: &Self| this.info.clone())?;
        fields.set_closure("memory_info", |this: &Self| {
            SerdeValue(MemoryPageInfo::from(this))
        })?;

        Ok(())
    }

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("is_commit", MemoryPage::is_commit)?
            .set_closure("is_reserve", MemoryPage::is_reserve)?
            .set_closure("is_free", MemoryPage::is_free)?
            .set_closure("is_private", MemoryPage::is_private)?;

        Ok(())
    }
}

impl ToLuaMulti for HandleInfo {
    fn push_multi(self, s: &LuaState) -> LuaResult<usize> {
        (
            self.handle,
            self.ty,
            self.type_name.as_ref(),
            self.name.as_str(),
        )
            .push_multi(s)
    }
}

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
        fields.set_closure("type_id", |s: &LuaState, this: &Self| {
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
        mt.set_closure("get_type", |this: &Self, id: u32| {
            this.get_type(id).map(SerdeValue)
        })?;
        mt.set_closure("find_type", |this: &Self, name: &str| {
            SerdeValue(this.find_type(name))
        })?;
        mt.set_closure("get_field", |this: &Self, type_id: u32, val: LuaValue| {
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
        mt.set_closure("enum_field", |this: &Self, type_id: u32| {
            StaticIter::from(this.get_field_list(type_id).into_iter().map(|x| x))
        })?;

        Ok(())
    }
}

pub struct ArcModule<'a>(pub Arc<dyn UDbgModule + 'a>);

impl<'a> std::ops::Deref for ArcModule<'a> {
    type Target = dyn UDbgModule + 'a;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<'a> AsRef<dyn UDbgModule + 'a> for ArcModule<'a> {
    #[inline(always)]
    fn as_ref(&self) -> &(dyn UDbgModule + 'a) {
        self.0.as_ref()
    }
}

impl UserData for ArcModule<'_> {
    const TYPE_NAME: &'static str = "UDbgModule*";

    fn metatable(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("__index", |s: &LuaState, this: &Self, key: &str| {
            this.0
                .get_prop(key)
                .map(|val| SerdeValue(val))
                .unwrap_or_else(|_| SerdeValue(serde_value::Value::Unit))
        })?;

        Ok(())
    }

    fn getter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields.add_field_get("data", |_, this: &Self| SerdeValue(this.data()))?;
        fields.set_closure("base", |this: &Self| this.data().base)?;
        fields.set_closure("size", |this: &Self| this.data().size)?;
        fields.add_field_get("name", |_, this: &Self| this.data().name.as_ref())?;
        fields.add_field_get("path", |_, this: &Self| this.data().path.as_ref())?;
        fields.set_closure("arch", |this: &Self| this.data().arch)?;
        fields.set_closure("entry", |this: &Self| this.data().entry)?;
        fields.set_closure("entry_point", |this: &Self| {
            let data = this.data();
            data.base + data.entry
        })?;
        fields.set_closure("user_module", |this: &Self| this.data().user_module.get())?;

        Ok(())
    }

    fn setter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields.set_closure("user_module", |this: &Self, user: bool| {
            this.data().user_module.set(user)
        })?;
        Ok(())
    }

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        // mt.as_deref()
        //     .add_deref("add_symbol", <dyn UDbgModule>::add_symbol)?
        //     .add_deref("load_symbol", <dyn UDbgModule>::load_symbol_file)?;

        mt.set_closure("symbol_file", |this: &Self| {
            this.symbol_file().map(ArcSymbolFile)
        })?;
        mt.add_method("enum_symbol", |s: &LuaState, this: &Self, pat: &str| {
            this.enum_symbol(Some(pat))
                .map(|x| unsafe { s.new_iter(x, [ArgRef(1)]) })
                .lua_result()
        })?;
        mt.add("enum_export", |this: &Self| {
            this.get_exports()
                .map(|exports| StaticIter::from(exports.into_iter()))
        })?;
        mt.add_method("get_symbol", |s, this: &Self, pat: &str| {
            this.enum_symbol(Some(pat))
                .map(|mut x| x.next().map(|sym| s.new_val(sym)).transpose())
                .lua_result()
        })?;
        #[cfg(all(windows, target_arch = "x86_64"))]
        mt.set_closure(
            "find_function",
            |s: &LuaState, this: &Self, a: usize| unsafe {
                this.find_function(a)
                    .map(|x| (x.BeginAddress, x.EndAddress, *x.u.UnwindData()))
                    .ok_or(())
            },
        )?;

        Ok(())
    }
}

#[derive(Deref)]
pub struct BoxThread(pub Box<dyn UDbgThread>);

impl UserData for BoxThread {
    const TYPE_NAME: &'static str = "UDbgThread*";

    fn getter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields.set_closure("tid", |this: &Self| this.tid)?;
        #[cfg(windows)]
        fields.set_closure("wow64", |this: &Self| this.wow64)?;
        #[cfg(windows)]
        fields.set_closure("handle", |this: &Self| this.handle.0 .0 .0)?;
        #[cfg(windows)]
        fields.set_closure("entry", |this: &Self| this.entry())?;
        #[cfg(windows)]
        fields.set_closure("teb", |this: &Self| this.teb())?;
        fields.set_closure("name", |this: &Self| this.name())?;
        fields.set_closure("status", |this: &Self| this.status())?;
        fields.set_closure("priority", |this: &Self| this.priority())?;
        // #[cfg(windows)]
        // fields.set_closure("context", |s: &LuaState, this: &Self| unsafe {
        //     let mut cx: ThreadContext = core::mem::zeroed();
        //     this.get_context(&mut cx).lua_result()?;
        //     s.new_userdata(cx)
        // })?;
        // #[cfg(all(windows, target_pointer_width = "32"))]
        // fields.set_closure("context32", |s: &LuaState, this: &Self| unsafe {
        //     let mut cx: ThreadContext32 = core::mem::zeroed();
        //     this.get_context32(&mut cx).lua_result()?;
        //     s.new_userdata(cx)
        // })?;

        Ok(())
    }

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("suspend", |this: &Self| this.suspend())?;
        mt.set_closure("resume", |this: &Self| this.resume())?;
        #[cfg(windows)]
        mt.set_closure("last_error", |this: &Self| this.last_error())?;

        Ok(())
    }

    fn metatable(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("__call", |s: &LuaState, this: &Self, key: &str| {
            this.0.get_prop(key).map(SerdeValue)
        })?;

        Ok(())
    }
}

pub struct ArcBreakpoint(pub Arc<dyn UDbgBreakpoint + 'static>);

impl std::ops::Deref for ArcBreakpoint {
    type Target = dyn UDbgBreakpoint;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl AsRef<dyn UDbgBreakpoint> for ArcBreakpoint {
    #[inline(always)]
    fn as_ref(&self) -> &(dyn UDbgBreakpoint + 'static) {
        self.0.as_ref()
    }
}

impl ToLua for BpType {
    #[inline(always)]
    fn to_lua<'a>(self, s: &'a LuaState) -> LuaResult<ValRef<'a>> {
        ToLua::to_lua(self.to_string(), s)
    }
}

impl UserData for ArcBreakpoint {
    const TYPE_NAME: &'static str = "UDbgBreakpoint*";
    const WEAK_REF_CACHE: bool = false;

    fn key_to_cache(&self) -> *const () {
        (self.as_ref() as *const dyn UDbgBreakpoint)
            .to_raw_parts()
            .0
    }

    fn uservalue_count(&self, s: &LuaState) -> i32 {
        1
    }

    fn getter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields
            .as_deref()
            .add_deref("address", <dyn UDbgBreakpoint>::address)?
            .add_deref("id", <dyn UDbgBreakpoint>::get_id)?
            .add_deref("type", <dyn UDbgBreakpoint>::get_type)?
            .add_deref("hitcount", <dyn UDbgBreakpoint>::hit_count)?
            .add_deref("enabled", <dyn UDbgBreakpoint>::enabled)?;

        let lua = fields.state();
        fields.set(
            "callback",
            lua.new_closure1(|s: &LuaState, this: LuaUserData| this.get_uservalue())?,
        )?;

        Ok(())
    }

    fn setter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields
            .as_deref()
            .add_deref("enabled", <dyn UDbgBreakpoint>::enable)?;

        let lua = fields.state();
        fields.set(
            "callback",
            lua.new_closure2(|_, this: LuaUserData, val: ValRef| this.set_uservalue(val))?,
        )?;
        Ok(())
    }

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("enable", |this: &Self| this.enable(true))?;
        mt.set_closure("disable", |this: &Self| this.enable(false))?;
        mt.set_closure("remove", |s: &LuaState, this: &Self| {
            // TODO:
            // this.clear_cached(s);
            this.remove();
        })?;
        Ok(())
    }
}

impl ToLuaMulti for UEvent {
    fn push_multi(self, s: &LuaState) -> LuaResult<usize> {
        use UEvent::*;
        match self {
            InitBp => INIT_BP.push_multi(s),
            Step => STEP.push_multi(s),
            Breakpoint(bp) => ((BREAKPOINT, ArcBreakpoint(bp))).push_multi(s),
            ProcessCreate => (PROCESS_CREATE).push_multi(s),
            ProcessExit(code) => ((PROCESS_EXIT, code)).push_multi(s),
            ModuleLoad(m) => (MODULE_LOAD, ArcModule(m)).push_multi(s),
            ModuleUnload(m) => (MODULE_UNLOAD, ArcModule(m)).push_multi(s),
            ThreadCreate(tid) => ((THREAD_CREATE, tid)).push_multi(s),
            ThreadExit(code) => ((THREAD_EXIT, code)).push_multi(s),
            Exception { first, code } => ((EXCEPTION, code, first)).push_multi(s),
        }
    }
}

#[derive(Clone)]
pub struct ArcTarget(pub Arc<dyn UDbgTarget>);

impl std::ops::Deref for ArcTarget {
    type Target = dyn UDbgTarget;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl From<Arc<dyn UDbgTarget>> for ArcTarget {
    fn from(value: Arc<dyn UDbgTarget>) -> Self {
        value.base().status.set(UDbgStatus::Opened);
        Self(value)
    }
}

impl AsRef<dyn UDbgTarget> for ArcTarget {
    #[inline(always)]
    fn as_ref(&self) -> &dyn UDbgTarget {
        self.0.as_ref()
    }
}

impl UserData for ArcTarget {
    const TYPE_NAME: &'static str = "UDbgTarget*";
    const INDEX_USERVALUE: bool = true;

    fn metatable(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("__index", |this: &Self, key: &str| {
            this.0.get_prop(key).map(SerdeValue).ok()
        })?;

        Ok(())
    }

    fn init_userdata(this: &Self::Trans, s: &LuaState, ud: &LuaUserData) -> LuaResult<()> {
        ud.set_uservalue(s.new_val(SerdeValue(this.base()))?)
    }

    fn key_to_cache(&self) -> *const () {
        (self.0.as_ref() as *const dyn UDbgTarget).to_raw_parts().0
    }

    fn getter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields
            .add_field_get("base", |_, this: &Self| SerdeValue(this.base()))?
            .set_closure("pid", |this: &Self| this.base().pid.get())?
            .set_closure("arch", |this: &Self| this.base().arch)?
            .set_closure("event_tid", |this: &Self| this.base().event_tid.get())?
            .set_closure("pointer_size", |this: &Self| this.base().pointer_size())?
            .set_closure("status", |this: &Self| this.base().status.get().as_str())?
            .set_closure("context_arch", |this: &Self| {
                match this.base().context_arch.get() {
                    ARCH_X86 => "x86",
                    ARCH_X64 => "x86_64",
                    ARCH_ARM => "arm",
                    ARCH_ARM64 => "arm64",
                    _ => unreachable!(),
                }
            })?;
        #[cfg(windows)]
        fields.set_closure("handle", |this: &Self| this.handle().0)?;
        Ok(())
    }

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.as_deref()
            .add_deref("read_u8", <dyn UDbgTarget>::read_value::<u8>)?
            .add_deref("read_u16", <dyn UDbgTarget>::read_value::<u16>)?
            .add_deref("read_u32", <dyn UDbgTarget>::read_value::<u32>)?
            .add_deref("read_u64", <dyn UDbgTarget>::read_value::<u64>)?
            .add_deref("read_f32", <dyn UDbgTarget>::read_value::<f32>)?
            .add_deref("read_f64", <dyn UDbgTarget>::read_value::<f64>)?
            .add_deref("image_path", <dyn UDbgTarget>::image_path)?
            .add_deref("detach", <dyn UDbgTarget>::detach)?
            .add_deref("kill", <dyn UDbgTarget>::kill)?
            .add_deref("pause", <dyn UDbgTarget>::breakk)?
            .add_deref("resume", <dyn UDbgTarget>::resume)?
            .add_deref("suspend", <dyn UDbgTarget>::suspend)?
            .add_deref("wait_exit", <dyn UDbgTarget>::wait_exit)?;

        fn write_value<T>(this: &ArcTarget, a: usize, val: T) {
            this.write_value(a, &val);
        }
        mt.set_closure("write_u8", write_value::<u8>)?
            .set_closure("write_u16", write_value::<u16>)?
            .set_closure("write_u32", write_value::<u32>)?
            .set_closure("write_u64", write_value::<u64>)?
            .set_closure("write_f32", write_value::<f32>)?
            .set_closure("write_f64", write_value::<f64>)?;

        let lua = mt.state();
        mt.set(
            "add_breakpoint",
            lua.new_closure6(
                |s: &LuaState,
                 this: &Self,
                 a: usize,
                 ty: Option<&str>,
                 size: Option<usize>,
                 temp: bool,
                 tid: Option<tid_t>| {
                    let r = match ty {
                        Some("int3") | Some("soft") | None => this.add_breakpoint(BpOpt {
                            address: a,
                            enable: false,
                            temp,
                            tid,
                            rw: None,
                            len: None,
                            table: false,
                        }),
                        Some("table") => this.add_breakpoint(BpOpt {
                            address: a,
                            enable: false,
                            temp,
                            tid,
                            table: true,
                            len: None,
                            rw: None,
                        }),
                        Some(tys) => this.add_breakpoint(BpOpt {
                            address: a,
                            enable: false,
                            temp,
                            tid,
                            table: false,
                            rw: Some(match tys {
                                "execute" => HwbpType::Execute,
                                "write" => HwbpType::Write,
                                "access" => HwbpType::Access,
                                _ => return Err(LuaError::convert("Invalid breakpoint type")),
                            }),
                            len: Some(match size {
                                Some(1) | None => HwbpLen::L1,
                                Some(2) => HwbpLen::L2,
                                Some(4) => HwbpLen::L4,
                                Some(8) => HwbpLen::L8,
                                _ => return Err(LuaError::convert("Invalid hwbp size")),
                            }),
                        }),
                    };
                    LuaResult::Ok(match r {
                        Ok(bp) => (s.new_val(ArcBreakpoint(bp))?, s.new_val(())?),
                        Err(UDbgError::BpExists) => (s.new_val(false)?, s.new_val("exists")?),
                        Err(e) => (s.new_val(false)?, s.new_val(format!("{:?}", e))?),
                    })
                },
            )?,
        )?;
        mt.set_closure("get_breakpoint", |this: &Self, id: BpID| {
            this.get_breakpoint(id).map(ArcBreakpoint)
        })?;
        mt.set_closure("breakpoint_list", |this: &Self| {
            IterVec(this.get_breakpoints().into_iter().map(ArcBreakpoint))
        })?;

        mt.set_closure(
            "read_string",
            |this: &Self, a: usize, size: Option<usize>| this.read_cstring(a, size.unwrap_or(1000)),
        )?;
        #[cfg(windows)]
        mt.set_closure(
            "read_wstring",
            |this: &Self, a: usize, size: Option<usize>| this.read_wstring(a, size.unwrap_or(1000)),
        )?;
        mt.set_closure("write_string", |this: &Self, a: usize, buf: &[u8]| {
            this.write_cstring(a, buf)
        })?;
        #[cfg(windows)]
        mt.set_closure("write_wstring", |this: &Self, a: usize, buf: &str| {
            this.write_wstring(a, buf)
        })?;

        mt.set_closure(
            "read_pack",
            |s: &LuaState, this: &Self, a: usize, pack: &[u8]| {
                read_pack(
                    s,
                    this.0.as_ref(),
                    a,
                    pack,
                    this.base().pointer_size().into(),
                )
                .map(|_| ReturnAll)
            },
        )?
        .set_closure(
            "detect_string",
            |this: &Self, p: usize, max: Option<usize>| {
                this.detect_string(p, max.unwrap_or(32))
                    .map(|(wide, text)| (text, wide))
            },
        )?
        .set_closure("open_thread", |this: &Self, tid: tid_t| {
            this.open_thread(tid).map(|x| BoxThread(x))
        })?
        .set_closure("thread_list", |this: &Self| unsafe {
            this.enum_thread(true).map(|iter| {
                IterMap(
                    core::mem::transmute::<
                        _,
                        Box<dyn Iterator<Item = Box<dyn UDbgThread>> + 'static>,
                    >(iter)
                    .map(|t| (t.tid, BoxThread(t))),
                )
            })
        })?;

        mt.add_method("enum_module", |s, this: &Self, ()| {
            this.enum_module().map(|r| unsafe {
                s.new_iter_map(r, |s, m| s.new_userdata(ArcModule(m)), [ArgRef(1)])
            })
        })?
        .add_method("enum_thread", |s, this: &Self, detail: bool| {
            this.enum_thread(detail)
                .map(|r| unsafe { s.new_iter(r.map(BoxThread), [ArgRef(1)]) })
        })?
        .add_method("enum_memory", |s, this: &Self, ()| {
            this.enum_memory()
                .map(|r| unsafe { s.new_iter(r, [ArgRef(1)]) })
        })?
        .add_method("enum_handle", |s, this: &Self, ()| {
            this.enum_handle()
                .map(|r| unsafe { s.new_iter(r, [ArgRef(1)]) })
        })?;

        mt.set_closure("collect_memory", |this: &Self| {
            IterVec(this.collect_memory_info().into_iter().map(SerdeValue))
        })?
        .set_closure("get_module", |s: &LuaState, this: &Self, val: ValRef| {
            (if val.type_of().is_none_or_nil() {
                this.find_module(this.base().image_base)
            } else {
                let base = val.to_integer() as usize;
                if base > 0 {
                    this.find_module(base)
                } else {
                    this.get_module(val.to_str().unwrap_or(""))
                }
            })
            .map(ArcModule)
        })?;

        mt.set_closure("virtual_query", |this: &Self, a: usize| {
            this.virtual_query(a)
        })?
        .set_closure(
            "virtual_alloc",
            |this: &Self, a: usize, size: usize, ty: Option<&str>| {
                this.virtual_alloc(a, size, ty.unwrap_or(""))
            },
        )?
        .set_closure("virtual_free", |this: &Self, a: usize| {
            this.virtual_free(a);
        })?;

        mt.set(
            "read_type",
            lua.new_closure3(|s: &LuaState, this: &Self, a: usize, ty: &str| {
                let address = a;
                match ty {
                    "usize" => s.new_val(this.read_value::<usize>(address)),
                    "u8" => s.new_val(this.read_value::<u8>(address)),
                    "u16" => s.new_val(this.read_value::<u16>(address)),
                    "u32" => s.new_val(this.read_value::<u32>(address)),
                    "u64" => s.new_val(this.read_value::<u64>(address)),
                    "isize" => s.new_val(this.read_value::<isize>(address)),
                    "i8" => s.new_val(this.read_value::<i8>(address)),
                    "i16" => s.new_val(this.read_value::<i16>(address)),
                    "i32" => s.new_val(this.read_value::<i32>(address)),
                    "i64" => s.new_val(this.read_value::<i64>(address)),
                    "f32" => s.new_val(this.read_value::<f32>(address)),
                    "f64" => s.new_val(this.read_value::<f64>(address)),
                    "ptr" => s.new_val(this.read_ptr(address)),
                    "z" => s.new_val(this.read_cstring(address, 1000).as_ref().map(Vec::as_slice)),
                    #[cfg(windows)]
                    "w" => s.new_val(this.read_wstring(address, 1000)),
                    _ => s.new_val(()),
                }
            })?,
        )?;

        mt.set(
            "read_bytes",
            lua.new_closure4(
                |s: &LuaState, this: &Self, a: usize, length: usize, userdata: bool| unsafe {
                    use ezlua::luaapi::UnsafeLuaApi;

                    if userdata {
                        let p = UnsafeLuaApi::new_userdata(s, length);
                        let buf = core::slice::from_raw_parts_mut(p.cast::<u8>(), length);
                        s.new_val(this.read_memory(a, buf).map(|x| x as &_))
                    } else if length > STACK_BUFFER_SIZE {
                        let mut buf: Vec<u8> = vec![0u8; length];
                        s.new_val(this.read_memory(a, &mut buf).map(|x| x as &_))
                    } else {
                        let mut buf = [0u8; STACK_BUFFER_SIZE];
                        s.new_val(this.read_memory(a, &mut buf[..length]).map(|x| x as &_))
                    }
                },
            )?,
        )?;

        mt.set_closure(
            "write_bytes",
            |this: &Self, a: usize, buf: &[u8], len: Option<usize>| {
                this.write_memory(a, len.map(|len| &buf[..len]).unwrap_or(buf))
            },
        )?;

        mt.set_closure(
            "write_type",
            |s: &LuaState, this: &Self, a: usize, ty: &str| {
                use ezlua::luaapi::UnsafeLuaApi;

                let address = a;
                match ty {
                    "usize" => this.write_value(address, &(s.to_integer(4) as usize)),
                    "u8" => this.write_value(address, &(s.to_integer(4) as u8)),
                    "u16" => this.write_value(address, &(s.to_integer(4) as u16)),
                    "u32" => this.write_value(address, &(s.to_integer(4) as u32)),
                    "u64" => this.write_value(address, &(s.to_integer(4) as u64)),
                    "isize" => this.write_value(address, &(s.to_integer(4) as isize)),
                    "i8" => this.write_value(address, &(s.to_integer(4) as i8)),
                    "i16" => this.write_value(address, &(s.to_integer(4) as i16)),
                    "i32" => this.write_value(address, &(s.to_integer(4) as i32)),
                    "i64" => this.write_value(address, &(s.to_integer(4) as i64)),
                    "f32" => this.write_value(address, &(s.to_number(4) as f32)),
                    "f64" => this.write_value(address, &(s.to_number(4) as f64)),
                    _ => None,
                }
            },
        )?;

        mt.set_closure("get_symbol", |this: &Self, a: usize, o: Option<usize>| {
            this.get_symbol_(a, o).map(|s| s.to_string(a))
        })?;

        mt.set_closure(
            "get_symbol_detail",
            |s: &LuaState, this: &Self, a: usize| {
                this.get_symbol_(a, None)
                    .map(|r| (r.module, r.symbol, r.offset, r.mod_base))
                    .ok_or(())
            },
        )?;

        Ok(())
    }
}

impl ToLua for ProcessInfo {
    #[inline(always)]
    fn to_lua<'a>(self, s: &'a LuaState) -> LuaResult<ValRef<'a>> {
        ToLua::to_lua(SerdeValue(self), s)
    }
}

#[derive(Deref, DerefMut)]
pub struct BoxEngine(pub Box<dyn UDbgEngine>);

impl UserData for BoxEngine {
    const TYPE_NAME: &'static str = "UDbgEngine*";

    type Trans = RefCell<Self>;

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.add("enum_process", |this: &Self| {
            this.enum_process().map(StaticIter::from)
        })?
        .add_mut("open", |this: &mut Self, pid: pid_t| {
            this.open(pid).map(ArcTarget::from)
        })?
        .add_mut("find", |this: &mut Self, name: &str| {
            #[cfg(windows)]
            let pred = |p: &ProcessInfo| p.name.eq_ignore_ascii_case(name);
            #[cfg(not(windows))]
            let pred = |p: &ProcessInfo| p.name == name;
            this.enum_process()
                .lua_result()?
                .find(pred)
                .map(|p| this.open(p.pid).map(ArcTarget::from))
                .transpose()
                .lua_result()
        })?
        .add_mut("attach", |this: &mut Self, pid: pid_t| {
            this.attach(pid).map(ArcTarget)
        })?
        .add_mut(
            "create",
            |this: &mut Self, path: &str, cwd: Option<&str>, args: SerdeValue<Vec<&str>>| {
                this.create(path, cwd, &args).map(ArcTarget)
            },
        )?;
        // mt.add_mut(
        //     "event_loop",
        //     |s: &LuaState, this: &mut Self, mut co: Coroutine| {
        //         todo!()
        //         // let ui = udbg_ui();
        //         // let mut resume = move |ctx: &dyn TraceContext, event| -> UserReply {
        //         //     let this = ArcTarget(ctx.target());
        //         //     let res =
        //         //         co.resume::<_, (Option<&str>, Value)>(ResumeArgs(this.clone(), event));
        //         //     match res {
        //         //         Ok((action, _)) => match action.unwrap_or_default() {
        //         //             "step" | "stepin" => UserReply::StepIn,
        //         //             "stepout" => UserReply::StepOut,
        //         //             "goto" => UserReply::Goto(co.to_integer(-1) as usize),
        //         //             "native" => UserReply::Native(co.to_integer(-1) as usize),
        //         //             "run" | _ => UserReply::Run(co.to_bool(-1)),
        //         //         },
        //         //         Err(err) => {
        //         //             s.traceback(&co, cstr!("resume event"), 1);
        //         //             s.error();
        //         //         }
        //         //     }
        //         // };
        //         // this.event_loop(&mut |ctx, event| resume(ctx, event));
        //     },
        // )?;

        Ok(())
    }

    fn metatable(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("default", || {
            BoxEngine(Box::new(crate::os::DefaultEngine::default()))
        })?;

        Ok(())
    }
}

pub struct ResumeArgs(pub ArcTarget, pub UEvent);

impl ToLuaMulti for ResumeArgs {
    fn push_multi(self, s: &LuaState) -> LuaResult<usize> {
        Ok(self.0.push_multi(s)? + self.1.push_multi(s)?)
    }
}

fn init_regid_x86(s: &LuaState) -> LuaResult<LuaTable> {
    use crate::register::regid::*;

    let t = s.new_table()?;
    for (name, val) in [
        ("ah", X86_REG_AH),
        ("al", X86_REG_AL),
        ("ax", X86_REG_AX),
        ("bh", X86_REG_BH),
        ("bl", X86_REG_BL),
        ("bp", X86_REG_BP),
        ("bpl", X86_REG_BPL),
        ("bx", X86_REG_BX),
        ("ch", X86_REG_CH),
        ("cl", X86_REG_CL),
        ("cs", X86_REG_CS),
        ("cx", X86_REG_CX),
        ("dh", X86_REG_DH),
        ("di", X86_REG_DI),
        ("dil", X86_REG_DIL),
        ("dl", X86_REG_DL),
        ("ds", X86_REG_DS),
        ("dx", X86_REG_DX),
        ("eax", X86_REG_EAX),
        ("ebp", X86_REG_EBP),
        ("ebx", X86_REG_EBX),
        ("ecx", X86_REG_ECX),
        ("edi", X86_REG_EDI),
        ("edx", X86_REG_EDX),
        ("eflags", X86_REG_EFLAGS),
        ("eip", X86_REG_EIP),
        ("eiz", X86_REG_EIZ),
        ("es", X86_REG_ES),
        ("esi", X86_REG_ESI),
        ("esp", X86_REG_ESP),
        ("fpsw", X86_REG_FPSW),
        ("fs", X86_REG_FS),
        ("gs", X86_REG_GS),
        ("ip", X86_REG_IP),
        ("rax", X86_REG_RAX),
        ("rbp", X86_REG_RBP),
        ("rbx", X86_REG_RBX),
        ("rcx", X86_REG_RCX),
        ("rdi", X86_REG_RDI),
        ("rdx", X86_REG_RDX),
        ("rip", X86_REG_RIP),
        ("riz", X86_REG_RIZ),
        ("rsi", X86_REG_RSI),
        ("rsp", X86_REG_RSP),
        ("si", X86_REG_SI),
        ("sil", X86_REG_SIL),
        ("sp", X86_REG_SP),
        ("spl", X86_REG_SPL),
        ("ss", X86_REG_SS),
        ("cr0", X86_REG_CR0),
        ("cr1", X86_REG_CR1),
        ("cr2", X86_REG_CR2),
        ("cr3", X86_REG_CR3),
        ("cr4", X86_REG_CR4),
        ("cr5", X86_REG_CR5),
        ("cr6", X86_REG_CR6),
        ("cr7", X86_REG_CR7),
        ("cr8", X86_REG_CR8),
        ("cr9", X86_REG_CR9),
        ("cr10", X86_REG_CR10),
        ("cr11", X86_REG_CR11),
        ("cr12", X86_REG_CR12),
        ("cr13", X86_REG_CR13),
        ("cr14", X86_REG_CR14),
        ("cr15", X86_REG_CR15),
        ("dr0", X86_REG_DR0),
        ("dr1", X86_REG_DR1),
        ("dr2", X86_REG_DR2),
        ("dr3", X86_REG_DR3),
        ("dr4", X86_REG_DR4),
        ("dr5", X86_REG_DR5),
        ("dr6", X86_REG_DR6),
        ("dr7", X86_REG_DR7),
        ("dr8", X86_REG_DR8),
        ("dr9", X86_REG_DR9),
        ("dr10", X86_REG_DR10),
        ("dr11", X86_REG_DR11),
        ("dr12", X86_REG_DR12),
        ("dr13", X86_REG_DR13),
        ("dr14", X86_REG_DR14),
        ("dr15", X86_REG_DR15),
        ("fp0", X86_REG_FP0),
        ("fp1", X86_REG_FP1),
        ("fp2", X86_REG_FP2),
        ("fp3", X86_REG_FP3),
        ("fp4", X86_REG_FP4),
        ("fp5", X86_REG_FP5),
        ("fp6", X86_REG_FP6),
        ("fp7", X86_REG_FP7),
        ("k0", X86_REG_K0),
        ("k1", X86_REG_K1),
        ("k2", X86_REG_K2),
        ("k3", X86_REG_K3),
        ("k4", X86_REG_K4),
        ("k5", X86_REG_K5),
        ("k6", X86_REG_K6),
        ("k7", X86_REG_K7),
        ("mm0", X86_REG_MM0),
        ("mm1", X86_REG_MM1),
        ("mm2", X86_REG_MM2),
        ("mm3", X86_REG_MM3),
        ("mm4", X86_REG_MM4),
        ("mm5", X86_REG_MM5),
        ("mm6", X86_REG_MM6),
        ("mm7", X86_REG_MM7),
        ("r8", X86_REG_R8),
        ("r9", X86_REG_R9),
        ("r10", X86_REG_R10),
        ("r11", X86_REG_R11),
        ("r12", X86_REG_R12),
        ("r13", X86_REG_R13),
        ("r14", X86_REG_R14),
        ("r15", X86_REG_R15),
        ("st0", X86_REG_ST0),
        ("st1", X86_REG_ST1),
        ("st2", X86_REG_ST2),
        ("st3", X86_REG_ST3),
        ("st4", X86_REG_ST4),
        ("st5", X86_REG_ST5),
        ("st6", X86_REG_ST6),
        ("st7", X86_REG_ST7),
        ("xmm0", X86_REG_XMM0),
        ("xmm1", X86_REG_XMM1),
        ("xmm2", X86_REG_XMM2),
        ("xmm3", X86_REG_XMM3),
        ("xmm4", X86_REG_XMM4),
        ("xmm5", X86_REG_XMM5),
        ("xmm6", X86_REG_XMM6),
        ("xmm7", X86_REG_XMM7),
        ("xmm8", X86_REG_XMM8),
        ("xmm9", X86_REG_XMM9),
        ("xmm10", X86_REG_XMM10),
        ("xmm11", X86_REG_XMM11),
        ("xmm12", X86_REG_XMM12),
        ("xmm13", X86_REG_XMM13),
        ("xmm14", X86_REG_XMM14),
        ("xmm15", X86_REG_XMM15),
        ("xmm16", X86_REG_XMM16),
        ("xmm17", X86_REG_XMM17),
        ("xmm18", X86_REG_XMM18),
        ("xmm19", X86_REG_XMM19),
        ("xmm20", X86_REG_XMM20),
        ("xmm21", X86_REG_XMM21),
        ("xmm22", X86_REG_XMM22),
        ("xmm23", X86_REG_XMM23),
        ("xmm24", X86_REG_XMM24),
        ("xmm25", X86_REG_XMM25),
        ("xmm26", X86_REG_XMM26),
        ("xmm27", X86_REG_XMM27),
        ("xmm28", X86_REG_XMM28),
        ("xmm29", X86_REG_XMM29),
        ("xmm30", X86_REG_XMM30),
        ("xmm31", X86_REG_XMM31),
        ("ymm0", X86_REG_YMM0),
        ("ymm1", X86_REG_YMM1),
        ("ymm2", X86_REG_YMM2),
        ("ymm3", X86_REG_YMM3),
        ("ymm4", X86_REG_YMM4),
        ("ymm5", X86_REG_YMM5),
        ("ymm6", X86_REG_YMM6),
        ("ymm7", X86_REG_YMM7),
        ("ymm8", X86_REG_YMM8),
        ("ymm9", X86_REG_YMM9),
        ("ymm10", X86_REG_YMM10),
        ("ymm11", X86_REG_YMM11),
        ("ymm12", X86_REG_YMM12),
        ("ymm13", X86_REG_YMM13),
        ("ymm14", X86_REG_YMM14),
        ("ymm15", X86_REG_YMM15),
        ("ymm16", X86_REG_YMM16),
        ("ymm17", X86_REG_YMM17),
        ("ymm18", X86_REG_YMM18),
        ("ymm19", X86_REG_YMM19),
        ("ymm20", X86_REG_YMM20),
        ("ymm21", X86_REG_YMM21),
        ("ymm22", X86_REG_YMM22),
        ("ymm23", X86_REG_YMM23),
        ("ymm24", X86_REG_YMM24),
        ("ymm25", X86_REG_YMM25),
        ("ymm26", X86_REG_YMM26),
        ("ymm27", X86_REG_YMM27),
        ("ymm28", X86_REG_YMM28),
        ("ymm29", X86_REG_YMM29),
        ("ymm30", X86_REG_YMM30),
        ("ymm31", X86_REG_YMM31),
        ("zmm0", X86_REG_ZMM0),
        ("zmm1", X86_REG_ZMM1),
        ("zmm2", X86_REG_ZMM2),
        ("zmm3", X86_REG_ZMM3),
        ("zmm4", X86_REG_ZMM4),
        ("zmm5", X86_REG_ZMM5),
        ("zmm6", X86_REG_ZMM6),
        ("zmm7", X86_REG_ZMM7),
        ("zmm8", X86_REG_ZMM8),
        ("zmm9", X86_REG_ZMM9),
        ("zmm10", X86_REG_ZMM10),
        ("zmm11", X86_REG_ZMM11),
        ("zmm12", X86_REG_ZMM12),
        ("zmm13", X86_REG_ZMM13),
        ("zmm14", X86_REG_ZMM14),
        ("zmm15", X86_REG_ZMM15),
        ("zmm16", X86_REG_ZMM16),
        ("zmm17", X86_REG_ZMM17),
        ("zmm18", X86_REG_ZMM18),
        ("zmm19", X86_REG_ZMM19),
        ("zmm20", X86_REG_ZMM20),
        ("zmm21", X86_REG_ZMM21),
        ("zmm22", X86_REG_ZMM22),
        ("zmm23", X86_REG_ZMM23),
        ("zmm24", X86_REG_ZMM24),
        ("zmm25", X86_REG_ZMM25),
        ("zmm26", X86_REG_ZMM26),
        ("zmm27", X86_REG_ZMM27),
        ("zmm28", X86_REG_ZMM28),
        ("zmm29", X86_REG_ZMM29),
        ("zmm30", X86_REG_ZMM30),
        ("zmm31", X86_REG_ZMM31),
        ("r8b", X86_REG_R8B),
        ("r9b", X86_REG_R9B),
        ("r10b", X86_REG_R10B),
        ("r11b", X86_REG_R11B),
        ("r12b", X86_REG_R12B),
        ("r13b", X86_REG_R13B),
        ("r14b", X86_REG_R14B),
        ("r15b", X86_REG_R15B),
        ("r8d", X86_REG_R8D),
        ("r9d", X86_REG_R9D),
        ("r10d", X86_REG_R10D),
        ("r11d", X86_REG_R11D),
        ("r12d", X86_REG_R12D),
        ("r13d", X86_REG_R13D),
        ("r14d", X86_REG_R14D),
        ("r15d", X86_REG_R15D),
        ("r8w", X86_REG_R8W),
        ("r9w", X86_REG_R9W),
        ("r10w", X86_REG_R10W),
        ("r11w", X86_REG_R11W),
        ("r12w", X86_REG_R12W),
        ("r13w", X86_REG_R13W),
        ("r14w", X86_REG_R14W),
        ("r15w", X86_REG_R15W),
        ("bnd0", X86_REG_BND0),
        ("bnd1", X86_REG_BND1),
        ("bnd2", X86_REG_BND2),
        ("bnd3", X86_REG_BND3),
        ("_sp", COMM_REG_SP),
        ("_pc", COMM_REG_PC),
    ] {
        t.set(name, val)?;
    }

    Ok(t)
}

fn init_regid_arm(s: &LuaState) -> LuaResult<LuaTable> {
    let t = s.new_table()?;

    use crate::register::regid::*;

    for (name, val) in [
        ("apsr", ARM_REG_APSR),
        ("apsr_nzcv", ARM_REG_APSR_NZCV),
        ("cpsr", ARM_REG_CPSR),
        ("fpexc", ARM_REG_FPEXC),
        ("fpinst", ARM_REG_FPINST),
        ("fpscr", ARM_REG_FPSCR),
        ("fpscr_nzcv", ARM_REG_FPSCR_NZCV),
        ("fpsid", ARM_REG_FPSID),
        ("itstate", ARM_REG_ITSTATE),
        ("lr", ARM_REG_LR),
        ("pc", ARM_REG_PC),
        ("sp", ARM_REG_SP),
        ("spsr", ARM_REG_SPSR),
        ("d0", ARM_REG_D0),
        ("d1", ARM_REG_D1),
        ("d2", ARM_REG_D2),
        ("d3", ARM_REG_D3),
        ("d4", ARM_REG_D4),
        ("d5", ARM_REG_D5),
        ("d6", ARM_REG_D6),
        ("d7", ARM_REG_D7),
        ("d8", ARM_REG_D8),
        ("d9", ARM_REG_D9),
        ("d10", ARM_REG_D10),
        ("d11", ARM_REG_D11),
        ("d12", ARM_REG_D12),
        ("d13", ARM_REG_D13),
        ("d14", ARM_REG_D14),
        ("d15", ARM_REG_D15),
        ("d16", ARM_REG_D16),
        ("d17", ARM_REG_D17),
        ("d18", ARM_REG_D18),
        ("d19", ARM_REG_D19),
        ("d20", ARM_REG_D20),
        ("d21", ARM_REG_D21),
        ("d22", ARM_REG_D22),
        ("d23", ARM_REG_D23),
        ("d24", ARM_REG_D24),
        ("d25", ARM_REG_D25),
        ("d26", ARM_REG_D26),
        ("d27", ARM_REG_D27),
        ("d28", ARM_REG_D28),
        ("d29", ARM_REG_D29),
        ("d30", ARM_REG_D30),
        ("d31", ARM_REG_D31),
        ("fpinst2", ARM_REG_FPINST2),
        ("mvfr0", ARM_REG_MVFR0),
        ("mvfr1", ARM_REG_MVFR1),
        ("mvfr2", ARM_REG_MVFR2),
        ("q0", ARM_REG_Q0),
        ("q1", ARM_REG_Q1),
        ("q2", ARM_REG_Q2),
        ("q3", ARM_REG_Q3),
        ("q4", ARM_REG_Q4),
        ("q5", ARM_REG_Q5),
        ("q6", ARM_REG_Q6),
        ("q7", ARM_REG_Q7),
        ("q8", ARM_REG_Q8),
        ("q9", ARM_REG_Q9),
        ("q10", ARM_REG_Q10),
        ("q11", ARM_REG_Q11),
        ("q12", ARM_REG_Q12),
        ("q13", ARM_REG_Q13),
        ("q14", ARM_REG_Q14),
        ("q15", ARM_REG_Q15),
        ("r0", ARM_REG_R0),
        ("r1", ARM_REG_R1),
        ("r2", ARM_REG_R2),
        ("r3", ARM_REG_R3),
        ("r4", ARM_REG_R4),
        ("r5", ARM_REG_R5),
        ("r6", ARM_REG_R6),
        ("r7", ARM_REG_R7),
        ("r8", ARM_REG_R8),
        ("r9", ARM_REG_R9),
        ("r10", ARM_REG_R10),
        ("r11", ARM_REG_R11),
        ("r12", ARM_REG_R12),
        ("s0", ARM_REG_S0),
        ("s1", ARM_REG_S1),
        ("s2", ARM_REG_S2),
        ("s3", ARM_REG_S3),
        ("s4", ARM_REG_S4),
        ("s5", ARM_REG_S5),
        ("s6", ARM_REG_S6),
        ("s7", ARM_REG_S7),
        ("s8", ARM_REG_S8),
        ("s9", ARM_REG_S9),
        ("s10", ARM_REG_S10),
        ("s11", ARM_REG_S11),
        ("s12", ARM_REG_S12),
        ("s13", ARM_REG_S13),
        ("s14", ARM_REG_S14),
        ("s15", ARM_REG_S15),
        ("s16", ARM_REG_S16),
        ("s17", ARM_REG_S17),
        ("s18", ARM_REG_S18),
        ("s19", ARM_REG_S19),
        ("s20", ARM_REG_S20),
        ("s21", ARM_REG_S21),
        ("s22", ARM_REG_S22),
        ("s23", ARM_REG_S23),
        ("s24", ARM_REG_S24),
        ("s25", ARM_REG_S25),
        ("s26", ARM_REG_S26),
        ("s27", ARM_REG_S27),
        ("s28", ARM_REG_S28),
        ("s29", ARM_REG_S29),
        ("s30", ARM_REG_S30),
        ("s31", ARM_REG_S31),
        ("r13", ARM_REG_R13),
        ("r14", ARM_REG_R14),
        ("r15", ARM_REG_R15),
        ("sb", ARM_REG_SB),
        ("sl", ARM_REG_SL),
        ("fp", ARM_REG_FP),
        ("ip", ARM_REG_IP),
        ("_sp", COMM_REG_SP),
        ("_pc", COMM_REG_PC),
    ] {
        t.set(name, val)?;
    }

    Ok(t)
}

fn init_regid_aarch64(s: &LuaState) -> LuaResult<LuaTable> {
    use crate::register::regid::*;

    let t = s.new_table()?;
    for (name, val) in [
        ("ffr", ARM64_REG_FFR),
        ("fp", ARM64_REG_FP),
        ("lr", ARM64_REG_LR),
        ("nzcv", ARM64_REG_NZCV),
        ("sp", ARM64_REG_SP),
        ("wsp", ARM64_REG_WSP),
        ("wzr", ARM64_REG_WZR),
        ("xzr", ARM64_REG_XZR),
        ("b0", ARM64_REG_B0),
        ("b1", ARM64_REG_B1),
        ("b2", ARM64_REG_B2),
        ("b3", ARM64_REG_B3),
        ("b4", ARM64_REG_B4),
        ("b5", ARM64_REG_B5),
        ("b6", ARM64_REG_B6),
        ("b7", ARM64_REG_B7),
        ("b8", ARM64_REG_B8),
        ("b9", ARM64_REG_B9),
        ("b10", ARM64_REG_B10),
        ("b11", ARM64_REG_B11),
        ("b12", ARM64_REG_B12),
        ("b13", ARM64_REG_B13),
        ("b14", ARM64_REG_B14),
        ("b15", ARM64_REG_B15),
        ("b16", ARM64_REG_B16),
        ("b17", ARM64_REG_B17),
        ("b18", ARM64_REG_B18),
        ("b19", ARM64_REG_B19),
        ("b20", ARM64_REG_B20),
        ("b21", ARM64_REG_B21),
        ("b22", ARM64_REG_B22),
        ("b23", ARM64_REG_B23),
        ("b24", ARM64_REG_B24),
        ("b25", ARM64_REG_B25),
        ("b26", ARM64_REG_B26),
        ("b27", ARM64_REG_B27),
        ("b28", ARM64_REG_B28),
        ("b29", ARM64_REG_B29),
        ("b30", ARM64_REG_B30),
        ("b31", ARM64_REG_B31),
        ("d0", ARM64_REG_D0),
        ("d1", ARM64_REG_D1),
        ("d2", ARM64_REG_D2),
        ("d3", ARM64_REG_D3),
        ("d4", ARM64_REG_D4),
        ("d5", ARM64_REG_D5),
        ("d6", ARM64_REG_D6),
        ("d7", ARM64_REG_D7),
        ("d8", ARM64_REG_D8),
        ("d9", ARM64_REG_D9),
        ("d10", ARM64_REG_D10),
        ("d11", ARM64_REG_D11),
        ("d12", ARM64_REG_D12),
        ("d13", ARM64_REG_D13),
        ("d14", ARM64_REG_D14),
        ("d15", ARM64_REG_D15),
        ("d16", ARM64_REG_D16),
        ("d17", ARM64_REG_D17),
        ("d18", ARM64_REG_D18),
        ("d19", ARM64_REG_D19),
        ("d20", ARM64_REG_D20),
        ("d21", ARM64_REG_D21),
        ("d22", ARM64_REG_D22),
        ("d23", ARM64_REG_D23),
        ("d24", ARM64_REG_D24),
        ("d25", ARM64_REG_D25),
        ("d26", ARM64_REG_D26),
        ("d27", ARM64_REG_D27),
        ("d28", ARM64_REG_D28),
        ("d29", ARM64_REG_D29),
        ("d30", ARM64_REG_D30),
        ("d31", ARM64_REG_D31),
        ("h0", ARM64_REG_H0),
        ("h1", ARM64_REG_H1),
        ("h2", ARM64_REG_H2),
        ("h3", ARM64_REG_H3),
        ("h4", ARM64_REG_H4),
        ("h5", ARM64_REG_H5),
        ("h6", ARM64_REG_H6),
        ("h7", ARM64_REG_H7),
        ("h8", ARM64_REG_H8),
        ("h9", ARM64_REG_H9),
        ("h10", ARM64_REG_H10),
        ("h11", ARM64_REG_H11),
        ("h12", ARM64_REG_H12),
        ("h13", ARM64_REG_H13),
        ("h14", ARM64_REG_H14),
        ("h15", ARM64_REG_H15),
        ("h16", ARM64_REG_H16),
        ("h17", ARM64_REG_H17),
        ("h18", ARM64_REG_H18),
        ("h19", ARM64_REG_H19),
        ("h20", ARM64_REG_H20),
        ("h21", ARM64_REG_H21),
        ("h22", ARM64_REG_H22),
        ("h23", ARM64_REG_H23),
        ("h24", ARM64_REG_H24),
        ("h25", ARM64_REG_H25),
        ("h26", ARM64_REG_H26),
        ("h27", ARM64_REG_H27),
        ("h28", ARM64_REG_H28),
        ("h29", ARM64_REG_H29),
        ("h30", ARM64_REG_H30),
        ("h31", ARM64_REG_H31),
        ("p0", ARM64_REG_P0),
        ("p1", ARM64_REG_P1),
        ("p2", ARM64_REG_P2),
        ("p3", ARM64_REG_P3),
        ("p4", ARM64_REG_P4),
        ("p5", ARM64_REG_P5),
        ("p6", ARM64_REG_P6),
        ("p7", ARM64_REG_P7),
        ("p8", ARM64_REG_P8),
        ("p9", ARM64_REG_P9),
        ("p10", ARM64_REG_P10),
        ("p11", ARM64_REG_P11),
        ("p12", ARM64_REG_P12),
        ("p13", ARM64_REG_P13),
        ("p14", ARM64_REG_P14),
        ("p15", ARM64_REG_P15),
        ("q0", ARM64_REG_Q0),
        ("q1", ARM64_REG_Q1),
        ("q2", ARM64_REG_Q2),
        ("q3", ARM64_REG_Q3),
        ("q4", ARM64_REG_Q4),
        ("q5", ARM64_REG_Q5),
        ("q6", ARM64_REG_Q6),
        ("q7", ARM64_REG_Q7),
        ("q8", ARM64_REG_Q8),
        ("q9", ARM64_REG_Q9),
        ("q10", ARM64_REG_Q10),
        ("q11", ARM64_REG_Q11),
        ("q12", ARM64_REG_Q12),
        ("q13", ARM64_REG_Q13),
        ("q14", ARM64_REG_Q14),
        ("q15", ARM64_REG_Q15),
        ("q16", ARM64_REG_Q16),
        ("q17", ARM64_REG_Q17),
        ("q18", ARM64_REG_Q18),
        ("q19", ARM64_REG_Q19),
        ("q20", ARM64_REG_Q20),
        ("q21", ARM64_REG_Q21),
        ("q22", ARM64_REG_Q22),
        ("q23", ARM64_REG_Q23),
        ("q24", ARM64_REG_Q24),
        ("q25", ARM64_REG_Q25),
        ("q26", ARM64_REG_Q26),
        ("q27", ARM64_REG_Q27),
        ("q28", ARM64_REG_Q28),
        ("q29", ARM64_REG_Q29),
        ("q30", ARM64_REG_Q30),
        ("q31", ARM64_REG_Q31),
        ("s0", ARM64_REG_S0),
        ("s1", ARM64_REG_S1),
        ("s2", ARM64_REG_S2),
        ("s3", ARM64_REG_S3),
        ("s4", ARM64_REG_S4),
        ("s5", ARM64_REG_S5),
        ("s6", ARM64_REG_S6),
        ("s7", ARM64_REG_S7),
        ("s8", ARM64_REG_S8),
        ("s9", ARM64_REG_S9),
        ("s10", ARM64_REG_S10),
        ("s11", ARM64_REG_S11),
        ("s12", ARM64_REG_S12),
        ("s13", ARM64_REG_S13),
        ("s14", ARM64_REG_S14),
        ("s15", ARM64_REG_S15),
        ("s16", ARM64_REG_S16),
        ("s17", ARM64_REG_S17),
        ("s18", ARM64_REG_S18),
        ("s19", ARM64_REG_S19),
        ("s20", ARM64_REG_S20),
        ("s21", ARM64_REG_S21),
        ("s22", ARM64_REG_S22),
        ("s23", ARM64_REG_S23),
        ("s24", ARM64_REG_S24),
        ("s25", ARM64_REG_S25),
        ("s26", ARM64_REG_S26),
        ("s27", ARM64_REG_S27),
        ("s28", ARM64_REG_S28),
        ("s29", ARM64_REG_S29),
        ("s30", ARM64_REG_S30),
        ("s31", ARM64_REG_S31),
        ("w0", ARM64_REG_W0),
        ("w1", ARM64_REG_W1),
        ("w2", ARM64_REG_W2),
        ("w3", ARM64_REG_W3),
        ("w4", ARM64_REG_W4),
        ("w5", ARM64_REG_W5),
        ("w6", ARM64_REG_W6),
        ("w7", ARM64_REG_W7),
        ("w8", ARM64_REG_W8),
        ("w9", ARM64_REG_W9),
        ("w10", ARM64_REG_W10),
        ("w11", ARM64_REG_W11),
        ("w12", ARM64_REG_W12),
        ("w13", ARM64_REG_W13),
        ("w14", ARM64_REG_W14),
        ("w15", ARM64_REG_W15),
        ("w16", ARM64_REG_W16),
        ("w17", ARM64_REG_W17),
        ("w18", ARM64_REG_W18),
        ("w19", ARM64_REG_W19),
        ("w20", ARM64_REG_W20),
        ("w21", ARM64_REG_W21),
        ("w22", ARM64_REG_W22),
        ("w23", ARM64_REG_W23),
        ("w24", ARM64_REG_W24),
        ("w25", ARM64_REG_W25),
        ("w26", ARM64_REG_W26),
        ("w27", ARM64_REG_W27),
        ("w28", ARM64_REG_W28),
        ("w29", ARM64_REG_W29),
        ("w30", ARM64_REG_W30),
        ("x0", ARM64_REG_X0),
        ("x1", ARM64_REG_X1),
        ("x2", ARM64_REG_X2),
        ("x3", ARM64_REG_X3),
        ("x4", ARM64_REG_X4),
        ("x5", ARM64_REG_X5),
        ("x6", ARM64_REG_X6),
        ("x7", ARM64_REG_X7),
        ("x8", ARM64_REG_X8),
        ("x9", ARM64_REG_X9),
        ("x10", ARM64_REG_X10),
        ("x11", ARM64_REG_X11),
        ("x12", ARM64_REG_X12),
        ("x13", ARM64_REG_X13),
        ("x14", ARM64_REG_X14),
        ("x15", ARM64_REG_X15),
        ("x16", ARM64_REG_X16),
        ("x17", ARM64_REG_X17),
        ("x18", ARM64_REG_X18),
        ("x19", ARM64_REG_X19),
        ("x20", ARM64_REG_X20),
        ("x21", ARM64_REG_X21),
        ("x22", ARM64_REG_X22),
        ("x23", ARM64_REG_X23),
        ("x24", ARM64_REG_X24),
        ("x25", ARM64_REG_X25),
        ("x26", ARM64_REG_X26),
        ("x27", ARM64_REG_X27),
        ("x28", ARM64_REG_X28),
        ("z0", ARM64_REG_Z0),
        ("z1", ARM64_REG_Z1),
        ("z2", ARM64_REG_Z2),
        ("z3", ARM64_REG_Z3),
        ("z4", ARM64_REG_Z4),
        ("z5", ARM64_REG_Z5),
        ("z6", ARM64_REG_Z6),
        ("z7", ARM64_REG_Z7),
        ("z8", ARM64_REG_Z8),
        ("z9", ARM64_REG_Z9),
        ("z10", ARM64_REG_Z10),
        ("z11", ARM64_REG_Z11),
        ("z12", ARM64_REG_Z12),
        ("z13", ARM64_REG_Z13),
        ("z14", ARM64_REG_Z14),
        ("z15", ARM64_REG_Z15),
        ("z16", ARM64_REG_Z16),
        ("z17", ARM64_REG_Z17),
        ("z18", ARM64_REG_Z18),
        ("z19", ARM64_REG_Z19),
        ("z20", ARM64_REG_Z20),
        ("z21", ARM64_REG_Z21),
        ("z22", ARM64_REG_Z22),
        ("z23", ARM64_REG_Z23),
        ("z24", ARM64_REG_Z24),
        ("z25", ARM64_REG_Z25),
        ("z26", ARM64_REG_Z26),
        ("z27", ARM64_REG_Z27),
        ("z28", ARM64_REG_Z28),
        ("z29", ARM64_REG_Z29),
        ("z30", ARM64_REG_Z30),
        ("z31", ARM64_REG_Z31),
        ("v0", ARM64_REG_V0),
        ("v1", ARM64_REG_V1),
        ("v2", ARM64_REG_V2),
        ("v3", ARM64_REG_V3),
        ("v4", ARM64_REG_V4),
        ("v5", ARM64_REG_V5),
        ("v6", ARM64_REG_V6),
        ("v7", ARM64_REG_V7),
        ("v8", ARM64_REG_V8),
        ("v9", ARM64_REG_V9),
        ("v10", ARM64_REG_V10),
        ("v11", ARM64_REG_V11),
        ("v12", ARM64_REG_V12),
        ("v13", ARM64_REG_V13),
        ("v14", ARM64_REG_V14),
        ("v15", ARM64_REG_V15),
        ("v16", ARM64_REG_V16),
        ("v17", ARM64_REG_V17),
        ("v18", ARM64_REG_V18),
        ("v19", ARM64_REG_V19),
        ("v20", ARM64_REG_V20),
        ("v21", ARM64_REG_V21),
        ("v22", ARM64_REG_V22),
        ("v23", ARM64_REG_V23),
        ("v24", ARM64_REG_V24),
        ("v25", ARM64_REG_V25),
        ("v26", ARM64_REG_V26),
        ("v27", ARM64_REG_V27),
        ("v28", ARM64_REG_V28),
        ("v29", ARM64_REG_V29),
        ("v30", ARM64_REG_V30),
        ("v31", ARM64_REG_V31),
        ("ip0", ARM64_REG_IP0),
        ("ip1", ARM64_REG_IP1),
        ("x29", ARM64_REG_X29),
        ("x30", ARM64_REG_X30),
        ("_sp", COMM_REG_SP),
        ("_pc", COMM_REG_PC),
    ] {
        t.set(name, val)?;
    }

    Ok(t)
}
