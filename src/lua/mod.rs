//! lua bindings for udbg

use crate::{
    os::{pid_t, tid_t},
    pdbfile,
    pe::PETarget,
    prelude::*,
    register::CpuReg,
};
use core::mem::transmute;
use llua::{cstr, *};
use std::sync::Arc;

pub extern crate llua;

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

pub fn init_udbg(t: &ValRef) {
    t.set("SymbolFile", ArcSymbolFile::metatable());
    t.set("UDbgTarget", ArcTarget::metatable());
    t.set("UDbgBreakpoint", ArcBreakpoint::metatable());

    t.state.create_table(0, 4);
    {
        use SymbolFlags as SF;
        let t = t.state.val(-1);
        t.set("FUNCTION", SF::FUNCTION.bits());
        t.set("IMPORT", SF::IMPORT.bits());
        t.set("EXPORT", SF::EXPORT.bits());
    }
    t.setf(cstr!("SymbolFlags"), TopVal);

    {
        let regid = t.state.table(0, 4);
        t.state.get_or_init_metatable(init_regid_x86);
        regid.set("x86", TopVal);
        t.state.get_or_init_metatable(init_regid_arm);
        regid.set("arm", TopVal);
        t.state.get_or_init_metatable(init_regid_aarch64);
        regid.set("aarch64", TopVal);
    }
    t.set("regid", TopVal);

    t.state.create_table(0, 8);
    {
        let t = t.state.val(-1);
        t.set("INIT_BP", INIT_BP);
        t.set("BREAKPOINT", BREAKPOINT);
        t.set("PROCESS_CREATE", PROCESS_CREATE);
        t.set("PROCESS_EXIT", PROCESS_EXIT);
        t.set("THREAD_CREATE", THREAD_CREATE);
        t.set("THREAD_EXIT", THREAD_EXIT);
        t.set("MODULE_LOAD", MODULE_LOAD);
        t.set("MODULE_UNLOAD", MODULE_UNLOAD);
        t.set("EXCEPTION", EXCEPTION);
        t.set("STEP", STEP);
    }
    t.set("Event", TopVal);
}

pub fn read_pack<R: ReadMemory + ?Sized>(
    s: &State,
    d: &R,
    a: usize,
    pack: &[u8],
    psize: Option<usize>,
) -> Result<(), &'static str> {
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
                    }
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
                    }
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
    fn to_lua(self, s: &llua::State) {
        match self {
            CpuReg::Int(n) => s.push_integer(n as _),
            CpuReg::Flt(n) => s.push_number(n as _),
        };
    }
}

impl UserData for MemoryPage {
    const TYPE_NAME: &'static str = "MemoryPage";

    fn getter(fields: &ValRef) {
        fields.register("alloc_base", |this: &Self| this.alloc_base);
        fields.register("alloc_protect", |this: &Self| this.alloc_protect);
        fields.register("base", |this: &Self| this.base);
        fields.register("size", |this: &Self| this.size);
        fields.register("executable", |this: &Self| this.is_executable());
        fields.register("writable", |this: &Self| this.is_writable());
        fields.register("readonly", |this: &Self| this.is_readonly());
        fields.register("private", |this: &Self| this.is_private());
        fields.register("commited", |this: &Self| this.is_commit());
        fields.register("protect", |this: &Self| this.protect);
        fields.register("type", |this: &Self| this.type_);
        fields.register("state", |this: &Self| this.state);
        fields.register("info", |this: &Self| this.info.clone());
        fields.register("memory_info", |this: &Self| {
            SerdeValue(MemoryPageInfo::from(this))
        });
    }

    fn methods(mt: &ValRef) {
        mt.register("is_commit", MemoryPage::is_commit)
            .register("is_reserve", MemoryPage::is_reserve)
            .register("is_free", MemoryPage::is_free)
            .register("is_private", MemoryPage::is_private);
    }
}

impl ToLuaMulti for HandleInfo {
    fn to_lua(self, s: &State) -> i32 {
        s.pushx((
            self.handle,
            self.ty,
            self.type_name.as_str(),
            self.name.as_str(),
        ))
    }
}

impl UserData for Symbol {
    const TYPE_NAME: &'static str = "UDbgSymbol";
    const INDEX_METATABLE: bool = false;

    fn getter(fields: &ValRef) {
        fields.register("name", |this: &'static Self| this.name.as_ref());
        fields.register("offset", |this: &Self| this.offset);
        fields.register("len", |this: &Self| this.len);
        fields.register("flags", |this: &Self| this.flags);
        fields.register("uname", |s: &State, this: &Self| {
            if let Some(n) = Symbol::undecorate(&this.name, Default::default()) {
                s.pushed(n)
            } else {
                s.pushed(this.name.as_ref())
            }
        });
        fields.register("type_id", |s: &State, this: &Self| {
            if this.type_id > 0 {
                s.pushed(this.type_id)
            } else {
                Pushed(0)
            }
        });
    }
}

impl ToLuaMulti for FieldInfo {
    fn to_lua(self, s: &State) -> i32 {
        s.pushx((self.type_id, self.offset, self.name.as_str()));
        3
    }
}

#[derive(Deref)]
pub struct ArcSymbolFile(pub Arc<dyn SymbolFile>);

impl UserData for ArcSymbolFile {
    const TYPE_NAME: &'static str = "SymbolFile*";

    fn methods(mt: &ValRef) {
        #[cfg(windows)]
        mt.register("open", |path: &str| {
            pdbfile::PDBData::load(path, None).map(|r| ArcSymbolFile(Arc::new(r)))
        });
        mt.register("path", |s: &State, this: &Self| s.pushed(this.path()));
        mt.register("get_type", |this: &Self, id: u32| {
            this.get_type(id).map(SerdeValue)
        });
        mt.register("find_type", |this: &Self, name: &str| {
            SerdeValue(this.find_type(name))
        });
        mt.register(
            "get_field",
            |s: &State, this: &Self, type_id: u32, val: Value| {
                match val {
                    Value::Str(name) => this.find_field(type_id, name),
                    Value::Int(i) => this.get_field(type_id, i as usize),
                    _ => s.type_error(2, cstr!("integer|string")),
                }
                .map(|x| s.pushed(x))
                .unwrap_or_default()
            },
        );
        mt.register("enum_field", |this: &Self, type_id: u32| {
            BoxIter(Box::new(
                this.get_field_list(type_id).into_iter().map(|x| x),
            ))
        });
    }
}

#[derive(Deref)]
pub struct ArcModule(pub Arc<dyn UDbgModule + 'static>);

impl AsRef<dyn UDbgModule> for ArcModule {
    #[inline(always)]
    fn as_ref(&self) -> &(dyn UDbgModule + 'static) {
        self.0.as_ref()
    }
}

impl UserData for ArcModule {
    const TYPE_NAME: &'static str = "UDbgModule*";
    const INDEX_GETTER: lua_CFunction = RsFn::new(|s: &State, this: &Self, key: &str| {
        this.0
            .get_prop(key)
            .map(|val| s.pushed(SerdeValue(val)))
            .unwrap_or_default()
    })
    .wrapper();

    fn getter(fields: &ValRef) {
        fields.register("base", |this: &Self| this.data().base);
        fields.register("size", |this: &Self| this.data().size);
        fields.register("name", |this: &'static Self| this.data().name.as_ref());
        fields.register("path", |this: &'static Self| this.data().path.as_ref());
        fields.register("arch", |this: &Self| this.data().arch);
        fields.register("entry", |this: &Self| this.data().entry);
        fields.register("entry_point", |this: &Self| {
            let data = this.data();
            data.base + data.entry
        });
        fields.register("user_module", |this: &Self| this.data().user_module.get());
    }

    fn setter(fields: &ValRef) {
        fields.register("user_module", |this: &Self, user: bool| {
            this.data().user_module.set(user)
        });
    }

    fn methods(mt: &ValRef) {
        MethodRegistry::<Self, dyn UDbgModule>::new(mt)
            .register("add_symbol", <dyn UDbgModule>::add_symbol)
            .register("load_symbol", <dyn UDbgModule>::load_symbol_file);

        mt.register("symbol_file", |this: &Self| {
            this.symbol_file().map(ArcSymbolFile)
        });
        mt.register("enum_symbol", |s: &State, this: &Self, pat: &str| {
            this.enum_symbol(Some(pat)).map(|x| s.pushed(BoxIter(x)))
        });
        mt.register("enum_export", |s: &State, this: &Self| {
            this.get_exports()
                .map(|exports| s.pushed(BoxIter::from(exports.into_iter())))
                .unwrap_or_default()
        });
        mt.register("get_symbol", |s: &State, this: &Self, pat: &str| {
            this.enum_symbol(Some(pat))
                .map(|mut x| x.next().map(|sym| s.pushed(sym)).unwrap_or_default())
        });
        #[cfg(all(windows, target_arch = "x86_64"))]
        mt.register("find_function", |s: &State, this: &Self, a: usize| unsafe {
            this.find_function(a)
                .map(|x| s.pushed((x.BeginAddress, x.EndAddress, *x.u.UnwindData())))
                .unwrap_or_default()
        });
    }
}

#[derive(Deref)]
pub struct BoxThread(pub Box<dyn UDbgThread>);

impl UserData for BoxThread {
    const TYPE_NAME: &'static str = "UDbgThread*";

    fn getter(fields: &ValRef) {
        fields.register("tid", |this: &Self| this.tid);
        #[cfg(windows)]
        fields.register("wow64", |this: &Self| this.wow64);
        #[cfg(windows)]
        fields.register("handle", |this: &Self| *this.handle as usize);
        #[cfg(windows)]
        fields.register("entry", |this: &Self| this.entry());
        #[cfg(windows)]
        fields.register("teb", |this: &Self| this.teb());
        fields.register("name", |this: &Self| this.name());
        fields.register("status", |this: &Self| this.status());
        fields.register("priority", |this: &Self| this.priority());
        #[cfg(windows)]
        fields.register("context", |s: &State, this: &Self| unsafe {
            let mut cx: ThreadContext = core::mem::zeroed();
            s.check_result(this.get_context(&mut cx));
            s.push_userdata(cx, None);
            Pushed(1)
        });
        #[cfg(windows)]
        fields.register("context32", |s: &State, this: &Self| unsafe {
            let mut cx: ThreadContext32 = core::mem::zeroed();
            s.check_result(this.get_context32(&mut cx));
            s.push_userdata(cx, None);
            Pushed(1)
        });
    }

    fn methods(mt: &ValRef) {
        mt.register("suspend", |this: &Self| this.suspend());
        mt.register("resume", |this: &Self| this.resume());
        #[cfg(windows)]
        mt.register("last_error", |this: &Self| this.last_error());
        mt.register(
            "__call",
            |s: &State, this: &Self, key: &str| -> UDbgResult<Pushed> {
                Ok(s.pushed(SerdeValue(this.0.get_prop(key)?)))
            },
        );
    }
}

#[derive(Deref)]
pub struct ArcBreakpoint(pub Arc<dyn UDbgBreakpoint + 'static>);

impl AsRef<dyn UDbgBreakpoint> for ArcBreakpoint {
    #[inline(always)]
    fn as_ref(&self) -> &(dyn UDbgBreakpoint + 'static) {
        self.0.as_ref()
    }
}

impl ToLua for BpType {
    fn to_lua(self, s: &State) {
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

    fn uservalue_count(&self, s: &State) -> i32 {
        1
    }

    fn getter(fields: &ValRef) {
        MethodRegistry::<Self, dyn UDbgBreakpoint>::new(fields)
            .register("address", <dyn UDbgBreakpoint>::address)
            .register("id", <dyn UDbgBreakpoint>::get_id)
            .register("type", <dyn UDbgBreakpoint>::get_type)
            .register("hitcount", <dyn UDbgBreakpoint>::hit_count)
            .register("enabled", <dyn UDbgBreakpoint>::enabled);
        fields.register("callback", |s: &State| {
            s.get_iuservalue(1, 1);
            Pushed(1)
        });
    }

    fn setter(fields: &ValRef) {
        MethodRegistry::<Self, dyn UDbgBreakpoint>::new(fields)
            .register("enabled", <dyn UDbgBreakpoint>::enable);
        fields.register("callback", |s: &State| {
            s.push_value(2);
            s.set_iuservalue(1, 1);
        });
    }

    fn methods(mt: &ValRef) {
        mt.register("enable", |this: &Self| this.enable(true));
        mt.register("disable", |this: &Self| this.enable(false));
        mt.register("remove", |s: &State, this: &Self| {
            this.clear_cached(s);
            this.remove();
        });
    }
}

impl ToLuaMulti for UEvent {
    fn to_lua(self, s: &State) -> i32 {
        use UEvent::*;
        match self {
            InitBp => s.pushx(INIT_BP),
            Step => s.pushx(STEP),
            Breakpoint(bp) => s.pushx((BREAKPOINT, ArcBreakpoint(bp))),
            ProcessCreate => s.pushx(PROCESS_CREATE),
            ProcessExit(code) => s.pushx((PROCESS_EXIT, code)),
            ModuleLoad(m) => {
                s.push(MODULE_LOAD);
                s.push(ArcModule(m));
                2
            }
            ModuleUnload(m) => {
                s.push(MODULE_UNLOAD);
                s.push(ArcModule(m));
                2
            }
            ThreadCreate(tid) => s.pushx((THREAD_CREATE, tid)),
            ThreadExit(code) => s.pushx((THREAD_EXIT, code)),
            Exception { first, code } => s.pushx((EXCEPTION, code, first)),
        }
    }
}

#[derive(Deref, Clone)]
pub struct ArcTarget(pub Arc<dyn UDbgTarget>);

impl AsRef<dyn UDbgTarget> for ArcTarget {
    #[inline(always)]
    fn as_ref(&self) -> &dyn UDbgTarget {
        self.0.as_ref()
    }
}

impl UserData for ArcTarget {
    const TYPE_NAME: &'static str = "UDbgTarget*";
    const INDEX_USERVALUE: bool = true;

    const INDEX_GETTER: lua_CFunction =
        RsFn::new(|this: &Self, key: &str| this.0.get_prop(key).map(SerdeValue).ok()).wrapper();

    fn init_userdata(s: &State) {
        let this: &Self = s.arg(-1).unwrap();
        s.push(SerdeValue(this.base()));
        s.set_uservalue(-2);
    }

    fn key_to_cache(&self) -> *const () {
        (self.0.as_ref() as *const dyn UDbgTarget).to_raw_parts().0
    }

    fn getter(fields: &ValRef) {
        fields
            .register("base", |this: &'static Self| SerdeValue(this.base()))
            .register("pid", |this: &Self| this.base().pid.get())
            .register("arch", |this: &Self| this.base().arch)
            .register("event_tid", |this: &Self| this.base().event_tid.get())
            .register("pointer_size", |this: &Self| this.base().pointer_size())
            .register("status", |this: &Self| this.base().status.get().as_str())
            .register("context_arch", |this: &Self| {
                match this.base().context_arch.get() {
                    ARCH_X86 => "x86",
                    ARCH_X64 => "x86_64",
                    ARCH_ARM => "arm",
                    ARCH_ARM64 => "arm64",
                    _ => unreachable!(),
                }
            });
        #[cfg(windows)]
        fields.register("handle", |this: &Self| this.handle() as usize);
    }

    fn methods(mt: &ValRef) {
        MethodRegistry::<Self, dyn UDbgTarget>::new(mt)
            .register("read_u8", <dyn UDbgTarget>::read_value::<u8>)
            .register("read_u16", <dyn UDbgTarget>::read_value::<u16>)
            .register("read_u32", <dyn UDbgTarget>::read_value::<u32>)
            .register("read_u64", <dyn UDbgTarget>::read_value::<u64>)
            .register("read_f32", <dyn UDbgTarget>::read_value::<f32>)
            .register("read_f64", <dyn UDbgTarget>::read_value::<f64>)
            .register("image_path", <dyn UDbgTarget>::image_path)
            .register("detach", <dyn UDbgTarget>::detach)
            .register("kill", <dyn UDbgTarget>::kill)
            .register("pause", <dyn UDbgTarget>::breakk)
            .register("resume", <dyn UDbgTarget>::resume)
            .register("wait", <dyn UDbgTarget>::wait)
            .register("suspend", <dyn UDbgTarget>::suspend);

        fn write_value<T>(this: &ArcTarget, a: usize, val: T) {
            this.write_value(a, &val);
        }
        mt.register("write_u8", write_value::<u8>)
            .register("write_u16", write_value::<u16>)
            .register("write_u32", write_value::<u32>)
            .register("write_u64", write_value::<u64>)
            .register("write_f32", write_value::<f32>)
            .register("write_f64", write_value::<f64>);

        mt.register("add_breakpoint", |s: &State, this: &Self, a: usize| {
            let ty: Option<&str> = s.arg(3);
            let size: Option<usize> = s.arg(4);
            let temp: bool = s.arg(5).unwrap_or(false);
            let tid: Option<tid_t> = s.arg(6);
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
                        _ => {
                            s.raise_error("Invalid breakpoint type");
                        }
                    }),
                    len: Some(match size {
                        Some(1) | None => HwbpLen::L1,
                        Some(2) => HwbpLen::L2,
                        Some(4) => HwbpLen::L4,
                        Some(8) => HwbpLen::L8,
                        _ => {
                            s.raise_error("Invalid hwbp size");
                        }
                    }),
                }),
            };
            Pushed(match r {
                Ok(bp) => {
                    s.push(ArcBreakpoint(bp));
                    1
                }
                Err(UDbgError::BpExists) => {
                    s.push(false);
                    s.push("exists");
                    2
                }
                Err(e) => {
                    s.push(false);
                    s.push(format!("{:?}", e));
                    2
                }
            })
        });
        mt.register("get_breakpoint", |this: &'static Self, id: BpID| {
            this.get_breakpoint(id).map(ArcBreakpoint)
        });
        mt.register("breakpoint_list", |this: &'static Self| {
            IterVec(this.get_breakpoints().into_iter().map(ArcBreakpoint))
        });

        mt.register(
            "read_string",
            |this: &Self, a: usize, size: Option<usize>| this.read_cstring(a, size.unwrap_or(1000)),
        );
        #[cfg(windows)]
        mt.register(
            "read_wstring",
            |this: &Self, a: usize, size: Option<usize>| this.read_wstring(a, size.unwrap_or(1000)),
        );
        mt.register("write_string", |this: &Self, a: usize, buf: &[u8]| {
            this.write_cstring(a, buf)
        });
        #[cfg(windows)]
        mt.register("write_wstring", |this: &Self, a: usize, buf: &str| {
            this.write_wstring(a, buf)
        });

        mt.register(
            "read_pack",
            |s: &State, this: &Self, a: usize, pack: &[u8]| {
                let top = s.get_top();
                read_pack(
                    s,
                    this.0.as_ref(),
                    a,
                    pack,
                    this.base().pointer_size().into(),
                )
                .map(|_| Pushed(s.get_top() - top))
            },
        )
        .register(
            "detect_string",
            |this: &Self, p: usize, max: Option<usize>| {
                this.detect_string(p, max.unwrap_or(32))
                    .map(|(wide, text)| (text, wide))
            },
        )
        .register("open_thread", |this: &Self, tid: tid_t| {
            this.open_thread(tid).map(|x| BoxThread(x))
        })
        .register("thread_list", |this: &Self| unsafe {
            this.enum_thread(true).map(|iter| {
                IterMap(
                    core::mem::transmute::<
                        _,
                        Box<dyn Iterator<Item = Box<dyn UDbgThread>> + 'static>,
                    >(iter)
                    .map(|t| (t.tid, BoxThread(t))),
                )
            })
        });

        mt.register("enum_module", |this: &Self| unsafe {
            this.enum_module()
                .map(|r| BoxIter::<ArcModule>(transmute(r)))
        })
        .register("enum_thread", |this: &Self| unsafe {
            this.enum_thread(false)
                .map(|r| BoxIter::<BoxThread>(transmute(r)))
        })
        .register("enum_memory", |this: &'static Self| {
            this.enum_memory().map(BoxIter)
        })
        .register("enum_handle", |this: &'static Self| {
            this.enum_handle().map(BoxIter)
        });

        mt.register("collect_memory", |this: &Self| {
            IterVec(this.collect_memory_info().into_iter())
        })
        .register("get_module", |s: &State, this: &Self| {
            (if s.is_none_or_nil(2) {
                this.find_module(this.base().image_base)
            } else {
                let base = s.to_integer(2) as usize;
                if base > 0 {
                    this.find_module(base)
                } else {
                    this.get_module(s.to_str(2).unwrap_or(""))
                }
            })
            .map(ArcModule)
        });

        mt.register("virtual_query", |this: &Self, a: usize| {
            this.virtual_query(a)
        })
        .register(
            "virtual_alloc",
            |this: &Self, a: usize, size: usize, ty: Option<&str>| {
                this.virtual_alloc(a, size, ty.unwrap_or(""))
            },
        )
        .register("virtual_free", |this: &Self, a: usize| {
            this.virtual_free(a);
        });

        mt.register("read_type", |s: &State, this: &Self, a: usize, ty: &str| {
            let address = a;
            match ty {
                "usize" => s.push(this.read_value::<usize>(address)),
                "u8" => s.push(this.read_value::<u8>(address)),
                "u16" => s.push(this.read_value::<u16>(address)),
                "u32" => s.push(this.read_value::<u32>(address)),
                "u64" => s.push(this.read_value::<u64>(address)),
                "isize" => s.push(this.read_value::<isize>(address)),
                "i8" => s.push(this.read_value::<i8>(address)),
                "i16" => s.push(this.read_value::<i16>(address)),
                "i32" => s.push(this.read_value::<i32>(address)),
                "i64" => s.push(this.read_value::<i64>(address)),
                "f32" => s.push(this.read_value::<f32>(address)),
                "f64" => s.push(this.read_value::<f64>(address)),
                "ptr" => s.push(this.read_ptr(address)),
                "z" => s.push(this.read_cstring(address, 1000).as_ref().map(Vec::as_slice)),
                #[cfg(windows)]
                "w" => s.push(this.read_wstring(address, 1000)),
                _ => {
                    return Pushed(0);
                }
            };
            Pushed(1)
        });

        mt.register(
            "read_bytes",
            |s: &State, this: &Self, a: usize, length: usize, userdata: bool| unsafe {
                Pushed(if userdata {
                    let p = s.new_userdata(length);
                    let buf = core::slice::from_raw_parts_mut(p.cast::<u8>(), length);
                    match this.read_memory(a, buf) {
                        Some(_) => 1,
                        None => 0,
                    }
                } else if length > STACK_BUFFER_SIZE {
                    let mut buf: Vec<u8> = vec![0u8; length];
                    match this.read_memory(a, &mut buf) {
                        Some(slice) => s.pushx(&slice[..]),
                        None => 0,
                    }
                } else {
                    let mut buf = [0u8; STACK_BUFFER_SIZE];
                    match this.read_memory(a, &mut buf[..length]) {
                        Some(slice) => s.pushx(&slice[..]),
                        None => 0,
                    }
                })
            },
        );

        mt.register(
            "write_bytes",
            |this: &Self, a: usize, buf: &[u8], len: Option<usize>| {
                this.write_memory(a, len.map(|len| &buf[..len]).unwrap_or(buf))
            },
        );

        mt.register(
            "write_type",
            |s: &State, this: &Self, a: usize, ty: &str| {
                let address = a;
                match ty {
                    "usize" => s.push(this.write_value(address, &(s.to_integer(4) as usize))),
                    "u8" => s.push(this.write_value(address, &(s.to_integer(4) as u8))),
                    "u16" => s.push(this.write_value(address, &(s.to_integer(4) as u16))),
                    "u32" => s.push(this.write_value(address, &(s.to_integer(4) as u32))),
                    "u64" => s.push(this.write_value(address, &(s.to_integer(4) as u64))),
                    "isize" => s.push(this.write_value(address, &(s.to_integer(4) as isize))),
                    "i8" => s.push(this.write_value(address, &(s.to_integer(4) as i8))),
                    "i16" => s.push(this.write_value(address, &(s.to_integer(4) as i16))),
                    "i32" => s.push(this.write_value(address, &(s.to_integer(4) as i32))),
                    "i64" => s.push(this.write_value(address, &(s.to_integer(4) as i64))),
                    "f32" => s.push(this.write_value(address, &(s.to_number(4) as f32))),
                    "f64" => s.push(this.write_value(address, &(s.to_number(4) as f64))),
                    _ => {
                        return Pushed(0);
                    }
                };
                Pushed(1)
            },
        );

        mt.register("get_symbol", |s: &State, this: &Self, a: usize| {
            Pushed(if s.is_bool(3) && s.to_bool(3) {
                this.get_symbol_(a, None)
                    .map(|r| {
                        s.push(r.module.as_ref());
                        s.push(r.symbol.as_ref());
                        s.push(r.offset);
                        s.push(r.mod_base);
                        4
                    })
                    .unwrap_or(0)
            } else {
                this.get_symbol_(a, s.arg::<usize>(3))
                    .map(|s| s.to_string(a))
                    .map(|r| {
                        s.push(r);
                        1
                    })
                    .unwrap_or(0)
            })
        });

        mt.register("open_pe", |path: &str| {
            PETarget::new(path).map(Arc::new).map(|t| ArcTarget(t as _))
        });
    }
}

impl ToLua for ProcessInfo {
    fn to_lua(self, s: &State) {
        ToLua::to_lua(SerdeValue(self), s)
    }
}

#[derive(Deref, DerefMut)]
pub struct BoxEngine(pub Box<dyn UDbgEngine>);

impl UserData for BoxEngine {
    const TYPE_NAME: &'static str = "UDbgEngine*";

    fn methods(mt: &ValRef) {
        mt.register("enum_process", |this: &Self| {
            this.enum_process().map(BoxIter)
        })
        .register("open", |this: &mut Self, pid: pid_t| {
            this.open(pid).map(|d| {
                d.base().status.set(UDbgStatus::Opened);
                ArcTarget(d)
            })
        })
        .register("attach", |this: &mut Self, pid: pid_t| {
            this.attach(pid).map(ArcTarget)
        })
        .register(
            "create",
            |this: &mut Self, path: &str, cwd: Option<&str>, args: SerdeValue<Vec<&str>>| {
                this.create(path, cwd, &args).map(ArcTarget)
            },
        );
        mt.register("event_loop", |s: &State, this: &mut Self| {
            s.check_type(2, Type::Thread);
            let co = s.to_thread(2).unwrap();
            co.xmove(&s, 1);

            let ui = udbg_ui();
            let mut nres = 0;
            let mut resume = move |ctx: &dyn TraceContext, event| -> UserReply {
                co.pop(nres);
                s.push_value(-1);
                s.xmove(&co, 1);
                let this = ArcTarget(ctx.target());
                co.push(this.clone());
                let st = co.resume(Some(&s), co.pushx(event) + 1, &mut nres);
                if !matches!(st, ThreadStatus::Yield | ThreadStatus::Ok) {
                    s.traceback(&co, cstr!("resume event"), 1);
                    s.error();
                }

                let s = &co;
                let action = s.args::<Option<&str>>(1);
                match action.unwrap_or_default() {
                    "step" | "stepin" => UserReply::StepIn,
                    "stepout" => UserReply::StepOut,
                    "goto" => UserReply::Goto(s.to_integer(2) as usize),
                    "native" => UserReply::Native(s.to_integer(2) as usize),
                    "run" | _ => UserReply::Run(s.to_bool(2)),
                }
            };
            this.event_loop(&mut |ctx, event| resume(ctx, event));
        });
    }
}

fn init_regid_x86(t: &ValRef) {
    use crate::register::regid::*;

    t.set("ah", X86_REG_AH);
    t.set("al", X86_REG_AL);
    t.set("ax", X86_REG_AX);
    t.set("bh", X86_REG_BH);
    t.set("bl", X86_REG_BL);
    t.set("bp", X86_REG_BP);
    t.set("bpl", X86_REG_BPL);
    t.set("bx", X86_REG_BX);
    t.set("ch", X86_REG_CH);
    t.set("cl", X86_REG_CL);
    t.set("cs", X86_REG_CS);
    t.set("cx", X86_REG_CX);
    t.set("dh", X86_REG_DH);
    t.set("di", X86_REG_DI);
    t.set("dil", X86_REG_DIL);
    t.set("dl", X86_REG_DL);
    t.set("ds", X86_REG_DS);
    t.set("dx", X86_REG_DX);
    t.set("eax", X86_REG_EAX);
    t.set("ebp", X86_REG_EBP);
    t.set("ebx", X86_REG_EBX);
    t.set("ecx", X86_REG_ECX);
    t.set("edi", X86_REG_EDI);
    t.set("edx", X86_REG_EDX);
    t.set("eflags", X86_REG_EFLAGS);
    t.set("eip", X86_REG_EIP);
    t.set("eiz", X86_REG_EIZ);
    t.set("es", X86_REG_ES);
    t.set("esi", X86_REG_ESI);
    t.set("esp", X86_REG_ESP);
    t.set("fpsw", X86_REG_FPSW);
    t.set("fs", X86_REG_FS);
    t.set("gs", X86_REG_GS);
    t.set("ip", X86_REG_IP);
    t.set("rax", X86_REG_RAX);
    t.set("rbp", X86_REG_RBP);
    t.set("rbx", X86_REG_RBX);
    t.set("rcx", X86_REG_RCX);
    t.set("rdi", X86_REG_RDI);
    t.set("rdx", X86_REG_RDX);
    t.set("rip", X86_REG_RIP);
    t.set("riz", X86_REG_RIZ);
    t.set("rsi", X86_REG_RSI);
    t.set("rsp", X86_REG_RSP);
    t.set("si", X86_REG_SI);
    t.set("sil", X86_REG_SIL);
    t.set("sp", X86_REG_SP);
    t.set("spl", X86_REG_SPL);
    t.set("ss", X86_REG_SS);
    t.set("cr0", X86_REG_CR0);
    t.set("cr1", X86_REG_CR1);
    t.set("cr2", X86_REG_CR2);
    t.set("cr3", X86_REG_CR3);
    t.set("cr4", X86_REG_CR4);
    t.set("cr5", X86_REG_CR5);
    t.set("cr6", X86_REG_CR6);
    t.set("cr7", X86_REG_CR7);
    t.set("cr8", X86_REG_CR8);
    t.set("cr9", X86_REG_CR9);
    t.set("cr10", X86_REG_CR10);
    t.set("cr11", X86_REG_CR11);
    t.set("cr12", X86_REG_CR12);
    t.set("cr13", X86_REG_CR13);
    t.set("cr14", X86_REG_CR14);
    t.set("cr15", X86_REG_CR15);
    t.set("dr0", X86_REG_DR0);
    t.set("dr1", X86_REG_DR1);
    t.set("dr2", X86_REG_DR2);
    t.set("dr3", X86_REG_DR3);
    t.set("dr4", X86_REG_DR4);
    t.set("dr5", X86_REG_DR5);
    t.set("dr6", X86_REG_DR6);
    t.set("dr7", X86_REG_DR7);
    t.set("dr8", X86_REG_DR8);
    t.set("dr9", X86_REG_DR9);
    t.set("dr10", X86_REG_DR10);
    t.set("dr11", X86_REG_DR11);
    t.set("dr12", X86_REG_DR12);
    t.set("dr13", X86_REG_DR13);
    t.set("dr14", X86_REG_DR14);
    t.set("dr15", X86_REG_DR15);
    t.set("fp0", X86_REG_FP0);
    t.set("fp1", X86_REG_FP1);
    t.set("fp2", X86_REG_FP2);
    t.set("fp3", X86_REG_FP3);
    t.set("fp4", X86_REG_FP4);
    t.set("fp5", X86_REG_FP5);
    t.set("fp6", X86_REG_FP6);
    t.set("fp7", X86_REG_FP7);
    t.set("k0", X86_REG_K0);
    t.set("k1", X86_REG_K1);
    t.set("k2", X86_REG_K2);
    t.set("k3", X86_REG_K3);
    t.set("k4", X86_REG_K4);
    t.set("k5", X86_REG_K5);
    t.set("k6", X86_REG_K6);
    t.set("k7", X86_REG_K7);
    t.set("mm0", X86_REG_MM0);
    t.set("mm1", X86_REG_MM1);
    t.set("mm2", X86_REG_MM2);
    t.set("mm3", X86_REG_MM3);
    t.set("mm4", X86_REG_MM4);
    t.set("mm5", X86_REG_MM5);
    t.set("mm6", X86_REG_MM6);
    t.set("mm7", X86_REG_MM7);
    t.set("r8", X86_REG_R8);
    t.set("r9", X86_REG_R9);
    t.set("r10", X86_REG_R10);
    t.set("r11", X86_REG_R11);
    t.set("r12", X86_REG_R12);
    t.set("r13", X86_REG_R13);
    t.set("r14", X86_REG_R14);
    t.set("r15", X86_REG_R15);
    t.set("st0", X86_REG_ST0);
    t.set("st1", X86_REG_ST1);
    t.set("st2", X86_REG_ST2);
    t.set("st3", X86_REG_ST3);
    t.set("st4", X86_REG_ST4);
    t.set("st5", X86_REG_ST5);
    t.set("st6", X86_REG_ST6);
    t.set("st7", X86_REG_ST7);
    t.set("xmm0", X86_REG_XMM0);
    t.set("xmm1", X86_REG_XMM1);
    t.set("xmm2", X86_REG_XMM2);
    t.set("xmm3", X86_REG_XMM3);
    t.set("xmm4", X86_REG_XMM4);
    t.set("xmm5", X86_REG_XMM5);
    t.set("xmm6", X86_REG_XMM6);
    t.set("xmm7", X86_REG_XMM7);
    t.set("xmm8", X86_REG_XMM8);
    t.set("xmm9", X86_REG_XMM9);
    t.set("xmm10", X86_REG_XMM10);
    t.set("xmm11", X86_REG_XMM11);
    t.set("xmm12", X86_REG_XMM12);
    t.set("xmm13", X86_REG_XMM13);
    t.set("xmm14", X86_REG_XMM14);
    t.set("xmm15", X86_REG_XMM15);
    t.set("xmm16", X86_REG_XMM16);
    t.set("xmm17", X86_REG_XMM17);
    t.set("xmm18", X86_REG_XMM18);
    t.set("xmm19", X86_REG_XMM19);
    t.set("xmm20", X86_REG_XMM20);
    t.set("xmm21", X86_REG_XMM21);
    t.set("xmm22", X86_REG_XMM22);
    t.set("xmm23", X86_REG_XMM23);
    t.set("xmm24", X86_REG_XMM24);
    t.set("xmm25", X86_REG_XMM25);
    t.set("xmm26", X86_REG_XMM26);
    t.set("xmm27", X86_REG_XMM27);
    t.set("xmm28", X86_REG_XMM28);
    t.set("xmm29", X86_REG_XMM29);
    t.set("xmm30", X86_REG_XMM30);
    t.set("xmm31", X86_REG_XMM31);
    t.set("ymm0", X86_REG_YMM0);
    t.set("ymm1", X86_REG_YMM1);
    t.set("ymm2", X86_REG_YMM2);
    t.set("ymm3", X86_REG_YMM3);
    t.set("ymm4", X86_REG_YMM4);
    t.set("ymm5", X86_REG_YMM5);
    t.set("ymm6", X86_REG_YMM6);
    t.set("ymm7", X86_REG_YMM7);
    t.set("ymm8", X86_REG_YMM8);
    t.set("ymm9", X86_REG_YMM9);
    t.set("ymm10", X86_REG_YMM10);
    t.set("ymm11", X86_REG_YMM11);
    t.set("ymm12", X86_REG_YMM12);
    t.set("ymm13", X86_REG_YMM13);
    t.set("ymm14", X86_REG_YMM14);
    t.set("ymm15", X86_REG_YMM15);
    t.set("ymm16", X86_REG_YMM16);
    t.set("ymm17", X86_REG_YMM17);
    t.set("ymm18", X86_REG_YMM18);
    t.set("ymm19", X86_REG_YMM19);
    t.set("ymm20", X86_REG_YMM20);
    t.set("ymm21", X86_REG_YMM21);
    t.set("ymm22", X86_REG_YMM22);
    t.set("ymm23", X86_REG_YMM23);
    t.set("ymm24", X86_REG_YMM24);
    t.set("ymm25", X86_REG_YMM25);
    t.set("ymm26", X86_REG_YMM26);
    t.set("ymm27", X86_REG_YMM27);
    t.set("ymm28", X86_REG_YMM28);
    t.set("ymm29", X86_REG_YMM29);
    t.set("ymm30", X86_REG_YMM30);
    t.set("ymm31", X86_REG_YMM31);
    t.set("zmm0", X86_REG_ZMM0);
    t.set("zmm1", X86_REG_ZMM1);
    t.set("zmm2", X86_REG_ZMM2);
    t.set("zmm3", X86_REG_ZMM3);
    t.set("zmm4", X86_REG_ZMM4);
    t.set("zmm5", X86_REG_ZMM5);
    t.set("zmm6", X86_REG_ZMM6);
    t.set("zmm7", X86_REG_ZMM7);
    t.set("zmm8", X86_REG_ZMM8);
    t.set("zmm9", X86_REG_ZMM9);
    t.set("zmm10", X86_REG_ZMM10);
    t.set("zmm11", X86_REG_ZMM11);
    t.set("zmm12", X86_REG_ZMM12);
    t.set("zmm13", X86_REG_ZMM13);
    t.set("zmm14", X86_REG_ZMM14);
    t.set("zmm15", X86_REG_ZMM15);
    t.set("zmm16", X86_REG_ZMM16);
    t.set("zmm17", X86_REG_ZMM17);
    t.set("zmm18", X86_REG_ZMM18);
    t.set("zmm19", X86_REG_ZMM19);
    t.set("zmm20", X86_REG_ZMM20);
    t.set("zmm21", X86_REG_ZMM21);
    t.set("zmm22", X86_REG_ZMM22);
    t.set("zmm23", X86_REG_ZMM23);
    t.set("zmm24", X86_REG_ZMM24);
    t.set("zmm25", X86_REG_ZMM25);
    t.set("zmm26", X86_REG_ZMM26);
    t.set("zmm27", X86_REG_ZMM27);
    t.set("zmm28", X86_REG_ZMM28);
    t.set("zmm29", X86_REG_ZMM29);
    t.set("zmm30", X86_REG_ZMM30);
    t.set("zmm31", X86_REG_ZMM31);
    t.set("r8b", X86_REG_R8B);
    t.set("r9b", X86_REG_R9B);
    t.set("r10b", X86_REG_R10B);
    t.set("r11b", X86_REG_R11B);
    t.set("r12b", X86_REG_R12B);
    t.set("r13b", X86_REG_R13B);
    t.set("r14b", X86_REG_R14B);
    t.set("r15b", X86_REG_R15B);
    t.set("r8d", X86_REG_R8D);
    t.set("r9d", X86_REG_R9D);
    t.set("r10d", X86_REG_R10D);
    t.set("r11d", X86_REG_R11D);
    t.set("r12d", X86_REG_R12D);
    t.set("r13d", X86_REG_R13D);
    t.set("r14d", X86_REG_R14D);
    t.set("r15d", X86_REG_R15D);
    t.set("r8w", X86_REG_R8W);
    t.set("r9w", X86_REG_R9W);
    t.set("r10w", X86_REG_R10W);
    t.set("r11w", X86_REG_R11W);
    t.set("r12w", X86_REG_R12W);
    t.set("r13w", X86_REG_R13W);
    t.set("r14w", X86_REG_R14W);
    t.set("r15w", X86_REG_R15W);
    t.set("bnd0", X86_REG_BND0);
    t.set("bnd1", X86_REG_BND1);
    t.set("bnd2", X86_REG_BND2);
    t.set("bnd3", X86_REG_BND3);

    t.set("_sp", COMM_REG_SP);
    t.set("_pc", COMM_REG_PC);
}

fn init_regid_arm(t: &ValRef) {
    use crate::register::regid::*;

    t.set("apsr", ARM_REG_APSR);
    t.set("apsr_nzcv", ARM_REG_APSR_NZCV);
    t.set("cpsr", ARM_REG_CPSR);
    t.set("fpexc", ARM_REG_FPEXC);
    t.set("fpinst", ARM_REG_FPINST);
    t.set("fpscr", ARM_REG_FPSCR);
    t.set("fpscr_nzcv", ARM_REG_FPSCR_NZCV);
    t.set("fpsid", ARM_REG_FPSID);
    t.set("itstate", ARM_REG_ITSTATE);
    t.set("lr", ARM_REG_LR);
    t.set("pc", ARM_REG_PC);
    t.set("sp", ARM_REG_SP);
    t.set("spsr", ARM_REG_SPSR);
    t.set("d0", ARM_REG_D0);
    t.set("d1", ARM_REG_D1);
    t.set("d2", ARM_REG_D2);
    t.set("d3", ARM_REG_D3);
    t.set("d4", ARM_REG_D4);
    t.set("d5", ARM_REG_D5);
    t.set("d6", ARM_REG_D6);
    t.set("d7", ARM_REG_D7);
    t.set("d8", ARM_REG_D8);
    t.set("d9", ARM_REG_D9);
    t.set("d10", ARM_REG_D10);
    t.set("d11", ARM_REG_D11);
    t.set("d12", ARM_REG_D12);
    t.set("d13", ARM_REG_D13);
    t.set("d14", ARM_REG_D14);
    t.set("d15", ARM_REG_D15);
    t.set("d16", ARM_REG_D16);
    t.set("d17", ARM_REG_D17);
    t.set("d18", ARM_REG_D18);
    t.set("d19", ARM_REG_D19);
    t.set("d20", ARM_REG_D20);
    t.set("d21", ARM_REG_D21);
    t.set("d22", ARM_REG_D22);
    t.set("d23", ARM_REG_D23);
    t.set("d24", ARM_REG_D24);
    t.set("d25", ARM_REG_D25);
    t.set("d26", ARM_REG_D26);
    t.set("d27", ARM_REG_D27);
    t.set("d28", ARM_REG_D28);
    t.set("d29", ARM_REG_D29);
    t.set("d30", ARM_REG_D30);
    t.set("d31", ARM_REG_D31);
    t.set("fpinst2", ARM_REG_FPINST2);
    t.set("mvfr0", ARM_REG_MVFR0);
    t.set("mvfr1", ARM_REG_MVFR1);
    t.set("mvfr2", ARM_REG_MVFR2);
    t.set("q0", ARM_REG_Q0);
    t.set("q1", ARM_REG_Q1);
    t.set("q2", ARM_REG_Q2);
    t.set("q3", ARM_REG_Q3);
    t.set("q4", ARM_REG_Q4);
    t.set("q5", ARM_REG_Q5);
    t.set("q6", ARM_REG_Q6);
    t.set("q7", ARM_REG_Q7);
    t.set("q8", ARM_REG_Q8);
    t.set("q9", ARM_REG_Q9);
    t.set("q10", ARM_REG_Q10);
    t.set("q11", ARM_REG_Q11);
    t.set("q12", ARM_REG_Q12);
    t.set("q13", ARM_REG_Q13);
    t.set("q14", ARM_REG_Q14);
    t.set("q15", ARM_REG_Q15);
    t.set("r0", ARM_REG_R0);
    t.set("r1", ARM_REG_R1);
    t.set("r2", ARM_REG_R2);
    t.set("r3", ARM_REG_R3);
    t.set("r4", ARM_REG_R4);
    t.set("r5", ARM_REG_R5);
    t.set("r6", ARM_REG_R6);
    t.set("r7", ARM_REG_R7);
    t.set("r8", ARM_REG_R8);
    t.set("r9", ARM_REG_R9);
    t.set("r10", ARM_REG_R10);
    t.set("r11", ARM_REG_R11);
    t.set("r12", ARM_REG_R12);
    t.set("s0", ARM_REG_S0);
    t.set("s1", ARM_REG_S1);
    t.set("s2", ARM_REG_S2);
    t.set("s3", ARM_REG_S3);
    t.set("s4", ARM_REG_S4);
    t.set("s5", ARM_REG_S5);
    t.set("s6", ARM_REG_S6);
    t.set("s7", ARM_REG_S7);
    t.set("s8", ARM_REG_S8);
    t.set("s9", ARM_REG_S9);
    t.set("s10", ARM_REG_S10);
    t.set("s11", ARM_REG_S11);
    t.set("s12", ARM_REG_S12);
    t.set("s13", ARM_REG_S13);
    t.set("s14", ARM_REG_S14);
    t.set("s15", ARM_REG_S15);
    t.set("s16", ARM_REG_S16);
    t.set("s17", ARM_REG_S17);
    t.set("s18", ARM_REG_S18);
    t.set("s19", ARM_REG_S19);
    t.set("s20", ARM_REG_S20);
    t.set("s21", ARM_REG_S21);
    t.set("s22", ARM_REG_S22);
    t.set("s23", ARM_REG_S23);
    t.set("s24", ARM_REG_S24);
    t.set("s25", ARM_REG_S25);
    t.set("s26", ARM_REG_S26);
    t.set("s27", ARM_REG_S27);
    t.set("s28", ARM_REG_S28);
    t.set("s29", ARM_REG_S29);
    t.set("s30", ARM_REG_S30);
    t.set("s31", ARM_REG_S31);
    t.set("r13", ARM_REG_R13);
    t.set("r14", ARM_REG_R14);
    t.set("r15", ARM_REG_R15);
    t.set("sb", ARM_REG_SB);
    t.set("sl", ARM_REG_SL);
    t.set("fp", ARM_REG_FP);
    t.set("ip", ARM_REG_IP);

    t.set("_sp", COMM_REG_SP);
    t.set("_pc", COMM_REG_PC);
}

fn init_regid_aarch64(t: &ValRef) {
    use crate::register::regid::*;

    t.set("ffr", ARM64_REG_FFR);
    t.set("fp", ARM64_REG_FP);
    t.set("lr", ARM64_REG_LR);
    t.set("nzcv", ARM64_REG_NZCV);
    t.set("sp", ARM64_REG_SP);
    t.set("wsp", ARM64_REG_WSP);
    t.set("wzr", ARM64_REG_WZR);
    t.set("xzr", ARM64_REG_XZR);
    t.set("b0", ARM64_REG_B0);
    t.set("b1", ARM64_REG_B1);
    t.set("b2", ARM64_REG_B2);
    t.set("b3", ARM64_REG_B3);
    t.set("b4", ARM64_REG_B4);
    t.set("b5", ARM64_REG_B5);
    t.set("b6", ARM64_REG_B6);
    t.set("b7", ARM64_REG_B7);
    t.set("b8", ARM64_REG_B8);
    t.set("b9", ARM64_REG_B9);
    t.set("b10", ARM64_REG_B10);
    t.set("b11", ARM64_REG_B11);
    t.set("b12", ARM64_REG_B12);
    t.set("b13", ARM64_REG_B13);
    t.set("b14", ARM64_REG_B14);
    t.set("b15", ARM64_REG_B15);
    t.set("b16", ARM64_REG_B16);
    t.set("b17", ARM64_REG_B17);
    t.set("b18", ARM64_REG_B18);
    t.set("b19", ARM64_REG_B19);
    t.set("b20", ARM64_REG_B20);
    t.set("b21", ARM64_REG_B21);
    t.set("b22", ARM64_REG_B22);
    t.set("b23", ARM64_REG_B23);
    t.set("b24", ARM64_REG_B24);
    t.set("b25", ARM64_REG_B25);
    t.set("b26", ARM64_REG_B26);
    t.set("b27", ARM64_REG_B27);
    t.set("b28", ARM64_REG_B28);
    t.set("b29", ARM64_REG_B29);
    t.set("b30", ARM64_REG_B30);
    t.set("b31", ARM64_REG_B31);
    t.set("d0", ARM64_REG_D0);
    t.set("d1", ARM64_REG_D1);
    t.set("d2", ARM64_REG_D2);
    t.set("d3", ARM64_REG_D3);
    t.set("d4", ARM64_REG_D4);
    t.set("d5", ARM64_REG_D5);
    t.set("d6", ARM64_REG_D6);
    t.set("d7", ARM64_REG_D7);
    t.set("d8", ARM64_REG_D8);
    t.set("d9", ARM64_REG_D9);
    t.set("d10", ARM64_REG_D10);
    t.set("d11", ARM64_REG_D11);
    t.set("d12", ARM64_REG_D12);
    t.set("d13", ARM64_REG_D13);
    t.set("d14", ARM64_REG_D14);
    t.set("d15", ARM64_REG_D15);
    t.set("d16", ARM64_REG_D16);
    t.set("d17", ARM64_REG_D17);
    t.set("d18", ARM64_REG_D18);
    t.set("d19", ARM64_REG_D19);
    t.set("d20", ARM64_REG_D20);
    t.set("d21", ARM64_REG_D21);
    t.set("d22", ARM64_REG_D22);
    t.set("d23", ARM64_REG_D23);
    t.set("d24", ARM64_REG_D24);
    t.set("d25", ARM64_REG_D25);
    t.set("d26", ARM64_REG_D26);
    t.set("d27", ARM64_REG_D27);
    t.set("d28", ARM64_REG_D28);
    t.set("d29", ARM64_REG_D29);
    t.set("d30", ARM64_REG_D30);
    t.set("d31", ARM64_REG_D31);
    t.set("h0", ARM64_REG_H0);
    t.set("h1", ARM64_REG_H1);
    t.set("h2", ARM64_REG_H2);
    t.set("h3", ARM64_REG_H3);
    t.set("h4", ARM64_REG_H4);
    t.set("h5", ARM64_REG_H5);
    t.set("h6", ARM64_REG_H6);
    t.set("h7", ARM64_REG_H7);
    t.set("h8", ARM64_REG_H8);
    t.set("h9", ARM64_REG_H9);
    t.set("h10", ARM64_REG_H10);
    t.set("h11", ARM64_REG_H11);
    t.set("h12", ARM64_REG_H12);
    t.set("h13", ARM64_REG_H13);
    t.set("h14", ARM64_REG_H14);
    t.set("h15", ARM64_REG_H15);
    t.set("h16", ARM64_REG_H16);
    t.set("h17", ARM64_REG_H17);
    t.set("h18", ARM64_REG_H18);
    t.set("h19", ARM64_REG_H19);
    t.set("h20", ARM64_REG_H20);
    t.set("h21", ARM64_REG_H21);
    t.set("h22", ARM64_REG_H22);
    t.set("h23", ARM64_REG_H23);
    t.set("h24", ARM64_REG_H24);
    t.set("h25", ARM64_REG_H25);
    t.set("h26", ARM64_REG_H26);
    t.set("h27", ARM64_REG_H27);
    t.set("h28", ARM64_REG_H28);
    t.set("h29", ARM64_REG_H29);
    t.set("h30", ARM64_REG_H30);
    t.set("h31", ARM64_REG_H31);
    t.set("p0", ARM64_REG_P0);
    t.set("p1", ARM64_REG_P1);
    t.set("p2", ARM64_REG_P2);
    t.set("p3", ARM64_REG_P3);
    t.set("p4", ARM64_REG_P4);
    t.set("p5", ARM64_REG_P5);
    t.set("p6", ARM64_REG_P6);
    t.set("p7", ARM64_REG_P7);
    t.set("p8", ARM64_REG_P8);
    t.set("p9", ARM64_REG_P9);
    t.set("p10", ARM64_REG_P10);
    t.set("p11", ARM64_REG_P11);
    t.set("p12", ARM64_REG_P12);
    t.set("p13", ARM64_REG_P13);
    t.set("p14", ARM64_REG_P14);
    t.set("p15", ARM64_REG_P15);
    t.set("q0", ARM64_REG_Q0);
    t.set("q1", ARM64_REG_Q1);
    t.set("q2", ARM64_REG_Q2);
    t.set("q3", ARM64_REG_Q3);
    t.set("q4", ARM64_REG_Q4);
    t.set("q5", ARM64_REG_Q5);
    t.set("q6", ARM64_REG_Q6);
    t.set("q7", ARM64_REG_Q7);
    t.set("q8", ARM64_REG_Q8);
    t.set("q9", ARM64_REG_Q9);
    t.set("q10", ARM64_REG_Q10);
    t.set("q11", ARM64_REG_Q11);
    t.set("q12", ARM64_REG_Q12);
    t.set("q13", ARM64_REG_Q13);
    t.set("q14", ARM64_REG_Q14);
    t.set("q15", ARM64_REG_Q15);
    t.set("q16", ARM64_REG_Q16);
    t.set("q17", ARM64_REG_Q17);
    t.set("q18", ARM64_REG_Q18);
    t.set("q19", ARM64_REG_Q19);
    t.set("q20", ARM64_REG_Q20);
    t.set("q21", ARM64_REG_Q21);
    t.set("q22", ARM64_REG_Q22);
    t.set("q23", ARM64_REG_Q23);
    t.set("q24", ARM64_REG_Q24);
    t.set("q25", ARM64_REG_Q25);
    t.set("q26", ARM64_REG_Q26);
    t.set("q27", ARM64_REG_Q27);
    t.set("q28", ARM64_REG_Q28);
    t.set("q29", ARM64_REG_Q29);
    t.set("q30", ARM64_REG_Q30);
    t.set("q31", ARM64_REG_Q31);
    t.set("s0", ARM64_REG_S0);
    t.set("s1", ARM64_REG_S1);
    t.set("s2", ARM64_REG_S2);
    t.set("s3", ARM64_REG_S3);
    t.set("s4", ARM64_REG_S4);
    t.set("s5", ARM64_REG_S5);
    t.set("s6", ARM64_REG_S6);
    t.set("s7", ARM64_REG_S7);
    t.set("s8", ARM64_REG_S8);
    t.set("s9", ARM64_REG_S9);
    t.set("s10", ARM64_REG_S10);
    t.set("s11", ARM64_REG_S11);
    t.set("s12", ARM64_REG_S12);
    t.set("s13", ARM64_REG_S13);
    t.set("s14", ARM64_REG_S14);
    t.set("s15", ARM64_REG_S15);
    t.set("s16", ARM64_REG_S16);
    t.set("s17", ARM64_REG_S17);
    t.set("s18", ARM64_REG_S18);
    t.set("s19", ARM64_REG_S19);
    t.set("s20", ARM64_REG_S20);
    t.set("s21", ARM64_REG_S21);
    t.set("s22", ARM64_REG_S22);
    t.set("s23", ARM64_REG_S23);
    t.set("s24", ARM64_REG_S24);
    t.set("s25", ARM64_REG_S25);
    t.set("s26", ARM64_REG_S26);
    t.set("s27", ARM64_REG_S27);
    t.set("s28", ARM64_REG_S28);
    t.set("s29", ARM64_REG_S29);
    t.set("s30", ARM64_REG_S30);
    t.set("s31", ARM64_REG_S31);
    t.set("w0", ARM64_REG_W0);
    t.set("w1", ARM64_REG_W1);
    t.set("w2", ARM64_REG_W2);
    t.set("w3", ARM64_REG_W3);
    t.set("w4", ARM64_REG_W4);
    t.set("w5", ARM64_REG_W5);
    t.set("w6", ARM64_REG_W6);
    t.set("w7", ARM64_REG_W7);
    t.set("w8", ARM64_REG_W8);
    t.set("w9", ARM64_REG_W9);
    t.set("w10", ARM64_REG_W10);
    t.set("w11", ARM64_REG_W11);
    t.set("w12", ARM64_REG_W12);
    t.set("w13", ARM64_REG_W13);
    t.set("w14", ARM64_REG_W14);
    t.set("w15", ARM64_REG_W15);
    t.set("w16", ARM64_REG_W16);
    t.set("w17", ARM64_REG_W17);
    t.set("w18", ARM64_REG_W18);
    t.set("w19", ARM64_REG_W19);
    t.set("w20", ARM64_REG_W20);
    t.set("w21", ARM64_REG_W21);
    t.set("w22", ARM64_REG_W22);
    t.set("w23", ARM64_REG_W23);
    t.set("w24", ARM64_REG_W24);
    t.set("w25", ARM64_REG_W25);
    t.set("w26", ARM64_REG_W26);
    t.set("w27", ARM64_REG_W27);
    t.set("w28", ARM64_REG_W28);
    t.set("w29", ARM64_REG_W29);
    t.set("w30", ARM64_REG_W30);
    t.set("x0", ARM64_REG_X0);
    t.set("x1", ARM64_REG_X1);
    t.set("x2", ARM64_REG_X2);
    t.set("x3", ARM64_REG_X3);
    t.set("x4", ARM64_REG_X4);
    t.set("x5", ARM64_REG_X5);
    t.set("x6", ARM64_REG_X6);
    t.set("x7", ARM64_REG_X7);
    t.set("x8", ARM64_REG_X8);
    t.set("x9", ARM64_REG_X9);
    t.set("x10", ARM64_REG_X10);
    t.set("x11", ARM64_REG_X11);
    t.set("x12", ARM64_REG_X12);
    t.set("x13", ARM64_REG_X13);
    t.set("x14", ARM64_REG_X14);
    t.set("x15", ARM64_REG_X15);
    t.set("x16", ARM64_REG_X16);
    t.set("x17", ARM64_REG_X17);
    t.set("x18", ARM64_REG_X18);
    t.set("x19", ARM64_REG_X19);
    t.set("x20", ARM64_REG_X20);
    t.set("x21", ARM64_REG_X21);
    t.set("x22", ARM64_REG_X22);
    t.set("x23", ARM64_REG_X23);
    t.set("x24", ARM64_REG_X24);
    t.set("x25", ARM64_REG_X25);
    t.set("x26", ARM64_REG_X26);
    t.set("x27", ARM64_REG_X27);
    t.set("x28", ARM64_REG_X28);
    t.set("z0", ARM64_REG_Z0);
    t.set("z1", ARM64_REG_Z1);
    t.set("z2", ARM64_REG_Z2);
    t.set("z3", ARM64_REG_Z3);
    t.set("z4", ARM64_REG_Z4);
    t.set("z5", ARM64_REG_Z5);
    t.set("z6", ARM64_REG_Z6);
    t.set("z7", ARM64_REG_Z7);
    t.set("z8", ARM64_REG_Z8);
    t.set("z9", ARM64_REG_Z9);
    t.set("z10", ARM64_REG_Z10);
    t.set("z11", ARM64_REG_Z11);
    t.set("z12", ARM64_REG_Z12);
    t.set("z13", ARM64_REG_Z13);
    t.set("z14", ARM64_REG_Z14);
    t.set("z15", ARM64_REG_Z15);
    t.set("z16", ARM64_REG_Z16);
    t.set("z17", ARM64_REG_Z17);
    t.set("z18", ARM64_REG_Z18);
    t.set("z19", ARM64_REG_Z19);
    t.set("z20", ARM64_REG_Z20);
    t.set("z21", ARM64_REG_Z21);
    t.set("z22", ARM64_REG_Z22);
    t.set("z23", ARM64_REG_Z23);
    t.set("z24", ARM64_REG_Z24);
    t.set("z25", ARM64_REG_Z25);
    t.set("z26", ARM64_REG_Z26);
    t.set("z27", ARM64_REG_Z27);
    t.set("z28", ARM64_REG_Z28);
    t.set("z29", ARM64_REG_Z29);
    t.set("z30", ARM64_REG_Z30);
    t.set("z31", ARM64_REG_Z31);
    t.set("v0", ARM64_REG_V0);
    t.set("v1", ARM64_REG_V1);
    t.set("v2", ARM64_REG_V2);
    t.set("v3", ARM64_REG_V3);
    t.set("v4", ARM64_REG_V4);
    t.set("v5", ARM64_REG_V5);
    t.set("v6", ARM64_REG_V6);
    t.set("v7", ARM64_REG_V7);
    t.set("v8", ARM64_REG_V8);
    t.set("v9", ARM64_REG_V9);
    t.set("v10", ARM64_REG_V10);
    t.set("v11", ARM64_REG_V11);
    t.set("v12", ARM64_REG_V12);
    t.set("v13", ARM64_REG_V13);
    t.set("v14", ARM64_REG_V14);
    t.set("v15", ARM64_REG_V15);
    t.set("v16", ARM64_REG_V16);
    t.set("v17", ARM64_REG_V17);
    t.set("v18", ARM64_REG_V18);
    t.set("v19", ARM64_REG_V19);
    t.set("v20", ARM64_REG_V20);
    t.set("v21", ARM64_REG_V21);
    t.set("v22", ARM64_REG_V22);
    t.set("v23", ARM64_REG_V23);
    t.set("v24", ARM64_REG_V24);
    t.set("v25", ARM64_REG_V25);
    t.set("v26", ARM64_REG_V26);
    t.set("v27", ARM64_REG_V27);
    t.set("v28", ARM64_REG_V28);
    t.set("v29", ARM64_REG_V29);
    t.set("v30", ARM64_REG_V30);
    t.set("v31", ARM64_REG_V31);
    t.set("ip0", ARM64_REG_IP0);
    t.set("ip1", ARM64_REG_IP1);
    t.set("x29", ARM64_REG_X29);
    t.set("x30", ARM64_REG_X30);

    t.set("_sp", COMM_REG_SP);
    t.set("_pc", COMM_REG_PC);
}
