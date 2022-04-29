use crate::{
    os::{pid_t, tid_t},
    pdbfile,
    pe::PETarget,
    prelude::*,
    register::{get_regid, CpuReg},
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

    t.register("get_regid", get_regid);
    t.register("open_pe_target", |path: &str| {
        PETarget::new(path).map(Arc::new).map(|t| ArcTarget(t as _))
    });

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
    #[cfg(windows)]
    const INDEX_GETTER: lua_CFunction = RsFn::new(|s: &State, this: &Self, key: &str| {
        use winapi::um::winnt::PAGE_READONLY;
        match key {
            "alloc_base" => s.pushed(this.alloc_base),
            "base" => s.pushed(this.base),
            "size" => s.pushed(this.size),
            "executable" => s.pushed(this.protect & 0xF0 > 0),
            "writable" => s.pushed(this.protect & 0xCC > 0),
            "readonly" => s.pushed(this.protect == PAGE_READONLY),
            "protect" => s.pushed(this.protect),
            "type" => s.pushed(this.type_),
            "state" => s.pushed(this.state),
            _ => 0.into(),
        }
    })
    .wrapper();

    #[cfg(not(windows))]
    const INDEX_GETTER: lua_CFunction = RsFn::new(|s: &State, this: &Self, key: &str| match key {
        "base" => s.pushed(this.base),
        "size" => s.pushed(this.size),
        "executable" => s.pushed(this.is_executable()),
        "writable" => s.pushed(this.is_writable()),
        "readonly" => s.pushed(this.is_readonly()),
        "protect" => s.pushed(&this.prot[..]),
        "type" => s.pushed(if this.is_private() { "private" } else { "" }),
        "image" => s.pushed(this.usage.as_ref()),
        _ => return 0.into(),
    })
    .wrapper();

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
            this.enum_memory().map(|r| BoxIter(r))
        })
        .register("enum_handle", |this: &'static Self| {
            this.enum_handle().map(|r| BoxIter(r))
        });

        mt.register("get_memory_map", |this: &Self| {
            SerdeValue(this.collect_memory_info())
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
