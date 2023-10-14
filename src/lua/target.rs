use serde_bytes::ByteBuf;

use super::*;

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
    const TYPE_NAME: &'static str = "UDbgTarget";
    const INDEX_USERVALUE: bool = true;

    fn metatable(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("Index", |this: &Self, key: &str| {
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
            .set_closure("eventTid", |this: &Self| this.base().event_tid.get())?
            .set_closure("pointerSize", |this: &Self| this.base().pointer_size())?
            .set_closure("status", |this: &Self| this.base().status.get().as_str())?
            .set_closure("contextArch", |this: &Self| {
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
            .add_deref("readU8", <dyn UDbgTarget>::read_value::<u8>)?
            .add_deref("readU16", <dyn UDbgTarget>::read_value::<u16>)?
            .add_deref("readU32", <dyn UDbgTarget>::read_value::<u32>)?
            .add_deref("readU64", <dyn UDbgTarget>::read_value::<u64>)?
            .add_deref("readF32", <dyn UDbgTarget>::read_value::<f32>)?
            .add_deref("readF64", <dyn UDbgTarget>::read_value::<f64>)?
            .add_deref("parseAddress", <dyn UDbgTarget>::parse_address)?
            .add_deref("getSymbol", <dyn UDbgTarget>::get_symbol_string)?
            .add_deref("getSymbolInfo", <dyn UDbgTarget>::get_symbol_)?
            .add_deref("imagePath", <dyn UDbgTarget>::image_path)?
            .add_deref("detach", <dyn UDbgTarget>::detach)?
            .add_deref("kill", <dyn UDbgTarget>::kill)?
            .add_deref("pause", <dyn UDbgTarget>::breakk)?
            .add_deref("resume", <dyn UDbgTarget>::resume)?
            .add_deref("suspend", <dyn UDbgTarget>::suspend)?
            .add_deref("waitExit", <dyn UDbgTarget>::wait_exit)?;

        fn write_value<T>(this: &ArcTarget, a: usize, val: T) {
            this.write_value(a, &val);
        }
        mt.set_closure("writeU8", write_value::<u8>)?
            .set_closure("writeU16", write_value::<u16>)?
            .set_closure("writeU32", write_value::<u32>)?
            .set_closure("writeU64", write_value::<u64>)?
            .set_closure("writeF32", write_value::<f32>)?
            .set_closure("writeF64", write_value::<f64>)?;

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
        mt.set_closure("getBreakpoint", |this: &Self, id: BpID| {
            this.get_breakpoint(id).map(ArcBreakpoint)
        })?;
        mt.set_closure("breakpointList", |this: &Self| {
            IterVec(this.get_breakpoints().into_iter().map(ArcBreakpoint))
        })?;

        mt.set_closure(
            "readString",
            |this: &Self, a: usize, size: Option<usize>| {
                this.read_cstring(a, size.unwrap_or(1000))
                    .map(ByteBuf::from)
            },
        )?;
        #[cfg(windows)]
        mt.set_closure(
            "readWstring",
            |this: &Self, a: usize, size: Option<usize>| this.read_wstring(a, size.unwrap_or(1000)),
        )?;
        mt.set_closure("writeString", |this: &Self, a: usize, buf: &[u8]| {
            this.write_cstring(a, buf)
        })?;
        #[cfg(windows)]
        mt.set_closure("writeWstring", |this: &Self, a: usize, buf: &str| {
            this.write_wstring(a, buf)
        })?;

        mt.set_closure(
            "readPack",
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
            "detectString",
            |this: &Self, p: usize, max: Option<usize>| {
                this.detect_string(p, max.unwrap_or(32))
                    .map(|(wide, text)| (text, wide))
            },
        )?
        .set_closure("openThread", |this: &Self, tid: tid_t| {
            this.open_thread(tid).map(|x| BoxThread(x))
        })?
        .set_closure("threadList", |this: &Self| unsafe {
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

        mt.add_method("enumModule", |s, this: &Self, ()| {
            this.enum_module()
                .map(|r| unsafe { s.new_iter(r.map(ArcModule), [ArgRef(1)]) })
        })?
        .add_method("enumThread", |s, this: &Self, detail: bool| {
            this.enum_thread(detail)
                .map(|r| unsafe { s.new_iter(r.map(BoxThread), [ArgRef(1)]) })
        })?
        .add_method("enumMemory", |s, this: &Self, ()| {
            this.enum_memory()
                .map(|r| unsafe { s.new_iter(r, [ArgRef(1)]) })
        })?
        .add_method("enumHandle", |s, this: &Self, ()| {
            this.enum_handle()
                .map(|r| unsafe { s.new_iter(r, [ArgRef(1)]) })
        })?;

        mt.set_closure("collectMemory", |this: &Self| {
            IterVec(this.collect_memory_info().into_iter().map(SerdeValue))
        })?
        .set_closure("getModule", |s: &LuaState, this: &Self, val: ValRef| {
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

        mt.set_closure("virtualQuery", |this: &Self, a: usize| {
            this.virtual_query(a)
        })?
        .set_closure(
            "virtualAlloc",
            |this: &Self, a: usize, size: usize, ty: Option<&str>| {
                this.virtual_alloc(a, size, ty.unwrap_or(""))
            },
        )?
        .set_closure("virtualFree", |this: &Self, a: usize| {
            this.virtual_free(a);
        })?;

        mt.set(
            "readType",
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
            "readBytes",
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
            "writeBytes",
            |this: &Self, a: usize, buf: &[u8], len: Option<usize>| {
                this.write_memory(a, len.map(|len| &buf[..len]).unwrap_or(buf))
            },
        )?;

        mt.set_closure(
            "writeType",
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

        Ok(())
    }
}

impl ToLua for SymbolInfo {
    fn to_lua<'a>(self, lua: &'a LuaState) -> LuaResult<ValRef<'a>> {
        lua.new_val(SerdeValue(self))
    }
}

#[extend::ext(pub)]
impl dyn UDbgTarget {
    fn parse_address(&self, symbol: &str) -> Option<usize> {
        let (mut left, right) = match symbol.find('+') {
            Some(pos) => ((&symbol[..pos]).trim(), Some((&symbol[pos + 1..]).trim())),
            None => (symbol.trim(), None),
        };

        if left.starts_with("0x") || left.starts_with("0X") {
            left = &left[2..];
        }
        let mut val = if let Ok(address) = usize::from_str_radix(left, 16) {
            address
        } else {
            self.get_address_by_symbol(left)?
        };

        if let Some(right) = right {
            val += self.parse_address(right)?;
        }

        Some(val)
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
    const TYPE_NAME: &'static str = "UDbgModule";

    fn metatable(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("Index", |s: &LuaState, this: &Self, key: &str| {
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
        fields.set_closure("entryPoint", |this: &Self| {
            let data = this.data();
            data.base + data.entry
        })?;
        fields.set_closure("userModule", |this: &Self| this.data().user_module.get())?;

        Ok(())
    }

    fn setter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields.set_closure("userModule", |this: &Self, user: bool| {
            this.data().user_module.set(user)
        })?;
        Ok(())
    }

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        // mt.as_deref()
        //     .add_deref("add_symbol", <dyn UDbgModule>::add_symbol)?
        //     .add_deref("load_symbol", <dyn UDbgModule>::load_symbol_file)?;

        mt.set_closure("symbolFile", |this: &Self| {
            this.symbol_file().map(ArcSymbolFile)
        })?;
        mt.add_method("enumSymbol", |s: &LuaState, this: &Self, pat: &str| {
            this.enum_symbol(Some(pat))
                .map(|x| unsafe { s.new_iter(x, [ArgRef(1)]) })
                .lua_result()
        })?;
        mt.add("enum_export", |this: &Self| {
            this.get_exports()
                .map(|exports| StaticIter::from(exports.into_iter()))
        })?;
        mt.add_method("getSymbol", |s, this: &Self, pat: &str| {
            this.enum_symbol(Some(pat))
                .map(|mut x| x.next().map(|sym| s.new_val(sym)).transpose())
                .lua_result()
        })?;
        #[cfg(all(windows, target_arch = "x86_64"))]
        mt.set_closure(
            "findFunction",
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
    const TYPE_NAME: &'static str = "UDbgThread";

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
        mt.set_closure("lastError", |this: &Self| this.last_error())?;

        Ok(())
    }

    fn metatable(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("Call", |s: &LuaState, this: &Self, key: &str| {
            this.0.get_prop(key).map(SerdeValue)
        })?;

        Ok(())
    }
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

impl UserData for MemoryPage {
    const TYPE_NAME: &'static str = "MemoryPage";

    fn getter(fields: UserdataRegistry<Self>) -> LuaResult<()> {
        fields.set_closure("allocBase", |this: &Self| this.alloc_base)?;
        fields.set_closure("allocProtect", |this: &Self| this.alloc_protect)?;
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
        fields.set_closure("memoryInfo", |this: &Self| {
            SerdeValue(MemoryPageInfo::from(this))
        })?;

        Ok(())
    }

    fn methods(mt: UserdataRegistry<Self>) -> LuaResult<()> {
        mt.set_closure("isCommit", MemoryPage::is_commit)?
            .set_closure("isReserve", MemoryPage::is_reserve)?
            .set_closure("isFree", MemoryPage::is_free)?
            .set_closure("isPrivate", MemoryPage::is_private)?;

        Ok(())
    }
}
