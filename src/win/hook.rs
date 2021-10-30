
use super::{*, disasm::*};

use core::mem::{transmute, size_of};
use core::slice;
use std::sync::Arc;
use spin::RwLock;
use std::collections::HashMap;

use spin::Mutex as Spinlock;
use winapi::um::winnt::*;

#[derive(Debug)]
pub enum Error {
    Reason(&'static str),
    Failure,
    DisAsm,
    Exists,
    ReadMemory,
    LoadLibrary,
    VirtualAlloc,
    GetProcAddress,
    WindowNotFound,
    ThreadNotFound,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct HookContext {
    pub EFlags: usize,
    pub R15: usize,
    pub R14: usize,
    pub R13: usize,
    pub R12: usize,
    pub R11: usize,
    pub R10: usize,
    pub R9: usize,
    pub R8: usize,
    pub Rdi: usize,
    pub Rsi: usize,
    pub Rbp: usize,
    pub Rbx: usize,
    pub Rdx: usize,
    pub Rcx: usize,
    pub Rax: usize,
    pub Rsp: usize,
    retn: usize,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct HookContext {
    pub EFlags: usize,
    pub Edi: usize,
    pub Esi: usize,
    pub Ebx: usize,
    pub Edx: usize,
    pub Ecx: usize,
    pub Eax: usize,
    pub Ebp: usize,
    pub Esp: usize,
    retn: usize,
}

impl HookContext {
    #[cfg(target_arch = "x86_64")]
    pub fn arg(&self, i: usize) -> usize {
        unsafe {
            match i {
                1 => self.Rcx,
                2 => self.Rdx,
                3 => self.R8,
                4 => self.R9,
                e => {
                    let p: *const usize = transmute(self.Rsp + if e > 0 { 0x20 } else { 0 });
                    slice::from_raw_parts(p, i + 1)[e]
                }
            }
        }
    }

    #[cfg(target_arch = "x86")]
    pub fn arg(&self, i: usize) -> usize {
        unsafe {
            let p: *const usize = transmute(self.Esp);
            slice::from_raw_parts(p, i + 1)[i]
        }
    }

    pub fn arg_mut(&mut self, i: isize) -> &mut usize {
        #[cfg(target_arch = "x86_64")]
        match i {
            1 => &mut self.Rcx,
            2 => &mut self.Rdx,
            3 => &mut self.R8,
            4 => &mut self.R9,
            _ => unsafe {
                let p: *mut usize = transmute(self.Rsp + if i > 0 { 0x20 } else { 0 });
                transmute(p.offset(i))
            }
        }
        #[cfg(target_arch = "x86")] unsafe {
            let p: *mut usize = transmute(self.Esp);
            transmute(p.offset(i))
        }
    }

    pub fn reg_mut(&mut self, reg: &str) -> Option<&mut usize> {
        #[cfg(target_arch = "x86_64")] {
            Some(match reg {
                "eflags" => &mut self.EFlags,
                "r15" | "_15" => &mut self.R15,
                "r14" | "_14" => &mut self.R14,
                "r13" | "_13" => &mut self.R13,
                "r12" | "_12" => &mut self.R12,
                "r11" | "_11" => &mut self.R11,
                "r10" | "_10" => &mut self.R10,
                "r9" | "_9" => &mut self.R9,
                "r8" | "_8" => &mut self.R8,
                "rdi" | "_di" => &mut self.Rdi,
                "rsi" | "_si" => &mut self.Rsi,
                "rbp" | "_bp" => &mut self.Rbp,
                "rbx" | "_bx" => &mut self.Rbx,
                "rdx" | "_dx" => &mut self.Rdx,
                "rcx" | "_cx" => &mut self.Rcx,
                "rax" | "_ax" => &mut self.Rax,
                "rsp" | "_sp" => &mut self.Rsp,
                _ => return None,
            })
        }
        #[cfg(target_arch = "x86")] {
            Some(match reg {
                "eflags" => &mut self.EFlags,
                "edi" | "_di" => &mut self.Edi,
                "esi" | "_si" => &mut self.Esi,
                "ebx" | "_bx" => &mut self.Ebx,
                "edx" | "_dx" => &mut self.Edx,
                "ecx" | "_cx" => &mut self.Ecx,
                "eax" | "_ax" => &mut self.Eax,
                "ebp" | "_bp" => &mut self.Ebp,
                "esp" | "_sp" => &mut self.Esp,
                _ => return None,
            })
        }
    }

    #[inline]
    pub fn back(&self) -> usize { self.arg(0) }

    #[cfg(target_arch = "x86_64")]
    pub fn sp(&mut self) -> &mut usize { unsafe { transmute(&mut self.Rsp) } }

    #[cfg(target_arch = "x86")]
    pub fn sp(&mut self) -> &mut usize { unsafe { transmute(&mut self.Esp) } }
}

#[repr(C)]
pub struct HookArgs<'a> {
    pub hook: &'a HookBase,
    pub regs: &'a mut HookContext,
    pub reject: Option<u32>,
}

impl HookArgs<'_> {
    pub fn trampoline(&self) -> usize {
        self.hook.codeback
    }
}

pub type HookCallback = Box<dyn Fn(&mut HookArgs)>;
pub type HookCallbackFn = unsafe extern "C" fn(&mut HookArgs);

// TODO: prevent to re-entry
#[allow(improper_ctypes)]
#[no_mangle]
unsafe extern "system" fn hook_handler(hook: &mut HookBase, regs: &mut HookContext) {
    // *regs.sp() += size_of::<usize>();
    let mut arg = HookArgs { hook, regs, reject: None };
    hook.callback.lock()(&mut arg);
    if let Some(stack_argc) = arg.reject {
        if stack_argc > 0 {
            let sp = arg.regs.sp();
            let retn = *(*sp as *const usize);
            *sp += stack_argc as usize * size_of::<usize>();
            *(*sp as *mut usize) = retn;
        }
    } else {
        *arg.regs.sp() -= size_of::<usize>();
        regs.retn = arg.hook.codeback;
    }
}

#[cfg(target_arch = "x86_64")]
fn create_hook_handler() -> *const u8 {
    shellcode!(
        "push rsp"      // +80
        "push rax"      // +78
        "push rcx"      // +70
        "push rdx"      // +68
        "push rbx"      // +60
        "push rbp"      // +58
        "push rsi"      // +50
        "push rdi"      // +48
        "push r8"       // +40
        "push r9"       // +38
        "push r10"      // +30
        "push r11"      // +28
        "push r12"      // +20
        "push r13"      // +18
        "push r14"      // +10
        "push r15"      // +8
        "pushfq"        // +0
        "add qword ptr [rsp+0x80], 8" // .rsp += 8
        "mov rcx, [rsp+0x88]"
        "mov rdx, rsp"
        // align16
        "sub rsp, 0x10"
        "and rsp, 0xfffffffffffffff0"
        "mov [rsp], rdx"
        "call hook_handler"
        "pop rsp"
        "popfq"
        "pop r15"
        "pop r14"
        "pop r13"
        "pop r12"
        "pop r11"
        "pop r10"
        "pop r9"
        "pop r8"
        "pop rdi"
        "pop rsi"
        "pop rbp"
        "pop rbx"
        "pop rdx"
        "pop rcx"
        "pop rax"
        "pop rsp"
        "ret"
    ).as_ptr()
}

#[cfg(target_arch = "x86")]
fn create_hook_handler() -> *const u8 {
    shellcode!(
        "push esp"      // +20
        "push ebp"      // +1c
        "push eax"      // +18
        "push ecx"      // +14
        "push edx"      // +10
        "push ebx"      // +c
        "push esi"      // +8
        "push edi"      // +4
        "pushfd"        // +0
        "add dword ptr [esp+0x20], 4"
        "mov ebp, esp"
        "push ebp"
        "push dword ptr [ebp+0x24]"
        "call _hook_handler@8"
        "popfd"
        "pop edi"
        "pop esi"
        "pop ebx"
        "pop edx"
        "pop ecx"
        "pop eax"
        "pop ebp"
        "pop esp"
        "ret"
    ).as_ptr()
}

// generate the handler function dynamiclly
unsafe fn get_hook_handler() -> usize {
    static mut CODEBUF: Option<*const u8> = None;

    *CODEBUF.get_or_insert_with(create_hook_handler) as usize
}

pub struct InsnWriter {
    pc: usize,
}

#[cfg(target_arch = "x86_64")]
fn is_in_same_4gb(from: usize, to: usize) -> (bool, isize) {
    let delta = to as isize - from as isize;
    return (delta.abs() < 0x80000000, delta);
}

pub enum Register {
    ZAX = 0, ZCX, ZDX, ZBX, ZSP, ZBP, ZSI, ZDI,
}

impl InsnWriter {
    pub fn new<T>(pc: *const T) -> InsnWriter {
        InsnWriter {pc: pc as usize}
    }

    // xxx [dest]
    #[cfg(target_arch = "x86_64")]
    fn write_dest(&mut self, dest: usize) {
        let (in_same_4gb, _delta) = is_in_same_4gb(self.pc as usize + size_of::<u32>(), dest);
        if !in_same_4gb { msgbox("NOT IN SAME 4GB"); }
        self.write_offset(dest);
    }
    #[cfg(target_arch = "x86")]
    fn write_dest(&mut self, dest: usize) { self.write(dest as isize); }

    fn write_offset(&mut self, dest: usize) {
        let offset = dest as isize - self.pc as isize - size_of::<i32>() as isize;
        self.write(offset as i32);
    }

    fn write<T>(&mut self, val: T) {
        unsafe {
            *(self.pc as *mut T) = val;
            self.pc = self.pc + size_of::<T>();
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        unsafe {
            let s = slice::from_raw_parts_mut(self.pc as *mut u8, bytes.len());
            s.copy_from_slice(bytes);
            self.pc += s.len();
        }
    }

    fn jmp(&mut self, addr: usize) {
        self.write(0xE9u8);
        self.write_offset(addr);
    }

    fn call(&mut self, addr: usize) {
        self.write(0xE8u8);
        self.write_offset(addr);
    }

    pub fn jmp_mem<T>(&mut self, addr: *const T) {
        self.write(0x25FFu16);
        self.write_dest(addr as usize);
    }

    pub fn call_mem<T>(&mut self, addr: *const T) {
        self.write(0x15FFu16);
        self.write_dest(addr as usize);
    }

    // push imm
    pub fn push_imm(&mut self, imm: u32) {
        self.write(0x68u8);
        self.write(imm);
    }

    #[cfg(target_arch = "x86_64")]
    pub fn push_usize(&mut self, imm: usize) {
        self.push_imm((imm & 0xFFFFFFFF) as u32);
        // c7 44 24 04 ?? ?? ?? ??  // mov dword ptr [rsp+4], 0x????????
        self.write(0x042444C7u32);
        self.write((imm >> 32) as u32);
    }

    #[cfg(target_arch = "x86")]
    pub fn push_usize(&mut self, imm: usize) { self.push_imm(imm as u32); }

    // push [mem]
    pub fn push_mem(&mut self, mem: usize) {
        self.write(0x35FFu16);
        self.write_dest(mem);
    }

    pub fn push_reg(&mut self, reg: Register) {
        self.write((0x50 | reg as u8) as u8);
    }

    pub fn pop_reg(&mut self, reg: Register) {
        self.write((0x58 | reg as u8) as u8);
    }

    /// mov rax, [mem]
    pub fn mov_zax_mem(&mut self, mem: usize) {
        #[cfg(target_arch = "x86_64")] {
            self.write(0x48u8);
        }
        self.write(0xA1u8);
        self.write(mem);
    }

    /// xchg rax, [rsp]
    pub fn xchg_zax_stack(&mut self) {
        #[cfg(target_arch = "x86_64")] {
            self.write(0x48u8);
        }
        self.write(0x87u8);
        self.write(0x04u8);
        self.write(0x24u8);
    }

    pub fn ret(&mut self) { self.write(0xC3u8); }

    pub fn retn(&mut self, n: u16) { self.write(0xC2u8); self.write(n); }

    pub fn pushfd(&mut self) { self.write(0x9cu8); }

    pub fn popfd(&mut self) { self.write(0x9du8); }

    pub fn pushad(&mut self) { self.write(0x60u8); }

    pub fn popad(&mut self) { self.write(0x61u8); }
}

#[repr(C)]
pub struct HookBase {
    pub address: usize,
    pub codeback: usize,    // trampoline
    pub callback: Spinlock<HookCallback>,
}

pub trait Hook {
    fn enable(&self) -> bool;
    fn disable(&self) -> bool;
    fn base<'a>(&'a self) -> &'a HookBase;
}

pub struct TrapLine {
    pub jmp_back: usize,
    pub trap_left: [u8; MAX_INSN_SIZE * 2],
    pub trap_right: [u8; MAX_INSN_SIZE * 2],
}

#[inline]
fn virtual_reserve_commit(address: usize, size: usize, protect: u32) -> usize {
    this_process().virtual_alloc(address, size, MEM_RESERVE | MEM_COMMIT, protect)
}

#[cfg(target_arch = "x86_64")]
fn alloc_mem_in_4gb(address: usize, size: usize) -> Result<usize, Error> {
    const LOW_2GB: usize = 0x7FFFFFFF;
    // let begin_address = if address > LOW_2GB { address - LOW_2GB } else { 0x10000 };
    let begin_address = address;
    for m in this_process().enum_memory(begin_address) {
        if m.base > address && m.base - address > LOW_2GB { break; }
        if m.is_free() {
            let sub_size = m.base & 0xFFFF;
            let align_address = m.base - sub_size + 0x10000;
            if m.size - (align_address - m.base) >= size {
                let r = virtual_reserve_commit(align_address, size, PAGE_EXECUTE_READWRITE);
                if r > 0 { return Ok(r) }
            }
        }
    }
    Err(Error::Reason("alloc_mem_in_4gb"))
}

#[cfg(target_arch = "x86")]
fn alloc_mem_in_4gb(_address: usize, size: usize) -> Result<usize, Error> {
    let r = virtual_reserve_commit(0usize, size, PAGE_EXECUTE_READWRITE);
    if r > 0 { Ok(r) } else { Err(Error::VirtualAlloc) }
}

impl TrapLine {
    pub fn alloc_in_4gb(address: usize) -> Result<&'static mut TrapLine, Error> {
        let result = alloc_mem_in_4gb(address, size_of::<TrapLine>())?;
        unsafe { Ok(transmute(result)) }
    }

    pub fn alloc() -> Result<&'static mut TrapLine, Error> {
        let result = virtual_reserve_commit(0usize, size_of::<TrapLine>(), PAGE_EXECUTE_READWRITE);
        unsafe {
            if result > 0 { Ok(transmute(result)) } else { Err(Error::VirtualAlloc) }
        }
    }

    pub(crate) fn write_left(&self, arg: *const HookBase) {
        let mut iw = InsnWriter::new(self.trap_left.as_ptr());
        unsafe {
            iw.push_usize(arg as usize);
            iw.push_usize(get_hook_handler());
            iw.ret();
        }
    }

    fn left(&self) -> *const u8 { self.trap_left.as_ptr() }
}

pub struct InlineHook {
    pub base: HookBase,
    pub rawbytes: [u8; SIZE_OF_CALL],
    pub trapline: &'static mut TrapLine,
}

impl InlineHook {
    pub fn trap_back(&self) -> usize {
        self.trapline.trap_right.as_ptr() as usize
    }

    pub fn jmp_code_bytes(&self) -> [u8; SIZE_OF_CALL] {
        let left = self.trapline.left() as isize;
        let disp = left - (self.base.address as isize) - SIZE_OF_CALL as isize;
        let mut r = [0xE9u8, 0, 0, 0, 0];
        unsafe {
            *((&mut r[1..]).as_mut_ptr() as *mut i32) = disp as i32;
            return r;
        }
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        unsafe {
            this_process().virtual_free(transmute(self.trapline as *mut TrapLine));
        }
    }
}

impl Hook for InlineHook {
    fn base<'a>(&'a self) -> &'a HookBase { &self.base }

    fn enable(&self) -> bool {
        // let tids = suspend_else_threads();
        let r = this_process().write_memory(self.base.address, &self.jmp_code_bytes()) > 0;
        // tids.iter().for_each(resume_thread);
        return r;
    }

    fn disable(&self) -> bool {
        // let tids = suspend_else_threads();
        let r = this_process().write_memory(self.base.address, &self.rawbytes) > 0;
        // tids.iter().for_each(resume_thread);
        return r;
    }
}

pub struct TableHook {
    pub base: HookBase,
    pub trapline: &'static mut TrapLine,
}

impl Hook for TableHook {
    fn base<'a>(&'a self) -> &'a HookBase { &self.base }

    fn enable(&self) -> bool {
        let trap_left = self.trapline.left() as usize;
        this_process().write_value(self.base.address, &trap_left).is_some()
    }

    fn disable(&self) -> bool {
        this_process().write_value(self.base.address, &self.base.codeback).is_some()
    }
}

pub fn get_code_bytes(address: usize, len: usize) -> Result<Vec<u8>, &'static str> {
    let mut result: Vec<u8> = Vec::with_capacity(MAX_INSN_SIZE);

    let tp = this_process();
    while let Some(insn) = tp.disasm(address + result.len()) {
        result.extend_from_slice(insn.bytes());
        if result.len() >= len { return Ok(result); }
    }
    return Err("disasm");
}

pub trait IntoHookCallback {
    fn into(self) -> HookCallback;
}

impl IntoHookCallback for HookCallbackFn {
    fn into(self) -> HookCallback {
        Box::new(move |args| unsafe { self(args) })
    }
}

impl<T: Fn(&mut HookArgs)> IntoHookCallback for T {
    fn into(self) -> HookCallback {
        unsafe { transmute(Box::new(self) as Box<dyn FnMut(&mut HookArgs)>) }
    }
}

pub fn suspend_else_threads() -> Vec<Handle> {
    let mut result: Vec<Handle> = Vec::new();
    let tid = get_current_tid();
    for t in this_process().enum_thread() {
        if t.tid() != tid {
            result.push(suspend_thread(t.tid()));
        }
    }
    return result;
}

pub struct HookManager {
    map: RwLock<HashMap<usize, Arc<dyn Hook>>>,
}

impl HookManager {
    fn new() -> Self {
        HookManager { map: RwLock::new(HashMap::new()) }
    }

    pub fn instance() -> &'static Self {
        static mut INSTANCE: usize = 0;
        unsafe {
            if 0 == INSTANCE {
                let hm = Box::new(Self::new());
                INSTANCE = transmute(hm.as_ref());
                std::mem::forget(hm);
            }
            transmute(INSTANCE)
        }
    }

    pub fn inline_hook_(&self, address: usize, callback: HookCallback) -> Result<Arc<dyn Hook>, &'static str> {
        if let Some(hook) = self.get_hook(address) {
            *hook.base().callback.lock() = callback;
            return Ok(hook);
        }

        let tp = this_process();
        let trapline = TrapLine::alloc_in_4gb(address).map_err(|_| "alloc memory")?;
        let right_ptr = trapline.trap_right.as_ptr();
        let hook = InlineHook {
            base: HookBase { address, callback: Spinlock::new(callback), codeback: right_ptr as usize },
            trapline, rawbytes: tp.read_value(address).ok_or("read memory")?,
        };

        let origin_code = get_code_bytes(address, SIZE_OF_CALL)?;
        assert!(origin_code.len() >= SIZE_OF_CALL);
        assert!(origin_code.len() <= MAX_INSN_SIZE);

        use iced_x86::{Mnemonic, OpKind};
        let jmpback_address = address + origin_code.len();
        let mut iw = InsnWriter::new(right_ptr);
        let mut offset = 0usize;
        let mut redirected = false;
        // redirect specific instruction, like 'jmp xxx'/'call xxx'
        while let Some(insn) = DisAsmWrapper::new(address + offset, &origin_code[offset..]) {
            offset += insn.len();
            let is_call = insn.mnemonic() == Mnemonic::Call;
            if is_call { iw.push_usize(jmpback_address); }          // push jmpback     ; Ensure the callee can return back
            if is_call || insn.mnemonic() == Mnemonic::Jmp {
                redirected = true;
                // jump to the real address of call/jmp instruction
                match insn.op0_kind() {
                    OpKind::Immediate32to64 => {
                        hook.trapline.jmp_back = insn.immediate32to64() as usize;
                        iw.jmp_mem(&hook.trapline.jmp_back);                    // jmp [target_address]
                    }
                    OpKind::Memory => {
                        // already add the instruction's lenght
                        if cfg!(target_arch = "x86_64") {
                            let disp = insn.memory_displacement32() as i32 as isize;
                            if disp == 0 { return Err("invalid displacement"); }
                            let mem = (insn.address as isize + disp) as usize;
                            iw.push_reg(Register::ZAX);                         // push rax
                            iw.mov_zax_mem(mem);                                // mov rax, [target_address]
                            iw.xchg_zax_stack();                                // xchg rax, [rsp]
                            iw.ret();                                           // ret
                        } else {
                            let mem = insn.memory_displacement32() as usize;
                            iw.jmp_mem(mem as *const u8);                  // jmp [target_address]
                        }
                    }
                    _ => { return Err("invalid operand"); }
                }
                break;
            } else {
                iw.write_bytes(insn.bytes());
            }
        }
        if !redirected {
            hook.trapline.jmp_back = jmpback_address;
            iw.jmp_mem(&hook.trapline.jmp_back);
        }

        let hook = Arc::new(hook);
        hook.trapline.write_left(&hook.base);

        self.map.write().insert(address, hook.clone());
        Ok(hook)
    }

    #[inline]
    pub fn inline_hook(&self, address: usize, callback: impl IntoHookCallback, enable: bool) -> Result<Arc<dyn Hook>, &'static str> {
        self.inline_hook_(address, callback.into()).map(|r| { if enable { r.enable(); } r })
    }

    pub fn table_hook_(&self, address: usize, callback: HookCallback) -> Result<Arc<dyn Hook>, Error> {
        if let Some(hook) = self.get_hook(address) {
            *hook.base().callback.lock() = callback;
            return Ok(hook);
        }

        let tp = this_process();
        let raw_pointer: usize = tp.read_value(address).ok_or(Error::ReadMemory)?;
        let hook = Arc::new(TableHook {
            base: HookBase {address, callback: Spinlock::new(callback), codeback: raw_pointer},
            trapline: TrapLine::alloc_in_4gb(address)?,
        });
        hook.trapline.write_left(&hook.base);

        self.map.write().insert(address, hook.clone());
        Ok(hook)
    }

    #[inline]
    pub fn table_hook(&self, address: usize, callback: impl IntoHookCallback, enable: bool) -> Result<Arc<dyn Hook>, Error> {
        self.table_hook_(address, callback.into()).map(|r| { if enable { r.enable(); } r })
    }

    #[inline]
    pub fn get_hook(&self, address: usize) -> Option<Arc<dyn Hook>> {
        self.map.read().get(&address).map(|r| r.clone())
    }

    pub fn remove_hook(&self, address: usize) -> Option<Arc<dyn Hook>> {
        self.map.write().remove(&address).map(|hook| { hook.disable(); hook })
    }
}

#[cfg(test)]
mod hook_test {
    use super::*;
    use std::println;

    use winapi::um::winuser::*;
    use winapi::um::libloaderapi::*;

    const MAGIC_VALUE: u64 = 1001234;

    #[test]
    fn inline_hook() {
        let m = unsafe { GetProcAddress(LoadLibraryA(b"user32\0".as_ptr() as *const i8), b"MessageBoxA\0".as_ptr() as *const i8) };
        assert!(!m.is_null());

        static mut CHECK_MSG: u64 = 0;
        unsafe extern "C" fn callback(args: &mut HookArgs) {
            *args.regs.reg_mut("_ax").unwrap() = 0x1234;
            args.reject = Some(if cfg!(target_arch = "x86_64") { 0 } else { 4 });
        }
        let hm = HookManager::instance();
        hm.inline_hook(m as usize, callback as HookCallbackFn, true).expect("MessageBoxA");
        unsafe {
            let r = MessageBoxA(std::ptr::null_mut(), b"error\0".as_ptr() as *const i8, b"\0".as_ptr() as *const i8, 0);
            assert_eq!(r, 0x1234);
        }
    }

    #[test]
    fn inline_hook_middle() {
        unsafe {
            let f = GetProcAddress(GetModuleHandleA(b"kernelbase\0".as_ptr() as *const i8), b"CreateFileW\0".as_ptr() as *const i8);
            assert!(!f.is_null());
            let dis = DisAsmWrapper::new(f as usize, core::slice::from_raw_parts(f as *const u8, 16)).unwrap();
            println!("[kernelbase!CreateFileW] {}", dis.to_string());

            let hm = HookManager::instance();
            hm.inline_hook(f as usize + dis.len(), |args: &mut HookArgs| {
                println!("[hook] in the middle");
            }, true);
            std::fs::File::open("C:\\");
            hm.remove_hook(f as usize + dis.len());
        }
    }

    #[test]
    fn inline_hook_jmp() {
        let f = unsafe { GetProcAddress(GetModuleHandleA(b"kernel32\0".as_ptr() as *const i8), b"CreateFileW\0".as_ptr() as *const i8) };
        assert!(!f.is_null());
        unsafe {
            let dis = DisAsmWrapper::new(f as usize, core::slice::from_raw_parts(f as *const u8, 16)).unwrap();
            println!("[CreateFileW] {}", dis.to_string());
        }
        let hm = HookManager::instance();
        hm.inline_hook(f as usize, |args: &mut HookArgs| {
            println!("[hook] CreateFileW");
        }, true).expect("CreateFileW");
        std::fs::File::open("C:\\");
    }

    #[test]
    fn inline_hook_reject() {
        type FnRtlQueryPerformanceCounter = extern "system" fn(&mut u64) -> usize;
        let m = unsafe { GetProcAddress(GetModuleHandleA(b"ntdll\0".as_ptr() as *const i8), b"RtlQueryPerformanceCounter\0".as_ptr() as *const i8) };
        assert!(!m.is_null());
        HookManager::instance().inline_hook(m as usize, |args: &mut HookArgs| unsafe {
            let RtlQueryPerformanceCounter = transmute::<_, FnRtlQueryPerformanceCounter>(args.trampoline());
            let regs = &mut args.regs;
            let arg1 = regs.arg(1);
            *regs.reg_mut("_ax").unwrap() = RtlQueryPerformanceCounter(transmute(arg1));
            *(arg1 as *mut u64) = MAGIC_VALUE;
            args.reject = Some(if size_of::<usize>() == 8 { 0 } else { 1 });
        }, true).expect("RtlQueryPerformanceCounter");

        let mut counter: u64 = 0;
        unsafe {
            let RtlQueryPerformanceCounter: FnRtlQueryPerformanceCounter = transmute(m);
            RtlQueryPerformanceCounter(transmute(&mut counter));
            assert_eq!(MAGIC_VALUE, counter);
        }
    }

    #[test]
    fn table_hook() {
        static mut CHECK_HOOK: u64 = 0;
        unsafe {
            let m = GetProcAddress(LoadLibraryA(b"kernel32\0".as_ptr() as *const i8), b"OutputDebugStringW\0".as_ptr() as *const i8);
            let output_debug_string: extern "win64" fn(LPCWSTR) = transmute(m);
            let address: usize = transmute(&output_debug_string);

            HookManager::instance().table_hook(address, |_arg: &mut HookArgs| {
                println!("TableHook success");
                CHECK_HOOK = MAGIC_VALUE;
            }, true).expect("table hook");

            let s = "OutputDebugString".to_wide();
            output_debug_string(s.as_ptr());
            assert_eq!(MAGIC_VALUE, CHECK_HOOK);
        }
    }
}