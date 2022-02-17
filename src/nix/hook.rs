
use crate::win::*;
use crate::csutil::*;

use std::mem::{transmute, size_of};
use std::slice;
use std::sync::Arc;
use std::sync::RwLock;
use std::collections::HashMap;

use spinlock::*;

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

#[cfg(target_arch = "aarch64")]
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

impl HookContext {
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
fn create_hook_handler() ->  ExecutableBuffer {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; push rsp      // +80
        ; push rax      // +78
        ; push rcx      // +70
        ; push rdx      // +68
        ; push rbx      // +60
        ; push rbp      // +58
        ; push rsi      // +50
        ; push rdi      // +48
        ; push r8       // +40
        ; push r9       // +38
        ; push r10      // +30
        ; push r11      // +28
        ; push r12      // +20
        ; push r13      // +18
        ; push r14      // +10
        ; push r15      // +8
        ; pushfq        // +0
        ; add [rsp+0x80], 8
        ; mov rcx, [rsp+0x88]
        ; mov rdx, rsp
        ; sub rsp, 0x18
        ; mov rax, QWORD hook_handler as _
        ; call rax
        ; add rsp, 0x18
        ; popfq
        ; pop r15
        ; pop r14
        ; pop r13
        ; pop r12
        ; pop r11
        ; pop r10
        ; pop r9
        ; pop r8
        ; pop rdi
        ; pop rsi
        ; pop rbp
        ; pop rbx
        ; pop rdx
        ; pop rcx
        ; pop rax
        ; pop rsp
        ; ret
    );

    ops.finalize().unwrap()
}

#[cfg(target_arch = "x86")]
fn create_hook_handler() ->  ExecutableBuffer {
    let mut ops = dynasmrt::x86::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x86
        ; push esp      // +20
        ; push ebp      // +1c
        ; push eax      // +18
        ; push ecx      // +14
        ; push edx      // +10
        ; push ebx      // +c
        ; push esi      // +8
        ; push edi      // +4
        ; pushf         // +0
        ; add [esp+0x20], 4
        ; mov ebp, esp
        ; push ebp
        ; push DWORD [ebp+0x24]
        ; mov eax, DWORD hook_handler as _
        ; call eax
        ; popf
        ; pop edi
        ; pop esi
        ; pop ebx
        ; pop edx
        ; pop ecx
        ; pop eax
        ; pop ebp
        ; pop esp
        ; ret
    );

    ops.finalize().unwrap()
}

// generate the handler function dynamiclly
unsafe fn get_hook_handler() -> usize {
    static mut CODEBUF: Option<ExecutableBuffer> = None;

    CODEBUF.get_or_insert_with(create_hook_handler).ptr(dynasmrt::AssemblyOffset(0usize)) as usize
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
    pub codeback: usize,
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
    Process::current().virtual_alloc(address, size, MEM_RESERVE | MEM_COMMIT, protect)
}

#[cfg(target_arch = "x86_64")]
fn alloc_mem_in_4gb(address: usize, size: usize) -> Result<usize, Error> {
    const LOW_2GB: usize = 0x7FFFFFFF;
    // let begin_address = if address > LOW_2GB { address - LOW_2GB } else { 0x10000 };
    let begin_address = address;
    for m in Process::current().enum_memory(begin_address) {
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
            Process::current().virtual_free(transmute(self.trapline as *mut TrapLine));
        }
    }
}

impl Hook for InlineHook {
    fn base<'a>(&'a self) -> &'a HookBase { &self.base }

    fn enable(&self) -> bool {
        // let tids = suspend_else_threads();
        let r = Process::current().write_memory(self.base.address, &self.jmp_code_bytes()) > 0;
        // tids.iter().for_each(resume_thread);
        return r;
    }

    fn disable(&self) -> bool {
        // let tids = suspend_else_threads();
        let r = Process::current().write_memory(self.base.address, &self.rawbytes) > 0;
        // tids.iter().for_each(resume_thread);
        return r;
    }
}

pub fn get_code_bytes(address: usize, len: usize) -> Result<Vec<u8>, Error> {
    let mut result: Vec<u8> = Vec::with_capacity(MAX_INSN_SIZE);

    let tp = Process::current();
    let cs = create_cs();
    while !(result.len() >= len) {
        let mut data = vec![0u8; MAX_INSN_SIZE];
        if let Some(data) = tp.read_memory(address + result.len(), &mut data) {
            if let Err(_) = cs.disasm_count(&data, (address + result.len()) as u64, 5).map(|insns| {
                for insn in insns.iter() {
                    result.extend_from_slice(insn.bytes());
                    if result.len() >= len { break; }
                }
            }) { return Err(Error::DisAsm); }
        } else { return Err(Error::ReadMemory); }
    }
    Ok(result)
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

    pub fn inline_hook_(&self, address: usize, callback: HookCallback, enable: bool) -> Result<Arc<dyn Hook>, Error> {
        if let Some(hook) = self.get_hook(address) {
            *hook.base().callback.lock() = callback;
            return Ok(hook);
        }

        let tp = Process::current();
        let trapline = TrapLine::alloc_in_4gb(address)?;
        let right_ptr = trapline.trap_right.as_ptr();
        let hook = InlineHook {
            base: HookBase { address, callback: Spinlock::new(callback), codeback: right_ptr as usize },
            trapline, rawbytes: tp.read_value(address).ok_or(Error::ReadMemory)?,
        };

        let origin_code = get_code_bytes(address, SIZE_OF_CALL)?;
        assert!(origin_code.len() >= SIZE_OF_CALL);
        assert!(origin_code.len() <= MAX_INSN_SIZE);

        let jmpback_address = address + origin_code.len();
        let mut iw = InsnWriter::new(right_ptr);

        let cs = create_cs();
        if let Ok(insns) = cs.disasm_count(&origin_code, address as u64, 5) {
            let mut transformed = false;
            for insn in insns.iter() {
                let is_call = insn.mnemonic() == Some("call");
                if is_call || insn.mnemonic() == Some("jmp") {
                    transformed = true;
                    match cs.get_absolute_address(&insn, 0) {
                        SimpleOperand::Imm(target_address) => {
                            if is_call { iw.push_usize(jmpback_address); }          // push jmpback     ; Ensure the callee can return back
                            hook.trapline.jmp_back = target_address;
                            iw.jmp_mem(&hook.trapline.jmp_back);                    // jmp [target_address]
                        }
                        SimpleOperand::Mem(target_address) => {
                            if is_call { iw.push_usize(jmpback_address); }          // push jmpback     ; Ensure the callee can return back
                            if cfg!(target_arch = "x86_64") {
                                iw.push_reg(Register::ZAX);                         // push rax
                                iw.mov_zax_mem(target_address);                     // mov rax, [target_address]
                                iw.xchg_zax_stack();                                // xchg rax, [rsp]
                                iw.ret();                                           // ret
                            } else {
                                iw.jmp_mem(target_address as *const u8);            // jmp [target_address]
                            }
                        }
                        _ => { return Err(Error::Reason("Invalid Operand")); }
                    }
                    break;
                } else { iw.write_bytes(insn.bytes()); }
            }
            if !transformed {
                hook.trapline.jmp_back = address + origin_code.len();
                iw.jmp_mem(&hook.trapline.jmp_back);
            }
        } else { return Err(Error::DisAsm); }

        let hook = Arc::new(hook);
        hook.trapline.write_left(&hook.base);

        self.map.write().unwrap().insert(address, hook.clone());
        if enable { hook.enable(); }
        Ok(hook)
    }

    #[inline]
    pub fn inline_hook(&self, address: usize, callback: impl IntoHookCallback, enable: bool) -> Result<Arc<dyn Hook>, Error> {
        self.inline_hook_(address, callback.into(), enable)
    }

    #[inline]
    pub fn get_hook(&self, address: usize) -> Option<Arc<dyn Hook>> {
        self.map.read().unwrap().get(&address).map(|r| r.clone())
    }

    pub fn remove_hook(&self, address: usize) -> Option<Arc<dyn Hook>> {
        self.map.write().unwrap().remove(&address).map(|hook| { hook.disable(); hook })
    }
}