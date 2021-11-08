
use core::mem::*;
use udbg_base::{*, hook::*, disasm::*};

use winapi::um::winuser::*;
use winapi::um::libloaderapi::*;
use winapi::um::winnt::LPCWSTR;

const MAGIC_VALUE: u64 = 1001234;

#[test]
fn inline_hook() {
    let m = unsafe { GetProcAddress(LoadLibraryA(b"user32\0".as_ptr().cast()), b"MessageBoxA\0".as_ptr().cast()) };
    assert!(!m.is_null());

    static mut CHECK_MSG: u64 = 0;

    let hm = HookManager::instance();
    hm.inline_hook(m as usize, |args: &mut HookArgs| {
        *args.regs.reg_mut("_ax").unwrap() = 0x1234;
        args.reject = Some(if cfg!(target_arch = "x86_64") { 0 } else { 4 });
    }, true).expect("MessageBoxA");
    unsafe {
        let r = MessageBoxA(std::ptr::null_mut(), b"error\0".as_ptr().cast(), b"\0".as_ptr().cast(), 0);
        assert_eq!(r, 0x1234);
    }
}

#[test]
fn inline_hook_middle() {
    unsafe {
        let f = GetProcAddress(GetModuleHandleA(b"kernelbase\0".as_ptr().cast()), b"CreateFileW\0".as_ptr().cast());
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
    static mut CHECK_HOOK: u64 = 0;
    let f = unsafe { GetProcAddress(GetModuleHandleA(b"kernel32\0".as_ptr().cast()), b"CreateFileW\0".as_ptr() as *const i8) };
    assert!(!f.is_null());
    unsafe {
        let dis = DisAsmWrapper::new(f as usize, core::slice::from_raw_parts(f as *const u8, 16)).unwrap();
        println!("[CreateFileW] {}", dis.to_string());
        let hm = HookManager::instance();
        hm.inline_hook(f as usize, |args: &mut HookArgs| {
            println!("[hook] CreateFileW");
            CHECK_HOOK = MAGIC_VALUE;
        }, true).expect("CreateFileW");
        std::fs::File::open("C:\\");
        assert_eq!(MAGIC_VALUE, CHECK_HOOK);
    }
}

#[test]
fn inline_hook_reject() {
    type FnRtlQueryPerformanceCounter = extern "system" fn(&mut u64) -> usize;
    let m = unsafe { GetProcAddress(GetModuleHandleA(b"ntdll\0".as_ptr().cast()), b"RtlQueryPerformanceCounter\0".as_ptr().cast()) };
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
        let m = GetProcAddress(LoadLibraryA(b"kernel32\0".as_ptr().cast()), b"OutputDebugStringW\0".as_ptr().cast());
        let output_debug_string: extern "system" fn(LPCWSTR) = transmute(m);
        let address: usize = transmute(&output_debug_string);

        HookManager::instance().table_hook(address, |arg: &mut HookArgs| {
            println!("TableHook success");
            CHECK_HOOK = MAGIC_VALUE;
        }, true).expect("table hook");

        let s = "OutputDebugString".to_wide();
        output_debug_string(s.as_ptr());
        assert_eq!(MAGIC_VALUE, CHECK_HOOK);
    }
}

#[test]
fn instrumentation_hook() {
    static mut R10: usize = 0;
    static mut RAX: usize = 0;
    instrumentation_callback(|args| unsafe {
        R10 = args.R10;
        RAX = args.Rax;
    }).unwrap();
    std::fs::File::open("C:\\");
    remove_instrumentation_callback().unwrap();

    unsafe {
        println!("r10: {:x}, rax: {:x}", R10, RAX);
        assert!(R10 > 0);
    }
}