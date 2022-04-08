#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/61437564?s=200&v=4")]
#![feature(trait_alias)]
#![feature(once_cell)]
#![feature(min_specialization)]
#![feature(stmt_expr_attributes)]
#![feature(const_ptr_offset_from)]
#![feature(associated_type_defaults)]
#![allow(rustdoc::bare_urls)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate derive_more;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate log;
#[macro_use]
extern crate ctor;
#[macro_use]
extern crate cstrptr;

pub mod breakpoint;
pub mod elf;
pub mod error;
pub mod event;
pub mod memory;
pub mod os;
pub mod pdbfile;
pub mod pe;
pub mod prelude;
pub mod range;
pub mod register;
pub mod shell;
pub mod string;
pub mod symbol;
pub mod target;

/// Constants for current environment
pub mod consts {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub const MAX_INSN_SIZE: usize = 16;

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub const MAX_INSN_SIZE: usize = 4;

    pub const ARCH_X86: u32 = 0;
    pub const ARCH_X64: u32 = 1;
    pub const ARCH_ARM: u32 = 2;
    pub const ARCH_ARM64: u32 = 3;

    #[cfg(target_arch = "x86_64")]
    pub const UDBG_ARCH: u32 = ARCH_X64;
    #[cfg(target_arch = "x86")]
    pub const UDBG_ARCH: u32 = ARCH_X86;
    #[cfg(target_arch = "arm")]
    pub const UDBG_ARCH: u32 = ARCH_ARM;
    #[cfg(target_arch = "aarch64")]
    pub const UDBG_ARCH: u32 = ARCH_ARM64;

    pub const IS_ARCH_ARM: bool = cfg!(target_arch = "arm");
    pub const IS_ARCH_ARM64: bool = cfg!(target_arch = "aarch64");
    pub const IS_ARM: bool = IS_ARCH_ARM || IS_ARCH_ARM64;
    pub const IS_ARCH_X86: bool = cfg!(target_arch = "x86");
    pub const IS_ARCH_X64: bool = cfg!(target_arch = "x86_64");
    pub const IS_X86: bool = IS_ARCH_X86 || IS_ARCH_X64;
}

/// Fragmented utilities
pub mod util {
    use memmap::Mmap;

    use alloc::sync::{Arc, Weak};
    use std::io::{BufRead, BufReader, Result as IoResult};
    use std::path::Path;

    /// Fragmented utilities code
    pub struct Utils;

    impl Utils {
        pub fn mapfile(path: &str) -> Option<Mmap> {
            std::fs::File::open(path)
                .and_then(|f| unsafe { Mmap::map(&f) })
                .ok()
        }

        pub fn file_lines<P: AsRef<Path>>(path: P) -> IoResult<impl Iterator<Item = String>> {
            Ok(BufReader::new(std::fs::File::open(path)?)
                .lines()
                .map(|line| line.unwrap_or_default()))
        }

        /// Convert a reference to Weak<T>, please ensure the reference is from Arc<T>
        pub unsafe fn to_weak<T: ?Sized>(t: &T) -> Weak<T> {
            let t = Arc::from_raw(t);
            let result = Arc::downgrade(&t);
            Arc::into_raw(t);
            result
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::prelude::*;
    use std::{cell::Cell, rc::Rc, sync::Arc};

    #[cfg(windows)]
    const TARGET: &str = "notepad.exe";

    #[cfg(unix)]
    const TARGET: &str = "cat";

    async fn loop_util(
        state: &UEventState,
        exit: impl Fn(&Arc<dyn UDbgAdaptor>, &UEvent) -> bool,
    ) -> Arc<dyn UDbgAdaptor> {
        state
            .loop_util(|target, event| {
                println!(
                    "[event]~{}:{} {event}",
                    target.pid(),
                    target.base().event_tid.get()
                );
                exit(target, event)
            })
            .await
    }

    #[test]
    fn debug() -> anyhow::Result<()> {
        flexi_logger::Logger::try_with_env_or_str("info")?
            .use_utc()
            .start()?;

        let arg = "!!!---";
        let mut engine = crate::os::DefaultEngine::default();
        engine.create(TARGET, None, &[arg]).expect("create target");

        #[derive(Default)]
        struct State {
            entry_hitted: Cell<bool>,
            fopen_hitted: Cell<bool>,
            hwbp_hitted: Cell<bool>,
        }
        let st = Rc::new(State::default());
        let ds = st.clone();
        engine.task_loop(DebugTask::from(|state: UEventState| async move {
            let state = &state;
            let target = loop_util(state, |_, e| matches!(e, UEvent::InitBp)).await;
            info!("target path: {}", target.base().image_path);

            info!("initbp occured");
            let main = target.get_main_module().unwrap();
            info!(
                "main module: {} entry: {:x}",
                main.data().path,
                main.data().entry_point()
            );
            target.addbp(main.data().entry_point()).expect("add bp");
            info!("breakpoint added");

            loop_util(state, |target, event| match event {
                UEvent::Breakpoint(bp) => {
                    let regs = state.context().register().unwrap();
                    assert_eq!(regs.get("_pc").unwrap().as_int(), bp.address() as _);
                    info!("entrypoint bp occured");
                    bp.remove().unwrap();
                    ds.entry_hitted.set(true);

                    target
                        .add_bp(
                            target
                                .get_address_by_symbol("kernel32!CreateFileW")
                                .or_else(|| target.get_address_by_symbol("libc!open"))
                                .or_else(|| target.get_address_by_symbol("libc!__open64"))
                                .unwrap()
                                .into(),
                        )
                        .expect("add bp");
                    true
                }
                _ => false,
            })
            .await;

            loop_util(state, |target, event| match event {
                UEvent::Breakpoint(bp) => {
                    let regs = state.context().register().unwrap();
                    assert_eq!(regs.get("_pc").unwrap().as_int(), bp.address());
                    info!("CreateFile/open bp occured");
                    ds.fopen_hitted.set(true);
                    let arg1;
                    #[cfg(windows)]
                    {
                        arg1 = regs.get("rcx").unwrap().as_int();
                        let arg1 = target.read_wstring(arg1, None).unwrap_or_default();
                        let arg1 = arg1.strip_suffix(".txt").unwrap_or(&arg1);
                        assert_eq!(arg1, arg);
                    }
                    #[cfg(unix)]
                    {
                        arg1 = regs.get("rdi").unwrap().as_int();
                        assert_eq!(target.read_utf8(arg1, None).unwrap_or_default(), arg);
                    }
                    target
                        .add_bp((arg1, HwbpType::Access).into())
                        .expect("add hwbp");
                    bp.remove().unwrap();
                    true
                }
                _ => false,
            })
            .await;

            loop_util(state, |_, event| match event {
                UEvent::Breakpoint(bp) => {
                    assert!(bp.get_type().is_hard());
                    ds.hwbp_hitted.set(true);
                    info!("HWBP occured");
                    bp.remove().unwrap();
                    true
                }
                _ => false,
            })
            .await;

            target.kill().expect("kill");

            loop_util(state, |_, _| false).await;
        }))?;
        assert!(st.entry_hitted.get());
        assert!(st.fopen_hitted.get());
        assert!(st.hwbp_hitted.get());

        Ok(())
    }
}
