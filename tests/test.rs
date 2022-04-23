#![feature(assert_matches)]

use log::info;
use std::{cell::Cell, path::Path, rc::Rc, sync::Arc};
use udbg::{
    prelude::*,
    register::{regid, CallingConv},
};

fn set_logger() {
    use std::sync::Once;
    static ONCE: Once = Once::new();

    ONCE.call_once(|| {
        flexi_logger::Logger::try_with_env_or_str("info")
            .expect("flexi_logger")
            .use_utc()
            .start()
            .expect("flexi_logger");
    });
}

async fn loop_util<'a>(
    state: &UEventState,
    mut exit: impl FnMut(&Arc<dyn UDbgTarget>, &UEvent) -> bool + 'a,
) -> Arc<dyn UDbgTarget> {
    state
        .loop_util(|target, event| {
            info!(
                "[event]~{}:{} {event}",
                target.pid(),
                target.base().event_tid.get()
            );
            let pc = state
                .context()
                .register()
                .unwrap()
                .get("_pc")
                .unwrap()
                .as_int();
            info!("  PC: {pc:x} {:?}", target.get_symbol_string(pc));
            match event {
                // UEvent::Exception { .. } | UEvent::Step | UEvent::Breakpoint(_) => {
                // }
                UEvent::ProcessCreate => {
                    info!("  {:?}", target.image_path());
                }
                _ => {}
            }
            exit(target, event)
        })
        .await
}

const ARG: &str = "!!!---";

fn test_debug(path: &str, args: &[&str]) -> anyhow::Result<()> {
    let mut engine = udbg::os::DefaultEngine::default();
    engine.create(path, None, args).expect("create target");

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
        let mut target = loop_util(state, |_, e| matches!(e, UEvent::InitBp)).await;
        info!("target path: {:?}", target.image_path());

        info!("initbp occured");
        let main = target.get_main_module().unwrap();
        info!(
            "main module: {} entry: {:x} +{:x}",
            main.data().path,
            main.data().entry_point(),
            main.data().entry,
        );
        let bp = target.add_bp(main.data().entry_point()).expect("add bp");
        assert_eq!(
            &target
                .read_value::<BpInsn>(main.data().entry_point())
                .unwrap(),
            BP_INSN
        );
        info!("breakpoint added");
        core::mem::drop(main);

        let mut file_bp: Option<Arc<dyn UDbgBreakpoint>> = None;
        target = loop_util(state, |target, event| match event {
            UEvent::Breakpoint(_) => {
                info!("entrypoint bp occured");
                let regs = state.context().register().unwrap();
                assert_eq!(
                    regs.get_reg(regid::COMM_REG_PC).unwrap().as_int(),
                    bp.address() as _
                );

                ds.entry_hitted.set(true);
                #[cfg(windows)]
                let a = target
                    .get_address_by_symbol("kernelbase!CreateFileW")
                    .or_else(|| target.get_address_by_symbol("kernel32!CreateFileW"));
                #[cfg(unix)]
                let a = target
                    .get_address_by_symbol("libc!open")
                    .or_else(|| target.get_address_by_symbol("libc!__open64"));
                file_bp.replace(target.add_breakpoint(a.unwrap().into()).expect("add bp"));
                true
            }
            _ => false,
        })
        .await;

        state.reply(UserReply::StepIn);
        target = loop_util(state, |target, event| {
            std::assert_matches::assert_matches!(event, UEvent::Step);
            let pc = state
                .context()
                .register()
                .unwrap()
                .get_reg(regid::COMM_REG_PC)
                .unwrap()
                .as_int();
            assert_ne!(pc, bp.address());
            true
        })
        .await;

        state.reply(UserReply::Run(true));
        target = loop_util(state, |target, event| match event {
            UEvent::Breakpoint(_) => {
                let regs = state.context().register().unwrap();
                assert_eq!(
                    regs.get_reg(regid::COMM_REG_PC).unwrap().as_int(),
                    file_bp.as_ref().unwrap().address()
                );
                let cc = if state.context().arch() == ARCH_X86 {
                    Some(CallingConv::StdCall)
                } else {
                    None
                };
                let arg1 = target.read_argument(regs, 1, cc).unwrap();
                let argstr;
                #[cfg(windows)]
                {
                    let arg1 = target.read_wstring(arg1, None).unwrap_or_default();
                    argstr = arg1.strip_suffix(".txt").unwrap_or(&arg1).to_string();
                }
                #[cfg(unix)]
                {
                    argstr = target.read_utf8(arg1, None).unwrap_or_default();
                }
                info!("fopen bp occured: 0x{arg1:x} {argstr}");
                if argstr == ARG {
                    ds.fopen_hitted.set(true);
                    let hwbp = target
                        .add_breakpoint((arg1, HwbpType::Access).into())
                        .expect("add hwbp");
                    bp.remove().unwrap();
                    true
                } else {
                    false
                }
            }
            _ => false,
        })
        .await;

        target = loop_util(state, |_, event| match event {
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

        // #[cfg(windows)]
        // target.kill().expect("kill");

        loop_util(state, |_, _| false).await;
    }))?;
    assert!(st.entry_hitted.get());
    assert!(st.fopen_hitted.get());
    assert!(st.hwbp_hitted.get());

    Ok(())
}

#[test]
fn debug() -> anyhow::Result<()> {
    set_logger();

    #[cfg(windows)]
    test_debug(r"C:\Windows\System32\cmd.exe", &["/c", "type", ARG])?;
    #[cfg(unix)]
    test_debug("cat", &[ARG])?;

    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn debug_wow64() -> anyhow::Result<()> {
    set_logger();

    test_debug(r"C:\Windows\SysWOW64\cmd.exe", &["/c", "type", ARG])
}

#[test]
fn target() {
    use llua::*;
    use udbg::lua::*;

    let mut engine = udbg::os::DefaultEngine::default();
    let target = engine.open_self().unwrap();

    let lua = &State::new();
    lua.open_libs();
    lua.global().set("target", ArcTarget(target.clone()));
    lua.do_string("print(target.base, target:image_path())")
        .chk_err(lua);

    println!("Modules:");
    for m in target.enum_module().unwrap() {
        println!("  {:x?}", m.data());
    }

    println!("Memory:");
    for m in target.collect_memory_info() {
        println!("  {:x?}", m);
    }

    println!("Threads:");
    for th in target.enum_thread(true).unwrap() {
        println!("  {:?}", th);
    }

    println!("Handles:");
    for h in target.enum_handle().unwrap() {
        println!("  {h:x?}");
    }
}

#[test]
fn tracee() -> anyhow::Result<()> {
    use std::cell::RefCell;

    let mut tracee = env!("CARGO_BIN_EXE_tracee");
    if !Path::new(tracee).exists() {
        tracee = "./tracee";
        assert!(Path::new(tracee).exists());
    }
    set_logger();

    let mut engine = udbg::os::DefaultEngine::default();
    engine.create(tracee, None, &[]).expect("create target");

    #[derive(Default)]
    struct State {
        thread_count: RefCell<usize>,
        child_count: RefCell<usize>,
    }
    let st = Rc::new(State::default());
    let ds = st.clone();
    engine.event_loop(&mut |ctx, event| {
        let target = ctx.target();
        info!(
            "[event]~{}:{} {event}",
            target.pid(),
            target.base().event_tid.get()
        );
        match event {
            UEvent::InitBp => {
                udbg_ui().base().trace_child.set(true);
            }
            UEvent::ThreadCreate(_) => {
                *ds.thread_count.borrow_mut() += 1;
            }
            UEvent::ProcessCreate => {
                info!("  {:?}", target.image_path());
                *ds.child_count.borrow_mut() += 1;
            }
            // UEvent::ProcessExit(code) => assert_eq!(code, 0),
            UEvent::Exception { .. } => {
                let pc = ctx.register().unwrap().get("_pc").unwrap().as_int();
                info!("  PC: {pc:x} {:?}", target.get_symbol_string(pc));
            }
            _ => {}
        };
        UserReply::Run(false)
    })?;
    assert!(*st.thread_count.borrow() > 1);
    assert!(*st.child_count.borrow() > 1);

    Ok(())
}
