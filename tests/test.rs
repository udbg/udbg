#![feature(assert_matches)]

use log::info;
use std::{cell::Cell, rc::Rc, sync::Arc};
use udbg::{prelude::*, register::regid};

#[cfg(windows)]
const TARGET: &str = "notepad.exe";

#[cfg(unix)]
const TARGET: &str = "cat";

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
                    info!("  {}", target.base().image_path);
                }
                _ => {}
            }
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
    let mut engine = udbg::os::DefaultEngine::default();
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

        let mut file_bp: Option<Arc<dyn UDbgBreakpoint>> = None;
        loop_util(state, |target, event| match event {
            UEvent::Breakpoint(_) => {
                info!("entrypoint bp occured");
                let regs = state.context().register().unwrap();
                assert_eq!(
                    regs.get_reg(regid::COMM_REG_PC).unwrap().as_int(),
                    bp.address() as _
                );

                ds.entry_hitted.set(true);
                file_bp.replace(
                    target
                        .add_breakpoint(
                            target
                                .get_address_by_symbol("kernel32!CreateFileW")
                                .or_else(|| target.get_address_by_symbol("libc!open"))
                                .or_else(|| target.get_address_by_symbol("libc!__open64"))
                                .unwrap()
                                .into(),
                        )
                        .expect("add bp"),
                );
                true
            }
            _ => false,
        })
        .await;

        state.reply(UserReply::StepIn);
        loop_util(state, |target, event| {
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
        loop_util(state, |target, event| match event {
            UEvent::Breakpoint(_) => {
                let regs = state.context().register().unwrap();
                assert_eq!(
                    regs.get_reg(regid::COMM_REG_PC).unwrap().as_int(),
                    file_bp.as_ref().unwrap().address()
                );
                let arg1;
                let argstr;
                #[cfg(windows)]
                {
                    arg1 = regs
                        .get_reg(match std::env::consts::ARCH {
                            "aarch64" => regid::ARM64_REG_X0,
                            "x86_64" => regid::X86_REG_RCX,
                            _ => unreachable!(),
                        })
                        .unwrap()
                        .as_int();
                    let arg1 = target.read_wstring(arg1, None).unwrap_or_default();
                    argstr = arg1.strip_suffix(".txt").unwrap_or(&arg1).to_string();
                }
                #[cfg(unix)]
                {
                    arg1 = regs
                        .get_reg(match std::env::consts::ARCH {
                            "aarch64" => regid::ARM64_REG_X0,
                            "x86_64" => regid::X86_REG_RDI,
                            _ => unreachable!(),
                        })
                        .unwrap()
                        .as_int();
                    argstr = target.read_utf8(arg1, None).unwrap_or_default();
                }
                info!("fopen bp occured: 0x{arg1:x} {argstr}");
                if argstr == arg {
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

        #[cfg(windows)]
        target.kill().expect("kill");

        loop_util(state, |_, _| false).await;
    }))?;
    assert!(st.entry_hitted.get());
    assert!(st.fopen_hitted.get());
    assert!(st.hwbp_hitted.get());

    Ok(())
}

#[test]
fn target() {
    let mut engine = udbg::os::DefaultEngine::default();
    let target = engine.open_self().unwrap();

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

    let tracee = env!("CARGO_BIN_EXE_tracee");
    flexi_logger::Logger::try_with_env_or_str("info")?
        .use_utc()
        .start()?;

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
            UEvent::ThreadCreate(tid) => {
                *ds.thread_count.borrow_mut() += 1;
            }
            UEvent::ProcessCreate => {
                println!("  {}", target.base().image_path);
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
