#[macro_use]
extern crate derive_more;

use udbg::prelude::*;

#[derive(AsRef)]
struct Debugger(ShellData);

impl UDbgShell for Debugger {}

fn main() -> anyhow::Result<()> {
    set_ui(Debugger(ShellData::default()));
    flexi_logger::Logger::try_with_env_or_str("info")?
        .use_utc()
        .start()?;

    let mut engine = udbg::os::DefaultEngine::new();
    engine.create(r"notepad.exe", None, &[]).unwrap();
    engine.event_loop(&mut |target, event| {
        println!("[event]~{} {event}", target.base().event_tid.get());
        match event {
            UEvent::Exception { .. } => UserReply::Run(false),
            _ => UserReply::Run(true),
        }
    })?;
    // dbg.loop_event(|dbg, state| async move {
    //     while let Some(event) = state.cont(UserReply::Run(false)).await {
    //         println!("[event]~{} {event}", dbg.base().event_tid.get());
    //     }
    // });

    Ok(())
}
