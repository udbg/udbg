#[macro_use]
extern crate derive_more;

use rustyline::Editor;
use structopt::StructOpt;
use udbg::prelude::*;

#[derive(AsRef)]
struct Debugger(ShellData);

impl UDbgShell for Debugger {}

#[cfg(windows)]
const TARGET: &str = "notepad.exe";

#[cfg(unix)]
const TARGET: &str = "ls";

#[derive(StructOpt)]
#[structopt(name = "debugger", author = "metaworm", about = "debugger demo")]
struct ShellArg {
    #[structopt(default_value = TARGET)]
    target: String,
}

fn main() -> anyhow::Result<()> {
    set_ui(Debugger(ShellData::default()));
    flexi_logger::Logger::try_with_env_or_str("info")?
        .use_utc()
        .start()?;

    let args = ShellArg::from_args();
    let mut engine = udbg::os::DefaultEngine::default();
    engine
        .create(&args.target, None, &[])
        .expect("create target");

    let mut rl = Editor::<()>::new();

    let mut handle_input = || {
        match rl.readline(">> ") {
            Ok(cmd) => {}
            Err(_) => {}
        };
        UserReply::Run(false)
    };

    engine.event_loop(&mut |target, event| {
        println!(
            "[event]~{}:{} {event}",
            target.pid(),
            target.base().event_tid.get()
        );
        match event {
            UEvent::Exception { .. } => handle_input(),
            UEvent::Breakpoint(bp) => handle_input(),
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
