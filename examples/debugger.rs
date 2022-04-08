use rustyline::Editor;
use structopt::StructOpt;
use udbg::prelude::*;

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

    engine.event_loop(&mut |ctx, event| {
        let target = ctx.target();
        println!(
            "[event]~{}:{} {event}",
            target.pid(),
            target.base().event_tid.get()
        );
        match event {
            UEvent::InitBp { .. } => handle_input(),
            UEvent::Exception { .. } => handle_input(),
            UEvent::Breakpoint(bp) => handle_input(),
            _ => UserReply::Run(true),
        }
    })?;

    Ok(())
}
