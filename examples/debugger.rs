use clap::Parser;
use rustyline::Editor;
use udbg::prelude::*;

#[cfg(windows)]
const TARGET: &str = "notepad.exe";

#[cfg(unix)]
const TARGET: &str = "ls";

#[derive(Parser)]
#[clap(name = "debugger", author = "metaworm", about = "debugger demo")]
struct ShellArg {
    #[clap(default_value = TARGET)]
    target: String,
    #[clap(short, long)]
    attach: Option<pid_t>,
}

fn main() -> anyhow::Result<()> {
    flexi_logger::Logger::try_with_env_or_str("info")?
        .use_utc()
        .start()?;

    let args = ShellArg::parse();
    let mut engine = udbg::os::DefaultEngine::default();

    if let Some(pid) = args.attach {
        engine.attach(pid)
    } else {
        engine.create(&args.target, None, &[])
    }
    .expect("create/attach target");

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
