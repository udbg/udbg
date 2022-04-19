use clap::Parser;
use udbg::{prelude::Symbol, shell::UDbgFlags};

#[derive(Parser)]
#[clap(
    name = "demangle",
    author = "metaworm",
    about = "demangle the cpp name"
)]
struct ShellArg {
    name: String,
}

fn main() {
    let args = ShellArg::parse();
    println!(
        "{}",
        Symbol::undecorate(&args.name, UDbgFlags::UNDEC_TYPE | UDbgFlags::UNDEC_RETN)
            .unwrap_or_default()
    );
}
