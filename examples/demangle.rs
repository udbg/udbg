use structopt::StructOpt;
use udbg::{prelude::Symbol, shell::UDbgFlags};

#[derive(StructOpt)]
#[structopt(
    name = "demangle",
    author = "metaworm",
    about = "demangle the cpp name"
)]
struct ShellArg {
    name: String,
}

fn main() {
    let args = ShellArg::from_args();
    println!(
        "{}",
        Symbol::undecorate(&args.name, UDbgFlags::UNDEC_TYPE | UDbgFlags::UNDEC_RETN)
            .unwrap_or_default()
    );
}
