use structopt::StructOpt;
use udbg::util::*;

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
        undecorate_symbol(&args.name, UFlags::UNDEC_TYPE | UFlags::UNDEC_RETN).unwrap_or_default()
    );
}
