#![feature(format_args_capture)]

use udbg_base::*;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "detect-process", author = "metaworm", about = "detect suspicious footprint in a process")]
struct ShellArg {
    /// process name or pid
    process: String,
}

#[cfg(windows)]
fn main() {
    let args = ShellArg::from_args();
    let p = &args.process;
    let pid = pid_t::from_str_radix(p, 10).ok().unwrap_or_else(
        || enum_process_filter_name(p).next().expect("process not found").pid()
    );

    let mut modules = vec![];

    println!("Suspicious modules");
    for m in enum_module(pid) {
        let path = m.path();
        match wintrust::verify_file(&path) {
            Ok((code, context)) => {
                if code != 0 {
                    println!("- 0x{:x}\t{}\t0x{code:x}", m.base(), path);
                    for ctx in context.iter() {
                        println!("  {}\t{}", ctx.get_signer_name().unwrap_or_default(), ctx.get_name().unwrap_or_default());
                    }
                }
            }
            Err(err) => {
                eprintln!("  {} {:?}", path, err);
            }
        }
        modules.push(m);
    }

    println!("Executale memory NOT in module");
    let p = Process::open(pid, None).check_last().expect("open process");
    modules.sort_by(|a, b| a.base().cmp(&b.base()));

    use udbg_base::range::*;
    for m in p.enum_memory(0) {
        if m.is_executable() {
            if RangeValue::binary_search(&modules, m.base).is_none() {
                println!("- 0x{:x}\t0x{:x}", m.base, m.size);
            }
        }
    }
}