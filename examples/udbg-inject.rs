
use udbg_base::*;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "udbg-inject", author = "metaworm", about = "inject a dynamic library to another process")]
struct ShellArg {
    /// process name or pid
    process: String,
    /// path of dynamic library
    libpath: String,
    /// the export name of window hook handler in dynamic library
    #[structopt(short, long)]
    window: Option<String>,
}

#[cfg(windows)]
fn main() {
    let args = ShellArg::from_args();
    let pid = if let Ok(pid) = pid_t::from_str_radix(&args.process, 10) {
        pid
    } else {
        enum_process_filter_name(&args.process).next().expect("process not found").pid()
    };
    if let Some(n) = args.window {
        let hwnd = get_window(pid).unwrap();
        inject::by_windowhook(hwnd, &args.libpath, &n).unwrap();
        return;
    } else {
        let p = Process::open(pid, None).unwrap();
        inject::by_remotethread(&p, &args.libpath).unwrap();
    }
}