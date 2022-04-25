use super::*;

#[test]
fn process() {
    for pid in Process::enum_pid().unwrap() {
        let ps = match Process::from_pid(pid) {
            Ok(r) => r,
            Err(_) => continue,
        };

        println!(
            "{pid} {:?} {:?}",
            Process::pid_name(pid),
            Process::pid_path(pid),
            // process_cmdline(pid)
        );

        // for i in ps.list_module() {
        //     println!("  {:x} 0x{:x} {:?}", i.base, i.size, i.path);
        // }

        println!("Handles:");
        for h in Process::pid_fds(pid).unwrap() {
            println!("  {h:x?}");
        }
    }
}

#[test]
fn udbg() {
    let a = StandardAdaptor::open(std::process::id() as _).unwrap();
    for m in a.enum_module().unwrap() {
        // println!("{}", m.data().path);
    }

    for p in a.collect_memory_info() {
        println!("{}", p.usage);
    }
}
