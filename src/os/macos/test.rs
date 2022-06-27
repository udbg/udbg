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

fn set_logger() {
    use std::sync::Once;
    static ONCE: Once = Once::new();

    ONCE.call_once(|| {
        flexi_logger::Logger::try_with_env_or_str("info")
            .expect("flexi_logger")
            .use_utc()
            .start()
            .expect("flexi_logger");
    });
}

#[test]
fn udbg() {
    set_logger();
    let a = ProcessTarget::open(std::process::id() as _).unwrap();

    for m in a.enum_module().unwrap() {
        let data = m.data();
        println!("{data:x?}");
        // let bytes = a.read_bytes(data.base, 80);
        // println!("  {bytes:x?}");
    }

    let mods = a.enum_module().unwrap().collect::<Vec<_>>();
    let mods2 = a.enum_module().unwrap().collect::<Vec<_>>();
    assert_eq!(mods.len(), mods2.len());

    for p in a.collect_memory_info() {
        println!("{:x?}", p);
    }
}
