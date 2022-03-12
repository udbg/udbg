use udbg::*;

#[cfg(target_os = "linux")]
#[test]
fn process() {
    // let pid = enum_pid().filter(|&pid| process_name(pid) == Some("bash".into())).next().unwrap();
    let p = Process::from_comm("bash").unwrap();
    let m = p.enum_module().unwrap().next().unwrap();

    assert_eq!(p.read_value::<[u8; 4]>(m.base), Some(ELF_SIG));
}

#[test]
fn mac() {
    for pid in enum_pid() {
        let ps = match Process::from_pid(pid) {
            Ok(r) => r,
            Err(_) => continue,
        };

        println!(
            "{pid} {:?} {:?}",
            process_name(pid),
            process_path(pid),
            // process_cmdline(pid)
        );

        for i in ps.list_module() {
            println!("{:x} {:?}", i.base, i.path);
        }

        // process_fds(pid);
    }
}
