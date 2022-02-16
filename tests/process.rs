
#[cfg(target_os = "linux")]
#[test]
fn process() {
    use udbg_base::*;

    // let pid = enum_pid().filter(|&pid| process_name(pid) == Some("bash".into())).next().unwrap();
    let p = Process::from_comm("bash").unwrap();
    let m = p.enum_module().unwrap().next().unwrap();

    assert_eq!(p.read_value::<[u8; 4]>(m.base), Some(ELF_SIG));
}