use super::*;

#[test]
fn memory() {
    let ps = Process::current();
    let m = ps.enum_module().next().unwrap();
    assert!(ps.read_value::<IMAGE_DOS_HEADER>(m.base()).is_some());
    assert!(ps.read_copy::<IMAGE_DOS_HEADER>(m.base() + 8).is_some());
    assert!(ps.read_value::<IMAGE_DOS_HEADER>(m.base() + 8).is_none());
}
