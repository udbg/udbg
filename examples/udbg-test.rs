
use udbg_base::*;

fn main() {
    let p = Process::current();

    let m = p.enum_module().find(|m| m.name().ends_with(".exe")).unwrap();
    println!("{:x}", m.base());
}