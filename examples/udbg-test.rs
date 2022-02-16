
use udbg_base::*;

fn main() {
    let p = this_process();

    let m = p.enum_module().find(|m| m.name().ends_with(".exe")).unwrap();
    println!("{:x}", m.base());
}