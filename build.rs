#![cfg(target_os = "macos")]

use std::{env, path::Path, process::Command};

fn main() {
    let defs = Path::new("src/os/macos/exc.defs").canonicalize().unwrap();
    let out = env::var("OUT_DIR").unwrap();
    let outdir = Path::new(&out);

    env::set_current_dir(outdir).expect("chdir");
    if !outdir.join("mach_exc.h").exists() {
        Command::new("mig")
            .arg(defs)
            .spawn()
            .expect("exec mig")
            .wait()
            .unwrap();
    }
    let mut build = cc::Build::new();
    build
        .file("mach_excServer.c")
        .file("mach_excUser.c")
        .compile("exc");
}
