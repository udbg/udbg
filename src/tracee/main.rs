use std::*;

fn main() -> anyhow::Result<()> {
    println!("[+] new thread");
    thread::spawn(|| {
        println!("  in new thread");
    })
    .join()
    .unwrap();

    println!("[+] new subprocess");
    #[cfg(unix)]
    process::Command::new("ls").spawn().unwrap();
    #[cfg(windows)]
    process::Command::new("cmd")
        .args(&["/c", "echo", "in child process"])
        .spawn()
        .unwrap();

    Ok(())
}
