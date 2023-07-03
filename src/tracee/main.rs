use std::{time::Duration, *};

fn main() -> anyhow::Result<()> {
    let args = env::args().collect::<Vec<_>>();
    println!("shell args: {args:?}");
    if args.get(1).map(String::as_str) == Some("sleep") {
        thread::sleep(Duration::from_secs_f64(args.get(2).unwrap().parse()?));
        return Ok(());
    }

    println!("[+] new thread");
    thread::spawn(|| {
        println!("  in new thread");
    })
    .join()
    .unwrap();

    println!("[+] new subprocess");
    #[cfg(unix)]
    process::Command::new("ls").spawn().unwrap().wait().unwrap();
    #[cfg(windows)]
    process::Command::new("cmd")
        .args(&["/c", "echo", "in child process"])
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    Ok(())
}
