
#[macro_use] extern crate derive_more;

use udbg_base::udbg::*;

#[derive(AsRef)]
struct MyDebugger(ShellData);

impl UDbgShell for MyDebugger {
    // fn runtime_config(&self, key: &str) -> Option<serde_value::Value> {
    // }
}

fn main() -> anyhow::Result<()> {
    use win::*;

    set_ui(MyDebugger(ShellData::default()));
    flexi_logger::Logger::try_with_env_or_str("info")?.use_utc().start()?;

    let dbg = DefaultEngine.create(Default::default(), r"C:\Windows\System32\notepad.exe", None, &[]).unwrap();
    dbg.event_loop(&mut |event| {
        println!("[event]~{} {event}", dbg.base().event_tid.get());
        match event {
            UEvent::Exception{..} => UserReply::Run(false),
            _ => UserReply::Run(true),
        }
    })?;

    Ok(())
}