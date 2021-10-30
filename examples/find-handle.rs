
use udbg_base::*;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "find-handle", author = "metaworm", about = "find handles or dlls")]
struct ShellArg {
    /// Regular expression pattern
    name: String,
}

#[cfg(windows)]
fn main() {
    use std::time::Duration;
    use std::collections::HashMap;

    use udbg_base::{ntdll::*, strutil::*};
    use winapi::um::processthreadsapi::*;
    use winapi::um::handleapi::DuplicateHandle;
    use winapi::um::winnt::*;
    use winapi::shared::minwindef::*;

    pub fn query_object_name_timeout(handle: HANDLE) -> String {
        call_with_timeout(Duration::from_millis(10),
            || query_object_name(handle).ok()
        ).flatten().map(|x| x.to_string()).unwrap_or_default()
    }

    let mut type_cache = HashMap::<u32, String>::new();
    let args = ShellArg::from_args();
    let pattern = regex::Regex::new(&args.name).expect("Regular expression pattern");

    system_handle_information().for_each(|h| {
        let pid = h.pid();
        match Process::open(pid, None) {
            None => {
                // eprintln!("open {}: {:?}", pid, std::io::Error::last_os_error());
            }
            Some(p) => unsafe {
                let mut handle = 0 as HANDLE;

                let r = DuplicateHandle(*p.handle, h.HandleValue as HANDLE, GetCurrentProcess(), &mut handle, 0, FALSE, DUPLICATE_SAME_ACCESS);
                if 0 == r || handle.is_null() { return; }

                let handle = Handle::from_raw_handle(handle);
                let type_name = type_cache.entry(h.ObjectTypeIndex as u32).or_insert_with(||
                    query_object_type(*handle).map(|t| t.TypeName.to_string()).unwrap_or_default()
                );
                let name = if type_name == "Process" {
                    Process { handle }.image_path().unwrap_or_default()
                } else {
                    query_object_name_timeout(*handle)
                };
                if pattern.find(&name).is_some() {
                    let image_path = std::path::PathBuf::from(p.image_path().unwrap_or_default());
                    println!("{}\t{}\t[{}] {}", pid, image_path.file_name().unwrap_or_default().to_string_lossy(), type_name, name);
                }
            }
        }
    });

    for p in enum_process() {
        if let Some(p) = Process::open(p.pid(), None) {
            let image_path = std::path::PathBuf::from(p.image_path().unwrap_or_default());
            p.enum_module().for_each(|m| {
                let path = m.path();
                if pattern.find(&path).is_some() {
                    println!("{}\t{}\t[DLL] {}", p.pid(), image_path.file_name().unwrap_or_default().to_string_lossy(), path);
                }
            })
        }
    }
}