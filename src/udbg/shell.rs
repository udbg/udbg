
use super::*;

use log::*;
use std::path::PathBuf;
use serde::de::DeserializeOwned;

pub struct ShellData {
    pub symcache: Option<PathBuf>,
}

impl Default for ShellData {
    fn default() -> Self {
        #[cfg(windows)]
        let symcache = {
            let var = std::env::var("_NT_SYMBOL_PATH").ok();
            var.and_then(|s| s.split('*').nth(1).map(PathBuf::from)).filter(|p| p.is_dir())
        };
        #[cfg(not(windows))]
        let symcache = None;
        Self {
            symcache,
        }
    }
}

pub trait UDbgShell: AsRef<ShellData> {
    fn base(&self) -> &ShellData { self.as_ref() }

    fn register_engine(&self, name: &str, engine: Box<dyn UDbgEngine>) {}

    fn update_arch(&self, arch: u32) {}

    fn log_level(&self, level: log::Level, msg: &str) {
        match level {
            Level::Debug => debug!("[udbg] {msg}"),
            Level::Info => info!("[udbg] {msg}"),
            Level::Warn => warn!("[udbg] {msg}"),
            Level::Error => error!("[udbg] {msg}"),
            Level::Trace => trace!("[udbg] {msg}"),
        }
    }

    // #[cfg(windows)]
    // fn new_symgr(&self) -> Arc<dyn UDbgSymMgr>;
    // fn get_util(&self) -> &'static dyn UDbgUtil;

    fn runtime_config(&self, key: &str) -> Option<serde_value::Value> { None }
}

pub trait ShellUtil: UDbgShell {
    #[inline(always)]
    fn debug(&self, data: impl AsRef<str>) { self.log_level(Level::Debug, data.as_ref()); }
    #[inline(always)]
    fn warn(&self, err: impl AsRef<str>) { self.log_level(Level::Warn, err.as_ref()); }
    #[inline(always)]
    fn error(&self, err: impl AsRef<str>) { self.log_level(Level::Error, err.as_ref()); }
    #[inline(always)]
    fn info(&self, msg: impl AsRef<str>) { self.log_level(Level::Info, msg.as_ref()); }

    #[inline(always)]
    fn get_config<D: DeserializeOwned>(&self, key: &str) -> Option<D> {
        self.runtime_config(key).and_then(|r| r.deserialize_into().ok())
    }
}
impl<T: UDbgShell + ?Sized> ShellUtil for T {}

pub trait UDbgUtil {
    #[cfg(windows)]
    fn enum_process_handle<'a>(&self, pid: pid_t, p: HANDLE) -> UDbgResult<Box<dyn Iterator<Item = UiHandle> + 'a>>;
    #[cfg(not(windows))]
    fn enum_process_handle<'a>(&self, pid: pid_t) -> UDbgResult<Box<dyn Iterator<Item = UiHandle> + 'a>> {
        Err(UDbgError::NotSupport)
    }
    #[cfg(windows)]
    fn get_memory_map(&self, p: &Process, this: &dyn UDbgAdaptor) -> Vec<UiMemory>;
    #[cfg(windows)]
    fn open_all_thread(&self, p: &Process, pid: pid_t) -> Vec<(tid_t, Box<dyn UDbgThread>)>;
}

pub static mut UDBG_UI: Option<Arc<dyn UDbgShell>> = None;

#[no_mangle]
pub fn plugin_load(ui: &Arc<dyn UDbgShell>) -> bool {
    unsafe {
        let loaded = UDBG_UI.is_some();
        UDBG_UI.get_or_insert_with(|| ui.clone());
        loaded
    }
}

pub fn set_ui(ui: impl UDbgShell + 'static) {
    unsafe {
        UDBG_UI = Some(Arc::new(ui));
    }
}

pub fn udbg_ui() -> &'static dyn UDbgShell {
    unsafe { UDBG_UI.as_ref().expect("plugin not inited").as_ref() }
}