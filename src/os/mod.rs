#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

cfg_if! {
    if #[cfg(windows)] {
        pub type pid_t = u32;
        pub use self::windows::*;
    } else {
        pub type pid_t = libc::pid_t;
    }
}

cfg_if! {
    if #[cfg(target_os="macos")] {
        pub type tid_t = u64;
    } else {
        pub type tid_t = pid_t;
    }
}
