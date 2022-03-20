//! OS-specific functionality

cfg_if! {
    if #[cfg(target_os="linux")] {
        pub mod linux;
        pub use self::linux::*;
    }
}

cfg_if! {
    if #[cfg(target_os="macos")] {
        pub mod macos;
        pub use self::macos::*;
    }
}

cfg_if! {
    if #[cfg(windows)] {
        pub mod windows;
        pub type pid_t = u32;
        pub use self::windows::*;
    } else {
        pub mod unix;
        pub type pid_t = libc::pid_t;
        pub use self::unix::*;
    }
}

cfg_if! {
    if #[cfg(target_os="macos")] {
        pub type tid_t = u64;
    } else {
        pub type tid_t = pid_t;
    }
}
