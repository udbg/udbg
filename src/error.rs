//! Error types for udbg and utilities for system error code

use std::{fmt, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UDbgError {
    NotSupport,
    BpExists,
    NotFound,
    NotAttached,
    NoTarget,
    TimeOut,
    InvalidAddress,
    InvalidRegister,
    MemoryError,
    HWBPSlotMiss,
    BindFailed,
    SpawnFailed,
    TargetIsBusy,
    GetContext(u32),
    SetContext(u32),
    Text(String),
    IoErr(#[from] io::Error),
    Code(usize),
    /// for macos kern_return_t
    Kern(i32),
    #[cfg(windows)]
    Windows(#[from] ::windows::core::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
pub type UDbgResult<T> = std::result::Result<T, UDbgError>;

impl UDbgError {
    #[inline]
    pub fn system() -> UDbgError {
        UDbgError::IoErr(io::Error::last_os_error())
    }

    #[cfg(target_os = "macos")]
    pub fn from_kern_return(code: i32) -> UDbgResult<()> {
        if code == mach2::kern_return::KERN_SUCCESS {
            Ok(())
        } else {
            Err(UDbgError::Kern(code))
        }
    }
}

impl From<&str> for UDbgError {
    fn from(s: &str) -> Self {
        UDbgError::Text(s.to_string())
    }
}

impl From<String> for UDbgError {
    fn from(s: String) -> Self {
        UDbgError::Text(s)
    }
}

#[cfg(target_os = "macos")]
impl From<nix::Error> for UDbgError {
    fn from(err: nix::Error) -> Self {
        UDbgError::Kern(err as i32)
    }
}

impl fmt::Display for UDbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

pub trait LogError {
    type Output;
    type Error;

    fn log_error(self, msg: &str) -> Option<Self::Output>;
    fn log_error_with<F: FnOnce(Self::Error) -> String>(self, msg: F) -> Option<Self::Output>;
}

impl<T, E: fmt::Debug> LogError for Result<T, E> {
    type Output = T;
    type Error = E;

    fn log_error(self, msg: &str) -> Option<T> {
        match self {
            Ok(res) => Some(res),
            Err(err) => {
                use crate::shell::*;
                udbg_ui().error(format!("{msg}: {err:?}"));
                None
            }
        }
    }

    fn log_error_with<F: FnOnce(E) -> String>(self, msg: F) -> Option<Self::Output> {
        match self {
            Ok(res) => Some(res),
            Err(err) => {
                use crate::shell::*;
                udbg_ui().error(msg(err));
                None
            }
        }
    }
}
