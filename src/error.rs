//! Error types for udbg and utilities for system error code

use std::{fmt, io};
use thiserror::Error;

#[derive(Error)]
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

impl fmt::Debug for UDbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupport => write!(f, "NotSupport"),
            Self::BpExists => write!(f, "BpExists"),
            Self::NotFound => write!(f, "NotFound"),
            Self::NotAttached => write!(f, "NotAttached"),
            Self::NoTarget => write!(f, "NoTarget"),
            Self::TimeOut => write!(f, "TimeOut"),
            Self::InvalidAddress => write!(f, "InvalidAddress"),
            Self::InvalidRegister => write!(f, "InvalidRegister"),
            Self::MemoryError => write!(f, "MemoryError"),
            Self::HWBPSlotMiss => write!(f, "HWBPSlotMiss"),
            Self::BindFailed => write!(f, "BindFailed"),
            Self::SpawnFailed => write!(f, "SpawnFailed"),
            Self::TargetIsBusy => write!(f, "TargetIsBusy"),
            Self::GetContext(arg0) => f.debug_tuple("GetContext").field(arg0).finish(),
            Self::SetContext(arg0) => f.debug_tuple("SetContext").field(arg0).finish(),
            Self::Text(arg0) => f.debug_tuple("Text").field(arg0).finish(),
            Self::IoErr(arg0) => f.debug_tuple("IoErr").field(arg0).finish(),
            Self::Code(arg0) => f.debug_tuple("Code").field(arg0).finish(),
            Self::Kern(arg0) => f.debug_tuple("Kern").field(arg0).finish(),
            #[cfg(windows)]
            Self::Windows(arg0) => f.debug_tuple("Windows").field(arg0).finish(),
            Self::Other(arg0) => arg0.fmt(f),
        }
    }
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

#[cfg(unix)]
impl From<nix::Error> for UDbgError {
    fn from(err: nix::Error) -> Self {
        UDbgError::Kern(err as i32)
    }
}

impl fmt::Display for UDbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub use log_error::*;
