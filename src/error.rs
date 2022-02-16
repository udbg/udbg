
use std::{fmt, io};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UDbgError {
    NotSupport,
    BpExists,
    NotFound,
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
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
pub type UDbgResult<T>  = std::result::Result<T, UDbgError>;

impl UDbgError {
    #[inline]
    pub fn system() -> UDbgError { UDbgError::IoErr(io::Error::last_os_error()) }
}

impl From<&str> for UDbgError {
    fn from(s: &str) -> Self { UDbgError::Text(s.to_string()) }
}

impl From<String> for UDbgError {
    fn from(s: String) -> Self { UDbgError::Text(s) }
}

impl fmt::Display for UDbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}
