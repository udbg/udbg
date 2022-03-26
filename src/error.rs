//! Error types for udbg and utilities for system error code

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
    /// for macos kern_return_t
    Kern(i32),
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

impl fmt::Display for UDbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

pub trait CheckErrno {
    type R;
    fn check_errno(self, err: &str) -> Result<Self::R, String>;
    fn check_errstr(self, err: &str) -> Result<Self::R, String>;

    fn check_last(self) -> Result<Self::R, io::Error>;
}

impl<T> CheckErrno for Option<T> {
    type R = T;

    fn check_errno(self, err: &str) -> Result<Self::R, String> {
        self.ok_or_else(|| {
            format!(
                "{}: 0x{:x}",
                err,
                io::Error::last_os_error().raw_os_error().unwrap_or(0)
            )
        })
    }

    fn check_errstr(self, err: &str) -> Result<Self::R, String> {
        let error = io::Error::last_os_error();
        self.ok_or_else(|| {
            format!(
                "{}: 0x{:x} {:?}",
                err,
                error.raw_os_error().unwrap_or(0),
                error
            )
        })
    }

    #[inline(always)]
    fn check_last(self) -> Result<Self::R, std::io::Error> {
        self.ok_or_else(io::Error::last_os_error)
    }
}

impl CheckErrno for bool {
    type R = ();

    fn check_errno(self, err: &str) -> Result<Self::R, String> {
        if self {
            Ok(())
        } else {
            None.check_errno(err)
        }
    }

    fn check_errstr(self, err: &str) -> Result<Self::R, String> {
        if self {
            Ok(())
        } else {
            None.check_errstr(err)
        }
    }

    fn check_last(self) -> Result<Self::R, io::Error> {
        if self {
            Ok(())
        } else {
            None.check_last()
        }
    }
}

impl<T> CheckErrno for *const T {
    type R = *const T;

    fn check_errno(self, err: &str) -> Result<Self::R, String> {
        if self.is_null() {
            None.check_errno(err)
        } else {
            Ok(self)
        }
    }

    fn check_errstr(self, err: &str) -> Result<Self::R, String> {
        if self.is_null() {
            None.check_errstr(err)
        } else {
            Ok(self)
        }
    }

    fn check_last(self) -> Result<Self::R, io::Error> {
        if self.is_null() {
            None.check_last()
        } else {
            Ok(self)
        }
    }
}

impl<T> CheckErrno for *mut T {
    type R = *mut T;

    fn check_errno(self, err: &str) -> Result<Self::R, String> {
        if self.is_null() {
            None.check_errno(err)
        } else {
            Ok(self)
        }
    }

    fn check_errstr(self, err: &str) -> Result<Self::R, String> {
        if self.is_null() {
            None.check_errstr(err)
        } else {
            Ok(self)
        }
    }

    fn check_last(self) -> Result<Self::R, io::Error> {
        if self.is_null() {
            None.check_last()
        } else {
            Ok(self)
        }
    }
}

macro_rules! impl_errno {
    ($t:ty) => {
        impl CheckErrno for $t {
            type R = ();

            #[inline(always)]
            fn check_errno(self, err: &str) -> Result<Self::R, String> {
                (self > 0).check_errno(err)
            }

            #[inline(always)]
            fn check_errstr(self, err: &str) -> Result<Self::R, String> {
                (self > 0).check_errstr(err)
            }

            #[inline(always)]
            fn check_last(self) -> Result<Self::R, std::io::Error> {
                (self > 0).check_last()
            }
        }
    };
}
impl_errno!(u8);
impl_errno!(i32);
impl_errno!(u32);

pub trait LogError {
    type Output;

    fn log_error(self, msg: &str) -> Option<Self::Output>;
}

impl<T, E: fmt::Debug> LogError for Result<T, E> {
    type Output = T;

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
}
