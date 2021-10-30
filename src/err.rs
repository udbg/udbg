
use std::io::Error;

#[cfg(windows)]
pub use crate::win::error::*;
#[cfg(not(windows))]
use errno::{Errno, errno};

#[cfg(not(windows))]
#[inline]
pub fn get_last_error() -> u32 { errno().0 as u32 }

#[cfg(not(windows))]
#[inline]
pub fn get_error_string(e: u32) -> String {
    format!("{}", Errno(e as i32))
}

pub fn get_last_error_string() -> String {
    get_error_string(get_last_error())
}

pub trait CheckErrno {
    type R;
    fn check_errno(self, err: &str) -> Result<Self::R, String>;
    fn check_errstr(self, err: &str) -> Result<Self::R, String>;

    fn check_last(self) -> Result<Self::R, Error>;
}

impl<T> CheckErrno for Option<T> {
    type R = T;

    fn check_errno(self, err: &str) -> Result<Self::R, String> {
        self.ok_or_else(|| format!("{}: 0x{:x}", err, get_last_error()))
    }

    fn check_errstr(self, err: &str) -> Result<Self::R, String> {
        let code = get_last_error();
        self.ok_or_else(|| format!("{}: 0x{:x} {}", err, code, get_error_string(code)))
    }

    #[inline(always)]
    fn check_last(self) -> Result<Self::R, std::io::Error> {
        self.ok_or_else(Error::last_os_error)
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

    fn check_last(self) -> Result<Self::R, Error> {
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
        } else { Ok(self) }
    }

    fn check_errstr(self, err: &str) -> Result<Self::R, String> {
        if self.is_null() {
            None.check_errstr(err)
        } else { Ok(self) }
    }

    fn check_last(self) -> Result<Self::R, Error> {
        if self.is_null() {
            None.check_last()
        } else { Ok(self) }
    }
}

impl<T> CheckErrno for *mut T {
    type R = *mut T;

    fn check_errno(self, err: &str) -> Result<Self::R, String> {
        if self.is_null() {
            None.check_errno(err)
        } else { Ok(self) }
    }

    fn check_errstr(self, err: &str) -> Result<Self::R, String> {
        if self.is_null() {
            None.check_errstr(err)
        } else { Ok(self) }
    }

    fn check_last(self) -> Result<Self::R, Error> {
        if self.is_null() {
            None.check_last()
        } else { Ok(self) }
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
    }
}
impl_errno!(u8);
impl_errno!(i32);
impl_errno!(u32);