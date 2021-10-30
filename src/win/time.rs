
use winapi::{
    shared::minwindef::FILETIME,
    um::fileapi::FileTimeToLocalFileTime,
};

pub use chrono::{DateTime, TimeZone, Utc, Duration};

pub fn filetime_to_utc(ft: FILETIME) -> DateTime<Utc> {
    unsafe {
        let mut lft: FILETIME = std::mem::zeroed();
        FileTimeToLocalFileTime(&ft, &mut lft);
        let t = (lft.dwHighDateTime as i64) << 32 | lft.dwLowDateTime as i64;
        Utc.ymd(1601, 1, 1).and_hms(0, 0, 0) + Duration::milliseconds(t / 10000)
    }
}