
use crate::AsByteArray;

use alloc::vec::Vec;
use alloc::string::*;
use core::{
    slice::*,
    mem::{size_of, transmute, zeroed}
};

pub trait ReadMemory {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]>;
}

pub trait ReadMemUtil: ReadMemory {
    /// read continuous values until the conditions are met
    fn read_util<T: PartialEq + Copy>(&self, address: usize, pred: impl Fn(&T)->bool + Copy, max_count: usize) -> Vec<T> {
        const BUFLEN: usize = 100usize;
        let mut result: Vec<T> = Vec::with_capacity(BUFLEN);

        unsafe {
            let mut buf: [T; BUFLEN] = core::mem::zeroed();
            let mut addr = address;

            let pdata: *mut u8 = transmute(buf.as_mut_ptr());
            let size = buf.len() * size_of::<T>();
            let mut end = false;
            while let Some(data) = self.read_memory(addr, from_raw_parts_mut(pdata, size)) {
                let mut pos = match buf.iter().position(pred) {
                    None => buf.len(),
                    Some(pos) => { end = true; pos },
                };
                if result.len() + pos > max_count {
                    end = true;
                    pos = max_count - result.len();
                }
                result.extend_from_slice(&buf[..pos]);
                if end { break; }
                addr += data.len();
            }
        }
        return result;
    }

    #[inline(always)]
    fn read_util_eq<T: PartialOrd + Copy>(&self, address: usize, val: T, max_bytes: usize) -> Vec<T> {
        self.read_util(address, |&x| x == val, max_bytes)
    }

    #[inline(always)]
    fn read_util_lt<T: PartialOrd + Copy>(&self, address: usize, val: T, max_bytes: usize) -> Vec<T> {
        self.read_util(address, |&x| x < val, max_bytes)
    }

    fn read_cstring(&self, address: usize, max: impl Into<Option<usize>>) -> Option<Vec<u8>> {
        let result = self.read_util_eq(address, 0, max.into().unwrap_or(1000));
        if result.len() == 0 || (result.len() == 1 && result[0] < b' ') { return None; }
        Some(result)
    }

    fn read_utf8(&self, address: usize, max: impl Into<Option<usize>>) -> Option<String> {
        String::from_utf8(self.read_cstring(address, max)?).ok()
    }

    fn read_array<T>(&self, addr: usize, count: usize) -> Vec<Option<T>> {
        let mut result = Vec::<Option<T>>::with_capacity(count);
        for i in 0..count {
            result.push(self.read_value::<T>(addr + size_of::<T>() * i));
        }
        result
    }

    fn read_bytes(&self, addr: usize, size: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; size];
        let len = match self.read_memory(addr, &mut buf) {
            Some(slice) => slice.len(), None => 0
        };
        buf.resize(len, 0); buf
    }

    /// read any typed value
    fn read_value<T>(&self, address: usize) -> Option<T> {
        unsafe {
            let mut val: T = zeroed();
            self.read_memory(
                address, from_raw_parts_mut(transmute::<_, *mut u8>(&mut val), size_of::<T>())
            ).and_then(|buf| if buf.len() == size_of::<T>() { Some(val) } else { None })
        }
    }

    /// read some values into existing array data
    fn read_to_array<T>(&self, address: usize, buf: &mut [T]) -> usize {
        unsafe {
            let size = size_of::<T>() * buf.len();
            let pdata: *mut u8 = transmute(buf.as_mut_ptr());
            let mut buf = from_raw_parts_mut(pdata, size);
            self.read_memory(address, &mut buf).map(|b| b.len() / size_of::<T>()).unwrap_or(0)
        }
    }

    /// read multiple-level pointer
    fn read_multilevel<T>(&self, address: usize, offset: &[usize]) -> Option<T> {
        let mut p = address;
        for o in offset.iter() {
            if p == 0 { return None; }
            if let Some(v) = self.read_value(p + *o) {
                p = v;
            } else { return None; }
        }
        self.read_value(p)
    }
}

pub trait WriteMemory {
    fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize>;
}

pub trait WriteMemUtil: WriteMemory {
    #[inline]
    fn write_value<T>(&self, address: usize, val: &T) -> Option<usize> {
        self.write_memory(address, val.as_byte_array())
    }

    #[inline]
    fn write_array<T>(&self, address: usize, data: &[T]) -> Option<usize> {
        self.write_memory(address, unsafe {
            from_raw_parts(data.as_ptr() as *const u8, data.len() * size_of::<T>())
        })
    }

    fn write_cstring(&self, address: usize, data: impl AsRef<[u8]>) -> Option<usize> {
        let r = data.as_ref();
        Some(self.write_memory(address, r)? + self.write_memory(address + r.len(), &[0u8])?)
    }

    #[cfg(windows)]
    fn write_wstring(&self, address: usize, data: &str) -> Option<usize> {
        use crate::ToUnicode;
        self.write_array(address, data.to_unicode_with_null().as_slice())
    }
}

impl<T: ReadMemory + ?Sized> ReadMemUtil for T {}
impl<T: WriteMemory + ?Sized> WriteMemUtil for T {}