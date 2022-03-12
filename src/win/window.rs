use alloc::string::String;
use core::mem::{transmute, zeroed};
use core::ptr::null_mut;

use winapi::shared::minwindef::*;
use winapi::shared::windef::*;
use winapi::um::winuser::*;

use super::string::*;

/// Wrapper of EnumWindows
pub fn enum_window(mut callback: impl FnMut(HWND) -> bool) {
    extern "system" fn wrapper(hwnd: HWND, param: LPARAM) -> BOOL {
        unsafe {
            let callback: *mut &'static mut dyn FnMut(HWND) -> bool = transmute(param);
            return (*callback)(hwnd) as BOOL;
        }
    }
    unsafe {
        let r: &mut dyn FnMut(HWND) -> bool = &mut callback;
        EnumWindows(Some(wrapper), transmute(&r));
    }
}

#[extend::ext(name = WindowInfo)]
pub impl HWND {
    fn get_tid_pid(self) -> (u32, u32) {
        unsafe {
            let mut pid: u32 = 0;
            let tid = GetWindowThreadProcessId(self, &mut pid);
            (tid, pid)
        }
    }

    fn is_visible(self) -> bool {
        unsafe { IsWindowVisible(self) > 0 }
    }

    fn get_text(self) -> String {
        unsafe {
            let mut buf = [0u16; 2000];
            // let get_text = GetWindowTextW;
            let get_text = InternalGetWindowText;
            if get_text(self, buf.as_mut_ptr(), buf.len() as i32) > 0 {
                buf.as_ref().to_utf8()
            } else {
                String::new()
            }
        }
    }

    fn get_class_name(self) -> String {
        unsafe {
            let mut buf = [0u16; 2000];
            if GetClassNameW(self, buf.as_mut_ptr(), buf.len() as i32) > 0 {
                buf.as_ref().to_utf8()
            } else {
                String::new()
            }
        }
    }

    fn get_wndproc(self) -> usize {
        unsafe {
            let r = GetWindowLongPtrW(self, GWL_WNDPROC) as usize;
            if r == 0 {
                GetClassLongPtrW(self, GCL_WNDPROC) as usize
            } else {
                r
            }
        }
    }

    fn set_wndproc(self, ptr: usize) -> usize {
        unsafe { transmute(SetWindowLongPtrW(self, GWL_WNDPROC, transmute(ptr))) }
    }

    fn client_area(self) -> Option<RECT> {
        unsafe {
            let mut rect: RECT = zeroed();
            if GetClientRect(self, &mut rect) > 0 {
                Some(rect)
            } else {
                None
            }
        }
    }

    fn client_size(self) -> (usize, usize) {
        match self.client_area() {
            Some(r) => ((r.right - r.left) as usize, (r.bottom - r.top) as usize),
            None => (0, 0),
        }
    }

    fn iter(self) -> Box<dyn Iterator<Item = HWND>> {
        let mut hwnd = self;
        Box::new(core::iter::from_fn(move || {
            let w = unsafe { GetWindow(hwnd, GW_HWNDNEXT) };
            if w.is_null() {
                None
            } else {
                hwnd = w;
                Some(w)
            }
        }))
    }
}

#[inline]
pub fn enum_process_window(pid: u32, mut callback: impl FnMut(HWND) -> bool) {
    enum_window(|hwnd| {
        if hwnd.get_tid_pid().1 == pid {
            callback(hwnd)
        } else {
            true
        }
    })
}

/// Wrapper of GetTopWindow
pub fn get_top_window() -> HWND {
    unsafe { GetTopWindow(null_mut()) }
}
