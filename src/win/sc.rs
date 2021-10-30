
use crate::*;
use std::{ptr, mem};
use anyhow::Context;

pub use winapi::um::winsvc::*;
use winapi::shared::winerror::*;

#[derive(Clone)]
pub struct ScHandle(SC_HANDLE);
pub struct ScHandle2(ScHandle);

impl ScHandle {
    #[inline(always)]
    pub fn from_handle(handle: SC_HANDLE) -> Option<Self> {
        if handle.is_null() { None } else { Some(Self(handle)) }
    }

    pub fn open_manager(access: u32) -> Option<Self> {
        Self::from_handle(unsafe {
            OpenSCManagerW(ptr::null(), ptr::null(), access)
        })
    }

    pub fn open_service(&self, name: LPCWSTR, access: u32) -> Option<ScHandle2> {
        Self::from_handle(unsafe { OpenServiceW(self.0, name, access) }).map(|v| ScHandle2(v))
    }

    pub fn create_driver(&self, name: LPCWSTR, display: LPCWSTR, path: LPCWSTR) -> Option<ScHandle2> {
        use ptr::{null, null_mut};
        Self::from_handle(unsafe {
            CreateServiceW(self.0,
            name, display,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            path,
            null(), null_mut(), null(), null(), null())
        }).map(|v| ScHandle2(v))
    }

    pub fn list_service(&self, all: bool) -> Vec<ServiceStatus> {
        unsafe {
            let mut buf = Vec::new();
            let mut service: ENUM_SERVICE_STATUSW = mem::zeroed();
            let mut needed = 0u32;
            let mut returned = 0u32;
            let mut resumehandle = 0u32;
            // Query services
            let types = SERVICE_KERNEL_DRIVER | SERVICE_WIN32 | SERVICE_DRIVER;
            let state = if all { SERVICE_STATE_ALL } else { SERVICE_ACTIVE };
            let r = EnumServicesStatusW(
                self.0, types, state,
                &mut service, 0, &mut needed, &mut returned,
                &mut resumehandle);
            if 0 == r && ERROR_MORE_DATA == get_last_error() {
                buf.resize((needed as usize / mem::size_of::<ENUM_SERVICE_STATUSW>()) + 1, ServiceStatus(service));
                // Now query again for services
                let r = EnumServicesStatusW(
                    self.0, types, state,
                    buf.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW, needed,
                    &mut needed, &mut returned, &mut resumehandle
                );
                buf.resize(returned as usize, ServiceStatus(service));
                if r == 0 { buf.clear(); return buf; }
            }
            buf
        }
    }

    pub fn query_config(&self, name: LPCWSTR) -> Option<ServiceConfig> {
        self.open_service(name, SERVICE_QUERY_CONFIG)?.query_config()
    }

    pub fn stop_service(&self, name: LPCWSTR) -> Option<SERVICE_STATUS> {
        self.open_service(name, SERVICE_STOP)?.stop()
    }

    pub fn delete_service(&self, name: LPCWSTR) -> Option<bool> {
        Some(self.open_service(name, DELETE)?.delete())
    }
}

impl ScHandle2 {
    pub fn start(&self) -> bool {
        unsafe {
            StartServiceW(self.0.0, 0, ptr::null_mut()) > 0
        }
    }

    pub fn stop(&self) -> Option<SERVICE_STATUS> {
        unsafe {
            let mut status: SERVICE_STATUS = mem::zeroed();
            if ControlService(
                self.0.0, SERVICE_CONTROL_STOP, &mut status
            ) == 0 { None } else { Some(status) }
        }
    }

    pub fn delete(&self) -> bool {
        unsafe {
            DeleteService(self.0.0) > 0
        }
    }

    pub fn query_config(&self) -> Option<ServiceConfig> {
        unsafe {
            let mut needed = 0u32;
            let r = QueryServiceConfigW(self.0.0, ptr::null_mut(), 0, &mut needed);
            if r == 0 && get_last_error() == ERROR_INSUFFICIENT_BUFFER {
                let mut buf = BufferType::<QUERY_SERVICE_CONFIGW>::with_size(needed as usize);
                let r = QueryServiceConfigW(self.0.0, buf.as_mut_ptr(), needed, &mut needed);
                if r > 0 { return Some(ServiceConfig(buf)); }
            }
            None
        }
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0); }
    }
}

#[derive(Deref, Clone, Copy)]
pub struct ServiceStatus(pub ENUM_SERVICE_STATUSW);

impl ServiceStatus {
    pub fn name(&self) -> String {
        String::from_wide_ptr(self.lpServiceName)
    }

    pub fn display(&self) -> String {
        String::from_wide_ptr(self.lpDisplayName)
    }
}

#[derive(Deref, Clone)]
pub struct ServiceConfig(BufferType<QUERY_SERVICE_CONFIGW>);

impl ServiceConfig {
    pub fn start_name(&self) -> String {
        String::from_wide_ptr(self.lpServiceStartName)
    }

    pub fn display(&self) -> String {
        String::from_wide_ptr(self.lpDisplayName)
    }

    pub fn binary(&self) -> String {
        String::from_wide_ptr(self.lpBinaryPathName)
    }
}

pub fn load_driver<P: AsRef<std::path::Path>>(path: P, name: Option<&str>, delete: bool) -> anyhow::Result<()> {
    let path = path.as_ref();
    let service_name = name.unwrap_or_else(|| {
        path.file_stem().unwrap().to_str().unwrap().into()
    });
    let name = service_name.to_wide();
    let path = path.canonicalize().context("canonicalize")?;
    let path = normalize_path(path.to_str().unwrap().into());
    let sc = ScHandle::open_manager(SC_MANAGER_ALL_ACCESS).check_last().context("OpenSCManager")?;
    let s = sc.create_driver(name.as_ptr(), name.as_ptr(), path.to_wide().as_ptr()).check_last().context("CreateService")?;
    let result = s.start().check_last().context("StartDriver");
    if delete {
        s.delete();
    }
    result
}

pub fn unload_driver(name: &str) -> anyhow::Result<()> {
    let name = std::path::Path::new(&name).file_stem().unwrap().to_str().unwrap().to_wide();
    let sc = ScHandle::open_manager(SC_MANAGER_ALL_ACCESS).check_last().context("OpenSCManager")?;
    sc.stop_service(name.as_ptr()).unwrap();
    sc.delete_service(name.as_ptr()).check_last().context("open service")?.check_last().context("delete service")?;
    Ok(())
}