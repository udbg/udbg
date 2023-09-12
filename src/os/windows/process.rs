use std::{
    mem::{size_of, size_of_val},
    ptr::null_mut,
};

use anyhow::Context;
use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use windows::Win32::{
    Foundation::{
        DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, HMODULE, MAX_PATH, UNICODE_STRING,
    },
    System::{
        Diagnostics::{
            Debug::*,
            ToolHelp::{MODULEENTRY32W, THREADENTRY32},
        },
        Memory::*,
        ProcessStatus::*,
        Threading::*,
    },
};

use super::{
    ntdll::{ProcessInfoClass, SystemHandleInformation},
    toolhelp::*,
    util, Handle,
};
use crate::{
    error::*,
    memory::*,
    shell::{HandleInfo, ProcessInfo},
    string::ToMbstr,
};

#[derive(Debug, Clone)]
pub struct Process {
    pub handle: Handle,
}

impl ReadMemory for Process {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let r = read_process_memory(*self.handle, addr, data).ok()?;
        if r > 0 {
            Some(&mut data[..r])
        } else {
            None
        }
    }
}

impl WriteMemory for Process {
    fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        let r = self.write_memory(address, data);
        if r > 0 {
            Some(r)
        } else {
            None
        }
    }

    fn flush_cache(&self, address: usize, len: usize) -> std::io::Result<()> {
        if unsafe { FlushInstructionCache(*self.handle, Some(address as _), len).is_ok() } {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl Process {
    pub fn open(pid: u32, access: Option<PROCESS_ACCESS_RIGHTS>) -> anyhow::Result<Process> {
        unsafe {
            let handle = OpenProcess(access.unwrap_or(PROCESS_ALL_ACCESS), false, pid)?;
            Self::from_handle(Handle::from_raw_handle(handle)).context("from handle")
        }
    }

    #[inline]
    pub unsafe fn borrow_raw(handle: &HANDLE) -> &Self {
        Self::borrow_handle(Handle::borrow(handle))
    }

    #[inline]
    pub unsafe fn borrow_handle(handle: &Handle) -> &Self {
        &*(handle as *const _ as *const Self)
    }

    pub fn duplicate_from_other_process(pid: u32, access: u32) -> anyhow::Result<Process> {
        let handle = super::duplicate_process(pid, access)
            .next()
            .context("dup not found")?;
        Self::from_handle(handle).context("from handle")
    }

    pub fn from_name(name: &str, access: Option<PROCESS_ACCESS_RIGHTS>) -> anyhow::Result<Process> {
        let pid = enum_process()?
            .filter(move |p| p.name().eq_ignore_ascii_case(name))
            .next()
            .context("not found")?
            .pid();
        Self::open(pid, access).context("open")
    }

    pub fn from_handle(handle: Handle) -> Option<Process> {
        unsafe {
            let pid = GetProcessId(*handle);
            if pid == 0 {
                return None;
            }

            return Some(Process { handle });
        }
    }

    pub fn current() -> Process {
        unsafe { Self::from_handle(Handle::from_raw_handle(GetCurrentProcess())).unwrap() }
    }

    pub fn basic_information(&self) -> Option<PROCESS_BASIC_INFORMATION> {
        super::ntdll::query_process(
            self.handle.as_winapi(),
            ProcessInfoClass::BasicInformation,
            None,
        )
    }

    pub fn pid(&self) -> u32 {
        unsafe { GetProcessId(*self.handle) }
    }

    pub fn peb(&self) -> Option<usize> {
        self.basic_information().map(|i| i.PebBaseAddress as usize)
    }

    // https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
    pub fn is_wow64(&self) -> bool {
        let mut result = Default::default();
        unsafe {
            IsWow64Process(*self.handle, &mut result).ok();
        }
        result.as_bool()
    }

    pub fn get_module_name(&self, module: u64) -> UDbgResult<String> {
        unsafe {
            let mut name = [0 as u16; MAX_PATH as usize];
            if GetModuleBaseNameW(*self.handle, HMODULE(module as _), &mut name) > 0 {
                Ok(name.as_ref().to_utf8())
            } else {
                Err(UDbgError::system())
            }
        }
    }

    // TODO: [bug] wow64进程下32位dll取到的是64位的路径
    #[deprecated]
    pub fn get_module_path(&self, module: usize) -> Option<String> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH as usize];
            if GetModuleFileNameExW(*self.handle, HMODULE(module as _), &mut path) > 0 {
                Some(path.as_ref().to_utf8())
            } else {
                None
            }
        }
    }

    /// use EnumProcessModulesEx
    pub fn get_module_list(&self, flag: ENUM_PROCESS_MODULES_EX_FLAGS) -> Option<Vec<usize>> {
        unsafe {
            let mut len = 0u32;
            EnumProcessModulesEx(*self.handle, null_mut(), 0, &mut len, flag);
            let mut result = vec![0usize; len as usize];
            if len > 0 {
                if EnumProcessModulesEx(
                    *self.handle,
                    result.as_mut_ptr() as _,
                    result.len() as u32,
                    &mut len,
                    flag,
                )
                .is_ok()
                {
                    return Some(result.into_iter().filter(|&m| m > 0).collect());
                }
            }
            None
        }
    }

    /// use GetModuleInformation
    pub fn get_module_info(&self, base: usize) -> Option<MODULEINFO> {
        unsafe {
            let mut result: MODULEINFO = core::mem::zeroed();
            if GetModuleInformation(
                *self.handle,
                HMODULE(base as _),
                &mut result,
                size_of::<MODULEINFO>() as u32,
            )
            .is_ok()
            {
                return Some(result);
            }
            None
        }
    }

    pub fn duplicate_handle_to_current(&self, src: HANDLE) -> windows::core::Result<Handle> {
        self.duplicate_handle(src, unsafe { GetCurrentProcess() })
            .map(|x| unsafe { Handle::from_raw_handle(x) })
    }

    pub fn duplicate_handle(&self, src: HANDLE, dst_ps: HANDLE) -> windows::core::Result<HANDLE> {
        let mut handle = HANDLE::default();
        unsafe {
            DuplicateHandle(
                *self.handle,
                src,
                dst_ps,
                &mut handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )?;
            Ok(handle)
        }
    }

    #[inline]
    pub fn enum_thread<'a>(
        &'a self,
    ) -> windows::core::Result<impl Iterator<Item = THREADENTRY32> + 'a> {
        let pid = self.pid();
        Ok(enum_thread()?.filter(move |x| x.pid() == pid))
    }

    #[inline]
    pub fn enum_module(&self) -> windows::core::Result<ToolHelperIter<MODULEENTRY32W>> {
        enum_module(self.pid())
    }

    /// Wrapper of QueryFullProcessImageNameW
    pub fn image_path(&self) -> windows::core::Result<String> {
        unsafe {
            let mut path = [0 as u16; MAX_PATH as usize];
            let mut size = path.len() as u32;
            QueryFullProcessImageNameW(
                *self.handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(path.as_mut_ptr()),
                &mut size,
            )?;
            Ok(path.as_ref().to_utf8())
        }
    }

    pub fn cmdline(&self) -> Option<String> {
        use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
        use ntapi::FIELD_OFFSET;

        self.peb()
            .and_then(|peb| {
                self.read_value::<usize>(peb as usize + FIELD_OFFSET!(PEB, ProcessParameters))
            })
            .and_then(|p| {
                self.read_value::<UNICODE_STRING>(
                    p + FIELD_OFFSET!(RTL_USER_PROCESS_PARAMETERS, CommandLine),
                )
            })
    }

    pub fn protect_memory(
        &self,
        address: usize,
        size: usize,
        attr: PAGE_PROTECTION_FLAGS,
    ) -> windows::core::Result<PAGE_PROTECTION_FLAGS> {
        unsafe {
            let mut oldattr = Default::default();
            VirtualProtectEx(*self.handle, address as _, size, attr, &mut oldattr)?;
            Ok(oldattr)
        }
    }

    #[inline]
    pub fn write_memory(&self, address: usize, data: &[u8]) -> usize {
        write_process_memory(*self.handle, address, data).unwrap_or_default()
    }

    pub fn enum_memory(&self, address: usize) -> impl Iterator<Item = MemoryPage> + '_ {
        pub struct MemoryIter<'p> {
            pub process: &'p Process,
            pub address: usize,
        }

        impl MemoryIter<'_> {
            pub fn next_commit(&mut self) -> Option<MemoryPage> {
                while let Some(m) = self.next() {
                    if m.is_commit() {
                        return Some(m);
                    }
                }
                return None;
            }
        }

        impl Iterator for MemoryIter<'_> {
            type Item = MemoryPage;

            fn next(&mut self) -> Option<Self::Item> {
                let result = self.process.virtual_query(self.address);
                if let Some(m) = result.as_ref() {
                    self.address += m.size;
                }
                return result;
            }
        }

        MemoryIter {
            process: self,
            address,
        }
    }

    pub fn virtual_alloc(
        &self,
        address: usize,
        size: usize,
        mem_type: VIRTUAL_ALLOCATION_TYPE,
        protect: PAGE_PROTECTION_FLAGS,
    ) -> usize {
        unsafe {
            VirtualAllocEx(*self.handle, Some(address as _), size, mem_type, protect) as usize
        }
    }

    pub fn virtual_free(&self, address: usize) -> bool {
        unsafe { VirtualFreeEx(*self.handle, address as _, 0, MEM_RELEASE).is_ok() }
    }

    pub fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
            match VirtualQueryEx(
                *self.handle,
                Some(address as _),
                &mut mbi,
                size_of_val(&mbi),
            ) {
                0 => None,
                _ => Some(MemoryPage::from(&mbi)),
            }
        }
    }

    #[inline]
    pub fn terminate(&self) -> windows::core::Result<()> {
        unsafe { TerminateProcess(*self.handle, 0) }
    }

    pub fn get_exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        unsafe {
            GetExitCodeProcess(*self.handle, &mut code)
                .is_ok()
                .then_some(code)
        }
    }

    // https://docs.microsoft.com/zh-cn/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
    pub fn get_mapped_file_name(&self, address: usize) -> Option<String> {
        unsafe {
            let mut buf = [0u16; 300];
            let len = GetMappedFileNameW(*self.handle, address as _, &mut buf);
            if len > 0 {
                util::to_dos_path(&mut buf)
                    .map(|s| s.to_utf8())
                    .or_else(|| Some(buf.as_ref().to_utf8()))
            } else {
                None
            }
        }
    }

    pub fn enum_handle(&self, pid: Option<u32>) -> impl Iterator<Item = HandleInfo> + '_ {
        let pid = pid.unwrap_or_else(|| self.pid());
        let mut type_cache = util::HandleTypeCache::default();
        super::ntdll::system_handle_information().filter_map(move |h| {
            if h.pid() != pid {
                return None;
            }
            type_cache.cache_get(self, h)
        })
    }
}

pub fn read_process_memory(
    handle: HANDLE,
    address: usize,
    data: &mut [u8],
) -> anyhow::Result<usize> {
    let mut readed = 0usize;
    unsafe {
        ReadProcessMemory(
            handle,
            address as _,
            data.as_mut_ptr().cast(),
            data.len(),
            Some(&mut readed),
        )?;
    }
    Ok(readed)
}

pub fn write_process_memory(handle: HANDLE, address: usize, data: &[u8]) -> anyhow::Result<usize> {
    let mut written = 0usize;
    let mut old_protect = Default::default();
    let mut new_protect = Default::default();
    unsafe {
        VirtualProtectEx(
            handle,
            address as _,
            data.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .context("protect")?;
        let result = WriteProcessMemory(
            handle,
            address as _,
            data.as_ptr() as _,
            data.len(),
            Some(&mut written),
        )
        .context("write")?;
        VirtualProtectEx(
            handle,
            address as _,
            data.len(),
            old_protect,
            &mut new_protect,
        )
        .context("protect2")?;
    }
    Ok(written)
}

impl ProcessInfo {
    pub fn enumerate() -> UDbgResult<impl Iterator<Item = ProcessInfo>> {
        Ok(enum_process()?.map(|p| {
            let pid = p.pid();
            let mut result = ProcessInfo {
                pid,
                name: p.name(),
                wow64: false,
                path: String::new(),
                cmdline: String::new(),
            };
            Process::open(pid, Some(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ))
                .map(|p| {
                    result.wow64 = p.is_wow64();
                    p.image_path().map(|path| result.path = path);
                    p.cmdline().map(|cmd| result.cmdline = cmd);
                })
                .ok();
            result
        }))
    }
}

impl From<&MEMORY_BASIC_INFORMATION> for MemoryPage {
    fn from(mbi: &MEMORY_BASIC_INFORMATION) -> Self {
        MemoryPage {
            base: mbi.BaseAddress as usize,
            alloc_base: mbi.AllocationBase as usize,
            size: mbi.RegionSize,
            type_: mbi.Type.0,
            state: mbi.State.0,
            protect: mbi.Protect.0,
            alloc_protect: mbi.AllocationProtect.0,
            ..Default::default()
        }
    }
}
