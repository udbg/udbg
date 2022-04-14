//! Practical wrappers for functions/structs in ntdll

pub use super::ffi::*;
use super::util::BufferType;
pub use ntapi::ntexapi::*;
pub use ntapi::ntldr::*;
pub use ntapi::ntmmapi::*;
use ntapi::ntobapi::*;
pub use ntapi::ntpebteb::*;
pub use ntapi::ntpsapi::*;
pub use ntapi::ntzwapi::*;

use alloc::string::*;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::{size_of, size_of_val, transmute, zeroed};
use core::ptr::{null, null_mut};
use core::slice::from_raw_parts;

use winapi::shared::ntdef::*;
use winapi::shared::{minwindef::LPVOID, ntstatus::STATUS_INFO_LENGTH_MISMATCH};
use winapi::um::winnt::HANDLE;

pub enum ProcessInfoClass {
    BasicInformation = 0,
    DebugPort = 7,
    Wow64Information = 26,
    ImageFileName = 27,
    BreakOnTermination = 29,
    SubsystemInformation = 75,
}

pub enum ThreadInfoClass {
    BasicInformation = 0,
    Times = 1,
    Priority = 2,
    BasePriority = 3,
    AffinityMask = 4,
    ImpersonationToken = 5,
    DescriptorTableEntry = 6,
    EnableAlignmentFaultFixup = 7,
    EventPair = 8,
    QuerySetWin32StartAddress = 9,
    ZeroTlsCell = 10,
    PerformanceCount = 11,
    AmILastThread = 12,
    IdealProcessor = 13,
    PriorityBoost = 14,
    SetTlsArrayAddress = 15,
    IsIoPending = 16,
    HideFromDebugger = 17,
}

pub fn query_thread<T>(
    handle: HANDLE,
    info: ThreadInfoClass,
    out_len: Option<&mut usize>,
) -> Option<T> {
    let mut len: ULONG = 0;
    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread
        let mut result: T = zeroed();
        let r = NtQueryInformationThread(
            handle,
            info as u32,
            transmute(&mut result),
            size_of::<T>() as u32,
            &mut len,
        );
        if let Some(out_len) = out_len {
            *out_len = len as usize;
        }
        if NT_SUCCESS(r) {
            Some(result)
        } else {
            None
        }
    }
}

pub fn query_process<T>(
    handle: HANDLE,
    info: ProcessInfoClass,
    out_len: Option<&mut usize>,
) -> Option<T> {
    let mut len: ULONG = 0;
    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
        let mut result: T = zeroed();
        let r = ZwQueryInformationProcess(
            handle,
            info as u32,
            transmute(&mut result),
            size_of::<T>() as u32,
            &mut len,
        );
        if let Some(out_len) = out_len {
            *out_len = len as usize;
        }
        if NT_SUCCESS(r) {
            Some(result)
        } else {
            None
        }
    }
}

pub fn read_object_info(handle: HANDLE, info: u32, extra_size: usize) -> Result<Vec<u8>, NTSTATUS> {
    let mut size = 0u32;
    unsafe {
        let mut result = vec![0u8; 1024];
        let err = loop {
            let err = NtQueryObject(
                handle,
                info,
                transmute(result.as_mut_ptr()),
                result.len() as u32,
                &mut size,
            );
            if err != STATUS_INFO_LENGTH_MISMATCH {
                break err;
            }
            result.resize(size as usize + extra_size, 0u8);
        };
        err.check()?;
        Ok(result)
    }
}

// maybe block, you can call this function within `call_with_timeout`
pub fn query_object_name(handle: HANDLE) -> Result<BufferType<UNICODE_STRING>, NTSTATUS> {
    read_object_info(handle, ObjectNameInformation, size_of::<u16>() * 16)
        .map(|r| BufferType::from_vec(r))
}

pub fn query_object_type(handle: HANDLE) -> Result<BufferType<OBJECT_TYPE_INFORMATION>, NTSTATUS> {
    read_object_info(handle, ObjectTypeInformation, 0).map(|r| BufferType::from_vec(r))
}

// https://docs.rs/ntapi/0.3.3/ntapi/ntexapi/struct.SYSTEM_PROCESS_INFORMATION.html
pub struct SystemProcessInfoIter<'a> {
    data: Vec<u8>,
    ptr: PSYSTEM_PROCESS_INFORMATION,
    _phan: core::marker::PhantomData<&'a SYSTEM_PROCESS_INFORMATION>,
}

impl<'a> SystemProcessInfoIter<'a> {
    pub fn new() -> SystemProcessInfoIter<'a> {
        SystemProcessInfoIter {
            data: vec![],
            ptr: core::ptr::null_mut(),
            _phan: PhantomData,
        }
    }

    pub fn from(mut data: Vec<u8>) -> SystemProcessInfoIter<'a> {
        let ptr = data.as_mut_ptr() as PSYSTEM_PROCESS_INFORMATION;
        SystemProcessInfoIter {
            data,
            ptr,
            _phan: PhantomData,
        }
    }
}

impl<'a> Iterator for SystemProcessInfoIter<'a> {
    type Item = &'a SYSTEM_PROCESS_INFORMATION;
    fn next(&mut self) -> Option<Self::Item> {
        if self.ptr.is_null() {
            return None;
        }
        unsafe {
            let next = (*self.ptr).NextEntryOffset as usize;
            if next == 0 {
                return None;
            }
            let result: &'static SYSTEM_PROCESS_INFORMATION = transmute(self.ptr);
            self.ptr = transmute(self.ptr as usize + next);
            Some(result)
        }
    }
}

pub trait SystemProcessInfo {
    fn threads(&self) -> &[SYSTEM_THREAD_INFORMATION];
}

impl SystemProcessInfo for SYSTEM_PROCESS_INFORMATION {
    fn threads(&self) -> &[SYSTEM_THREAD_INFORMATION] {
        unsafe { core::slice::from_raw_parts(self.Threads.as_ptr(), self.NumberOfThreads as usize) }
    }
}

pub fn system_process_information<'a>() -> Result<SystemProcessInfoIter<'a>, NTSTATUS> {
    let v = read_system_information(SystemProcessInformation, 0)?;
    Ok(SystemProcessInfoIter::from(v))
}

pub struct SystemHandleInfoIter<'a> {
    data: Vec<u8>,
    ptr: PSYSTEM_HANDLE_INFORMATION,
    i: usize,
    _phan: core::marker::PhantomData<&'a SYSTEM_HANDLE_INFORMATION>,
}

impl<'a> SystemHandleInfoIter<'a> {
    pub fn new() -> SystemHandleInfoIter<'a> {
        SystemHandleInfoIter {
            data: vec![],
            ptr: core::ptr::null_mut(),
            _phan: PhantomData,
            i: 0,
        }
    }

    pub fn from(mut data: Vec<u8>) -> SystemHandleInfoIter<'a> {
        let ptr = data.as_mut_ptr() as PSYSTEM_HANDLE_INFORMATION;
        SystemHandleInfoIter {
            data,
            ptr,
            i: 0,
            _phan: PhantomData,
        }
    }
}

impl<'a> Iterator for SystemHandleInfoIter<'a> {
    type Item = &'a SYSTEM_HANDLE_TABLE_ENTRY_INFO;
    fn next(&mut self) -> Option<Self::Item> {
        if self.ptr.is_null() {
            return None;
        }
        unsafe {
            let this = &*self.ptr;
            let r = from_raw_parts(this.Handles.as_ptr(), this.NumberOfHandles as usize);
            if self.i >= r.len() {
                return None;
            }
            let result = Some(&r[self.i]);
            self.i += 1;
            result
        }
    }
}

pub fn read_system_information(
    si: SYSTEM_INFORMATION_CLASS,
    extra_size: usize,
) -> Result<Vec<u8>, NTSTATUS> {
    let mut size = 0u32;
    unsafe {
        let mut result = vec![0u8; 1024];
        let err = loop {
            let err = ZwQuerySystemInformation(
                si,
                transmute(result.as_mut_ptr()),
                result.len() as u32,
                &mut size,
            );
            if err != STATUS_INFO_LENGTH_MISMATCH {
                break err;
            }
            result.resize(size as usize + extra_size, 0u8);
        };
        if NT_SUCCESS(err) {
            Ok(result)
        } else {
            Err(err)
        }
    }
}

pub fn system_handle_information<'a>() -> SystemHandleInfoIter<'a> {
    let mut size: ULONG = 0;
    unsafe {
        let mut result = vec![0u8; 16 * 1024];
        let err = loop {
            let err = ZwQuerySystemInformation(
                SystemHandleInformation,
                transmute(result.as_mut_ptr()),
                result.len() as u32,
                &mut size,
            );
            if err != STATUS_INFO_LENGTH_MISMATCH {
                break err;
            }
            result.resize(result.len() * 2, 0u8);
        };
        if NT_SUCCESS(err) {
            SystemHandleInfoIter::from(result)
        } else {
            SystemHandleInfoIter::new()
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SYSTEM_MODULE_INFORMATION_ENTRY {
    pub Section: usize,
    pub MappedBase: usize,
    pub ImageBase: PVOID,
    pub ImageSize: ULONG,
    pub Flags: ULONG,
    pub LoadOrderIndex: USHORT,
    pub InitOrderIndex: USHORT,
    pub LoadCount: USHORT,
    pub OffsetToFileName: USHORT,
    pub FullPathName: [u8; 256],
}

#[repr(C)]
pub struct SYSTEM_MODULE_INFORMATION {
    Count: u32,
    Module: [SYSTEM_MODULE_INFORMATION_ENTRY; 1],
}

impl SYSTEM_MODULE_INFORMATION_ENTRY {
    pub fn full_path(&self) -> &[u8] {
        let len = self.FullPathName.len();
        let len = self
            .FullPathName
            .iter()
            .position(|&x| x == 0)
            .unwrap_or(len);
        &self.FullPathName[..len]
    }

    #[inline(always)]
    pub fn full_path_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(self.full_path()) }
    }
}

pub fn system_module_list<'a>(
) -> Result<impl Iterator<Item = &'a SYSTEM_MODULE_INFORMATION_ENTRY>, NTSTATUS> {
    let v = read_system_information(SystemModuleInformation, 0)?;

    let smi = BufferType::<SYSTEM_MODULE_INFORMATION>::from_vec(v);
    let p = smi.Module.as_ptr();
    let mut i = 0;
    Ok(core::iter::from_fn(move || unsafe {
        if i >= smi.Count {
            return None;
        }
        let m = &*p.offset(i as isize);
        i += 1;
        Some(m)
    }))
}

pub trait SystemThreadInformation {
    fn state(&self) -> &'static str;
    fn wait_reason(&self) -> &'static str;
    fn priority(&self) -> &'static str;
    fn status(&self) -> String;
}

pub fn priority_str(p: u32) -> &'static str {
    use winapi::um::winbase::*;
    match p {
        THREAD_PRIORITY_LOWEST => "Lowest",
        THREAD_PRIORITY_BELOW_NORMAL => "BelowNormal",
        THREAD_PRIORITY_NORMAL => "Normal",
        THREAD_PRIORITY_HIGHEST => "Highest",
        THREAD_PRIORITY_ABOVE_NORMAL => "AboveNormal",
        THREAD_PRIORITY_ERROR_RETURN => "ErrorReturn",
        THREAD_PRIORITY_TIME_CRITICAL => "TimeCritical",
        THREAD_PRIORITY_IDLE => "Idle",
        _ => "-",
    }
}

impl SystemThreadInformation for SYSTEM_THREAD_INFORMATION {
    fn state(&self) -> &'static str {
        use ntapi::ntkeapi::*;

        match self.ThreadState {
            Initialized => "Initialized",
            Ready => "Ready",
            Running => "Running",
            Standby => "Standby",
            Terminated => "Terminated",
            Waiting => "Waiting",
            Transition => "Transition",
            DeferredReady => "DeferredReady",
            GateWaitObsolete => "GateWaitObsolete",
            WaitingForProcessInSwap => "WaitingForProcessInSwap",
            // MaximumThreadState => "MaximumThreadState",
            _ => "-",
        }
    }

    fn wait_reason(&self) -> &'static str {
        use ntapi::ntkeapi::*;

        match self.WaitReason {
            Executive => "Executive",
            FreePage => "FreePage",
            PageIn => "PageIn",
            PoolAllocation => "PoolAllocation",
            DelayExecution => "DelayExecution",
            Suspended => "Suspended",
            UserRequest => "UserRequest",
            WrExecutive => "WrExecutive",
            WrFreePage => "WrFreePage",
            WrPageIn => "WrPageIn",
            WrPoolAllocation => "WrPoolAllocation",
            WrDelayExecution => "WrDelayExecution",
            WrSuspended => "WrSuspended",
            WrUserRequest => "WrUserRequest",
            WrEventPair => "WrEventPair",
            WrQueue => "WrQueue",
            WrLpcReceive => "WrLpcReceive",
            WrLpcReply => "WrLpcReply",
            WrVirtualMemory => "WrVirtualMemory",
            WrPageOut => "WrPageOut",
            WrRendezvous => "WrRendezvous",
            // Spare2 => "Spare2",
            // Spare3 => "Spare3",
            // Spare4 => "Spare4",
            // Spare5 => "Spare5",
            WrCalloutStack => "WrCalloutStack",
            WrKernel => "WrKernel",
            WrResource => "WrResource",
            WrPushLock => "WrPushLock",
            WrMutex => "WrMutex",
            WrQuantumEnd => "WrQuantumEnd",
            WrDispatchInt => "WrDispatchInt",
            WrPreempted => "WrPreempted",
            WrYieldExecution => "WrYieldExecution",
            WrFastMutex => "WrFastMutex",
            WrGuardedMutex => "WrGuardedMutex",
            WrRundown => "WrRundown",
            WrAlertByThreadId => "WrAlertByThreadId",
            WrDeferredPreempt => "WrDeferredPreempt",
            // MaximumWaitReason => "MaximumWaitReason",
            _ => "-",
        }
    }

    fn priority(&self) -> &'static str {
        priority_str(self.Priority as u32)
    }

    fn status(&self) -> String {
        let st = self.state();
        if st == "Waiting" {
            format!("Waiting: {}", self.wait_reason())
        } else {
            st.to_string()
        }
    }
}

pub trait SystemHandleInformation {
    fn pid(&self) -> u32;
    fn type_name(&self) -> &'static str;
}

impl SystemHandleInformation for SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    #[inline]
    fn pid(&self) -> u32 {
        self.UniqueProcessId as u32
    }

    fn type_name(&self) -> &'static str {
        ""
    }
}

pub fn get_mapped_file_name(handle: HANDLE, base: usize) -> Option<String> {
    struct MEMORY_MAPPED_FILE_NAME_INFORMATION {
        name: UNICODE_STRING,
        buffer: [WCHAR; 512],
    }

    let mut buffer: MEMORY_MAPPED_FILE_NAME_INFORMATION = unsafe { zeroed() };
    buffer.name.Length = 0;
    buffer.name.Buffer = buffer.buffer.as_mut_ptr();
    let mut len: usize = 0;
    unsafe {
        use super::string::UnicodeUtil;

        let r = ZwQueryVirtualMemory(
            handle,
            transmute(base),
            MemoryMappedFilenameInformation as u32,
            transmute(&mut buffer),
            size_of_val(&buffer),
            &mut len,
        );
        if NT_SUCCESS(r) {
            Some(buffer.name.to_string())
        } else {
            None
        }
    }
}

pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SHIFT: usize = 12;

pub fn query_working_set_ex(
    handle: HANDLE,
    base: usize,
    size: usize,
) -> Result<Vec<MEMORY_WORKING_SET_EX_INFORMATION>, NTSTATUS> {
    let count = size / PAGE_SIZE;
    let mut len: usize = 0;
    unsafe {
        let mut infos = vec![zeroed::<MEMORY_WORKING_SET_EX_INFORMATION>(); count];
        for i in 0..count {
            infos[i].VirtualAddress = transmute(base + PAGE_SIZE * i);
        }
        let r = ZwQueryVirtualMemory(
            handle,
            null_mut(),
            MemoryWorkingSetExInformation as u32,
            transmute(infos.as_mut_ptr()),
            infos.len() * size_of::<MEMORY_WORKING_SET_EX_INFORMATION>(),
            &mut len,
        );
        if NT_SUCCESS(r) {
            Ok(infos)
        } else {
            Err(r)
        }
    }
}

// https://docs.microsoft.com/en-us/windows/win32/devnotes/ldrregisterdllnotification
pub type FnLdrRegisterDllNotification = unsafe extern "system" fn(
    flags: ULONG,
    callback: PLDR_DLL_NOTIFICATION_FUNCTION,
    context: PVOID,
    cookie: *mut usize,
) -> NTSTATUS;

// ----------------- utils -----------------

pub fn find_handle<'a>(
    type_index: u32,
    access: u32,
) -> impl Iterator<Item = &'a SYSTEM_HANDLE_TABLE_ENTRY_INFO> {
    system_handle_information().filter(move |h| {
        type_index == h.ObjectTypeIndex as u32 && h.GrantedAccess & access == access
    })
}

pub trait CheckNtStatus {
    type R;

    fn check(self) -> Result<Self::R, NTSTATUS>;
    fn check_err(self, err: &str) -> Result<Self::R, String>;
}

impl<T> CheckNtStatus for Result<T, NTSTATUS> {
    type R = T;

    fn check(self) -> Result<Self::R, NTSTATUS> {
        self
    }

    fn check_err(self, err: &str) -> Result<Self::R, String> {
        self.map_err(|e| format!("{}: 0x{:x}", err, e))
    }
}

impl CheckNtStatus for NTSTATUS {
    type R = ();

    fn check(self) -> Result<Self::R, NTSTATUS> {
        if NT_SUCCESS(self) {
            Ok(())
        } else {
            Err(self)
        }
    }

    fn check_err(self, err: &str) -> Result<Self::R, String> {
        if NT_SUCCESS(self) {
            Ok(())
        } else {
            Err(format!("{}: 0x{:x}", err, self))
        }
    }
}

pub fn get_pbi() -> Result<PROCESS_BASIC_INFORMATION, NTSTATUS> {
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    unsafe {
        ZwQueryInformationProcess(
            ZwCurrentProcess,
            ProcessBasicInformation,
            transmute(&mut pbi),
            size_of_val(&pbi) as u32,
            null_mut(),
        )
        .check()?;
        Ok(pbi)
    }
}

pub fn get_peb() -> &'static mut PEB {
    unsafe { transmute(get_pbi().unwrap().PebBaseAddress) }
}

#[inline]
pub fn traverse_list<F: FnMut(usize) -> bool>(list: &LIST_ENTRY, mut callback: F) {
    unsafe {
        let first: *const LIST_ENTRY = transmute(list.Flink);
        let mut current = first;
        while current != null() && (*current).Flink as *const LIST_ENTRY != first {
            if !callback(current as usize) {
                break;
            }
            current = (*current).Flink;
        }
    }
}

pub fn foreach_in_initorder<F>(ldr: &PEB_LDR_DATA, mut callback: F)
where
    F: FnMut(&mut LDR_DATA_TABLE_ENTRY) -> bool,
{
    traverse_list(&ldr.InInitializationOrderModuleList, |p| {
        let p: *mut LDR_DATA_TABLE_ENTRY = unsafe { transmute(p - size_of::<LPVOID>() * 4) };
        callback(unsafe { transmute(p) })
    });
}

pub fn foreach_in_loadorder<F>(ldr: &PEB_LDR_DATA, mut callback: F)
where
    F: FnMut(&mut LDR_DATA_TABLE_ENTRY) -> bool,
{
    traverse_list(&ldr.InLoadOrderModuleList, |p| {
        let p: *mut LDR_DATA_TABLE_ENTRY = unsafe { transmute(p - size_of::<LPVOID>() * 0) };
        callback(unsafe { transmute(p) })
    });
}

pub fn foreach_in_memoryorder<F>(ldr: &PEB_LDR_DATA, mut callback: F)
where
    F: FnMut(&mut LDR_DATA_TABLE_ENTRY) -> bool,
{
    traverse_list(&ldr.InMemoryOrderModuleList, |p| {
        let p: *mut LDR_DATA_TABLE_ENTRY = unsafe { transmute(p - size_of::<LPVOID>() * 2) };
        callback(unsafe { transmute(p) })
    });
}
