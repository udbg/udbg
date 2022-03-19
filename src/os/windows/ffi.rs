
use core::ffi::c_void;
use winapi::um::winnt::*;
use winapi::shared::minwindef::*;

// #[repr(C)]
// pub struct IMAGEHLP_MODULE64 {
//     pub SizeOfStruct: DWORD,           // set to sizeof(IMAGEHLP_MODULE64)
//     pub BaseOfImage: u64,            // base load address of module
//     pub ImageSize: DWORD,              // virtual size of the loaded module
//     pub TimeDateStamp: DWORD,          // date/time stamp from pe header
//     pub CheckSum: DWORD,               // checksum from the pe header
//     pub NumSyms: DWORD,                // number of symbols in the symbol table
//     pub SymType: DWORD,                // type of symbols loaded
//     pub ModuleName: [WCHAR; 32],         // module name
//     pub ImageName: [WCHAR; 256],         // image name
//     pub LoadedImageName: [WCHAR; 256],   // symbol file name
//     pub LoadedPdbName: [WCHAR; 256],     // pdb file name
//     pub CVSig: DWORD,                  // Signature of the CV record in the debug directories
//     pub CVData: [WCHAR; MAX_PATH * 3],   // Contents of the CV record
//     pub PdbSig: DWORD,                 // Signature of PDB
//     pub PdbSig70: DWORD,               // Signature of PDB (VC 7 and up)
//     pub PdbAge: DWORD,                 // DBI age of pdb
//     pub PdbUnmatched: BOOL,           // loaded an unmatched pdb
//     pub DbgUnmatched: BOOL,           // loaded an unmatched dbg
//     pub LineNumbers: BOOL,            // we have line number information
//     pub GlobalSymbols: BOOL,          // we have internal symbol information
//     pub TypeInfo: BOOL,               // we have type information
//     pub SourceIndexed: BOOL,          // pdb supports source server
//     pub Publics: BOOL,                // contains public symbols
//     pub MachineType: DWORD,            // IMAGE_FILE_MACHINE_XXX from ntimage.h and winnt.h
//     pub Reserved: DWORD,               // Padding - don't remove.
// }

// extern "system" {
    // https://docs.microsoft.com/zh-cn/windows/win32/api/dbghelp/nf-dbghelp-symsetoptions
    // pub fn SymSetOptions(options: u32) -> u32;
    // pub fn SymGetOptions() -> u32;
    // pub fn SymGetModuleInfoW64(handle: HANDLE, address: u64, im: *mut IMAGEHLP_MODULE64) -> u32;
    // pub fn SymAddSymbolW(handle: HANDLE, base: usize, name: PCWSTR, address: usize, size: u32, flags: u32) -> u32;
// }

pub const SYMOPT_CASE_INSENSITIVE: u32 = 0x00000001;
pub const SYMOPT_UNDNAME: u32 = 0x00000002;

#[repr(C)]
pub struct MINIDUMP_CALLBACK_INPUT {
    pub ProcessId: u32,
    pub ProcessHandle: HANDLE,
    pub CallbackType: u32,
}

#[repr(C)]
pub struct MINIDUMP_MEMORY_INFO {
    pub BaseAddress: u64,
    pub AllocationBase: u64,
    pub AllocationProtect: u32,
    pub __alignment1: u32,
    pub RegionSize: u64,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
    pub __alignment2: u32,
}

#[repr(C)]
pub struct MINIDUMP_CALLBACK_OUTPUT {
    pub VmRegion: MINIDUMP_MEMORY_INFO,
    pub Continue: BOOL,
}

pub type MINIDUMP_CALLBACK_ROUTINE = unsafe extern "system" fn(
    *const c_void, *const MINIDUMP_CALLBACK_INPUT, *mut MINIDUMP_CALLBACK_OUTPUT) -> BOOL;

#[repr(C)]
pub struct MINIDUMP_CALLBACK_INFORMATION {
    pub CallbackRoutine: MINIDUMP_CALLBACK_ROUTINE,
    pub CallbackParam: *const c_void,
}

#[repr(C)]
pub struct MINIDUMP_EXCEPTION_INFORMATION {
    pub ThreadId: u32,
    pub ExceptionPointers: PEXCEPTION_POINTERS,
    pub ClientPointers: BOOL,
}

extern "system" {
    // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
    pub fn MiniDumpWriteDump(
        handle: HANDLE, pid: u32, file: HANDLE,
        dump_type: usize,
        ExceptionParam: Option<&MINIDUMP_EXCEPTION_INFORMATION>,
        UserStreamParam: PVOID,
        CallbackParam: *const MINIDUMP_CALLBACK_INFORMATION
    ) -> u32;
}

pub const MiniDumpNormal                        :usize = 0x00000000;
pub const MiniDumpWithDataSegs                  :usize = 0x00000001;
pub const MiniDumpWithFullMemory                :usize = 0x00000002;
pub const MiniDumpWithHandleData                :usize = 0x00000004;
pub const MiniDumpFilterMemory                  :usize = 0x00000008;
pub const MiniDumpScanMemory                    :usize = 0x00000010;
pub const MiniDumpWithUnloadedModules           :usize = 0x00000020;
pub const MiniDumpWithIndirectlyReferencedMemory:usize = 0x00000040;
pub const MiniDumpFilterModulePaths             :usize = 0x00000080;
pub const MiniDumpWithProcessThreadData         :usize = 0x00000100;
pub const MiniDumpWithPrivateReadWriteMemory    :usize = 0x00000200;
pub const MiniDumpWithoutOptionalData           :usize = 0x00000400;
pub const MiniDumpWithFullMemoryInfo            :usize = 0x00000800;
pub const MiniDumpWithThreadInfo                :usize = 0x00001000;
pub const MiniDumpWithCodeSegs                  :usize = 0x00002000;
pub const MiniDumpWithoutAuxiliaryState         :usize = 0x00004000;
pub const MiniDumpWithFullAuxiliaryState        :usize = 0x00008000;
pub const MiniDumpWithPrivateWriteCopyMemory    :usize = 0x00010000;
pub const MiniDumpIgnoreInaccessibleMemory      :usize = 0x00020000;
pub const MiniDumpWithTokenInformation          :usize = 0x00040000;
pub const MiniDumpWithModuleHeaders             :usize = 0x00080000;
pub const MiniDumpFilterTriage                  :usize = 0x00100000;
pub const MiniDumpWithAvxXStateContext          :usize = 0x00200000;
pub const MiniDumpWithIptTrace                  :usize = 0x00400000;
pub const MiniDumpValidTypeFlags                :usize = 0x007fffff;

#[repr(C)]
pub enum MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0, // MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // UNICODE_STRING
    MemoryRegionInformation, // MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
    MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
    MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped
}

// typedef enum _MINIDUMP_CALLBACK_TYPE {
//     ModuleCallback,
//     ThreadCallback,
//     ThreadExCallback,
//     IncludeThreadCallback,
//     IncludeModuleCallback,
//     MemoryCallback,
//     CancelCallback,
//     WriteKernelMinidumpCallback,
//     KernelMinidumpStatusCallback,
//     RemoveMemoryCallback,
pub const IncludeVmRegionCallback: u32 = 10;
//     IoStartCallback,
//     IoWriteAllCallback,
//     IoFinishCallback,
//     ReadMemoryFailureCallback,
//     SecondaryFlagsCallback,
//     IsProcessSnapshotCallback,
//     VmStartCallback,
//     VmQueryCallback,
//     VmPreReadCallback,
//     VmPostReadCallback
// } MINIDUMP_CALLBACK_TYPE;

// #[repr(C)]
// pub union LDR_DLL_NOTIFICATION_DATA {
//     pub Loaded: LDR_DLL_LOADED_NOTIFICATION_DATA,
//     pub Unloaded: LDR_DLL_UNLOADED_NOTIFICATION_DATA,
// }

// #[repr(C)]
// pub struct LDR_DLL_LOADED_NOTIFICATION_DATA {
//     pub Flags: ULONG,                    //Reserved.
//     pub FullDllName: *const UNICODE_STRING,   //The full path name of the DLL module.
//     pub BaseDllName: *const UNICODE_STRING,   //The base file name of the DLL module.
//     pub DllBase: PVOID,                  //A pointer to the base address for the DLL in memory.
//     pub SizeOfImage: ULONG,              //The size of the DLL image, in bytes.
// }

// #[repr(C)]
// pub struct LDR_DLL_UNLOADED_NOTIFICATION_DATA {
//     pub Flags: ULONG,                    //Reserved.
//     pub FullDllName: *const UNICODE_STRING,   //The full path name of the DLL module.
//     pub BaseDllName: *const UNICODE_STRING,   //The base file name of the DLL module.
//     pub DllBase: PVOID,                  //A pointer to the base address for the DLL in memory.
//     pub SizeOfImage: ULONG,              //The size of the DLL image, in bytes.
// }

// pub const LDR_DLL_NOTIFICATION_REASON_LOADED: ULONG = 1;
// pub const LDR_DLL_NOTIFICATION_REASON_UNLOADED: ULONG = 2;
// pub type LDR_DLL_NOTIFICATION_FUNCTION = unsafe extern "system" fn(reason: ULONG, data: &LDR_DLL_NOTIFICATION_DATA, context: PVOID);

// extern "system" {
//     // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory
//     pub fn NtQueryVirtualMemory(handle: HANDLE, base: usize, class: MEMORY_INFORMATION_CLASS, info: PVOID, len: usize, out_len: PULONG) -> NTSTATUS;
// }