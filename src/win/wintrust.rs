
use core::{ptr, mem};
use std::ffi::*;
use winapi::{shared::{minwindef::{BOOL, MAX_PATH}, winerror::TRUST_E_NOSIGNATURE}, um::{handleapi::INVALID_HANDLE_VALUE, winnt::*}};
use winapi::um::wincrypt::*;
use winapi::shared::minwindef::FILETIME;

use crate::*;

use super::time::*;
use std::error::Error;
use std::os::windows::io::AsRawHandle;
use winapi::shared::guiddef::GUID;
use winapi::um::softpub::WINTRUST_ACTION_GENERIC_VERIFY_V2;

#[link(name="wintrust")]
extern "system" {
    pub fn WinVerifyTrust(hwnd: HANDLE, pgActionId: *const GUID, pWvtData: *const WINTRUST_DATA) -> i32;
    pub fn WTHelperProvDataFromStateData(hStateData: HANDLE) -> PCRYPT_PROVIDER_DATA;
    pub fn WTHelperGetProvSignerFromChain(pProvData: PCRYPT_PROVIDER_DATA, idxSigner: u32, fCounterSigner: u32, idxCounterSigner: u32) -> PCRYPT_PROVIDER_SGNR;

    pub fn CryptCATAdminAcquireContext(phCatAdmin: *mut HANDLE, pgSubsystem: *const GUID, dwFlags: u32) -> BOOL;
    pub fn CryptCATAdminReleaseContext(hCatAdmin: HANDLE);
    pub fn CryptCATAdminCalcHashFromFileHandle(hFile: HANDLE, pcbHash: *mut u32, pbHash: *mut u8, dwFlags: u32) -> BOOL;

    pub fn CryptCATAdminEnumCatalogFromHash(hCatAdmin: HANDLE, pbHash: *const u8, cbHash: u32, dwFlags: u32, phPrevCatInfo: *mut isize) -> isize;
    pub fn CryptCATCatalogInfoFromContext(hCatInfo: isize, psCatInfo: *mut CATALOG_INFO, dwFlags: u32) -> BOOL;
    pub fn CryptCATAdminReleaseCatalogContext(hCatAdmin: HANDLE, hCatInfo: isize, dwFlags: u32) -> BOOL;
    // Only Win8+
    // fn CryptCATAdminAcquireContext2(
    //     ph_cat_admin: *mut isize, 
    //     pg_subsystem: *const Guid, 
    //     pwsz_hash_algorithm: *const u16, 
    //     p_strong_hash_policy: *mut CERT_STRONG_SIGN_PARA, 
    //     dw_flags: u32
    // ) -> BOOL;
}

pub type PCRYPT_PROVIDER_DATA = PVOID;
pub type PCRYPT_PROVIDER_SGNR = *mut CRYPT_PROVIDER_SGNR;

const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

#[derive(Deref)]
pub struct CMsgSignerInfo(BufferType<CMSG_SIGNER_INFO>);

impl CMsgSignerInfo {
    pub fn auth_attrs(&self) -> &[CRYPT_ATTRIBUTE] {
        unsafe {
            std::slice::from_raw_parts(self.AuthAttrs.rgAttr, self.AuthAttrs.cAttr as usize)
        }
    }

    pub fn unauth_attrs(&self) -> &[CRYPT_ATTRIBUTE] {
        unsafe {
            std::slice::from_raw_parts(self.UnauthAttrs.rgAttr, self.UnauthAttrs.cAttr as usize)
        }
    }

    fn GetTimeStampSignerInfo(&self) -> Option<CMsgSignerInfo> {
        unsafe {
            for a in self.unauth_attrs() {
                let attr = CStr::from_ptr(a.pszObjId).to_str();
                if attr == Ok(szOID_RSA_counterSign) {
                    let mut len = 0u32;
                    if 0 == CryptDecodeObject(
                        ENCODING, PKCS7_SIGNER_INFO, (*a.rgValue).pbData,
                        (*a.rgValue).cbData, 0, ptr::null_mut(), &mut len
                    ) { return None; }
                    let mut r = BufferType::<CMSG_SIGNER_INFO>::with_size(len as usize);
                    if 0 == CryptDecodeObject(
                        ENCODING, PKCS7_SIGNER_INFO, (*a.rgValue).pbData,
                        (*a.rgValue).cbData, 0, mem::transmute(r.as_mut_ptr()), &mut len
                    ) { return None; }
                    return Some(CMsgSignerInfo(r));
                }
            }
        }
        None
    }

    pub fn time_stamp(&self) -> Option<DateTime<Utc>> {
        unsafe {
            for a in self.auth_attrs() {
                let attr = CStr::from_ptr(a.pszObjId).to_str();
                if attr == Ok(szOID_RSA_signingTime) {
                    let mut ft: FILETIME = mem::zeroed();
                    let mut len = mem::size_of_val(&ft) as u32;
                    let r = CryptDecodeObject(
                        ENCODING, a.pszObjId, (*a.rgValue).pbData,
                        (*a.rgValue).cbData, 0, mem::transmute(&mut ft), &mut len);
                    if r == 0 { return None; }
                    return Some(filetime_to_utc(ft));
                }
            }
        }
        self.GetTimeStampSignerInfo().and_then(|r| r.time_stamp())
    }

    pub fn to_certinfo(&self) -> CERT_INFO {
        unsafe {
            let mut ci: CERT_INFO = mem::zeroed();
            ci.Issuer = self.Issuer;
            ci.SerialNumber = self.SerialNumber;
            return ci;
        }
    }
}

pub struct CryptMsg(HCRYPTMSG);

impl CryptMsg {
    pub fn get_signer_info(&self) -> Option<CMsgSignerInfo> {
        let mut si_size = 0u32;
        unsafe {
            if 0 == CryptMsgGetParam(self.0, CMSG_SIGNER_INFO_PARAM, 0, ptr::null_mut(), &mut si_size) { return None; }
            // Allocate memory for signer information.
            let mut si = BufferType::<CMSG_SIGNER_INFO>::with_size(si_size as usize);
            // Get Signer Information.
            if CryptMsgGetParam(
                self.0, CMSG_SIGNER_INFO_PARAM, 0, mem::transmute(si.as_mut_ptr()), &mut si_size
            ) > 0 { Some(CMsgSignerInfo(si)) } else { None }
        }
    }
}

impl Drop for CryptMsg {
    fn drop(&mut self) { unsafe { CryptMsgClose(self.0); } }
}

pub struct CertStore(HCERTSTORE);

impl CertStore {
    pub fn find_cert(&self, ci: &CERT_INFO) -> Option<CertContext> {
        unsafe {
            let p = CertFindCertificateInStore(self.0, ENCODING, 0, CERT_FIND_SUBJECT_CERT, mem::transmute(ci), ptr::null());
            if p.is_null() { None } else { Some(CertContext(p)) }
        }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) { unsafe { CertCloseStore(self.0, 0); } }
}

pub struct CertContext(PCCERT_CONTEXT);

impl CertContext {
    pub fn cert_name_to_str(blob: PCERT_NAME_BLOB) -> Vec<u16> {
        unsafe {
            let len = CertNameToStrW(ENCODING, blob, CERT_X500_NAME_STR, ptr::null_mut(), 0);
            let mut result = vec![0; len as usize];
            CertNameToStrW(ENCODING, blob, CERT_X500_NAME_STR, result.as_mut_ptr(), len);
            result
        }
    }

    pub fn get_name(&self) -> Option<String> {
        unsafe {
            let cert = self.0 as usize as PCERT_CONTEXT;
            cert.as_mut().and_then(|c| c.pCertInfo.as_mut()).map(|info| {
                let name = Self::cert_name_to_str(&mut info.Subject);
                String::from_utf16_lossy(&name)
            })
        }
    }

    pub fn get_signer_name(&self) -> Option<String> {
        unsafe {
            let len = CertGetNameStringW(
                self.0, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, ptr::null_mut(), ptr::null_mut(), 0
            );
            if 0 == len { return None; }
            let mut result = vec![0; len as usize];
            // Get subject name.
            if CertGetNameStringW(
                self.0, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, ptr::null_mut(), result.as_mut_ptr(), len
            ) == 0 { return None; }
            Some(String::from_utf16_lossy(&result))
        }
    }
}

impl Drop for CertContext {
    fn drop(&mut self) { unsafe { CertFreeCertificateContext(self.0); } }
}

pub struct CATAdmin(HANDLE);

impl CATAdmin {
    pub fn acquire() -> Option<Self> {
        unsafe {
            let mut phCatAdmin = ptr::null_mut();
            if CryptCATAdminAcquireContext(&mut phCatAdmin, &DRIVER_ACTION_VERIFY, 0) > 0 {
                Some(Self(phCatAdmin))
            } else { None }
        }
    }

    fn calc_hash_from_file_handle<'a>(file: HANDLE, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        unsafe {
            let mut hash_len = buf.len() as u32;
            if CryptCATAdminCalcHashFromFileHandle(file, &mut hash_len, buf.as_mut_ptr(), 0) > 0 {
                Some(std::slice::from_raw_parts(
                    buf.as_ptr(), hash_len as usize
                ).into())
            } else { None }
        }
    }
}

#[cfg(not(target_arch = "x86"))]
impl Drop for CATAdmin {
    fn drop(&mut self) {
        unsafe {
            CryptCATAdminReleaseContext(self.0);
        }
    }
}

pub fn crypt_query_object(file_path: LPCWSTR) -> Option<(CryptMsg, CertStore)> {
    unsafe {
        let mut dwEncoding = 0u32;
        let mut dwContentType = 0u32;
        let mut dwFormatType = 0u32;
        let mut hMsg: HCRYPTMSG = ptr::null_mut();
        let mut hStore: HCERTSTORE = ptr::null_mut();
        if CryptQueryObject(CERT_QUERY_OBJECT_FILE, mem::transmute(file_path),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            &mut dwEncoding, &mut dwContentType, &mut dwFormatType, &mut hStore, &mut hMsg, ptr::null_mut()
        ) == 0 { None } else { Some((CryptMsg(hMsg), CertStore(hStore))) }
    }
}

pub fn read_signature(file_path: LPCWSTR) -> Option<String> {
    let (msg, store) = crypt_query_object(file_path)?;
    let si = msg.get_signer_info()?;
    store.find_cert(&si.to_certinfo())?.get_name()
}

pub fn read_signature_timestamp(file_path: LPCWSTR) -> Option<(String, DateTime<Utc>)> {
    let (msg, store) = crypt_query_object(file_path)?;
    let si = msg.get_signer_info()?;
    Some((store.find_cert(&si.to_certinfo())?.get_name()?, si.time_stamp()?))
}

#[repr(C)]
pub struct WINTRUST_FILE_INFO {
    pub cbStruct: u32,
    pub pcwszFilePath: *const u16,
    pub hFile: HANDLE,
    pub pgKnownSubject: *const GUID,
}

#[repr(C)]
pub struct CATALOG_INFO {
    pub cbStruct: u32,
    pub wszCatalogFile: [u16; MAX_PATH],
}

#[repr(C)]
pub struct WINTRUST_DATA {
    pub cbStruct: u32,
    pub pPolicyCallbackData: *mut c_void,
    pub pSipClientData: *mut c_void,
    pub dwUIChoice: u32,
    pub fdwRevocationChecks: u32,
    pub dwUnionChoice: u32,
    pub pFile: *const WINTRUST_FILE_INFO,
    pub dwStateAction: u32,
    pub hWVTStateData: HANDLE,
    pub pwszUrlReference: *mut u16,
    pub dwProvFlags: u32,
    pub dwUiContext: u32,
    // #if (NTDDI_VERSION >= NTDDI_WIN8)
    // pub pSignatureSettings: *mut (),
}

const WTD_UI_ALL: u32              = 1;
const WTD_UI_NONE: u32             = 2;
const WTD_UI_NOBAD: u32            = 3;
const WTD_UI_NOGOOD: u32           = 4;
const WTD_REVOKE_NONE: u32         = 0x00000000;
const WTD_REVOKE_WHOLECHAIN: u32   = 0x00000001;
const WTD_CHOICE_FILE: u32         = 1;
const WTD_CHOICE_CATALOG: u32      = 2;
const WTD_CHOICE_BLOB: u32         = 3;
const WTD_CHOICE_SIGNER: u32       = 4;
const WTD_CHOICE_CERT: u32         = 5;

// PhVerifyFileEx
pub fn verify_file(path: &str) -> Result<(i32, Vec<CertContext>), Box<dyn Error>> {
    unsafe {
        let file = std::fs::File::open(path)?;
        let wpath = path.to_unicode_with_null();
        let fileHandle = file.as_raw_handle();

        let mut fileInfo: WINTRUST_FILE_INFO = mem::zeroed();
        fileInfo.cbStruct = mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        fileInfo.pcwszFilePath = wpath.as_ptr();
        fileInfo.hFile = fileHandle;

        // let flags = PH_VERIFY_PREVENT_NETWORK_ACCESS;
        let flags = 0;
        let v = WinVerify::init(
            flags,
            WTD_CHOICE_FILE,
            &fileInfo,
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            ptr::null_mut()
        );
        let status = v.verify_trust();
        if status == TRUST_E_NOSIGNATURE {
            let cat = CATAdmin::acquire().check_errstr("CryptCATAdminAcquireContext")?;
            let mut hash = [0u8; 32];
            Ok(CATAdmin::calc_hash_from_file_handle(fileHandle, &mut hash).and_then(|hash| {
                let cat_info = CryptCATAdminEnumCatalogFromHash(
                    cat.0, hash.as_ptr(), hash.len() as u32, 0, ptr::null_mut()
                );
                let mut ci: CATALOG_INFO = mem::zeroed();
                ci.cbStruct = mem::size_of::<CATALOG_INFO>() as u32;
                let b = CryptCATCatalogInfoFromContext(cat_info, &mut ci, 0);
                CryptCATAdminReleaseCatalogContext(cat.0, cat_info, 0);
                if b == 0 { return None; }

                let mut hash_tag = String::new();
                for &n in hash {
                    hash_tag += &format!("{:02X}", n);
                }
                // println!("catalog: {}, hash: {}", ci.wszCatalogFile.to_utf8(), hash_tag);
                let hash_tag = hash_tag.to_unicode_with_null();

                let mut wci: WINTRUST_CATALOG_INFO = mem::zeroed();
                wci.cbStruct = mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
                wci.pcwszCatalogFilePath = ci.wszCatalogFile.as_ptr();
                wci.pcwszMemberFilePath = wpath.as_ptr();
                wci.hMemberFile = fileHandle;
                wci.pcwszMemberTag = hash_tag.as_ptr();
                wci.pbCalculatedFileHash = hash.as_ptr();
                wci.cbCalculatedFileHash = hash.len() as u32;
                // wci.hCatAdmin = cat.0;

                let v = WinVerify::init(
                    flags,
                    WTD_CHOICE_CATALOG,
                    mem::transmute(&wci),
                    &DRIVER_ACTION_VERIFY,
                    ptr::null_mut()
                );
                Some((v.verify_trust(), v.signatures()))
            }).unwrap_or_else(|| (status, v.signatures())))
        } else {
            Ok((status, v.signatures()))
        }
    }
}

const WTD_STATEACTION_IGNORE: u32 =           0x00000000;
const WTD_STATEACTION_VERIFY: u32 =           0x00000001;
const WTD_STATEACTION_CLOSE: u32 =            0x00000002;
const WTD_STATEACTION_AUTO_CACHE: u32 =       0x00000003;
const WTD_STATEACTION_AUTO_CACHE_FLUSH: u32 = 0x00000004;

const WTD_PROV_FLAGS_MASK: u32                      = 0x0000FFFF;
const WTD_USE_IE4_TRUST_FLAG: u32                   = 0x00000001;
const WTD_NO_IE4_CHAIN_FLAG: u32                    = 0x00000002;
const WTD_NO_POLICY_USAGE_FLAG: u32                 = 0x00000004;
const WTD_REVOCATION_CHECK_NONE: u32                = 0x00000010;
const WTD_REVOCATION_CHECK_END_CERT: u32            = 0x00000020;
const WTD_REVOCATION_CHECK_CHAIN: u32               = 0x00000040;
const WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: u32  = 0x00000080;
const WTD_SAFER_FLAG: u32                           = 0x00000100;
const WTD_HASH_ONLY_FLAG: u32                       = 0x00000200;
const WTD_USE_DEFAULT_OSVER_CHECK: u32              = 0x00000400;
const WTD_LIFETIME_SIGNING_FLAG: u32                = 0x00000800;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32             = 0x00001000; // affects CRL retrieval and AIA retrieval
const WTD_DISABLE_MD2_MD4: u32                      = 0x00002000;
const WTD_MOTW: u32                                 = 0x00004000; // Mark-Of-The-Web
const WTD_CODE_INTEGRITY_DRIVER_MODE: u32           = 0x00008000; // Code Integrity driver mode

const PH_VERIFY_PREVENT_NETWORK_ACCESS: u32 = 0x1;
const PH_VERIFY_VIEW_PROPERTIES: u32 = 0x2;

const DRIVER_ACTION_VERIFY: GUID = GUID {
    Data1: 0xf750e6c3, Data2: 0x38ee, Data3: 0x11d1,
    Data4: [0x85, 0xe5, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

#[repr(C)]
pub struct CRYPT_PROVIDER_SGNR {
    pub cbStruct: u32,
    pub sftVerifyAsOf: FILETIME,
    pub csCertChain: u32,
    pub pasCertChain: *mut CRYPT_PROVIDER_CERT,
    pub dwSignerType: u32,
    pub psSigner: *mut CMSG_SIGNER_INFO,
    pub dwError: u32,
    pub csCounterSigners: u32,
    pub pasCounterSigners: *mut CRYPT_PROVIDER_SGNR,
    pub pChainContext: *mut CERT_CHAIN_CONTEXT,
}
#[repr(C)]
pub struct CRYPT_PROVIDER_CERT {
    pub cbStruct: u32,
    pub pCert: *mut CERT_CONTEXT,
    pub fCommercial: BOOL,
    pub fTrustedRoot: BOOL,
    pub fSelfSigned: BOOL,
    pub fTestCert: BOOL,
    pub dwRevokedReason: u32,
    pub dwConfidence: u32,
    pub dwError: u32,
    pub pTrustListContext: *mut CTL_CONTEXT,
    pub fTrustListSignerCert: BOOL,
    pub pCtlContext: *mut CTL_CONTEXT,
    pub dwCtlError: u32,
    pub fIsCyclic: BOOL,
    pub pChainElement: *mut CERT_CHAIN_ELEMENT,
}

#[repr(C)]
pub struct WINTRUST_CATALOG_INFO {
    pub cbStruct: u32,
    pub dwCatalogVersion: u32,
    pub pcwszCatalogFilePath: *const u16,
    pub pcwszMemberTag: *const u16,
    pub pcwszMemberFilePath: *const u16,
    pub hMemberFile: HANDLE,
    pub pbCalculatedFileHash: *const u8,
    pub cbCalculatedFileHash: u32,
    pub pcCatalogContext: *mut CTL_CONTEXT,
    // #if (NTDDI_VERSION >= NTDDI_WIN8)
    // pub hCatAdmin: HANDLE,
}

#[derive(Deref, DerefMut)]
pub struct WinVerify(#[deref] #[deref_mut] WINTRUST_DATA, *const GUID);

impl WinVerify {
    pub fn init(Flags: u32, UnionChoice: u32, UnionData: *const WINTRUST_FILE_INFO, ActionId: *const GUID, PolicyCallbackData: PVOID) -> Self {
        unsafe {
            let mut trustData: WINTRUST_DATA = mem::zeroed();
            trustData.cbStruct = mem::size_of::<WINTRUST_DATA>() as u32;
            trustData.pPolicyCallbackData = PolicyCallbackData;
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            trustData.dwUnionChoice = UnionChoice;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.dwProvFlags = WTD_SAFER_FLAG;
        
            trustData.pFile = UnionData;
        
            if Flags & PH_VERIFY_PREVENT_NETWORK_ACCESS > 0 {
                trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
                trustData.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
            }
            Self(trustData, ActionId)
        }
    }

    pub fn signatures(&self) -> Vec<CertContext> {
        let mut result = vec![];

        unsafe {
            let provData = WTHelperProvDataFromStateData(self.hWVTStateData);
            if provData.is_null() { return result; }

            for i in 0..100 {
                let sgnr = WTHelperGetProvSignerFromChain(provData, i, 0, 0);
                if sgnr.is_null() { break; }

                result.push(CertContext(
                    CertDuplicateCertificateContext(sgnr.as_ref().unwrap().pasCertChain.as_ref().unwrap().pCert)
                ));
            }
            result
        }
    }

    pub fn verify_trust(&self) -> i32 {
        unsafe {
            WinVerifyTrust(INVALID_HANDLE_VALUE, self.1, &self.0)
        }
    }
}

impl Drop for WinVerify {
    fn drop(&mut self) {
        unsafe {
            self.0.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(INVALID_HANDLE_VALUE, self.1, &self.0);
        }
    }
}