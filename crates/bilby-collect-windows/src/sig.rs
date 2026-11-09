//! Authenticode verification: embedded signature first, then the Windows
//! catalogs. Most Windows binaries are catalog-signed, so without the
//! fallback they'd look unsigned. The approach comes from System Informer
//! (docs/research/system-informer.md, idea 1); this is our own code.
//!
//! No network access: revocation checks are off (`WTD_REVOKE_NONE`) and
//! URL retrieval is cache-only (`WTD_CACHE_ONLY_URL_RETRIEVAL`), as ADR 0004
//! requires. See the `WINTRUST_DATA` documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data>.

use std::ffi::c_void;
use std::ptr;

use bilby_core::snapshot::{SigKind, SignatureStatus};
use windows::Win32::Foundation::{
    CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, HANDLE, HWND, TRUST_E_BAD_DIGEST,
    TRUST_E_CERT_SIGNATURE, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE,
    TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN,
};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext, CryptCATAdminAcquireContext2,
    CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
    CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALGORITHM, CERT_CONTEXT, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CTL_USAGE, CertGetEnhancedKeyUsage, CertGetNameStringW,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_UNION_CHOICE, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::{HRESULT, HSTRING, PCWSTR};

use crate::handle::OwnedHandle;
use crate::hash::hex;

/// EKU for "Windows System Component Verification", which Microsoft only
/// puts on certificates that sign Windows itself.
pub const EKU_WINDOWS_COMPONENT: &str = "1.3.6.1.4.1.311.10.3.6";

/// `cbStruct` for a Win32 struct. These structs are a few hundred bytes, so
/// the size always fits in a `u32`.
fn cb<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).expect("Win32 struct sizes fit in u32")
}

/// Checks the digital signature of the file at `path`.
pub fn verify(path: &str) -> SignatureStatus {
    let file = match OwnedHandle::open_read(path) {
        Ok(file) => file,
        Err(e) => {
            return SignatureStatus::Error {
                reason: e.message(),
            };
        }
    };
    match verify_embedded(path, &file) {
        Outcome::NoSignature => verify_catalog(path, &file),
        Outcome::Done(status) => status,
    }
}

/// Checks many files at once, spread over the machine's cores. Results are
/// in the same order as `paths`. Each worker thread keeps its own catalog
/// contexts, so this is much faster than calling [`verify`] in a loop.
pub fn verify_many(paths: &[String]) -> Vec<SignatureStatus> {
    let workers = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(paths.len().max(1));
    let chunk = paths.len().div_ceil(workers).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = paths
            .chunks(chunk)
            .map(|part| scope.spawn(move || part.iter().map(|p| verify(p)).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| {
                h.join().unwrap_or_else(|_| {
                    vec![
                        SignatureStatus::Error {
                            reason: "signature check panicked".to_owned()
                        };
                        chunk
                    ]
                })
            })
            .take(paths.len())
            .collect()
    })
}

/// The raw `WinVerifyTrust` result for the embedded signature only, as an
/// HRESULT. For tests and the helper view.
#[doc(hidden)]
pub fn embedded_hresult(path: &str) -> i32 {
    OwnedHandle::open_read(path).map_or_else(
        |e| e.code().0,
        |file| {
            let wide = HSTRING::from(path);
            let mut info = WINTRUST_FILE_INFO {
                cbStruct: cb::<WINTRUST_FILE_INFO>(),
                pcwszFilePath: PCWSTR(wide.as_ptr()),
                hFile: file.raw(),
                pgKnownSubject: ptr::null_mut(),
            };
            win_verify_trust(WTD_CHOICE_FILE, ptr::from_mut(&mut info).cast())
                .result
                .0
        },
    )
}

enum Outcome {
    NoSignature,
    Done(SignatureStatus),
}

/// What `WinVerifyTrust` found, plus the signer if it verified.
struct Verified {
    result: HRESULT,
    signer: Option<(String, String, bool)>,
}

fn verify_embedded(path: &str, file: &OwnedHandle) -> Outcome {
    let wide = HSTRING::from(path);
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: cb::<WINTRUST_FILE_INFO>(),
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: file.raw(),
        pgKnownSubject: ptr::null_mut(),
    };
    let verified = win_verify_trust(WTD_CHOICE_FILE, ptr::from_mut(&mut info).cast());
    if is_no_signature(verified.result) {
        return Outcome::NoSignature;
    }
    Outcome::Done(to_status(verified, SigKind::Embedded))
}

fn is_no_signature(hr: HRESULT) -> bool {
    hr == TRUST_E_NOSIGNATURE
        || hr == TRUST_E_SUBJECT_FORM_UNKNOWN
        || hr == TRUST_E_PROVIDER_UNKNOWN
}

fn to_status(verified: Verified, kind: SigKind) -> SignatureStatus {
    let hr = verified.result;
    if hr.is_ok() {
        let (publisher, issuer, is_windows_component) = verified.signer.unwrap_or_default();
        return SignatureStatus::Signed {
            publisher,
            issuer,
            kind,
            is_windows_component,
        };
    }
    let reason = format!("{:#010x} {}", hr.0, hr.message());
    if hr == TRUST_E_BAD_DIGEST || hr == TRUST_E_CERT_SIGNATURE {
        SignatureStatus::Invalid { reason }
    } else if hr == CERT_E_UNTRUSTEDROOT
        || hr == CERT_E_EXPIRED
        || hr == CERT_E_CHAINING
        || hr == TRUST_E_EXPLICIT_DISTRUST
    {
        SignatureStatus::Untrusted { reason }
    } else {
        SignatureStatus::Error { reason }
    }
}

/// Runs `WinVerifyTrust` with the given union choice, reads the signer while
/// the state is open, and always closes the state.
fn win_verify_trust(choice: WINTRUST_DATA_UNION_CHOICE, union_ptr: *mut c_void) -> Verified {
    let mut data = WINTRUST_DATA {
        cbStruct: cb::<WINTRUST_DATA>(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG,
        ..Default::default()
    };
    // Both union members are pointers; the choice above says which one
    // WinVerifyTrust reads.
    data.Anonymous.pFile = union_ptr.cast();
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `data` is fully initialised with cbStruct set, the union
    // pointer refers to a live WINTRUST_FILE_INFO or WINTRUST_CATALOG_INFO
    // owned by the caller for the duration, and `action` is a valid GUID.
    // HWND(INVALID) means no UI, matching WTD_UI_NONE.
    let result = HRESULT(unsafe {
        WinVerifyTrust(
            HWND(-1isize as *mut c_void),
            &raw mut action,
            ptr::from_mut(&mut data).cast(),
        )
    });
    let signer = if result.is_ok() {
        signer_of(data.hWVTStateData)
    } else {
        None
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same structures as above, now asking WinVerifyTrust to free
    // the state it allocated. Required after every VERIFY call.
    let _ = unsafe {
        WinVerifyTrust(
            HWND(-1isize as *mut c_void),
            &raw mut action,
            ptr::from_mut(&mut data).cast(),
        )
    };
    Verified { result, signer }
}

/// Publisher, issuer and whether it's a Windows component, read from an
/// open `WinVerifyTrust` state.
fn signer_of(state: HANDLE) -> Option<(String, String, bool)> {
    // SAFETY: `state` is an open WinVerifyTrust state handle; the returned
    // provider data lives until the state is closed, after this returns.
    let prov = unsafe { WTHelperProvDataFromStateData(state) };
    if prov.is_null() {
        return None;
    }
    // SAFETY: `prov` is valid (checked above). Signer 0, not a countersigner.
    let sgnr = unsafe { WTHelperGetProvSignerFromChain(prov, 0, false, 0) };
    if sgnr.is_null() {
        return None;
    }
    // SAFETY: `sgnr` is valid and owned by the open state.
    let sgnr = unsafe { &*sgnr };
    if sgnr.csCertChain == 0 || sgnr.pasCertChain.is_null() {
        return None;
    }
    // SAFETY: csCertChain > 0 so element 0 (the leaf) exists.
    let leaf = unsafe { &*sgnr.pasCertChain }.pCert;
    if leaf.is_null() {
        return None;
    }
    let publisher = cert_name(leaf, 0);
    let issuer = cert_name(leaf, CERT_NAME_ISSUER_FLAG);
    // The root is the last element of the chain.
    // SAFETY: index csCertChain - 1 is within the chain array.
    let root = unsafe { &*sgnr.pasCertChain.add(sgnr.csCertChain as usize - 1) }.pCert;
    let microsoft_root = !root.is_null() && cert_name(root, 0).starts_with("Microsoft Root");
    let is_windows_component = microsoft_root && has_eku(leaf, EKU_WINDOWS_COMPONENT);
    Some((publisher, issuer, is_windows_component))
}

fn cert_name(cert: *const CERT_CONTEXT, flags: u32) -> String {
    // SAFETY: `cert` is a valid certificate context owned by the open
    // WinVerifyTrust state. With no buffer the call returns the size needed.
    let needed =
        unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None) };
    if needed <= 1 {
        return String::new();
    }
    let mut buf = vec![0u16; needed as usize];
    // SAFETY: as above, with a buffer of exactly the size Windows asked for.
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            None,
            Some(&mut buf),
        )
    };
    String::from_utf16_lossy(&buf[..(written as usize).saturating_sub(1)])
}

fn has_eku(cert: *const CERT_CONTEXT, oid: &str) -> bool {
    let mut size = 0u32;
    // SAFETY: `cert` is valid. First call asks for the size only.
    if unsafe { CertGetEnhancedKeyUsage(cert, 0, None, &raw mut size) }.is_err() || size == 0 {
        return false;
    }
    // u64 storage keeps the CTL_USAGE header correctly aligned.
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    let usage = buf.as_mut_ptr().cast::<CTL_USAGE>();
    // SAFETY: `buf` is at least `size` bytes and aligned for CTL_USAGE.
    if unsafe { CertGetEnhancedKeyUsage(cert, 0, Some(usage), &raw mut size) }.is_err() {
        return false;
    }
    // SAFETY: Windows filled `usage` with cUsageIdentifier valid pointers to
    // NUL-terminated ANSI strings, all inside `buf`, which is still alive.
    unsafe {
        let usage = &*usage;
        (0..usage.cUsageIdentifier as usize).any(|i| {
            let id = *usage.rgpszUsageIdentifier.add(i);
            !id.is_null() && id.to_string().is_ok_and(|s| s == oid)
        })
    }
}

/// A catalog admin context, released on drop.
struct CatAdmin(isize);

impl CatAdmin {
    fn acquire(sha256: bool) -> Option<Self> {
        let mut raw = 0isize;
        let acquired = if sha256 {
            // SAFETY: `raw` receives the context. Default subsystem and policy.
            unsafe {
                CryptCATAdminAcquireContext2(
                    &raw mut raw,
                    None,
                    BCRYPT_SHA256_ALGORITHM,
                    None,
                    None,
                )
            }
        } else {
            // SAFETY: as above, legacy SHA-1 context.
            unsafe { CryptCATAdminAcquireContext(&raw mut raw, None, None) }
        };
        acquired.ok().map(|()| Self(raw))
    }
}

impl Drop for CatAdmin {
    fn drop(&mut self) {
        // SAFETY: the context came from CryptCATAdminAcquireContext(2) and
        // is released exactly once.
        let _ = unsafe { CryptCATAdminReleaseContext(self.0, 0) };
    }
}

thread_local! {
    // Acquiring a catalog admin context goes through the Cryptographic
    // Services service and is the slowest part of a lookup, so each thread
    // keeps one per hash algorithm for its lifetime. Released when the
    // thread ends.
    static SHA256_ADMIN: Option<CatAdmin> = CatAdmin::acquire(true);
    static SHA1_ADMIN: Option<CatAdmin> = CatAdmin::acquire(false);
}

/// A catalog info context, released on drop.
struct CatInfo<'a> {
    admin: &'a CatAdmin,
    info: isize,
}

impl Drop for CatInfo<'_> {
    fn drop(&mut self) {
        // SAFETY: `info` came from CryptCATAdminEnumCatalogFromHash on this
        // admin context, which outlives it, and is released exactly once.
        let _ = unsafe { CryptCATAdminReleaseCatalogContext(self.admin.0, self.info, 0) };
    }
}

fn verify_catalog(path: &str, file: &OwnedHandle) -> SignatureStatus {
    // SHA-256 catalogs first, then SHA-1 for older ones.
    let found = SHA256_ADMIN
        .with(|admin| {
            admin
                .as_ref()
                .and_then(|a| verify_catalog_with(path, file, a))
        })
        .or_else(|| {
            SHA1_ADMIN.with(|admin| {
                admin
                    .as_ref()
                    .and_then(|a| verify_catalog_with(path, file, a))
            })
        });
    found.unwrap_or(SignatureStatus::Unsigned)
}

fn verify_catalog_with(
    path: &str,
    file: &OwnedHandle,
    admin: &CatAdmin,
) -> Option<SignatureStatus> {
    let mut size = 0u32;
    // SAFETY: valid admin context and file handle. First call gets the size.
    let _ = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin.0, file.raw(), &raw mut size, None, None)
    };
    if size == 0 {
        return None;
    }
    let mut hash = vec![0u8; size as usize];
    // SAFETY: `hash` has exactly the size Windows asked for.
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin.0,
            file.raw(),
            &raw mut size,
            Some(hash.as_mut_ptr()),
            None,
        )
    }
    .ok()?;

    // SAFETY: valid admin context and hash slice. No previous catalog.
    let info = unsafe { CryptCATAdminEnumCatalogFromHash(admin.0, &hash, None, None) };
    if info == 0 {
        return None;
    }
    let info = CatInfo { admin, info };
    let mut catalog = CATALOG_INFO {
        cbStruct: cb::<CATALOG_INFO>(),
        ..Default::default()
    };
    // SAFETY: `info.info` is a live catalog context and `catalog` is
    // initialised with cbStruct set.
    unsafe { CryptCATCatalogInfoFromContext(info.info, &raw mut catalog, 0) }.ok()?;

    let member_tag = HSTRING::from(hex(&hash).to_uppercase());
    let file_path = HSTRING::from(path);
    let mut cat = WINTRUST_CATALOG_INFO {
        cbStruct: cb::<WINTRUST_CATALOG_INFO>(),
        pcwszCatalogFilePath: PCWSTR(catalog.wszCatalogFile.as_ptr()),
        pcwszMemberTag: PCWSTR(member_tag.as_ptr()),
        pcwszMemberFilePath: PCWSTR(file_path.as_ptr()),
        hMemberFile: file.raw(),
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: size,
        hCatAdmin: admin.0,
        ..Default::default()
    };
    let verified = win_verify_trust(WTD_CHOICE_CATALOG, ptr::from_mut(&mut cat).cast());
    drop(info);
    Some(to_status(verified, SigKind::Catalog))
}
