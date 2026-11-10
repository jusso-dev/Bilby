//! Hosts file, proxy settings, root certificates and DNS servers.
//! Read-only: files are read, registry keys use `KEY_READ`, and certificate
//! stores are opened with `CERT_STORE_READONLY_FLAG`.

use std::collections::HashSet;
use std::path::Path;

use bilby_core::hosts::{decode, parse};
use bilby_core::model::CheckStatus;
use bilby_core::paths::{KnownFolders, normalise};
use bilby_core::snapshot::{
    ConnectionFact, HostsFacts, Management, ProcessFact, ProxyFacts, RootCert, RootStore,
    TamperFacts, TcpState,
};
use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::{
    WINHTTP_PROXY_INFO, WinHttpGetDefaultProxyConfiguration,
};
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_SHA1_HASH_PROP_ID,
    CERT_SHA256_HASH_PROP_ID, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W,
    CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
    CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID,
    CERT_SYSTEM_STORE_LOCATION_SHIFT, CertCloseStore, CertCreateCTLContext,
    CertEnumCertificatesInStore, CertFreeCTLContext, CertGetCertificateContextProperty,
    CertGetNameStringW, CertOpenStore, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    szOID_COMMON_NAME, szOID_ORGANIZATION_NAME,
};
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, REG_SAM_FLAGS,
};
use windows::core::{PCSTR, w};

use crate::hash::hex;
use crate::registry::{Data, Key};

/// What the tampering collector found and how each part went.
pub struct Collected {
    /// The facts.
    pub facts: TamperFacts,
    /// One status per part: hosts, proxy, roots.
    pub checks: Vec<(&'static str, CheckStatus)>,
}

/// Collects everything. `processes` and `connections` come from the
/// process and network collectors, so a local proxy can be tied to the
/// program listening on its port. `management` comes from the browser
/// collector's device check.
pub fn collect(
    folders: &KnownFolders,
    processes: &[ProcessFact],
    connections: &[ConnectionFact],
    management: Management,
) -> Collected {
    let mut checks = Vec::new();
    let hosts = hosts(folders);
    checks.push((
        "tamper.hosts",
        if hosts.is_some() {
            CheckStatus::Ran
        } else {
            CheckStatus::Failed("hosts file couldn't be read".to_owned())
        },
    ));
    let proxy = proxy(processes, connections);
    checks.push(("tamper.proxy", CheckStatus::Ran));
    let (microsoft, microsoft_list_read) = microsoft_roots();
    let roots = roots(&microsoft);
    checks.push((
        "tamper.root_certs",
        if roots.is_empty() {
            CheckStatus::Failed("no root stores could be read".to_owned())
        } else {
            CheckStatus::Ran
        },
    ));
    Collected {
        facts: TamperFacts {
            hosts,
            proxy: Some(proxy),
            winhttp_proxy: winhttp_proxy(),
            roots,
            microsoft_list_read,
            dns_servers: dns_servers(),
            management,
        },
        checks,
    }
}

const TCPIP: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

fn hosts(folders: &KnownFolders) -> Option<HostsFacts> {
    let default = format!(r"{}\System32\drivers\etc", folders.system_root);
    let configured = Key::open(HKEY_LOCAL_MACHINE, TCPIP, KEY_WOW64_64KEY)
        .and_then(|k| k.value("DataBasePath"))
        .and_then(|d| d.text().map(str::to_owned));
    let dir = configured.clone().unwrap_or_else(|| default.clone());
    let default_path =
        configured.is_none_or(|c| normalise(&c, folders) == normalise(&default, folders));
    let path = format!(r"{}\hosts", normalise(&dir, folders));
    let bytes = std::fs::read(Path::new(&expand(&dir, folders)).join("hosts")).ok()?;
    Some(HostsFacts {
        path,
        default_path,
        entries: parse(&decode(&bytes)),
    })
}

/// `%SystemRoot%` and friends in a registry path, for opening it.
fn expand(p: &str, folders: &KnownFolders) -> String {
    let mut out = p.to_owned();
    for (var, value) in [
        ("%systemroot%", &folders.system_root),
        ("%windir%", &folders.system_root),
    ] {
        if let Some(i) = out.to_ascii_lowercase().find(var) {
            out.replace_range(i..i + var.len(), value);
        }
    }
    out
}

fn dword(key: &Key, name: &str) -> Option<u32> {
    match key.value(name)? {
        Data::Dword(v) => Some(v),
        _ => None,
    }
}

fn proxy(processes: &[ProcessFact], connections: &[ConnectionFact]) -> ProxyFacts {
    let key = Key::open(
        HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        REG_SAM_FLAGS(0),
    );
    let text = |n: &str| {
        key.as_ref()
            .and_then(|k| k.value(n))
            .and_then(|d| d.text().map(str::to_owned))
            .filter(|t| !t.trim().is_empty())
    };
    let enabled = key.as_ref().and_then(|k| dword(k, "ProxyEnable")) == Some(1);
    let server = text("ProxyServer");
    let listener = if enabled {
        server
            .as_deref()
            .and_then(|s| local_listener(s, processes, connections))
    } else {
        None
    };
    // An organisation can set one proxy for every user on the machine.
    let per_machine_policy = Key::open(
        HKEY_LOCAL_MACHINE,
        r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
        KEY_WOW64_64KEY,
    )
    .and_then(|k| dword(&k, "ProxySettingsPerUser"))
        == Some(0);
    ProxyFacts {
        enabled,
        auto_detect: key.as_ref().and_then(|k| dword(k, "AutoDetect")) == Some(1),
        per_machine_policy,
        bypass: text("ProxyOverride"),
        pac_url: text("AutoConfigURL"),
        listener,
        server,
    }
}

/// The program listening on a proxy's port, if the proxy is this computer.
/// `ProxyServer` is `host:port` or `http=host:port;https=host:port`.
fn local_listener(
    server: &str,
    processes: &[ProcessFact],
    connections: &[ConnectionFact],
) -> Option<ProcessFact> {
    let first = server.split(';').next()?;
    let hostport = first.split_once('=').map_or(first, |(_, v)| v).trim();
    let (host, port) = hostport.rsplit_once(':')?;
    let port: u16 = port.trim().parse().ok()?;
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        return None;
    }
    let pid = connections
        .iter()
        .find(|c| c.state == Some(TcpState::Listen) && c.local.port() == port)?
        .pid;
    processes.iter().find(|p| p.pid == pid).cloned()
}

fn winhttp_proxy() -> Option<String> {
    let mut info = WINHTTP_PROXY_INFO::default();
    // SAFETY: fills `info`; its strings are GlobalAlloc'd and freed below.
    unsafe { WinHttpGetDefaultProxyConfiguration(&raw mut info) }.ok()?;
    // SAFETY: Windows wrote a valid NUL-terminated string or null.
    let proxy = (!info.lpszProxy.is_null())
        .then(|| unsafe { info.lpszProxy.to_string() }.ok())
        .flatten();
    for p in [info.lpszProxy, info.lpszProxyBypass] {
        if !p.is_null() {
            // SAFETY: freeing the buffers WinHTTP allocated for us.
            let _ = unsafe { GlobalFree(Some(HGLOBAL(p.0.cast()))) };
        }
    }
    proxy.filter(|s| !s.trim().is_empty())
}

/// A certificate store handle, closed on drop.
struct Store(HCERTSTORE);

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the store came from CertOpenStore and is closed once.
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
}

fn open_root(location: u32) -> Option<Store> {
    let flags = CERT_OPEN_STORE_FLAGS(
        location | CERT_STORE_READONLY_FLAG.0 | CERT_STORE_OPEN_EXISTING_FLAG.0,
    );
    // SAFETY: the system store provider with a wide store name; read-only
    // and open-existing, so nothing is created or changed.
    unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            flags,
            Some(w!("Root").as_ptr().cast()),
        )
    }
    .ok()
    .map(Store)
}

fn attr(cert: *const CERT_CONTEXT, oid: PCSTR, flags: u32) -> Option<String> {
    // SAFETY: valid certificate context; the type parameter is the OID
    // string. First call returns the size.
    let n =
        unsafe { CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, flags, Some(oid.0.cast()), None) };
    if n <= 1 {
        return None;
    }
    let mut buf = vec![0u16; n as usize];
    // SAFETY: as above, with a buffer of the size asked for.
    let w = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_ATTR_TYPE,
            flags,
            Some(oid.0.cast()),
            Some(&mut buf),
        )
    };
    Some(String::from_utf16_lossy(
        &buf[..(w as usize).saturating_sub(1)],
    ))
}

fn display(cert: *const CERT_CONTEXT, flags: u32) -> Option<String> {
    // SAFETY: valid certificate context; size query.
    let n = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None) };
    if n <= 1 {
        return None;
    }
    let mut buf = vec![0u16; n as usize];
    // SAFETY: as above.
    let w = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            None,
            Some(&mut buf),
        )
    };
    Some(String::from_utf16_lossy(
        &buf[..(w as usize).saturating_sub(1)],
    ))
}

fn sha1(cert: *const CERT_CONTEXT) -> Option<String> {
    thumbprint::<20>(cert, CERT_SHA1_HASH_PROP_ID)
}

/// A hash of the certificate, `N` bytes long. Windows computes it if the
/// store hasn't cached it.
fn thumbprint<const N: usize>(cert: *const CERT_CONTEXT, prop: u32) -> Option<String> {
    let mut hash = [0u8; N];
    let mut size = u32::try_from(N).ok()?;
    // SAFETY: the buffer holds N bytes and `size` says so.
    unsafe {
        CertGetCertificateContextProperty(cert, prop, Some(hash.as_mut_ptr().cast()), &raw mut size)
    }
    .ok()?;
    Some(hex(&hash[..(size as usize).min(N)]))
}

fn roots(microsoft: &HashSet<String>) -> Vec<RootCert> {
    let stores = [
        (CERT_SYSTEM_STORE_CURRENT_USER, RootStore::User),
        (CERT_SYSTEM_STORE_LOCAL_MACHINE, RootStore::Machine),
        (
            CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
            RootStore::GroupPolicy,
        ),
        (
            CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
            RootStore::Enterprise,
        ),
    ];
    let mut out = Vec::new();
    for (location, store) in stores {
        let Some(s) = open_root(location) else {
            continue;
        };
        let mut prev: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            // SAFETY: enumerating an open store; passing the previous
            // context frees it, and the loop ends on null.
            let cert = unsafe {
                CertEnumCertificatesInStore(s.0, (!prev.is_null()).then_some(prev.cast_const()))
            };
            if cert.is_null() {
                break;
            }
            prev = cert;
            let Some(sha) = sha1(cert) else { continue };
            // SAFETY: `cert` is a live context; read its validity dates.
            let info = unsafe { (*cert).pCertInfo.as_ref() };
            out.push(RootCert {
                store,
                in_microsoft_list: microsoft.contains(&sha),
                subject_cn: attr(cert, szOID_COMMON_NAME, 0),
                subject_o: attr(cert, szOID_ORGANIZATION_NAME, 0),
                issuer: display(cert, CERT_NAME_ISSUER_FLAG),
                not_before: info.and_then(|i| crate::processes::from_filetime(i.NotBefore)),
                not_after: info.and_then(|i| crate::processes::from_filetime(i.NotAfter)),
                sha256: thumbprint::<32>(cert, CERT_SHA256_HASH_PROP_ID),
                sha1: sha,
            });
        }
    }
    out
}

/// SHA-1 thumbprints in Microsoft's trusted root program list, from the
/// copy Windows keeps (`AuthRoot\AutoUpdate\EncodedCtl`). If it's missing,
/// the roots in the machine's `AuthRoot` store are used instead, and the
/// second value is false so findings know the list is incomplete.
fn microsoft_roots() -> (HashSet<String>, bool) {
    let encoded = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate",
        KEY_WOW64_64KEY,
    )
    .and_then(|k| k.value("EncodedCtl"));
    if let Some(Data::Bytes(bytes)) = encoded {
        let encoding = X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0;
        // SAFETY: decodes the CTL bytes; the context is freed below.
        let ctl = unsafe { CertCreateCTLContext(encoding, &bytes) };
        if !ctl.is_null() {
            let mut out = HashSet::new();
            // SAFETY: a non-null CTL context has valid info for its life.
            if let Some(info) = unsafe { (*ctl).pCtlInfo.as_ref() } {
                for i in 0..info.cCTLEntry as usize {
                    // SAFETY: `i` is within cCTLEntry.
                    let entry = unsafe { &*info.rgCTLEntry.add(i) };
                    let id = &entry.SubjectIdentifier;
                    // SAFETY: the blob points at cbData bytes inside the CTL.
                    let raw = unsafe { std::slice::from_raw_parts(id.pbData, id.cbData as usize) };
                    out.insert(hex(raw));
                }
            }
            // SAFETY: freeing the context created above.
            let _ = unsafe { CertFreeCTLContext(Some(ctl)) };
            if !out.is_empty() {
                return (out, true);
            }
        }
    }
    // Fallback: AuthRoot store, which holds roots Windows has downloaded.
    let mut out = HashSet::new();
    let flags = CERT_OPEN_STORE_FLAGS(
        CERT_SYSTEM_STORE_LOCAL_MACHINE
            | CERT_STORE_READONLY_FLAG.0
            | CERT_STORE_OPEN_EXISTING_FLAG.0,
    );
    // SAFETY: read-only open of the AuthRoot system store.
    if let Ok(h) = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            flags,
            Some(w!("AuthRoot").as_ptr().cast()),
        )
    } {
        let s = Store(h);
        let mut prev: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            // SAFETY: as in `roots`.
            let cert = unsafe {
                CertEnumCertificatesInStore(s.0, (!prev.is_null()).then_some(prev.cast_const()))
            };
            if cert.is_null() {
                break;
            }
            prev = cert;
            if let Some(sha) = sha1(cert) {
                out.insert(sha);
            }
        }
    }
    (out, false)
}

/// DNS servers on adapters that are up, for the helper view. No finding.
fn dns_servers() -> Vec<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 16 * 1024u32;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer is `size` bytes, 8-byte aligned.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(buf.as_mut_ptr().cast()),
                &raw mut size,
            )
        };
        match rc {
            0 => break,
            111 => {} // ERROR_BUFFER_OVERFLOW: `size` now holds what's needed.
            _ => return Vec::new(),
        }
    }
    let mut out = Vec::new();
    let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    // SAFETY: a linked list inside `buf`, filled by Windows, ending in null.
    while let Some(a) = unsafe { adapter.as_ref() } {
        if a.OperStatus == IfOperStatusUp {
            let mut dns = a.FirstDnsServerAddress;
            // SAFETY: as above.
            while let Some(d) = unsafe { dns.as_ref() } {
                let sa = d.Address.lpSockaddr;
                let len = usize::try_from(d.Address.iSockaddrLength).unwrap_or(0);
                // SAFETY: the family and length say which sockaddr type this
                // is; read_unaligned copes with any alignment.
                let ip: Option<std::net::IpAddr> = unsafe {
                    match sa.as_ref().map(|s| s.sa_family) {
                        Some(f) if f == AF_INET && len >= size_of::<SOCKADDR_IN>() => {
                            let v4 = sa.cast::<SOCKADDR_IN>().read_unaligned();
                            Some(
                                std::net::Ipv4Addr::from(u32::from_be(v4.sin_addr.S_un.S_addr))
                                    .into(),
                            )
                        }
                        Some(f) if f == AF_INET6 && len >= size_of::<SOCKADDR_IN6>() => {
                            let v6 = sa.cast::<SOCKADDR_IN6>().read_unaligned();
                            Some(std::net::Ipv6Addr::from(v6.sin6_addr.u.Byte).into())
                        }
                        _ => None,
                    }
                };
                if let Some(ip) = ip.map(|i| i.to_string())
                    && !out.contains(&ip)
                {
                    out.push(ip);
                }
                dns = d.Next;
            }
        }
        adapter = a.Next;
    }
    out
}
