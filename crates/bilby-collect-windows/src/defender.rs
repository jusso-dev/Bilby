//! Protection status: Microsoft Defender, Security Center products, Windows
//! Firewall, UAC and Windows Update. Read-only: WMI queries, COM getters and
//! registry reads only.
//!
//! Each source is collected on its own and reports its own [`CheckStatus`],
//! so one failing (for example detections needing admin) doesn't hide the
//! rest.

use std::collections::HashMap;

use bilby_core::cim;
use bilby_core::model::{Check, CheckStatus, SignalFamily};
use bilby_core::snapshot::{
    DefenderStatus, Detection, FirewallStatus, ProtectionFacts, SecurityProduct, UacStatus,
    UpdateStatus,
};
use windows::Win32::Foundation::{E_ACCESSDENIED, ERROR_SUCCESS, VARIANT_BOOL};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
    NetFwPolicy2,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
use windows::Win32::System::UpdateAgent::{
    IUpdateSession, UpdateSession, orcSucceeded, orcSucceededWithErrors, uoInstallation,
};
use windows::core::{HRESULT, w};
use wmi::{Variant, WMIConnection, WMIError};

/// Everything the protection collector found, plus how each part went.
pub struct Collected {
    /// The facts.
    pub facts: ProtectionFacts,
    /// One entry per source.
    pub checks: Vec<Check>,
}

fn check(id: &str, status: CheckStatus) -> Check {
    Check {
        id: id.to_owned(),
        family: SignalFamily::Protection,
        status,
    }
}

/// Makes sure COM is initialised on this thread (multithreaded). Safe to
/// call more than once; a thread already in another mode keeps it.
pub fn init_com() {
    // SAFETY: no reserved pointer. Returns S_FALSE if already initialised,
    // or RPC_E_CHANGED_MODE if this thread chose STA, both fine to ignore:
    // COM stays usable either way.
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
}

/// Collects all protection facts.
pub fn collect() -> Collected {
    init_com();
    let mut facts = ProtectionFacts::default();
    let mut checks = Vec::new();

    match WMIConnection::with_namespace_path(r"ROOT\Microsoft\Windows\Defender") {
        Ok(con) => {
            match defender_status(&con) {
                Ok(status) => {
                    facts.defender = status;
                    checks.push(check("protection.defender", CheckStatus::Ran));
                }
                Err(e) => checks.push(check("protection.defender", failed(&e))),
            }
            match detections(&con) {
                Ok(list) => {
                    facts.detections = Some(list);
                    checks.push(check("protection.detections", CheckStatus::Ran));
                }
                Err(e) => checks.push(check("protection.detections", failed(&e))),
            }
        }
        Err(e) => {
            // No Defender namespace: Defender is removed or this is an
            // unusual edition. Rules treat a missing status as unknown.
            checks.push(check("protection.defender", skipped_or_failed(&e)));
            checks.push(check("protection.detections", skipped_or_failed(&e)));
        }
    }

    match WMIConnection::with_namespace_path(r"ROOT\SecurityCenter2") {
        Ok(con) => {
            match products(&con, "AntiVirusProduct") {
                Ok(list) => {
                    facts.antivirus_products = Some(list);
                    checks.push(check("protection.security_center", CheckStatus::Ran));
                }
                Err(e) => checks.push(check("protection.security_center", failed(&e))),
            }
            facts.firewall_products = products(&con, "FirewallProduct").ok();
        }
        // Doesn't exist on Windows Server.
        Err(_) => checks.push(check(
            "protection.security_center",
            CheckStatus::Skipped("check.skipped.no_security_center".to_owned()),
        )),
    }

    match firewall() {
        Ok(fw) => {
            facts.firewall = Some(fw);
            checks.push(check("protection.firewall", CheckStatus::Ran));
        }
        Err(e) => checks.push(check(
            "protection.firewall",
            hresult_status(e.code(), &e.message()),
        )),
    }

    facts.uac = Some(uac());
    checks.push(check("protection.uac", CheckStatus::Ran));

    match updates() {
        Ok(u) => {
            facts.updates = Some(u);
            checks.push(check("protection.updates", CheckStatus::Ran));
        }
        Err(e) => checks.push(check(
            "protection.updates",
            // Skipped reasons are copy keys; the technical detail isn't
            // shown to the user here.
            CheckStatus::Skipped(update_skip_reason(&e).to_owned()),
        )),
    }

    Collected { facts, checks }
}

fn update_skip_reason(_e: &windows::core::Error) -> &'static str {
    "check.skipped.update_history"
}

fn failed(e: &WMIError) -> CheckStatus {
    let text = e.to_string();
    if is_access_denied(e) {
        CheckStatus::NeedsAdmin
    } else {
        CheckStatus::Failed(text)
    }
}

fn skipped_or_failed(e: &WMIError) -> CheckStatus {
    if is_access_denied(e) {
        CheckStatus::NeedsAdmin
    } else {
        CheckStatus::Skipped("check.skipped.no_defender".to_owned())
    }
}

fn is_access_denied(e: &WMIError) -> bool {
    match e {
        WMIError::HResultError { hres } => {
            HRESULT(*hres) == E_ACCESSDENIED || (*hres).cast_unsigned() == 0x8004_1003 // WBEM_E_ACCESS_DENIED
        }
        _ => e.to_string().to_ascii_lowercase().contains("access"),
    }
}

fn hresult_status(code: HRESULT, message: &str) -> CheckStatus {
    if code == E_ACCESSDENIED {
        CheckStatus::NeedsAdmin
    } else {
        CheckStatus::Failed(format!("{:#010x} {message}", code.0))
    }
}

type Row = HashMap<String, Variant>;

fn get_bool(row: &Row, key: &str) -> Option<bool> {
    match row.get(key)? {
        Variant::Bool(b) => Some(*b),
        _ => None,
    }
}

fn get_u32(row: &Row, key: &str) -> Option<u32> {
    match row.get(key)? {
        Variant::UI1(v) => Some(u32::from(*v)),
        Variant::UI2(v) => Some(u32::from(*v)),
        Variant::UI4(v) => Some(*v),
        Variant::UI8(v) => u32::try_from(*v).ok(),
        Variant::I1(v) => u32::try_from(*v).ok(),
        Variant::I2(v) => u32::try_from(*v).ok(),
        Variant::I4(v) => u32::try_from(*v).ok(),
        Variant::I8(v) => u32::try_from(*v).ok(),
        Variant::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn get_string(row: &Row, key: &str) -> Option<String> {
    match row.get(key)? {
        Variant::String(s) => Some(s.clone()),
        Variant::Null | Variant::Empty => None,
        other => Some(format!("{other:?}")),
    }
}

fn get_strings(row: &Row, key: &str) -> Vec<String> {
    match row.get(key) {
        Some(Variant::Array(items)) => items
            .iter()
            .filter_map(|v| match v {
                Variant::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        Some(Variant::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn get_time(row: &Row, key: &str) -> Option<time::OffsetDateTime> {
    cim::parse_datetime(&get_string(row, key)?)
}

fn defender_status(con: &WMIConnection) -> Result<Option<DefenderStatus>, WMIError> {
    let rows: Vec<Row> = con.raw_query(
        "SELECT AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, \
         BehaviorMonitorEnabled, IoavProtectionEnabled, AntivirusSignatureAge, \
         AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge, IsTamperProtected, \
         AMRunningMode FROM MSFT_MpComputerStatus",
    )?;
    Ok(rows.first().map(|r| DefenderStatus {
        am_service_enabled: get_bool(r, "AMServiceEnabled").unwrap_or(false),
        antivirus_enabled: get_bool(r, "AntivirusEnabled").unwrap_or(false),
        real_time_protection_enabled: get_bool(r, "RealTimeProtectionEnabled").unwrap_or(false),
        behavior_monitor_enabled: get_bool(r, "BehaviorMonitorEnabled").unwrap_or(false),
        ioav_protection_enabled: get_bool(r, "IoavProtectionEnabled").unwrap_or(false),
        // 65535 means "never" for these ages.
        antivirus_signature_age_days: get_u32(r, "AntivirusSignatureAge").filter(|d| *d != 65535),
        antivirus_signature_last_updated: get_time(r, "AntivirusSignatureLastUpdated"),
        quick_scan_age_days: get_u32(r, "QuickScanAge").filter(|d| *d != 65535),
        full_scan_age_days: get_u32(r, "FullScanAge").filter(|d| *d != 65535),
        is_tamper_protected: get_bool(r, "IsTamperProtected"),
        am_running_mode: get_string(r, "AMRunningMode"),
    }))
}

fn detections(con: &WMIConnection) -> Result<Vec<Detection>, WMIError> {
    let rows: Vec<Row> = con.raw_query(
        "SELECT ThreatID, InitialDetectionTime, LastThreatStatusChangeTime, ThreatStatusID, \
         ActionSuccess, Resources, ProcessName FROM MSFT_MpThreatDetection",
    )?;
    // MSFT_MpThreat adds the name and whether it ran. Missing is fine.
    let threats: HashMap<String, Row> = con
        .raw_query::<Row>(
            "SELECT ThreatID, ThreatName, SeverityID, IsActive, DidThreatExecute FROM MSFT_MpThreat",
        )
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| Some((get_string(&r, "ThreatID")?, r)))
        .collect();
    Ok(rows
        .iter()
        .map(|r| {
            let id = get_string(r, "ThreatID").unwrap_or_default();
            let threat = threats.get(&id);
            Detection {
                threat_name: threat.and_then(|t| get_string(t, "ThreatName")),
                severity_id: threat.and_then(|t| get_u32(t, "SeverityID")),
                is_active: threat.and_then(|t| get_bool(t, "IsActive")),
                did_threat_execute: threat.and_then(|t| get_bool(t, "DidThreatExecute")),
                initial_detection_time: get_time(r, "InitialDetectionTime"),
                last_status_change_time: get_time(r, "LastThreatStatusChangeTime"),
                threat_status_id: get_u32(r, "ThreatStatusID"),
                action_success: get_bool(r, "ActionSuccess"),
                resources: get_strings(r, "Resources"),
                process_name: get_string(r, "ProcessName"),
                threat_id: id,
            }
        })
        .collect())
}

fn products(con: &WMIConnection, class: &str) -> Result<Vec<SecurityProduct>, WMIError> {
    let rows: Vec<Row> = con.raw_query(format!(
        "SELECT displayName, productState, pathToSignedProductExe FROM {class}"
    ))?;
    Ok(rows
        .iter()
        .map(|r| SecurityProduct {
            display_name: get_string(r, "displayName").unwrap_or_default(),
            product_state: get_u32(r, "productState").unwrap_or(0),
            path: get_string(r, "pathToSignedProductExe"),
        })
        .collect())
}

fn firewall() -> windows::core::Result<FirewallStatus> {
    // SAFETY: COM is initialised on this thread (init_com). NetFwPolicy2 is
    // an in-process COM class; we only call its getters.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }?;
    let on = |v: VARIANT_BOOL| v.as_bool();
    // SAFETY: `policy` is a live interface pointer; getters have no side
    // effects.
    let current = unsafe { policy.CurrentProfileTypes() }?;
    // SAFETY: as above.
    let domain = unsafe { policy.get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN) }?;
    // SAFETY: as above.
    let private = unsafe { policy.get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE) }?;
    // SAFETY: as above.
    let public = unsafe { policy.get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC) }?;
    Ok(FirewallStatus {
        domain_enabled: on(domain),
        private_enabled: on(private),
        public_enabled: on(public),
        current_domain: current & NET_FW_PROFILE2_DOMAIN.0 != 0,
        current_private: current & NET_FW_PROFILE2_PRIVATE.0 != 0,
        current_public: current & NET_FW_PROFILE2_PUBLIC.0 != 0,
    })
}

/// Reads a DWORD under `HKLM\...\Policies\System`. `None` if absent.
fn policy_dword(name: windows::core::PCWSTR) -> Option<u32> {
    let mut value = 0u32;
    let mut size = u32::try_from(std::mem::size_of::<u32>()).ok()?;
    // SAFETY: RegGetValueW reads one DWORD into `value`, with `size` set to
    // its size. RRF_RT_REG_DWORD rejects anything else. Read-only.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
            name,
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&raw mut size),
        )
    };
    (rc == ERROR_SUCCESS).then_some(value)
}

fn uac() -> UacStatus {
    UacStatus {
        enable_lua: policy_dword(w!("EnableLUA")),
        consent_prompt_behavior_admin: policy_dword(w!("ConsentPromptBehaviorAdmin")),
    }
}

/// How many history entries to look through for the newest success.
const UPDATE_HISTORY_LIMIT: i32 = 50;

fn updates() -> windows::core::Result<UpdateStatus> {
    // SAFETY: COM is initialised. UpdateSession is the documented Windows
    // Update Agent entry point; we only search history, which is read-only.
    let session: IUpdateSession =
        unsafe { CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) }?;
    // SAFETY: live interface; creating a searcher changes nothing.
    let searcher = unsafe { session.CreateUpdateSearcher() }?;
    // SAFETY: as above.
    let total = unsafe { searcher.GetTotalHistoryCount() }?;
    let mut status = UpdateStatus {
        last_success: None,
        history_count: u32::try_from(total).unwrap_or(0),
    };
    if total <= 0 {
        return Ok(status);
    }
    // SAFETY: as above; QueryHistory only reads.
    let history = unsafe { searcher.QueryHistory(0, total.min(UPDATE_HISTORY_LIMIT)) }?;
    // SAFETY: as above.
    let count = unsafe { history.Count() }?;
    for i in 0..count {
        // SAFETY: `i` is within Count().
        let Ok(entry) = (unsafe { history.get_Item(i) }) else {
            continue;
        };
        // SAFETY: live entry; getters only.
        let (Ok(op), Ok(code), Ok(date)) = (
            unsafe { entry.Operation() },
            unsafe { entry.ResultCode() },
            unsafe { entry.Date() },
        ) else {
            continue;
        };
        if op != uoInstallation || (code != orcSucceeded && code != orcSucceededWithErrors) {
            continue;
        }
        if let Some(when) = cim::from_ole_date(date)
            && status.last_success.is_none_or(|best| when > best)
        {
            status.last_success = Some(when);
        }
    }
    Ok(status)
}
