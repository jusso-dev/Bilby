//! Opt-in IP address reports (ADR 0004, amended): VirusTotal, AbuseIPDB
//! and CrowdSec CTI, each with the user's own key and its own switch.
//!
//! Only addresses chosen by
//! [`bilby_core::rules::reputation::ip_candidates`] are sent: the public
//! peers of programs Bilby already flagged, at most
//! [`bilby_core::rules::reputation::MAX_IP_LOOKUPS`] a scan. Never every
//! connection on the computer, and never anything else about it.
//!
//! - VirusTotal: `GET https://www.virustotal.com/api/v3/ip_addresses/<ip>`
//!   with `x-apikey`. Reads `data.attributes.last_analysis_stats`,
//!   `as_owner` and `country` (VirusTotal API v3, "IP addresses" object,
//!   checked 11-11-2026). Shares the file lookups' rate limit and quota.
//! - AbuseIPDB: `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90`
//!   with headers `Key` and `Accept: application/json`. Reads
//!   `data.abuseConfidenceScore`, `totalReports`, `isWhitelisted`, `isp`,
//!   `usageType` and `countryCode`. 1,000 checks a day on the free plan;
//!   429 when spent (AbuseIPDB API v2 docs, checked 11-11-2026).
//! - CrowdSec CTI: `GET https://cti.api.crowdsec.net/v2/smoke/<ip>` with
//!   `x-api-key`. Reads `reputation`, `classifications.false_positives`,
//!   `behaviors[].label`, `as_name` and `location.country`. 404 means
//!   CrowdSec has nothing on the address. The free Community key allows
//!   120 lookups a month (CrowdSec docs, "CTI API keys", checked
//!   11-11-2026), so Bilby sends at most [`CROWDSEC_PER_SCAN`] a scan.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use bilby_core::net::{AddrClass, classify};
use bilby_core::settings::OnlineChecks;
use bilby_core::snapshot::{AbuseIpResult, CrowdSecIpResult, VtIpResult};

use crate::allowlist::{HttpError, Transport};
use crate::key::ApiKey;
use crate::{Cache, Limits, RateLimiter, Summary, describe};

/// Most CrowdSec lookups in one scan: 120 a month on the free key.
pub const CROWDSEC_PER_SCAN: usize = 10;

/// VirusTotal URL for an address.
pub fn vt_url(ip: IpAddr) -> String {
    format!("https://www.virustotal.com/api/v3/ip_addresses/{ip}")
}

/// AbuseIPDB URL for an address. IPv6 colons are percent-encoded.
pub fn abuseipdb_url(ip: IpAddr) -> String {
    let ip = ip.to_string().replace(':', "%3A");
    format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90")
}

/// CrowdSec CTI URL for an address.
pub fn crowdsec_url(ip: IpAddr) -> String {
    format!("https://cti.api.crowdsec.net/v2/smoke/{ip}")
}

fn bad_json(e: &serde_json::Error) -> HttpError {
    HttpError::BadReply(format!("bad JSON: {e}"))
}

#[derive(Deserialize)]
struct VtReport {
    data: VtData,
}

#[derive(Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: VtStats,
    #[serde(default)]
    as_owner: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

#[derive(Deserialize)]
struct VtStats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    harmless: u32,
}

/// Parses a VirusTotal 200 response.
pub fn parse_vt(ip: IpAddr, body: &str) -> Result<VtIpResult, HttpError> {
    let r: VtReport = serde_json::from_str(body).map_err(|e| bad_json(&e))?;
    let a = r.data.attributes;
    Ok(VtIpResult {
        ip,
        malicious: a.last_analysis_stats.malicious,
        suspicious: a.last_analysis_stats.suspicious,
        harmless: a.last_analysis_stats.harmless,
        as_owner: a.as_owner,
        country: a.country,
    })
}

#[derive(Deserialize)]
struct AbuseReply {
    data: AbuseData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseData {
    abuse_confidence_score: u8,
    #[serde(default)]
    total_reports: u32,
    #[serde(default)]
    is_whitelisted: Option<bool>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
}

/// Parses an AbuseIPDB 200 response.
pub fn parse_abuseipdb(ip: IpAddr, body: &str) -> Result<AbuseIpResult, HttpError> {
    let r: AbuseReply = serde_json::from_str(body).map_err(|e| bad_json(&e))?;
    let d = r.data;
    Ok(AbuseIpResult {
        ip,
        score: d.abuse_confidence_score.min(100),
        total_reports: d.total_reports,
        whitelisted: d.is_whitelisted,
        isp: d.isp,
        usage_type: d.usage_type,
        country: d.country_code,
    })
}

#[derive(Deserialize)]
struct CsReply {
    #[serde(default)]
    reputation: Option<String>,
    #[serde(default)]
    classifications: Option<CsClassifications>,
    #[serde(default)]
    behaviors: Vec<CsLabel>,
    #[serde(default)]
    as_name: Option<String>,
    #[serde(default)]
    location: Option<CsLocation>,
}

#[derive(Deserialize)]
struct CsClassifications {
    #[serde(default)]
    false_positives: Vec<CsLabel>,
}

#[derive(Deserialize)]
struct CsLabel {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct CsLocation {
    #[serde(default)]
    country: Option<String>,
}

/// Parses a CrowdSec CTI 200 response.
pub fn parse_crowdsec(ip: IpAddr, body: &str) -> Result<CrowdSecIpResult, HttpError> {
    let r: CsReply = serde_json::from_str(body).map_err(|e| bad_json(&e))?;
    Ok(CrowdSecIpResult {
        ip,
        reputation: r
            .reputation
            .unwrap_or_else(|| "unknown".to_owned())
            .to_ascii_lowercase(),
        false_positive: r
            .classifications
            .is_some_and(|c| !c.false_positives.is_empty()),
        behaviors: r
            .behaviors
            .into_iter()
            .filter_map(|b| b.label.or(b.name))
            .take(5)
            .collect(),
        as_name: r.as_name,
        country: r.location.and_then(|l| l.country),
    })
}

/// Only public addresses are ever sent: never a home network, loopback or
/// link-local address, even if a caller passes one.
fn sendable(ip: IpAddr) -> bool {
    classify(ip) == AddrClass::Public
}

fn not_public() -> HttpError {
    HttpError::NotAllowed("not a public address".to_owned())
}

/// One VirusTotal IP report. `Ok(None)` means VirusTotal hasn't seen it.
pub fn lookup_vt(
    http: &dyn Transport,
    key: &str,
    ip: IpAddr,
) -> Result<Option<VtIpResult>, HttpError> {
    if !sendable(ip) {
        return Err(not_public());
    }
    let r = http.get(&vt_url(ip), &[("x-apikey", key)])?;
    match r.status {
        200 => parse_vt(ip, &r.body).map(Some),
        404 => Ok(None),
        s => Err(HttpError::Status(s)),
    }
}

/// One AbuseIPDB check.
pub fn lookup_abuseipdb(
    http: &dyn Transport,
    key: &str,
    ip: IpAddr,
) -> Result<Option<AbuseIpResult>, HttpError> {
    if !sendable(ip) {
        return Err(not_public());
    }
    let r = http.get(
        &abuseipdb_url(ip),
        &[("Key", key), ("Accept", "application/json")],
    )?;
    match r.status {
        200 => parse_abuseipdb(ip, &r.body).map(Some),
        s => Err(HttpError::Status(s)),
    }
}

/// One CrowdSec CTI lookup. `Ok(None)` means CrowdSec has nothing on it.
pub fn lookup_crowdsec(
    http: &dyn Transport,
    key: &str,
    ip: IpAddr,
) -> Result<Option<CrowdSecIpResult>, HttpError> {
    if !sendable(ip) {
        return Err(not_public());
    }
    let r = http.get(&crowdsec_url(ip), &[("x-api-key", key)])?;
    match r.status {
        200 => parse_crowdsec(ip, &r.body).map(Some),
        404 => Ok(None),
        s => Err(HttpError::Status(s)),
    }
}

/// What the IP lookups found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IpFacts {
    /// VirusTotal reports.
    pub virustotal: Vec<VtIpResult>,
    /// AbuseIPDB reports.
    pub abuseipdb: Vec<AbuseIpResult>,
    /// CrowdSec CTI reports.
    pub crowdsec: Vec<CrowdSecIpResult>,
}

/// Keys for the IP services. Any can be missing.
#[derive(Debug, Default, Clone, Copy)]
pub struct IpKeys<'a> {
    /// VirusTotal key.
    pub virustotal: Option<&'a ApiKey>,
    /// AbuseIPDB key.
    pub abuseipdb: Option<&'a ApiKey>,
    /// CrowdSec CTI key.
    pub crowdsec: Option<&'a ApiKey>,
}

/// One service's run over the addresses: cache first, then the network,
/// stopping at the deadline, after repeated failures, or on an answer that
/// won't change mid-scan (bad key, quota spent).
struct Run<'a, T> {
    name: &'static str,
    max: usize,
    cache: &'a Mutex<HashMap<IpAddr, Option<T>>>,
    /// Waits for the service's rate limit; false means out of time.
    pace: &'a dyn Fn(Instant) -> bool,
    lookup: &'a dyn Fn(IpAddr) -> Result<Option<T>, HttpError>,
}

impl<T: Clone> Run<'_, T> {
    fn go(
        &self,
        ips: &[IpAddr],
        limits: Limits,
        deadline: Instant,
        summary: &mut Summary,
    ) -> (Vec<T>, usize) {
        let mut out = Vec::new();
        let mut sent = 0;
        let mut failures = 0;
        for ip in ips.iter().take(self.max) {
            let hit = self.cache.lock().ok().and_then(|c| c.get(ip).cloned());
            if let Some(hit) = hit {
                out.extend(hit);
                continue;
            }
            if Instant::now() >= deadline
                || failures >= limits.max_failures_in_a_row
                || !(self.pace)(deadline)
                || Instant::now() >= deadline
            {
                summary.errors.push(format!(
                    "{}: stopped early (slow, unreachable or out of time)",
                    self.name
                ));
                break;
            }
            sent += 1;
            match (self.lookup)(*ip) {
                Ok(r) => {
                    failures = 0;
                    if let Ok(mut c) = self.cache.lock() {
                        c.insert(*ip, r.clone());
                    }
                    out.extend(r);
                }
                Err(e) => {
                    summary
                        .errors
                        .push(format!("{}: {}", self.name, describe(&e)));
                    match e {
                        HttpError::Status(401 | 403 | 429) => break,
                        HttpError::Failed(_) => failures += 1,
                        _ => {}
                    }
                }
            }
        }
        (out, sent)
    }
}

/// Looks up `ips` (most important first) with the IP services switched on
/// in `settings`. With all three off, returns `None` straight away and
/// sends nothing.
pub fn check_ips(
    settings: OnlineChecks,
    ips: &[IpAddr],
    keys: IpKeys<'_>,
    http: &dyn Transport,
    cache: &Cache,
    limits: Limits,
    sleep: &dyn Fn(Duration),
) -> Option<(IpFacts, Summary)> {
    if !settings.ips() {
        return None;
    }
    let deadline = Instant::now() + limits.deadline;
    let ips: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|ip| sendable(*ip))
        .take(limits.ip_max)
        .collect();
    let mut facts = IpFacts::default();
    let mut summary = Summary::default();
    let no_wait = |_: Instant| true;

    if settings.virustotal_ips {
        if let Some(key) = keys.virustotal {
            // One key, one budget: shares the file lookups' limiter.
            let pace = |deadline: Instant| {
                cache.vt_limiter.lock().is_ok_and(|mut l| {
                    l.get_or_insert_with(|| RateLimiter::new(limits.vt_per_minute))
                        .wait_until(Instant::now, sleep, Some(deadline))
                })
            };
            let lookup = |ip| lookup_vt(http, key.expose(), ip);
            let run = Run {
                name: "VirusTotal IPs",
                max: limits.ip_max,
                cache: &cache.vt_ip,
                pace: &pace,
                lookup: &lookup,
            };
            let (found, sent) = run.go(&ips, limits, deadline, &mut summary);
            facts.virustotal = found;
            summary.vt_ip_sent = sent;
        } else {
            summary.errors.push("VirusTotal: no key saved".to_owned());
        }
    }

    if settings.abuseipdb {
        if let Some(key) = keys.abuseipdb {
            let lookup = |ip| lookup_abuseipdb(http, key.expose(), ip);
            let run = Run {
                name: "AbuseIPDB",
                max: limits.ip_max,
                cache: &cache.abuse,
                pace: &no_wait,
                lookup: &lookup,
            };
            let (found, sent) = run.go(&ips, limits, deadline, &mut summary);
            facts.abuseipdb = found;
            summary.abuseipdb_sent = sent;
        } else {
            summary.errors.push("AbuseIPDB: no key saved".to_owned());
        }
    }

    if settings.crowdsec {
        if let Some(key) = keys.crowdsec {
            let lookup = |ip| lookup_crowdsec(http, key.expose(), ip);
            let run = Run {
                name: "CrowdSec",
                max: limits.crowdsec_max.min(limits.ip_max),
                cache: &cache.crowdsec,
                pace: &no_wait,
                lookup: &lookup,
            };
            let (found, sent) = run.go(&ips, limits, deadline, &mut summary);
            facts.crowdsec = found;
            summary.crowdsec_sent = sent;
        } else {
            summary.errors.push("CrowdSec: no key saved".to_owned());
        }
    }
    Some((facts, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_parsing() {
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            vt_url(v4),
            "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.9"
        );
        assert_eq!(
            abuseipdb_url(v6),
            "https://api.abuseipdb.com/api/v2/check?ipAddress=2001%3Adb8%3A%3A1&maxAgeInDays=90"
        );
        assert_eq!(
            crowdsec_url(v4),
            "https://cti.api.crowdsec.net/v2/smoke/203.0.113.9"
        );
        let vt = parse_vt(
            v4,
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"suspicious":1,"harmless":50,"undetected":30,"timeout":0},"as_owner":"Example AS","country":"NL"}}}"#,
        )
        .unwrap();
        assert_eq!(
            (vt.malicious, vt.as_owner.as_deref()),
            (7, Some("Example AS"))
        );
        let ab = parse_abuseipdb(
            v4,
            r#"{"data":{"ipAddress":"203.0.113.9","abuseConfidenceScore":100,"totalReports":412,"isWhitelisted":null,"isp":"Example","usageType":"Data Center/Web Hosting/Transit","countryCode":"NL"}}"#,
        )
        .unwrap();
        assert_eq!(
            (ab.score, ab.total_reports, ab.whitelisted),
            (100, 412, None)
        );
        let cs = parse_crowdsec(
            v4,
            r#"{"ip":"203.0.113.9","reputation":"malicious","as_name":"Example AS","location":{"country":"NL"},"behaviors":[{"name":"http:scan","label":"HTTP Scan"},{"name":"ssh:bruteforce","label":"SSH Bruteforce"}],"classifications":{"false_positives":[],"classifications":[]},"scores":{"overall":{"total":4}}}"#,
        )
        .unwrap();
        assert_eq!(cs.reputation, "malicious");
        assert!(!cs.false_positive);
        assert_eq!(cs.behaviors, vec!["HTTP Scan", "SSH Bruteforce"]);
        let safe = parse_crowdsec(
            v4,
            r#"{"reputation":"safe","classifications":{"false_positives":[{"name":"seo:crawler","label":"SEO crawler"}]}}"#,
        )
        .unwrap();
        assert!(safe.false_positive);
    }

    #[test]
    fn private_addresses_are_never_sent() {
        struct Panics;
        impl Transport for Panics {
            fn get(
                &self,
                url: &str,
                _: &[(&str, &str)],
            ) -> Result<crate::allowlist::Reply, HttpError> {
                panic!("sent {url}");
            }
        }
        for ip in ["192.168.1.1", "10.0.0.5", "127.0.0.1", "::1", "fe80::1"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(lookup_vt(&Panics, "k", ip).is_err());
            assert!(lookup_abuseipdb(&Panics, "k", ip).is_err());
            assert!(lookup_crowdsec(&Panics, "k", ip).is_err());
        }
    }

    #[test]
    fn crowdsec_stays_inside_its_monthly_quota() {
        struct Counts(Mutex<usize>);
        impl Transport for Counts {
            fn get(
                &self,
                _: &str,
                _: &[(&str, &str)],
            ) -> Result<crate::allowlist::Reply, HttpError> {
                *self.0.lock().unwrap() += 1;
                Ok(crate::allowlist::Reply {
                    status: 404,
                    body: String::new(),
                })
            }
        }
        let http = Counts(Mutex::new(0));
        let key = ApiKey::new("k").unwrap();
        let ips: Vec<IpAddr> = (1..=30)
            .map(|n| format!("203.0.113.{n}").parse().unwrap())
            .collect();
        let settings = OnlineChecks {
            crowdsec: true,
            ..OnlineChecks::default()
        };
        let (_, summary) = check_ips(
            settings,
            &ips,
            IpKeys {
                crowdsec: Some(&key),
                ..IpKeys::default()
            },
            &http,
            &Cache::default(),
            Limits::default(),
            &|_| {},
        )
        .unwrap();
        assert_eq!(summary.crowdsec_sent, CROWDSEC_PER_SCAN);
        assert_eq!(*http.0.lock().unwrap(), CROWDSEC_PER_SCAN);
        assert!(
            check_ips(
                OnlineChecks::default(),
                &ips,
                IpKeys::default(),
                &http,
                &Cache::default(),
                Limits::default(),
                &|_| {}
            )
            .is_none()
        );
    }
}
