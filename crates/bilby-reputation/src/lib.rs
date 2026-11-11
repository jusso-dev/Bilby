//! Opt-in reputation checks (ADR 0004). Off by default.
//!
//! - CIRCL hashlookup and VirusTotal receive SHA-256 hashes only, and only
//!   when the user switched that service on. Never file contents, names,
//!   paths, the computer name or the user name.
//! - Which hashes are looked up is decided by
//!   [`bilby_core::rules::reputation::lookup_candidates`]: files behind
//!   findings, startup item targets, and non-Windows running programs.
//! - HTTP only to [`allowlist::ALLOWED`], through [`allowlist::Http`].
//! - "Ask Windows Security to check this file" ([`defender`]) is local and
//!   only runs when the user asks.
//! - Microsoft's cloud hash lookup isn't available to consumers outside
//!   Defender for Endpoint, so there's nothing here for it.

pub mod allowlist;
pub mod circl;
pub mod defender;
pub mod ip;
pub mod key;
pub mod virustotal;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bilby_core::rules::reputation::{MAX_CIRCL_LOOKUPS, MAX_IP_LOOKUPS};
use bilby_core::settings::OnlineChecks;
use bilby_core::snapshot::{
    AbuseIpResult, CrowdSecIpResult, ReputationFacts, VtIpResult, VtResult,
};

use allowlist::{HttpError, Transport};
use key::ApiKey;

/// 64 hex characters.
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// At most `per_minute` calls in any 60 seconds. `sleep` is injectable so
/// tests don't wait.
pub struct RateLimiter {
    per_minute: u32,
    sent: Vec<Instant>,
}

impl RateLimiter {
    /// A limiter for this many calls a minute (0 means none allowed).
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            sent: Vec::new(),
        }
    }

    /// Waits until another call is allowed, then records it.
    pub fn wait(&mut self, now: impl Fn() -> Instant, sleep: impl Fn(Duration)) {
        self.wait_until(now, sleep, None);
    }

    /// Like [`wait`](Self::wait), but gives up (returns false, records
    /// nothing) rather than sleep past `deadline`.
    pub fn wait_until(
        &mut self,
        now: impl Fn() -> Instant,
        sleep: impl Fn(Duration),
        deadline: Option<Instant>,
    ) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        loop {
            let t = now();
            self.sent
                .retain(|s| t.saturating_duration_since(*s) < Duration::from_secs(60));
            if self.sent.len() < self.per_minute as usize {
                self.sent.push(t);
                return true;
            }
            let oldest = self.sent[0];
            let pause = Duration::from_secs(60).saturating_sub(t.saturating_duration_since(oldest));
            if deadline.is_some_and(|d| t + pause >= d) {
                return false;
            }
            sleep(pause);
        }
    }
}

/// Limits for one scan.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most CIRCL lookups.
    pub circl_max: usize,
    /// Most VirusTotal lookups (the user's remaining daily quota).
    pub vt_max: usize,
    /// VirusTotal requests a minute.
    pub vt_per_minute: u32,
    /// Longest the whole online step may take. No request starts after it,
    /// and no rate-limit wait runs past it. A request already sent can
    /// still take up to its own 10 second timeout.
    pub deadline: Duration,
    /// Network failures in a row before a service is given up for this
    /// scan.
    pub max_failures_in_a_row: u32,
    /// Most IP addresses looked up with each IP service.
    pub ip_max: usize,
    /// Most CrowdSec lookups a scan: the free key allows 120 a month.
    pub crowdsec_max: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            circl_max: MAX_CIRCL_LOOKUPS,
            vt_max: virustotal::PUBLIC_PER_DAY as usize,
            vt_per_minute: virustotal::PUBLIC_PER_MINUTE,
            deadline: Duration::from_secs(120),
            max_failures_in_a_row: 3,
            ip_max: MAX_IP_LOOKUPS,
            crowdsec_max: ip::CROWDSEC_PER_SCAN,
        }
    }
}

/// What happened, for the scan's check list. Failures never fail a scan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    /// CIRCL lookups sent.
    pub circl_sent: usize,
    /// VirusTotal lookups sent.
    pub vt_sent: usize,
    /// VirusTotal IP reports asked for.
    pub vt_ip_sent: usize,
    /// AbuseIPDB checks sent.
    pub abuseipdb_sent: usize,
    /// CrowdSec lookups sent.
    pub crowdsec_sent: usize,
    /// Lookups that failed (network, timeout, quota). Reasons, no keys.
    pub errors: Vec<String>,
}

/// Session state: results, and VirusTotal's rate limiter, live in memory
/// until the app closes, so back-to-back scans share one budget.
#[derive(Default)]
pub struct Cache {
    circl: Mutex<HashMap<String, circl::Known>>,
    vt: Mutex<HashMap<String, Option<VtResult>>>,
    vt_ip: Mutex<HashMap<std::net::IpAddr, Option<VtIpResult>>>,
    abuse: Mutex<HashMap<std::net::IpAddr, Option<AbuseIpResult>>>,
    crowdsec: Mutex<HashMap<std::net::IpAddr, Option<CrowdSecIpResult>>>,
    /// Shared by file and IP lookups: one key, one budget.
    vt_limiter: Mutex<Option<RateLimiter>>,
}

/// Looks up `hashes` (most important first) with the services switched
/// on in `settings`. With both off, returns `None` straight away: no
/// client is built and nothing is sent.
pub fn check(
    settings: OnlineChecks,
    hashes: &[String],
    vt_key: Option<&ApiKey>,
    http: &dyn Transport,
    cache: &Cache,
    limits: Limits,
    sleep: &dyn Fn(Duration),
) -> Option<(ReputationFacts, Summary)> {
    if !(settings.circl || settings.virustotal) {
        return None;
    }
    let deadline = Instant::now() + limits.deadline;
    let in_time = || Instant::now() < deadline;
    let mut facts = ReputationFacts::default();
    let mut summary = Summary::default();
    let hashes: Vec<String> = hashes
        .iter()
        .filter(|h| is_sha256(h))
        .map(|h| h.to_ascii_lowercase())
        .collect();

    if settings.circl {
        let mut failures = 0;
        for h in hashes.iter().take(limits.circl_max) {
            let cached = cache.circl.lock().ok().and_then(|c| c.get(h).copied());
            let known = if let Some(k) = cached {
                Some(k)
            } else {
                if !in_time() || failures >= limits.max_failures_in_a_row {
                    summary
                        .errors
                        .push("CIRCL: stopped early (slow or unreachable)".to_owned());
                    break;
                }
                summary.circl_sent += 1;
                match circl::lookup(http, h) {
                    Ok(k) => {
                        failures = 0;
                        if let Ok(mut c) = cache.circl.lock() {
                            c.insert(h.clone(), k);
                        }
                        Some(k)
                    }
                    Err(e) => {
                        if matches!(e, HttpError::Failed(_)) {
                            failures += 1;
                        }
                        summary.errors.push(format!("CIRCL: {}", describe(&e)));
                        None
                    }
                }
            };
            if known == Some(circl::Known::Yes) {
                facts.known_good.push(h.clone());
            }
        }
    }

    if settings.virustotal {
        match vt_key {
            None => summary.errors.push("VirusTotal: no key saved".to_owned()),
            Some(key) => vt_lookups(
                &hashes,
                key,
                http,
                cache,
                limits,
                sleep,
                deadline,
                &mut facts,
                &mut summary,
            ),
        }
    }
    Some((facts, summary))
}

#[allow(clippy::too_many_arguments)]
fn vt_lookups(
    hashes: &[String],
    key: &ApiKey,
    http: &dyn Transport,
    cache: &Cache,
    limits: Limits,
    sleep: &dyn Fn(Duration),
    deadline: Instant,
    facts: &mut ReputationFacts,
    summary: &mut Summary,
) {
    let mut failures = 0;
    for h in hashes.iter().take(limits.vt_max) {
        let cached = cache.vt.lock().ok().and_then(|c| c.get(h).cloned());
        let result = if let Some(r) = cached {
            r
        } else {
            let stop = |summary: &mut Summary| {
                summary.errors.push(
                    "VirusTotal: stopped early (slow, unreachable or out of time)".to_owned(),
                );
            };
            if Instant::now() >= deadline || failures >= limits.max_failures_in_a_row {
                stop(summary);
                break;
            }
            let allowed = cache.vt_limiter.lock().is_ok_and(|mut l| {
                l.get_or_insert_with(|| RateLimiter::new(limits.vt_per_minute))
                    .wait_until(Instant::now, sleep, Some(deadline))
            });
            // Check again after any wait: never start a request late.
            if !allowed || Instant::now() >= deadline {
                stop(summary);
                break;
            }
            summary.vt_sent += 1;
            match virustotal::lookup(http, key.expose(), h) {
                Ok(r) => {
                    failures = 0;
                    if let Ok(mut c) = cache.vt.lock() {
                        c.insert(h.clone(), r.clone());
                    }
                    r
                }
                Err(e) => {
                    summary.errors.push(format!("VirusTotal: {}", describe(&e)));
                    match e {
                        // A bad or blocked key, or a spent quota, won't fix
                        // itself mid-scan: stop asking.
                        HttpError::Status(401 | 403 | 429) => break,
                        HttpError::Failed(_) => failures += 1,
                        _ => {}
                    }
                    None
                }
            }
        };
        facts.virustotal.extend(result);
    }
}

pub(crate) fn describe(e: &HttpError) -> String {
    match e {
        HttpError::NotAllowed(m) => format!("not sent ({m})"),
        HttpError::Status(s) => format!("returned HTTP {s}"),
        HttpError::BadReply(m) | HttpError::Failed(m) => m.clone(),
    }
}
