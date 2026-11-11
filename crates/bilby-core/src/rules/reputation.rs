//! Reputation rules: VirusTotal results, Defender scans the user asked for,
//! and CIRCL "known good" adjustments. See `docs/signals.md` and ADR 0004.
//!
//! Also decides which hashes are worth looking up ([`lookup_candidates`]),
//! so the online client never sees more than the rules allow.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use super::{FindingBuilder, Rule, RuleContext};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::net::{AddrClass, classify};
use crate::paths::{KnownFolders, normalise};
use crate::snapshot::{
    AbuseIpResult, ConnectionFact, CrowdSecIpResult, DefenderScanOutcome, FileFacts, ProcessFact,
    Proto, ReputationFacts, SignatureStatus, SystemSnapshot, TcpState, VtIpResult, VtResult,
};

/// Rule id of the known-good adjustment. It never makes a card.
pub const KNOWN_GOOD: &str = "rep.known_good";

/// VirusTotal engines that must call a file malicious for High.
pub const VT_MALICIOUS: u32 = 5;

/// Most CIRCL lookups in one scan.
pub const MAX_CIRCL_LOOKUPS: usize = 100;

/// Most IP addresses looked up in one scan.
pub const MAX_IP_LOOKUPS: usize = 20;

/// VirusTotal engines that must call an address malicious for
/// `rep.ip.known_bad`. Lower than for files: far fewer engines rate IPs.
pub const VT_IP_MALICIOUS: u32 = 3;

/// AbuseIPDB confidence score for `rep.ip.known_bad`.
pub const ABUSE_HIGH: u8 = 75;

/// AbuseIPDB score for High confidence on its own.
pub const ABUSE_VERY_HIGH: u8 = 90;

/// AbuseIPDB score at or above which `rep.ip.some_reports` shows.
pub const ABUSE_SOME: u8 = 25;

fn norm(p: &str) -> String {
    normalise(p, &KnownFolders::default())
}

/// Every file fact in the snapshot, by normalised path.
pub(crate) fn files(snap: &SystemSnapshot) -> HashMap<String, &FileFacts> {
    let mut all: Vec<&FileFacts> = Vec::new();
    if let Some(p) = &snap.processes {
        all.extend(p.iter().filter_map(|x| x.file.as_ref()));
    }
    if let Some(p) = &snap.persistence {
        all.extend(p.items.iter().filter_map(|i| i.target.as_ref()));
        all.extend(p.ifeo.iter().filter_map(|i| i.target.as_ref()));
        for s in &p.services {
            all.extend(s.binary.iter().chain(s.service_dll.iter()));
        }
        for t in &p.tasks {
            for a in &t.actions {
                if let crate::snapshot::TaskAction::Exec {
                    target: Some(f), ..
                } = a
                {
                    all.push(f);
                }
            }
        }
    }
    if let Some(d) = &snap.drivers {
        all.extend(d.loaded.iter());
    }
    let mut out = HashMap::new();
    for f in all {
        out.entry(norm(&f.path)).or_insert(f);
    }
    out
}

/// Every file path a finding is about: its subject and path evidence.
pub(crate) fn finding_paths(f: &Finding) -> Vec<String> {
    let mut out = Vec::new();
    if let Subject::File(p) = &f.subject {
        out.push(norm(p));
    }
    for e in &f.evidence {
        if let Evidence::Path(p) = e {
            let n = norm(p);
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

/// Hashes worth looking up, most important first: files behind findings
/// of Low or higher (by severity), then the targets of startup items, then
/// running programs that aren't part of Windows. Never every file. Each
/// hash once, at most `cap`, so a long list drops the least important.
pub fn lookup_candidates(snap: &SystemSnapshot, findings: &[Finding], cap: usize) -> Vec<String> {
    let by_path = files(snap);
    let mut ordered: Vec<String> = Vec::new();
    let mut push = |h: &str| {
        let h = h.to_ascii_lowercase();
        if !ordered.contains(&h) {
            ordered.push(h);
        }
    };
    let mut flagged: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Low)
        .collect();
    flagged.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.cmp(&a.confidence))
    });
    for f in flagged {
        for p in finding_paths(f) {
            if let Some(h) = by_path.get(&p).and_then(|x| x.sha256.as_deref()) {
                push(h);
            }
        }
    }
    if let Some(p) = &snap.persistence {
        for t in p.items.iter().filter_map(|i| i.target.as_ref()) {
            if let Some(h) = t.sha256.as_deref() {
                push(h);
            }
        }
    }
    if let Some(ps) = &snap.processes {
        for f in ps.iter().filter_map(|p| p.file.as_ref()) {
            let windows = matches!(
                f.signature,
                SignatureStatus::Signed {
                    is_windows_component: true,
                    ..
                }
            );
            if let (false, Some(h)) = (windows, f.sha256.as_deref()) {
                push(h);
            }
        }
    }
    ordered.truncate(cap);
    ordered
}

/// The public peer of an established TCP connection.
fn public_peer(c: &ConnectionFact) -> Option<IpAddr> {
    let remote = c.remote?;
    (c.proto == Proto::Tcp
        && c.state == Some(TcpState::Established)
        && classify(remote.ip()) == AddrClass::Public)
        .then_some(remote.ip())
}

/// Running programs a finding is about: a process it names, or a file it's
/// about that is running. By pid.
fn flagged_pids(snap: &SystemSnapshot, f: &Finding) -> Vec<u32> {
    let Some(procs) = snap.processes.as_deref() else {
        return Vec::new();
    };
    let paths: HashSet<String> = finding_paths(f).into_iter().collect();
    let named: HashSet<u32> = f
        .evidence
        .iter()
        .filter_map(|e| match e {
            Evidence::Process { pid, .. } => Some(*pid),
            _ => None,
        })
        .collect();
    procs
        .iter()
        .filter(|p| {
            named.contains(&p.pid)
                || p.image_path
                    .as_deref()
                    .is_some_and(|i| paths.contains(&norm(i)))
        })
        .map(|p| p.pid)
        .collect()
}

/// Public internet addresses worth looking up: the peers of programs that
/// already have a finding of Low or higher, most serious first. Never
/// every connection on the computer. Each address once, at most `cap`.
pub fn ip_candidates(snap: &SystemSnapshot, findings: &[Finding], cap: usize) -> Vec<IpAddr> {
    let Some(net) = &snap.network else {
        return Vec::new();
    };
    let mut flagged: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Low && f.family != SignalFamily::Reputation)
        .collect();
    flagged.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.cmp(&a.confidence))
    });
    let mut out: Vec<IpAddr> = Vec::new();
    for f in flagged {
        for pid in flagged_pids(snap, f) {
            for ip in net
                .connections
                .iter()
                .filter(|c| c.pid == pid)
                .filter_map(public_peer)
            {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out.truncate(cap);
    out
}

/// How bad an address looks across the services that answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IpVerdict {
    /// A few reports: might be nothing.
    Some,
    /// Reported as harmful by several engines or many people.
    Bad,
    /// Strongly reported, or both services agree.
    VeryBad,
}

/// What each IP service said about one address.
#[derive(Clone, Copy, Default)]
struct IpReports<'a> {
    vt: Option<&'a VtIpResult>,
    ab: Option<&'a AbuseIpResult>,
    cs: Option<&'a CrowdSecIpResult>,
}

fn ip_verdict(r: IpReports<'_>) -> Option<IpVerdict> {
    let vt_m = r.vt.map_or(0, |v| v.malicious);
    // An address on AbuseIPDB's allow list, or that CrowdSec calls safe or
    // benign or tags as a false positive (a big search engine or CDN, say),
    // never goes past "some reports". CrowdSec's "known" means it has seen
    // the address but can't decide yet, so it doesn't count either way.
    let listed = r.ab.is_some_and(|a| a.whitelisted == Some(true))
        || r.cs.is_some_and(|c| {
            c.false_positive || matches!(c.reputation.as_str(), "safe" | "benign")
        });
    let score = r.ab.map_or(0, |a| a.score);
    let cs_rep = r.cs.map_or("", |c| c.reputation.as_str());
    let vt_bad = vt_m >= VT_IP_MALICIOUS && !listed;
    let ab_bad = score >= ABUSE_HIGH && !listed;
    let cs_bad = cs_rep == "malicious" && !listed;
    let agreeing = [vt_bad, ab_bad, cs_bad].iter().filter(|b| **b).count();
    if agreeing >= 2 || (vt_m >= VT_MALICIOUS && !listed) || (score >= ABUSE_VERY_HIGH && !listed) {
        Some(IpVerdict::VeryBad)
    } else if agreeing == 1 {
        Some(IpVerdict::Bad)
    } else if vt_m >= 1 || score >= ABUSE_SOME || matches!(cs_rep, "malicious" | "suspicious") {
        Some(IpVerdict::Some)
    } else {
        None
    }
}

fn ip_line(ip: IpAddr, r: IpReports<'_>) -> String {
    let mut parts = Vec::new();
    if let Some(v) = r.vt {
        let mut t = format!(
            "VirusTotal {} malicious, {} suspicious, {} harmless",
            v.malicious, v.suspicious, v.harmless
        );
        if let Some(o) = &v.as_owner {
            t.push_str(", network ");
            t.push_str(o);
        }
        parts.push(t);
    }
    if let Some(c) = r.cs {
        let mut t = format!("CrowdSec {}", c.reputation);
        if c.false_positive {
            t.push_str(", marked as a false positive");
        }
        if !c.behaviors.is_empty() {
            t.push_str(" (");
            t.push_str(&c.behaviors.join(", "));
            t.push(')');
        }
        parts.push(t);
    }
    if let Some(a) = r.ab {
        let mut t = format!(
            "AbuseIPDB score {} of 100, {} reports",
            a.score, a.total_reports
        );
        if a.whitelisted == Some(true) {
            t.push_str(", on its allow list");
        }
        if let Some(u) = &a.usage_type {
            t.push_str(", ");
            t.push_str(u);
        }
        parts.push(t);
    }
    format!("{ip}: {}", parts.join("; "))
}

/// A program's reported connections, gathered for one finding.
struct Reported<'a> {
    verdict: IpVerdict,
    name: String,
    conns: Vec<&'a ConnectionFact>,
    lines: Vec<String>,
}

/// `rep.ip.known_bad` (`strong`) and `rep.ip.some_reports`: one finding
/// per program, listing every reported address it was connected to. The
/// subject is the program's file, so it groups with that program's other
/// findings.
fn ip_findings(rep: &ReputationFacts, snap: &SystemSnapshot, strong: bool) -> Vec<Finding> {
    let (Some(net), Some(procs)) = (&snap.network, snap.processes.as_deref()) else {
        return Vec::new();
    };
    let vt: HashMap<IpAddr, &VtIpResult> = rep.ip_virustotal.iter().map(|r| (r.ip, r)).collect();
    let ab: HashMap<IpAddr, &AbuseIpResult> = rep.ip_abuseipdb.iter().map(|r| (r.ip, r)).collect();
    let cs: HashMap<IpAddr, &CrowdSecIpResult> =
        rep.ip_crowdsec.iter().map(|r| (r.ip, r)).collect();
    let by_pid: HashMap<u32, &ProcessFact> = procs.iter().map(|p| (p.pid, p)).collect();
    let mut per: BTreeMap<String, Reported<'_>> = BTreeMap::new();
    for c in &net.connections {
        let Some(ip) = public_peer(c) else { continue };
        let reports = IpReports {
            vt: vt.get(&ip).copied(),
            ab: ab.get(&ip).copied(),
            cs: cs.get(&ip).copied(),
        };
        let Some(verdict) = ip_verdict(reports) else {
            continue;
        };
        if strong != (verdict >= IpVerdict::Bad) {
            continue;
        }
        let Some(p) = by_pid.get(&c.pid) else {
            continue;
        };
        let path = p.image_path.clone().unwrap_or_else(|| p.name.clone());
        let e = per.entry(norm(&path)).or_insert_with(|| Reported {
            verdict,
            name: p.name.clone(),
            conns: Vec::new(),
            lines: Vec::new(),
        });
        e.verdict = e.verdict.max(verdict);
        e.conns.push(c);
        let line = ip_line(ip, reports);
        if !e.lines.contains(&line) {
            e.lines.push(line);
        }
    }
    per.into_iter()
        .map(|(path, r)| {
            let (id, sev, conf) = match r.verdict {
                IpVerdict::VeryBad => ("rep.ip.known_bad", Severity::High, Confidence::High),
                IpVerdict::Bad => ("rep.ip.known_bad", Severity::High, Confidence::Medium),
                IpVerdict::Some => ("rep.ip.some_reports", Severity::Low, Confidence::Low),
            };
            let first = r
                .conns
                .first()
                .and_then(|c| c.remote)
                .map_or_else(String::new, |a| a.ip().to_string());
            let mut b =
                FindingBuilder::new(id, SignalFamily::Reputation, sev, conf, Subject::File(path))
                    .var("name", &r.name)
                    .var("ip", first)
                    .var("count", r.lines.len())
                    .next(NextStepKind::AskDefender);
            for l in r.lines {
                b = b.text("evidence.ip_reputation", l);
            }
            for c in r.conns.iter().take(10) {
                b = b.evidence(Evidence::Connection {
                    local: c.local.to_string(),
                    remote: c.remote.map_or_else(|| "-".to_owned(), |a| a.to_string()),
                    state: "established".to_owned(),
                });
            }
            b.build()
        })
        .collect()
}

fn ip_known_bad(rep: &ReputationFacts, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    ip_findings(rep, snap, true)
}

fn ip_some_reports(rep: &ReputationFacts, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    ip_findings(rep, snap, false)
}

pub(crate) fn down(c: Confidence) -> Confidence {
    match c {
        Confidence::High => Confidence::Medium,
        Confidence::Medium | Confidence::Low => Confidence::Low,
    }
}

/// `rep.known_good`: lowers confidence by one level on findings about a
/// file CIRCL recognised. Runs after every other rule and never makes a
/// card. Reputation findings themselves are left alone: a VirusTotal
/// verdict isn't softened by a known-software list.
pub fn soften_known_good(snap: &SystemSnapshot, findings: &mut [Finding]) {
    let Some(rep) = &snap.reputation else { return };
    if rep.known_good.is_empty() {
        return;
    }
    let known: BTreeSet<String> = rep
        .known_good
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let by_path = files(snap);
    for f in findings
        .iter_mut()
        .filter(|f| f.family != SignalFamily::Reputation)
    {
        let hit = finding_paths(f).iter().any(|p| {
            by_path
                .get(p)
                .and_then(|x| x.sha256.as_deref())
                .is_some_and(|h| known.contains(&h.to_ascii_lowercase()))
        });
        if hit {
            f.confidence = down(f.confidence);
            f.evidence.push(Evidence::Text {
                label_key: "evidence.lowered_by".to_owned(),
                value: KNOWN_GOOD.to_owned(),
            });
        }
    }
}

fn vt_files<'a>(snap: &'a SystemSnapshot, r: &VtResult) -> Vec<&'a FileFacts> {
    let mut v: Vec<&FileFacts> = files(snap)
        .into_values()
        .filter(|f| {
            f.sha256
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(&r.sha256))
        })
        .collect();
    v.sort_by(|a, b| a.path.cmp(&b.path));
    v
}

fn vt_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    snap: &SystemSnapshot,
    r: &VtResult,
) -> Finding {
    let files = vt_files(snap, r);
    let name = files
        .first()
        .and_then(|f| f.path.rsplit(['\\', '/']).next())
        .unwrap_or(&r.sha256)
        .to_owned();
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Reputation,
        severity,
        confidence,
        Subject::File(
            files
                .first()
                .map_or_else(|| r.sha256.clone(), |f| norm(&f.path)),
        ),
    )
    .var("name", &name)
    .var("count", r.malicious)
    .text("evidence.sha256", &r.sha256)
    .text(
        "evidence.vt_stats",
        format!(
            "{} malicious, {} suspicious, {} undetected, {} harmless",
            r.malicious, r.suspicious, r.undetected, r.harmless
        ),
    )
    .next(NextStepKind::AskDefender);
    if let Some(d) = r.analysed {
        b = b.text("evidence.vt_date", d);
    }
    for f in files {
        b = b.evidence(Evidence::Path(f.path.clone()));
    }
    b.build()
}

fn vt_malicious(rep: &ReputationFacts, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    rep.virustotal
        .iter()
        .filter(|r| r.malicious >= VT_MALICIOUS)
        .map(|r| {
            vt_finding(
                "rep.vt.malicious",
                Severity::High,
                Confidence::High,
                snap,
                r,
            )
        })
        .collect()
}

fn vt_few(rep: &ReputationFacts, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    rep.virustotal
        .iter()
        .filter(|r| (1..VT_MALICIOUS).contains(&r.malicious))
        .map(|r| vt_finding("rep.vt.few", Severity::Low, Confidence::Low, snap, r))
        .collect()
}

fn defender_threat(rep: &ReputationFacts, _: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
    rep.defender_scans
        .iter()
        .filter_map(|s| {
            let DefenderScanOutcome::Threat { name } = &s.outcome else {
                return None;
            };
            let file = s.path.rsplit(['\\', '/']).next().unwrap_or(&s.path);
            let mut b = FindingBuilder::new(
                "rep.defender.threat",
                SignalFamily::Reputation,
                Severity::High,
                Confidence::High,
                Subject::File(norm(&s.path)),
            )
            .var("name", file)
            .evidence(Evidence::Path(s.path.clone()))
            .next(NextStepKind::AskDefender);
            if let Some(n) = name {
                b = b.text("evidence.threat", n);
            }
            Some(b.build())
        })
        .collect()
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Reputation
            }
            fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
                snap.reputation
                    .as_ref()
                    .map(|r| $fn(r, snap, ctx))
                    .unwrap_or_default()
            }
        }
    };
}

rule!(VtMalicious, "rep.vt.malicious", vt_malicious);
rule!(VtFew, "rep.vt.few", vt_few);
rule!(DefenderThreat, "rep.defender.threat", defender_threat);
rule!(IpKnownBad, "rep.ip.known_bad", ip_known_bad);
rule!(IpSomeReports, "rep.ip.some_reports", ip_some_reports);

/// The reputation rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(VtMalicious),
        Box::new(VtFew),
        Box::new(DefenderThreat),
        Box::new(IpKnownBad),
        Box::new(IpSomeReports),
    ]
}

#[cfg(test)]
mod ip_tests {
    use super::*;
    use crate::model::{Confidence, Severity};
    use crate::snapshot::{NetworkFacts, ProcessFact};

    fn snap() -> SystemSnapshot {
        let p = |pid: u32, name: &str, path: &str| -> ProcessFact {
            serde_json::from_value(serde_json::json!({
                "pid": pid, "ppid": 1, "name": name, "image_path": path,
                "created": "2026-11-09T08:00:00Z", "session_id": 1
            }))
            .expect("process")
        };
        let c = |remote: &str, pid: u32| ConnectionFact {
            proto: Proto::Tcp,
            local: "192.168.1.20:50000".parse().expect("addr"),
            remote: Some(remote.parse().expect("addr")),
            state: Some(TcpState::Established),
            pid,
        };
        SystemSnapshot {
            processes: Some(vec![
                p(
                    10,
                    "updater.exe",
                    r"C:\Users\a\AppData\Local\Temp\updater.exe",
                ),
                p(
                    20,
                    "chrome.exe",
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                ),
            ]),
            network: Some(NetworkFacts {
                connections: vec![
                    c("203.0.113.66:443", 10),
                    c("203.0.113.66:8443", 10),
                    c("192.168.1.1:53", 10),
                    c("142.250.70.78:443", 20),
                ],
            }),
            ..SystemSnapshot::default()
        }
    }

    #[test]
    fn only_flagged_programs_public_peers_are_looked_up() {
        let s = snap();
        let flagged = FindingBuilder::new(
            "proc.unsigned_user_writable",
            SignalFamily::Processes,
            Severity::Medium,
            Confidence::Medium,
            Subject::File(norm(r"C:\Users\a\AppData\Local\Temp\updater.exe")),
        )
        .build();
        let info = FindingBuilder::new(
            "browser.store_wide",
            SignalFamily::Browser,
            Severity::Info,
            Confidence::High,
            Subject::File(norm(
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            )),
        )
        .build();
        let ips = ip_candidates(&s, &[flagged, info], MAX_IP_LOOKUPS);
        // One public address, once; not the router, not Chrome's.
        assert_eq!(ips, vec!["203.0.113.66".parse::<IpAddr>().expect("ip")]);
        assert_eq!(ip_candidates(&s, &[], MAX_IP_LOOKUPS), Vec::<IpAddr>::new());
    }
}
