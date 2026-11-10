//! Tampering rules: hosts file redirects, proxies and root certificates.
//! See `docs/signals.md`.

use std::sync::LazyLock;

use serde::Deserialize;
use time::Duration;

use super::{FindingBuilder, Rule, RuleContext};
use crate::hosts::{WatchGroup, is_blackhole, watched};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::net::{AddrClass, classify};
use crate::snapshot::{
    PathClass, RootCert, RootStore, SignatureStatus, SystemSnapshot, TamperFacts,
};

/// Fix id for removing a hosts line, with a backup (#32).
pub const FIX_HOSTS_LINE: &str = "remove_hosts_line";
/// Fix id for turning the per-user proxy off (#32).
pub const FIX_CLEAR_PROXY: &str = "clear_proxy";

/// Entries to `0.0.0.0` or `127.0.0.1` past this look like an ad blocker.
pub const MANY_ENTRIES: usize = 200;
/// A root newer than this (by not-before) is "recently added".
pub const RECENT_ROOT: Duration = Duration::days(60);

#[derive(Deserialize)]
struct BadRoot {
    name: String,
    sha1: String,
}

#[derive(Deserialize)]
struct BadSubject {
    name: String,
}

#[derive(Deserialize)]
struct BadTable {
    #[serde(default)]
    root: Vec<BadRoot>,
    #[serde(default)]
    subject: Vec<BadSubject>,
}

static BAD: LazyLock<BadTable> = LazyLock::new(|| {
    toml::from_str(include_str!("../../data/known_bad_roots.toml"))
        .expect("known_bad_roots.toml is valid")
});

#[derive(Deserialize)]
struct DevRoot {
    tool: String,
    field: String,
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct DevTable {
    root: Vec<DevRoot>,
}

static DEV: LazyLock<DevTable> = LazyLock::new(|| {
    toml::from_str(include_str!("../../data/known_dev_roots.toml"))
        .expect("known_dev_roots.toml is valid")
});

/// The known-bad root this certificate is, by thumbprint or subject.
pub fn known_bad(r: &RootCert) -> Option<&'static str> {
    let sha = r.sha1.to_ascii_lowercase();
    BAD.root
        .iter()
        .find(|b| b.sha1.eq_ignore_ascii_case(&sha))
        .map(|b| b.name.as_str())
        .or_else(|| {
            let cn = r.subject_cn.as_deref()?;
            BAD.subject
                .iter()
                .find(|s| s.name == cn)
                .map(|s| s.name.as_str())
        })
}

/// The developer tool this root belongs to, if any.
pub fn dev_tool(r: &RootCert) -> Option<&'static str> {
    DEV.root.iter().find_map(|d| {
        let field = match d.field.as_str() {
            "cn" => r.subject_cn.as_deref(),
            "o" => r.subject_o.as_deref(),
            _ => None,
        }?;
        let (f, v) = (field.to_ascii_lowercase(), d.value.to_ascii_lowercase());
        let hit = if d.kind == "prefix" {
            f.starts_with(&v)
        } else {
            f == v
        };
        hit.then_some(d.tool.as_str())
    })
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Tamper
            }
            fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
                snap.tamper
                    .as_ref()
                    .map(|t| $fn(t, ctx))
                    .unwrap_or_default()
            }
        }
    };
}

rule!(HostsWatch, "tamper.hosts.watch_domain", hosts_watch);
rule!(HostsMoved, "tamper.hosts.path_moved", hosts_moved);
rule!(HostsMany, "tamper.hosts.many_entries", hosts_many);
rule!(ProxyUnexpected, "tamper.proxy.unexpected", proxy_unexpected);
rule!(ProxyPacHttp, "tamper.proxy.pac_http", proxy_pac_http);
rule!(WinhttpProxy, "tamper.winhttp_proxy", winhttp_proxy);
rule!(RootKnownBad, "tamper.root.known_bad", root_known_bad);
rule!(RootUnknown, "tamper.root.unknown", root_unknown);
rule!(RootDevTool, "tamper.root.dev_tool", root_dev_tool);

/// Every tampering rule.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(HostsWatch),
        Box::new(HostsMoved),
        Box::new(HostsMany),
        Box::new(ProxyUnexpected),
        Box::new(ProxyPacHttp),
        Box::new(WinhttpProxy),
        Box::new(RootKnownBad),
        Box::new(RootUnknown),
        Box::new(RootDevTool),
    ]
}

fn hosts_watch(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(h) = &t.hosts else { return Vec::new() };
    let mut out = Vec::new();
    for e in &h.entries {
        for name in &e.names {
            let Some((domain, group)) = watched(name) else {
                continue;
            };
            // Some privacy tools block update and security sites on purpose;
            // a redirect anywhere else is the real trick.
            let confidence = if group == WatchGroup::UpdatesAndSecurity && e.ip == "0.0.0.0" {
                Confidence::Medium
            } else {
                Confidence::High
            };
            out.push(
                FindingBuilder::new(
                    "tamper.hosts.watch_domain",
                    SignalFamily::Tamper,
                    Severity::High,
                    confidence,
                    Subject::HostsEntry(format!("{}:{name}", e.line)),
                )
                .var("name", name)
                .var("domain", domain)
                .var("ip", &e.ip)
                .evidence(Evidence::Path(h.path.clone()))
                .text(
                    "evidence.hosts_line",
                    format!("line {}: {} {}", e.line, e.ip, e.names.join(" ")),
                )
                .next(NextStepKind::Fix(FIX_HOSTS_LINE.to_owned()))
                .build(),
            );
        }
    }
    out
}

fn hosts_moved(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(h) = t.hosts.as_ref().filter(|h| !h.default_path) else {
        return Vec::new();
    };
    vec![
        FindingBuilder::new(
            "tamper.hosts.path_moved",
            SignalFamily::Tamper,
            Severity::High,
            Confidence::Medium,
            Subject::Setting("tcpip.databasepath".to_owned()),
        )
        .evidence(Evidence::Path(h.path.clone()))
        .next(NextStepKind::TalkToHelper)
        .build(),
    ]
}

fn hosts_many(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(h) = &t.hosts else { return Vec::new() };
    let n: usize = h
        .entries
        .iter()
        .filter(|e| is_blackhole(&e.ip))
        .map(|e| e.names.len())
        .sum();
    if n <= MANY_ENTRIES {
        return Vec::new();
    }
    vec![
        FindingBuilder::new(
            "tamper.hosts.many_entries",
            SignalFamily::Tamper,
            Severity::Info,
            Confidence::High,
            Subject::Setting("hosts.blocklist".to_owned()),
        )
        .var("count", n)
        .evidence(Evidence::Path(h.path.clone()))
        .next(NextStepKind::Learn)
        .build(),
    ]
}

/// Tools people run on purpose that listen as a local proxy.
const KNOWN_PROXY_TOOLS: &[&str] = &[
    "fiddler.exe",
    "fiddler everywhere.exe",
    "charles.exe",
    "burpsuite.exe",
    "burpsuitepro.exe",
    "burpsuitecommunity.exe",
];

fn proxy_unexpected(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(p) = &t.proxy else { return Vec::new() };
    let active = (p.enabled && p.server.as_deref().is_some_and(|s| !s.trim().is_empty()))
        || p.pac_url.as_deref().is_some_and(|u| !u.trim().is_empty());
    if !active || t.management.managed {
        return Vec::new();
    }
    let confidence = match &p.listener {
        Some(l) if KNOWN_PROXY_TOOLS.contains(&l.name.to_ascii_lowercase().as_str()) => {
            Confidence::Low
        }
        Some(l) => match &l.file {
            Some(f)
                if f.user_writable
                    && f.class != PathClass::UserAppPrograms
                    && matches!(
                        f.signature,
                        SignatureStatus::Unsigned | SignatureStatus::Invalid { .. }
                    ) =>
            {
                Confidence::High
            }
            // A signed program, for example a security product's web filter.
            Some(f) if f.signature.is_signed() => Confidence::Low,
            _ => Confidence::Medium,
        },
        None => Confidence::Medium,
    };
    let mut b = FindingBuilder::new(
        "tamper.proxy.unexpected",
        SignalFamily::Tamper,
        Severity::Medium,
        confidence,
        Subject::Setting("wininet.proxy".to_owned()),
    )
    .var(
        "proxy",
        p.server
            .as_deref()
            .or(p.pac_url.as_deref())
            .unwrap_or_default(),
    )
    .next(NextStepKind::Fix(FIX_CLEAR_PROXY.to_owned()));
    if let Some(s) = &p.server {
        b = b.text("evidence.proxy_server", s);
    }
    if let Some(u) = &p.pac_url {
        b = b.text("evidence.pac_url", u);
    }
    if let Some(l) = &p.listener {
        b = b.evidence(Evidence::Process {
            pid: l.pid,
            name: l.name.clone(),
            path: l.image_path.clone(),
            parent: None,
        });
    }
    vec![b.build()]
}

/// The host part of a URL, without user info or port.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

fn proxy_pac_http(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(url) = t.proxy.as_ref().and_then(|p| p.pac_url.as_deref()) else {
        return Vec::new();
    };
    if !url.trim().to_ascii_lowercase().starts_with("http://") {
        return Vec::new();
    }
    let Some(host) = url_host(url.trim()) else {
        return Vec::new();
    };
    // A name, or a public address, is somewhere on the internet. Local
    // addresses (a router, wpad on the LAN) aren't.
    let public = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => classify(ip) == AddrClass::Public,
        Err(_) => {
            !host.eq_ignore_ascii_case("localhost")
                && host.contains('.')
                && !host.ends_with(".local")
        }
    };
    if !public {
        return Vec::new();
    }
    vec![
        FindingBuilder::new(
            "tamper.proxy.pac_http",
            SignalFamily::Tamper,
            Severity::Medium,
            Confidence::Medium,
            Subject::Setting("wininet.autoconfigurl".to_owned()),
        )
        .var("url", url)
        .text("evidence.pac_url", url)
        .next(NextStepKind::Fix(FIX_CLEAR_PROXY.to_owned()))
        .build(),
    ]
}

fn winhttp_proxy(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(server) = t.winhttp_proxy.as_deref().filter(|s| !s.trim().is_empty()) else {
        return Vec::new();
    };
    if t.management.managed {
        return Vec::new();
    }
    vec![
        FindingBuilder::new(
            "tamper.winhttp_proxy",
            SignalFamily::Tamper,
            Severity::Low,
            Confidence::Medium,
            Subject::Setting("winhttp.proxy".to_owned()),
        )
        .var("proxy", server)
        .text("evidence.proxy_server", server)
        .next(NextStepKind::TalkToHelper)
        .build(),
    ]
}

fn root_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    r: &RootCert,
) -> FindingBuilder {
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Tamper,
        severity,
        confidence,
        Subject::Certificate(r.sha1.to_ascii_lowercase()),
    )
    .var(
        "name",
        r.subject_cn
            .as_deref()
            .or(r.subject_o.as_deref())
            .unwrap_or(&r.sha1),
    )
    .text("evidence.thumbprint", &r.sha1)
    .text("evidence.cert_store", format!("{:?}", r.store));
    if let Some(i) = &r.issuer {
        b = b.text("evidence.issuer", i);
    }
    if let Some(nb) = r.not_before {
        b = b.text("evidence.not_before", nb);
    }
    b.next(NextStepKind::TalkToHelper)
}

/// The same root is often in more than one store; report each thumbprint
/// once, preferring the user's store (that's where unwanted ones go).
fn distinct_roots(t: &TamperFacts) -> Vec<&RootCert> {
    let mut out: Vec<&RootCert> = Vec::new();
    for r in &t.roots {
        if !out.iter().any(|o| o.sha1.eq_ignore_ascii_case(&r.sha1)) {
            out.push(r);
        }
    }
    out
}

fn root_known_bad(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    distinct_roots(t)
        .into_iter()
        .filter_map(|r| {
            let name = known_bad(r)?;
            Some(
                root_finding("tamper.root.known_bad", Severity::High, Confidence::High, r)
                    .var("known", name)
                    .build(),
            )
        })
        .collect()
}

fn enterprise(r: &RootCert) -> bool {
    matches!(r.store, RootStore::GroupPolicy | RootStore::Enterprise)
}

fn root_unknown(t: &TamperFacts, ctx: &RuleContext) -> Vec<Finding> {
    distinct_roots(t)
        .into_iter()
        .filter(|r| {
            !r.in_microsoft_list
                && !t
                    .roots
                    .iter()
                    .any(|o| o.sha1.eq_ignore_ascii_case(&r.sha1) && enterprise(o))
                && known_bad(r).is_none()
                && dev_tool(r).is_none()
        })
        .map(|r| {
            let recent = r.not_before.is_some_and(|nb| nb >= ctx.now - RECENT_ROOT);
            // Without Microsoft's list Bilby can't tell a root it doesn't
            // know from one it can't check, so stay at Low.
            let confidence = if recent && t.microsoft_list_read {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let mut b = root_finding("tamper.root.unknown", Severity::Medium, confidence, r);
            if recent {
                b = b.text(
                    "evidence.recent_root",
                    "valid from in the last 60 days, used as a stand-in for when it was added",
                );
            }
            if !t.microsoft_list_read {
                b = b.text("evidence.ms_list", "Microsoft's root list couldn't be read");
            }
            b.build()
        })
        .collect()
}

fn root_dev_tool(t: &TamperFacts, _: &RuleContext) -> Vec<Finding> {
    distinct_roots(t)
        .into_iter()
        .filter_map(|r| {
            let tool = dev_tool(r)?;
            Some(
                root_finding("tamper.root.dev_tool", Severity::Info, Confidence::High, r)
                    .var("tool", tool)
                    .next(NextStepKind::Learn)
                    .build(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_files_load() {
        assert_eq!(
            BAD.root.len(),
            2,
            "eDellRoot and DSDTestProvider, both from Microsoft 3119884"
        );
        assert!(
            BAD.root
                .iter()
                .all(|r| r.sha1.len() == 40 && r.sha1.chars().all(|c| c.is_ascii_hexdigit()))
        );
        assert_eq!(BAD.subject.len(), 1);
        assert_eq!(DEV.root.len(), 4);
    }

    #[test]
    fn url_hosts() {
        assert_eq!(
            url_host("http://wpad.example.test/proxy.pac"),
            Some("wpad.example.test")
        );
        assert_eq!(
            url_host("http://user:pw@203.0.113.5:8080/x.pac"),
            Some("203.0.113.5")
        );
        assert_eq!(
            url_host("http://[2001:db8::1]:80/x.pac"),
            Some("2001:db8::1")
        );
        assert_eq!(url_host("http://192.168.1.1/wpad.dat"), Some("192.168.1.1"));
        assert_eq!(url_host("nonsense"), None);
    }
}
