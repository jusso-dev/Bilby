//! Network rules. Bilby doesn't judge addresses or ports offline: ports alone
//! cause false alarms, and there are no lookups (ADR 0004). These rules only
//! speak about programs that are already out of place.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use super::{FindingBuilder, Rule, RuleContext};
use crate::model::{Confidence, Evidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::net::{AddrClass, classify};
use crate::paths::{KnownFolders, normalise};
use crate::snapshot::{
    ConnectionFact, FileFacts, NetworkFacts, PathClass, ProcessFact, Proto, SignatureStatus,
    SystemSnapshot, TcpState,
};

/// Boosts process findings; never makes its own card.
pub const OUTBOUND_FROM_SUSPICIOUS: &str = "net.outbound_from_suspicious";

/// Distinct public peers that count as "many".
pub const MANY_PEERS: usize = 50;

/// Process rules whose finding gets the outbound boost.
const BOOSTED: &[&str] = &[
    "proc.unsigned_user_writable",
    "proc.masquerade.system_name",
    "proc.masquerade.lookalike",
];

const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
];

fn norm(p: &str) -> String {
    normalise(p, &KnownFolders::default())
}

fn unsigned_writable(f: &FileFacts) -> bool {
    matches!(
        f.signature,
        SignatureStatus::Unsigned | SignatureStatus::Invalid { .. }
    ) && f.user_writable
        && f.class != PathClass::UserAppPrograms
}

fn listening_outside(c: &ConnectionFact) -> bool {
    c.proto == Proto::Tcp
        && c.state == Some(TcpState::Listen)
        && classify(c.local.ip()) != AddrClass::Loopback
}

fn public_peer(c: &ConnectionFact) -> Option<IpAddr> {
    let remote = c.remote?;
    (c.proto == Proto::Tcp
        && c.state == Some(TcpState::Established)
        && classify(remote.ip()) == AddrClass::Public)
        .then_some(remote.ip())
}

struct Ctx<'a> {
    by_pid: HashMap<u32, &'a ProcessFact>,
    net: &'a NetworkFacts,
}

fn ctx(snap: &SystemSnapshot) -> Option<Ctx<'_>> {
    Some(Ctx {
        by_pid: snap
            .processes
            .as_deref()?
            .iter()
            .map(|p| (p.pid, p))
            .collect(),
        net: snap.network.as_ref()?,
    })
}

fn finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    p: &ProcessFact,
    conns: &[&ConnectionFact],
) -> Finding {
    let path = p.image_path.clone().unwrap_or_else(|| p.name.clone());
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Network,
        severity,
        confidence,
        Subject::File(norm(&path)),
    )
    .var("name", &p.name)
    .evidence(Evidence::Process {
        pid: p.pid,
        name: p.name.clone(),
        path: p.image_path.clone(),
        parent: None,
    })
    .next(NextStepKind::AskDefender);
    for c in conns.iter().take(10) {
        b = b.evidence(connection_evidence(c));
    }
    if conns.len() > 10 {
        b = b.text("evidence.more_connections", conns.len() - 10);
    }
    b.build()
}

fn connection_evidence(c: &ConnectionFact) -> Evidence {
    Evidence::Connection {
        local: c.local.to_string(),
        remote: c.remote.map_or_else(|| "-".to_owned(), |r| r.to_string()),
        state: match c.state {
            Some(TcpState::Listen) => "listen",
            Some(TcpState::Established) => "established",
            Some(TcpState::Other) => "other",
            None => "udp",
        }
        .to_owned(),
    }
}

/// The key a finding is about: the program's file, so several running
/// copies of one program make one card with one id.
fn file_key(p: &ProcessFact) -> String {
    norm(p.image_path.as_deref().unwrap_or(&p.name))
}

/// Groups connections matching `keep` by program file. Returns one process
/// per file (the lowest pid, for a stable result) and all its connections.
fn by_file<'a>(
    c: &Ctx<'a>,
    keep: impl Fn(&ConnectionFact) -> bool,
) -> Vec<(&'a ProcessFact, Vec<&'a ConnectionFact>)> {
    let mut by: HashMap<String, (&ProcessFact, Vec<&ConnectionFact>)> = HashMap::new();
    for conn in c.net.connections.iter().filter(|x| keep(x)) {
        let Some(p) = c.by_pid.get(&conn.pid).copied() else {
            continue;
        };
        let e = by.entry(file_key(p)).or_insert((p, Vec::new()));
        if p.pid < e.0.pid {
            e.0 = p;
        }
        e.1.push(conn);
    }
    let mut out: Vec<_> = by.into_values().collect();
    out.sort_by_key(|(p, _)| file_key(p));
    out
}

fn listeners<'a>(c: &Ctx<'a>) -> Vec<(&'a ProcessFact, Vec<&'a ConnectionFact>)> {
    by_file(c, listening_outside)
}

struct ListenUnsigned;
impl Rule for ListenUnsigned {
    fn id(&self) -> &'static str {
        "net.listen_unsigned_user_writable"
    }
    fn family(&self) -> SignalFamily {
        SignalFamily::Network
    }
    fn evaluate(&self, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
        let Some(c) = ctx(snap) else {
            return Vec::new();
        };
        listeners(&c)
            .into_iter()
            .filter(|(p, _)| p.file.as_ref().is_some_and(unsigned_writable))
            .map(|(p, conns)| finding(self.id(), Severity::Medium, Confidence::Medium, p, &conns))
            .collect()
    }
}

struct ListenScriptHost;
impl Rule for ListenScriptHost {
    fn id(&self) -> &'static str {
        "net.listen_script_host"
    }
    fn family(&self) -> SignalFamily {
        SignalFamily::Network
    }
    fn evaluate(&self, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
        let Some(c) = ctx(snap) else {
            return Vec::new();
        };
        listeners(&c)
            .into_iter()
            .filter(|(p, _)| SCRIPT_HOSTS.contains(&p.name.to_ascii_lowercase().as_str()))
            .map(|(p, conns)| finding(self.id(), Severity::High, Confidence::Medium, p, &conns))
            .collect()
    }
}

struct ManyPeers;
impl Rule for ManyPeers {
    fn id(&self) -> &'static str {
        "net.many_remote_peers"
    }
    fn family(&self) -> SignalFamily {
        SignalFamily::Network
    }
    fn evaluate(&self, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
        let Some(c) = ctx(snap) else {
            return Vec::new();
        };
        let mut out: Vec<Finding> = by_file(&c, |x| public_peer(x).is_some())
            .into_iter()
            .filter_map(|(p, conns)| {
                p.file.as_ref().filter(|f| unsigned_writable(f))?;
                let ips: HashSet<IpAddr> = conns.iter().filter_map(|x| public_peer(x)).collect();
                if ips.len() < MANY_PEERS {
                    return None;
                }
                let mut f = finding(self.id(), Severity::Medium, Confidence::Low, p, &conns);
                f.vars.insert("count".to_owned(), ips.len().to_string());
                Some(f)
            })
            .collect();
        out.sort_by(|a, b| a.subject.cmp(&b.subject));
        out
    }
}

/// Every network rule that makes its own card.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ListenUnsigned),
        Box::new(ListenScriptHost),
        Box::new(ManyPeers),
    ]
}

fn up(c: crate::model::Confidence) -> crate::model::Confidence {
    match c {
        Confidence::Low => Confidence::Medium,
        Confidence::Medium | Confidence::High => Confidence::High,
    }
}

/// `net.outbound_from_suspicious`: a process that already has an
/// unsigned-in-user-folder or masquerade finding and is connected to a
/// public address. Its finding goes up one confidence level and gets the
/// connections as evidence. No separate card.
pub fn boost_outbound(snap: &SystemSnapshot, findings: &mut [Finding]) {
    let Some(c) = ctx(snap) else { return };
    // Public connections by normalised image path.
    let mut by_path: HashMap<String, Vec<&ConnectionFact>> = HashMap::new();
    for conn in c
        .net
        .connections
        .iter()
        .filter(|x| public_peer(x).is_some())
    {
        if let Some(path) = c
            .by_pid
            .get(&conn.pid)
            .and_then(|p| p.image_path.as_deref())
        {
            by_path.entry(norm(path)).or_default().push(conn);
        }
    }
    for f in findings
        .iter_mut()
        .filter(|f| BOOSTED.contains(&f.rule_id.as_str()))
    {
        let Subject::File(path) = &f.subject else {
            continue;
        };
        let Some(conns) = by_path.get(path) else {
            continue;
        };
        f.confidence = up(f.confidence);
        f.evidence.push(Evidence::Text {
            label_key: "evidence.boosted_by".to_owned(),
            value: OUTBOUND_FROM_SUSPICIOUS.to_owned(),
        });
        for conn in conns.iter().take(10) {
            f.evidence.push(connection_evidence(conn));
        }
    }
}
