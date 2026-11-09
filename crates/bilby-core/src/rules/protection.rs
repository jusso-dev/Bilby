//! Protection rules: antivirus, firewall, UAC and Windows Update. See
//! `docs/signals.md` for each rule's reasoning and false-positive notes.

use time::Duration;

use super::{FindingBuilder, Rule, RuleContext};
use crate::model::{Confidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::snapshot::{
    DefenderStatus, Detection, ProtectionFacts, SecurityProduct, SystemSnapshot,
};

/// Opens Windows Security's virus and threat protection page.
pub const SETTING_WINDOWS_SECURITY: &str = "windowsdefender:";
/// Opens the firewall page.
pub const SETTING_FIREWALL: &str = "windowsdefender://network";
/// Opens Windows Update.
pub const SETTING_WINDOWS_UPDATE: &str = "ms-settings:windowsupdate";
/// Opens UAC settings (there is no ms-settings page; the app maps this id).
pub const SETTING_UAC: &str = "uac";

/// Detections older than this don't count.
pub const DETECTION_WINDOW: Duration = Duration::days(30);
/// Definitions older than this many days are stale (Low).
pub const SIGNATURES_STALE_DAYS: u32 = 7;
/// Definitions older than this many days are very stale (Medium).
pub const SIGNATURES_VERY_STALE_DAYS: u32 = 14;
/// No successful update for this long is worth mentioning (Low).
pub const UPDATES_OLD_DAYS: i64 = 45;
/// No successful update for this long is Medium.
pub const UPDATES_VERY_OLD_DAYS: i64 = 90;

/// What the undocumented Security Center `productState` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductState {
    /// The product reports itself switched on.
    pub on: bool,
    /// The product reports its definitions are up to date.
    pub up_to_date: bool,
}

/// Decodes `productState` with the commonly used reading: bits 12 to 15 are
/// 1 when on, and bits 4 to 7 are 0 when definitions are up to date. It's
/// undocumented, so findings that rely on it are Medium confidence at most.
pub fn decode_product_state(state: u32) -> ProductState {
    ProductState {
        on: nibble(state, 3) == 1,
        up_to_date: nibble(state, 1) == 0,
    }
}

/// The `n`th 4-bit group of `value`, counting from the lowest.
fn nibble(value: u32, n: u32) -> u32 {
    (value >> (n * 4)) % 16
}

/// True if Security Center lists a product other than Defender that is on.
fn third_party_on(products: Option<&Vec<SecurityProduct>>) -> bool {
    products.is_some_and(|list| {
        list.iter()
            .any(|p| !is_defender(&p.display_name) && decode_product_state(p.product_state).on)
    })
}

fn is_defender(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("windows defender") || n.contains("microsoft defender")
}

fn finding(id: &str, severity: Severity, confidence: Confidence, setting: &str) -> FindingBuilder {
    FindingBuilder::new(
        id,
        SignalFamily::Protection,
        severity,
        confidence,
        Subject::Setting(id.to_owned()),
    )
    .next(NextStepKind::OpenSetting(setting.to_owned()))
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Protection
            }
            fn evaluate(&self, snap: &SystemSnapshot, ctx: &RuleContext) -> Vec<Finding> {
                snap.protection
                    .as_ref()
                    .map(|p| $fn(p, ctx))
                    .unwrap_or_default()
            }
        }
    };
}

rule!(NoActiveAv, "protection.no_active_av", no_active_av);
rule!(RealtimeOff, "protection.realtime_off", realtime_off);
rule!(
    SignaturesStale,
    "protection.signatures_stale",
    signatures_stale
);
rule!(
    DetectionActive,
    "protection.detection_active",
    detection_active
);
rule!(
    DetectionResolved,
    "protection.detection_resolved",
    detection_resolved
);
rule!(
    DetectionExecuted,
    "protection.detection_executed",
    detection_executed
);
rule!(TamperOff, "protection.tamper_off", tamper_off);
rule!(ThirdPartyOff, "protection.third_party_off", third_party_off);
rule!(FirewallOff, "protection.firewall_off", firewall_off);
rule!(UacOff, "protection.uac_off", uac_off);
rule!(UpdatesOld, "protection.updates_old", updates_old);

/// Every protection rule.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NoActiveAv),
        Box::new(RealtimeOff),
        Box::new(SignaturesStale),
        Box::new(DetectionActive),
        Box::new(DetectionResolved),
        Box::new(DetectionExecuted),
        Box::new(TamperOff),
        Box::new(ThirdPartyOff),
        Box::new(FirewallOff),
        Box::new(UacOff),
        Box::new(UpdatesOld),
    ]
}

fn no_active_av(p: &ProtectionFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(d) = &p.defender else {
        return Vec::new();
    };
    let defender_off = !d.antivirus_enabled || d.is_passive();
    // Any registered third-party product that is on counts. If Security
    // Center couldn't be read we can't rule one out, so stay quiet.
    let unknown_third_party = p.antivirus_products.is_none();
    if !defender_off || unknown_third_party || third_party_on(p.antivirus_products.as_ref()) {
        return Vec::new();
    }
    vec![
        finding(
            "protection.no_active_av",
            Severity::High,
            Confidence::High,
            SETTING_WINDOWS_SECURITY,
        )
        .text("evidence.antivirus_enabled", d.antivirus_enabled)
        .text(
            "evidence.running_mode",
            d.am_running_mode.as_deref().unwrap_or("unknown"),
        )
        .build(),
    ]
}

fn realtime_off(p: &ProtectionFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(d) = &p.defender else {
        return Vec::new();
    };
    if !d.is_active() || d.real_time_protection_enabled {
        return Vec::new();
    }
    vec![
        finding(
            "protection.realtime_off",
            Severity::High,
            Confidence::High,
            SETTING_WINDOWS_SECURITY,
        )
        .text("evidence.realtime", "RealTimeProtectionEnabled = false")
        .build(),
    ]
}

fn signatures_stale(p: &ProtectionFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(d) = &p.defender else {
        return Vec::new();
    };
    let Some(age) = d.antivirus_signature_age_days else {
        return Vec::new();
    };
    // Stale definitions only matter if Defender is the one protecting.
    if !d.is_active() || age <= SIGNATURES_STALE_DAYS {
        return Vec::new();
    }
    let severity = if age > SIGNATURES_VERY_STALE_DAYS {
        Severity::Medium
    } else {
        Severity::Low
    };
    vec![
        finding(
            "protection.signatures_stale",
            severity,
            Confidence::High,
            SETTING_WINDOWS_SECURITY,
        )
        .var("days", age)
        .text("evidence.signature_age", format!("{age} days"))
        .build(),
    ]
}

/// Detections in the last 30 days, newest first.
fn recent<'a>(p: &'a ProtectionFacts, ctx: &RuleContext) -> Vec<&'a Detection> {
    let cutoff = ctx.now - DETECTION_WINDOW;
    let mut list: Vec<&Detection> = p
        .detections
        .iter()
        .flatten()
        .filter(|d| {
            d.last_status_change_time
                .or(d.initial_detection_time)
                .is_some_and(|t| t >= cutoff)
        })
        .collect();
    list.sort_by_key(|d| std::cmp::Reverse(d.initial_detection_time));
    list
}

fn unresolved(d: &Detection) -> bool {
    d.is_active == Some(true) || d.action_success == Some(false)
}

fn detection_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    d: &Detection,
    resources: &[&str],
) -> Finding {
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Protection,
        severity,
        confidence,
        Subject::Setting(format!("defender.threat.{}", d.threat_id)),
    )
    .next(NextStepKind::OpenSetting(
        SETTING_WINDOWS_SECURITY.to_owned(),
    ))
    .var("threat", d.threat_name.as_deref().unwrap_or("unknown"))
    .text(
        "evidence.threat",
        d.threat_name.as_deref().unwrap_or(&d.threat_id),
    );
    for resource in resources {
        b = b.text("evidence.resource", resource);
    }
    if let Some(t) = d.initial_detection_time {
        b = b.text("evidence.detected_at", t);
    }
    b.build()
}

fn detection_active(p: &ProtectionFacts, ctx: &RuleContext) -> Vec<Finding> {
    by_threat(recent(p, ctx).into_iter().filter(|d| unresolved(d)))
        .into_iter()
        .map(|(d, resources)| {
            detection_finding(
                "protection.detection_active",
                Severity::High,
                Confidence::High,
                d,
                &resources,
            )
        })
        .collect()
}

/// Groups detection rows by threat. Defender can log several rows for one
/// threat (one per time it was seen), and one finding per threat keeps
/// finding ids unique. Returns the newest row of each group with every
/// affected resource from all its rows, in first-seen order.
fn by_threat<'a>(rows: impl Iterator<Item = &'a Detection>) -> Vec<(&'a Detection, Vec<&'a str>)> {
    let mut groups: Vec<(&Detection, Vec<&str>)> = Vec::new();
    for row in rows {
        let idx = groups
            .iter()
            .position(|(d, _)| d.threat_id == row.threat_id)
            .unwrap_or_else(|| {
                groups.push((row, Vec::new()));
                groups.len() - 1
            });
        let resources = &mut groups[idx].1;
        for r in &row.resources {
            if !resources.contains(&r.as_str()) {
                resources.push(r);
            }
        }
    }
    groups
}

fn detection_resolved(p: &ProtectionFacts, ctx: &RuleContext) -> Vec<Finding> {
    let recent = recent(p, ctx);
    // Only when everything was dealt with and nothing had run; otherwise a
    // stronger rule speaks for it.
    if recent.is_empty()
        || recent
            .iter()
            .any(|d| unresolved(d) || d.did_threat_execute == Some(true))
    {
        return Vec::new();
    }
    let newest = recent[0];
    let resources: Vec<&str> = newest.resources.iter().map(String::as_str).collect();
    let mut f = detection_finding(
        "protection.detection_resolved",
        Severity::Low,
        Confidence::High,
        newest,
        &resources,
    );
    f.subject = Subject::Setting("defender.detections.resolved".to_owned());
    f.vars.insert("count".to_owned(), recent.len().to_string());
    vec![f]
}

fn detection_executed(p: &ProtectionFacts, ctx: &RuleContext) -> Vec<Finding> {
    by_threat(
        recent(p, ctx)
            .into_iter()
            .filter(|d| !unresolved(d) && d.did_threat_execute == Some(true)),
    )
    .into_iter()
    .map(|(d, resources)| {
        detection_finding(
            "protection.detection_executed",
            Severity::Medium,
            Confidence::Medium,
            d,
            &resources,
        )
    })
    .collect()
}

fn tamper_off(p: &ProtectionFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(d) = &p.defender else {
        return Vec::new();
    };
    if !d.is_active() || d.is_tamper_protected != Some(false) {
        return Vec::new();
    }
    vec![
        finding(
            "protection.tamper_off",
            Severity::Low,
            Confidence::High,
            SETTING_WINDOWS_SECURITY,
        )
        .text("evidence.tamper", "IsTamperProtected = false")
        .build(),
    ]
}

fn third_party_off(p: &ProtectionFacts, _: &RuleContext) -> Vec<Finding> {
    let defender_active = p.defender.as_ref().is_some_and(DefenderStatus::is_active);
    if defender_active || third_party_on(p.antivirus_products.as_ref()) {
        return Vec::new();
    }
    p.antivirus_products
        .iter()
        .flatten()
        .filter(|prod| !is_defender(&prod.display_name))
        .map(|prod| {
            FindingBuilder::new(
                "protection.third_party_off",
                SignalFamily::Protection,
                Severity::High,
                Confidence::Medium,
                Subject::Setting(format!(
                    "security_center.av.{}",
                    prod.display_name.to_lowercase()
                )),
            )
            .next(NextStepKind::OpenSetting(
                SETTING_WINDOWS_SECURITY.to_owned(),
            ))
            .var("product", &prod.display_name)
            .text(
                "evidence.product_state",
                format!("{:#x}", prod.product_state),
            )
            .build()
        })
        .collect()
}

fn firewall_off(p: &ProtectionFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(fw) = &p.firewall else {
        return Vec::new();
    };
    let off = fw.current_profiles_off();
    if off.is_empty() || third_party_on(p.firewall_products.as_ref()) {
        return Vec::new();
    }
    vec![
        finding(
            "protection.firewall_off",
            Severity::Medium,
            Confidence::High,
            SETTING_FIREWALL,
        )
        .text("evidence.firewall_profiles_off", off.join(", "))
        .build(),
    ]
}

fn uac_off(p: &ProtectionFacts, _: &RuleContext) -> Vec<Finding> {
    let Some(uac) = &p.uac else { return Vec::new() };
    if uac.enable_lua != Some(0) {
        return Vec::new();
    }
    vec![
        finding(
            "protection.uac_off",
            Severity::Medium,
            Confidence::High,
            SETTING_UAC,
        )
        .text("evidence.setting", "EnableLUA = 0")
        .build(),
    ]
}

fn updates_old(p: &ProtectionFacts, ctx: &RuleContext) -> Vec<Finding> {
    let Some(u) = &p.updates else {
        return Vec::new();
    };
    // No successful entry in a non-empty history counts as old; an empty
    // history (fresh install or unreadable) says nothing.
    let days = match u.last_success {
        Some(t) => (ctx.now - t).whole_days(),
        None if u.history_count > 0 => i64::MAX,
        None => return Vec::new(),
    };
    if days < UPDATES_OLD_DAYS {
        return Vec::new();
    }
    let severity = if days >= UPDATES_VERY_OLD_DAYS {
        Severity::Medium
    } else {
        Severity::Low
    };
    let mut b = finding(
        "protection.updates_old",
        severity,
        Confidence::Medium,
        SETTING_WINDOWS_UPDATE,
    );
    b = match u.last_success {
        Some(t) => b.var("days", days).text("evidence.last_update", t),
        None => b
            .var("days", "many")
            .text("evidence.last_update", "none found"),
    };
    vec![b.build()]
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::snapshot::SystemSnapshot;
    use time::macros::datetime;

    fn row(id: &str, resource: &str, when: time::OffsetDateTime) -> Detection {
        Detection {
            threat_id: id.to_owned(),
            threat_name: Some("Trojan:Win32/Example".to_owned()),
            initial_detection_time: Some(when),
            last_status_change_time: Some(when),
            action_success: Some(false),
            is_active: Some(true),
            did_threat_execute: Some(true),
            resources: vec![resource.to_owned()],
            ..Detection::default()
        }
    }

    #[test]
    fn repeated_rows_for_one_threat_give_one_finding_with_all_resources() {
        let now = datetime!(2026-11-09 09:00 UTC);
        let snap = SystemSnapshot {
            protection: Some(ProtectionFacts {
                detections: Some(vec![
                    row("7", r"file:_C:\a.exe", datetime!(2026-11-08 09:00 UTC)),
                    row("7", r"file:_C:\b.exe", datetime!(2026-11-07 09:00 UTC)),
                    row("7", r"file:_C:\a.exe", datetime!(2026-11-06 09:00 UTC)),
                    row("9", r"file:_C:\c.exe", datetime!(2026-11-05 09:00 UTC)),
                ]),
                ..ProtectionFacts::default()
            }),
            ..SystemSnapshot::default()
        };
        let findings: Vec<Finding> = crate::rules::evaluate_all(&snap, &RuleContext::at(now))
            .into_iter()
            .filter(|f| f.rule_id == "protection.detection_active")
            .collect();
        assert_eq!(findings.len(), 2, "one finding per threat");
        let ids: std::collections::HashSet<String> = findings.iter().map(Finding::id).collect();
        assert_eq!(ids.len(), 2, "finding ids are unique");
        let seven = findings
            .iter()
            .find(|f| f.subject == Subject::Setting("defender.threat.7".to_owned()))
            .expect("threat 7");
        let resources: Vec<String> = seven
            .evidence
            .iter()
            .filter_map(|e| match e {
                crate::model::Evidence::Text { label_key, value }
                    if label_key == "evidence.resource" =>
                {
                    Some(value.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(resources, [r"file:_C:\a.exe", r"file:_C:\b.exe"]);
    }

    #[test]
    fn product_state_known_values() {
        assert_eq!(
            decode_product_state(0x61100),
            ProductState {
                on: true,
                up_to_date: true
            }
        );
        assert_eq!(
            decode_product_state(0x60100),
            ProductState {
                on: false,
                up_to_date: true
            }
        );
        assert_eq!(
            decode_product_state(0x61110),
            ProductState {
                on: true,
                up_to_date: false
            }
        );
        // 0x41000 (on, current) and 0x40000 (off) are also reported by
        // some third-party products.
        assert_eq!(
            decode_product_state(0x41000),
            ProductState {
                on: true,
                up_to_date: true
            }
        );
        assert!(!decode_product_state(0x40000).on);
    }
}
