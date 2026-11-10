//! What each screen shows, worked out from a [`ScanReport`]. Pure, so it's
//! tested on any OS. The templates only lay these values out; every word
//! comes from the copy catalogue (`docs/copy-guide.md`).

use std::collections::{BTreeMap, HashSet};

use bilby_core::copy::{self, CATALOGUE};
use bilby_core::model::{
    CheckStatus, Confidence, Evidence, Finding, Light, NextStepKind, ScanReport, Severity,
    SignalFamily,
};

/// The order areas are shown in, on the progress and results screens.
pub const STEPS: [&str; 7] = [
    "protection",
    "processes",
    "persistence",
    "network",
    "browser",
    "tamper",
    "drivers",
];

/// One row on the progress screen.
pub struct Step {
    /// Collector id, matched by `data-step` in `app.js`.
    pub id: &'static str,
    /// The area's name.
    pub name: &'static str,
}

/// The progress screen's rows.
pub fn steps() -> Vec<Step> {
    STEPS
        .iter()
        .map(|id| Step {
            id,
            name: family_name(family_of(id)),
        })
        .collect()
}

fn family_of(step: &str) -> SignalFamily {
    match step {
        "processes" => SignalFamily::Processes,
        "persistence" => SignalFamily::Persistence,
        "network" => SignalFamily::Network,
        "browser" => SignalFamily::Browser,
        "tamper" => SignalFamily::Tamper,
        "drivers" => SignalFamily::Drivers,
        _ => SignalFamily::Protection,
    }
}

/// The plain name for an area.
pub fn family_name(f: SignalFamily) -> &'static str {
    copy::t(match f {
        SignalFamily::Protection => "family.protection",
        SignalFamily::Processes => "family.processes",
        SignalFamily::Persistence => "family.persistence",
        SignalFamily::Network => "family.network",
        SignalFamily::Browser => "family.browser",
        SignalFamily::Tamper => "family.tamper",
        SignalFamily::Drivers => "family.drivers",
        SignalFamily::Reputation => "family.reputation",
    })
}

/// The id used for an area in HTML (`data-family`, icon choice).
pub fn family_id(f: SignalFamily) -> &'static str {
    match f {
        SignalFamily::Protection => "protection",
        SignalFamily::Processes => "processes",
        SignalFamily::Persistence => "persistence",
        SignalFamily::Network => "network",
        SignalFamily::Browser => "browser",
        SignalFamily::Tamper => "tamper",
        SignalFamily::Drivers => "drivers",
        SignalFamily::Reputation => "reputation",
    }
}

/// `healthy`, `worth` or `attention`, for CSS.
pub fn light_class(l: Light) -> &'static str {
    match l {
        Light::Healthy => "healthy",
        Light::WorthALook => "worth",
        Light::NeedsAttention => "attention",
    }
}

/// The headline for a light.
pub fn light_headline(l: Light) -> &'static str {
    copy::t(match l {
        Light::Healthy => "light.healthy.headline",
        Light::WorthALook => "light.worth_a_look.headline",
        Light::NeedsAttention => "light.needs_attention.headline",
    })
}

/// A button on a finding card.
pub struct Action {
    /// `open-setting` or `talk`, the `data-action` in `app.js`.
    pub kind: &'static str,
    /// The button's words.
    pub label: &'static str,
}

/// One label and value in "More detail".
pub struct Row {
    /// The label.
    pub label: String,
    /// The value. Paths and hashes are long, the CSS wraps them.
    pub value: String,
}

/// One finding card.
pub struct Card {
    /// [`Finding::id`].
    pub id: String,
    /// `high`, `medium`, `low` or `info`, for CSS and the filter.
    pub sev: &'static str,
    /// The severity in words.
    pub sev_word: &'static str,
    /// The area's name.
    pub family: &'static str,
    /// `data-family`, for the icon.
    pub family_id: &'static str,
    /// Title, from copy.
    pub title: String,
    /// "What we found".
    pub what: String,
    /// "Why it matters".
    pub why: String,
    /// "What to do".
    pub todo: String,
    /// How sure we are, in words.
    pub confidence: &'static str,
    /// 1 to 3, for the dots.
    pub conf_level: u8,
    /// The next step's button, if Bilby can take it.
    pub action: Option<Action>,
    /// "More detail" rows: the technical facts.
    pub evidence: Vec<Row>,
    /// The rule id, for the helper.
    pub rule_id: String,
    /// The finding came back because its file changed since it was ignored.
    pub changed: Option<String>,
}

/// One row in "What we checked".
pub struct Area {
    /// The area's name.
    pub name: &'static str,
    /// `data-family`, for the icon.
    pub id: &'static str,
    /// `ran`, `partial`, `needs-admin`, `skipped` or `failed`, for CSS.
    pub state: &'static str,
    /// The state in words.
    pub state_word: &'static str,
    /// The individual checks, for the helper.
    pub checks: Vec<Row>,
}

/// The results screen.
pub struct Results {
    /// `healthy`, `worth` or `attention`.
    pub light: &'static str,
    /// The headline.
    pub headline: &'static str,
    /// The line under it.
    pub sub: String,
    /// The top finding's next step, when not healthy.
    pub first: Option<Card>,
    /// Findings that count, most serious first.
    pub cards: Vec<Card>,
    /// How many cards at each severity: high, medium, low.
    pub counts: [usize; 3],
    /// Info findings.
    pub notes: Vec<Card>,
    /// Findings the user told Bilby to ignore.
    pub ignored: Vec<Card>,
    /// Every area and how it went.
    pub areas: Vec<Area>,
    /// Offer "Check more deeply".
    pub offer_deep_check: bool,
    /// The helper's facts about this scan.
    pub helper: Vec<Row>,
    /// Time per area, for the helper.
    pub timings: Vec<Row>,
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn sev_word(s: Severity) -> &'static str {
    copy::t(match s {
        Severity::High => "sev.high",
        Severity::Medium => "sev.medium",
        Severity::Low => "sev.low",
        Severity::Info => "sev.info",
    })
}

fn confidence(c: Confidence) -> (&'static str, u8) {
    match c {
        Confidence::High => (copy::t("confidence.high"), 3),
        Confidence::Medium => (copy::t("confidence.medium"), 2),
        Confidence::Low => (copy::t("confidence.low"), 1),
    }
}

/// A finding's copy variables, with values that are themselves copy keys
/// (`location.downloads`) turned into words.
fn vars(f: &Finding) -> BTreeMap<String, String> {
    f.vars
        .iter()
        .map(|(k, v)| {
            let v = CATALOGUE.get(v).cloned().unwrap_or_else(|| v.clone());
            (k.clone(), v)
        })
        .collect()
}

/// The copy for `<title_key>.<part>`, or empty if a rule has none.
fn part(f: &Finding, part: &str, vars: &BTreeMap<String, String>) -> String {
    let key = format!("{}.{part}", f.title_key);
    if CATALOGUE.contains_key(&key) {
        copy::tf(&key, vars)
    } else {
        String::new()
    }
}

/// True if the app can open this setting id (see `bilby_collect_windows::open`).
/// Browser extension pages can only be opened by the browser.
fn can_open(setting: &str) -> bool {
    setting != bilby_core::rules::browser::SETTING_EXTENSIONS
}

fn action(f: &Finding) -> Option<Action> {
    match &f.next_step {
        NextStepKind::OpenSetting(s) if can_open(s) => Some(Action {
            kind: "open-setting",
            label: if s.starts_with("windowsdefender") || s.starts_with("windows_security") {
                copy::t("results.open_security")
            } else {
                copy::t("results.open_setting")
            },
        }),
        // Asking Windows Security to scan one file comes with #33. Until
        // then, open Windows Security so the person can run a scan there.
        NextStepKind::AskDefender => Some(Action {
            kind: "open-setting",
            label: copy::t("results.open_security"),
        }),
        // Fixes come with #30 onwards, so the button stays hidden for now
        // and the card's "What to do" text says what to do by hand.
        NextStepKind::OpenSetting(_) | NextStepKind::Fix(_) | NextStepKind::Learn => None,
        NextStepKind::TalkToHelper => Some(Action {
            kind: "talk",
            label: copy::t("results.talk"),
        }),
    }
}

/// The Windows Settings or Security page a finding's button opens, as a
/// setting id for `bilby_collect_windows::open::target`.
pub fn setting_for(f: &Finding) -> Option<&str> {
    match &f.next_step {
        NextStepKind::OpenSetting(s) if can_open(s) => Some(s.as_str()),
        NextStepKind::AskDefender => Some("windows_security"),
        _ => None,
    }
}

fn label(key: &str) -> String {
    copy::t(key).to_owned()
}

/// The "More detail" rows for one finding. Paths, hashes and keys are fine
/// here (copy guide rule 10).
fn evidence(f: &Finding) -> Vec<Row> {
    let mut out = Vec::new();
    for e in &f.evidence {
        match e {
            Evidence::Path(p) => out.push(Row {
                label: label("helper.path"),
                value: p.clone(),
            }),
            Evidence::RegistryValue { key, name, data } => {
                out.push(Row {
                    label: label("helper.registry_key"),
                    value: key.clone(),
                });
                out.push(Row {
                    label: label("helper.registry_name"),
                    value: name.clone(),
                });
                out.push(Row {
                    label: label("helper.registry_data"),
                    value: data.clone(),
                });
            }
            Evidence::Signature { status, publisher } => out.push(Row {
                label: label("helper.signature"),
                value: match publisher {
                    Some(p) => format!("{status}, {p}"),
                    None => status.clone(),
                },
            }),
            Evidence::Process {
                pid,
                name,
                path,
                parent,
            } => {
                out.push(Row {
                    label: label("helper.process"),
                    value: path.clone().unwrap_or_else(|| name.clone()),
                });
                out.push(Row {
                    label: label("helper.pid"),
                    value: pid.to_string(),
                });
                if let Some(p) = parent {
                    out.push(Row {
                        label: label("evidence.parent"),
                        value: p.clone(),
                    });
                }
            }
            Evidence::Connection {
                local,
                remote,
                state,
            } => out.push(Row {
                label: label("helper.connection"),
                value: format!("{local} to {remote} ({state})"),
            }),
            Evidence::Text { label_key, value } => out.push(Row {
                label: CATALOGUE
                    .get(label_key)
                    .cloned()
                    .unwrap_or_else(|| label_key.clone()),
                value: value.clone(),
            }),
        }
    }
    let (_, level) = confidence(f.confidence);
    out.push(Row {
        label: label("helper.severity"),
        value: format!("{} ({:?})", sev_word(f.severity), f.severity).to_lowercase(),
    });
    out.push(Row {
        label: label("helper.confidence"),
        value: format!("{:?} ({level} of 3)", f.confidence).to_lowercase(),
    });
    out
}

fn card(f: &Finding) -> Card {
    let v = vars(f);
    let (conf, conf_level) = confidence(f.confidence);
    let changed = f.evidence.iter().find_map(|e| match e {
        Evidence::Text { label_key, .. }
            if label_key == bilby_core::suppress::CHANGED
                || label_key == bilby_core::suppress::UNVERIFIED =>
        {
            Some(copy::t(label_key).to_owned())
        }
        _ => None,
    });
    Card {
        id: f.id(),
        sev: sev_class(f.severity),
        sev_word: sev_word(f.severity),
        family: family_name(f.family),
        family_id: family_id(f.family),
        title: part(f, "title", &v),
        what: part(f, "what", &v),
        why: part(f, "why", &v),
        todo: part(f, "todo", &v),
        confidence: conf,
        conf_level,
        action: action(f),
        evidence: evidence(f),
        rule_id: f.rule_id.clone(),
        changed,
    }
}

fn status(s: &CheckStatus) -> (&'static str, &'static str) {
    match s {
        CheckStatus::Ran => ("ran", copy::t("status.ran")),
        CheckStatus::NeedsAdmin => ("needs-admin", copy::t("status.needs_admin")),
        CheckStatus::Skipped(_) => ("skipped", copy::t("status.skipped")),
        CheckStatus::Failed(_) => ("failed", copy::t("status.failed")),
    }
}

fn areas(report: &ScanReport) -> Vec<Area> {
    let mut families: Vec<SignalFamily> = report.checked.iter().map(|c| c.family).collect();
    families.sort();
    families.dedup();
    families
        .into_iter()
        .map(|fam| {
            let checks: Vec<_> = report.checked.iter().filter(|c| c.family == fam).collect();
            let all = |want: &str| checks.iter().all(|c| status(&c.status).0 == want);
            let any = |want: &str| checks.iter().any(|c| status(&c.status).0 == want);
            let (state, state_word) = if all("ran") {
                ("ran", copy::t("status.ran"))
            } else if all("skipped") {
                ("skipped", copy::t("status.skipped"))
            } else if any("ran") {
                ("partial", copy::t("status.partial"))
            } else if any("needs-admin") {
                ("needs-admin", copy::t("status.needs_admin"))
            } else {
                ("failed", copy::t("status.failed"))
            };
            Area {
                name: family_name(fam),
                id: family_id(fam),
                state,
                state_word,
                checks: checks
                    .iter()
                    .map(|c| {
                        let word = status(&c.status).1;
                        let value = match &c.status {
                            CheckStatus::Skipped(why) => format!(
                                "{word}: {}",
                                CATALOGUE.get(why).cloned().unwrap_or_else(|| why.clone())
                            ),
                            CheckStatus::Failed(why) => format!("{word}: {why}"),
                            _ => word.to_owned(),
                        };
                        Row {
                            label: c.id.clone(),
                            value,
                        }
                    })
                    .collect(),
            }
        })
        .collect()
}

/// The results screen for a report.
pub fn results(report: &ScanReport, can_deep_check: bool) -> Results {
    let ignored: HashSet<&str> = report.suppressed.iter().map(String::as_str).collect();
    let mut cards = Vec::new();
    let mut notes = Vec::new();
    let mut ignored_cards = Vec::new();
    // The engine already sorted findings, most serious first.
    for f in &report.findings {
        let c = card(f);
        if ignored.contains(c.id.as_str()) {
            ignored_cards.push(c);
        } else if f.severity == Severity::Info {
            notes.push(c);
        } else {
            cards.push(c);
        }
    }
    let count = |s: &str| cards.iter().filter(|c| c.sev == s).count();
    let counts = [count("high"), count("medium"), count("low")];
    let sub = match report.light {
        Light::Healthy => copy::tf(
            "light.healthy.sub",
            &BTreeMap::from([("count".to_owned(), report.checked.len().to_string())]),
        ),
        Light::WorthALook => copy::tf(
            "light.worth_a_look.sub",
            &BTreeMap::from([("n".to_owned(), cards.len().to_string())]),
        ),
        Light::NeedsAttention => copy::t("light.needs_attention.sub").to_owned(),
    };
    let first = (report.light != Light::Healthy)
        .then(|| {
            report
                .findings
                .iter()
                .find(|f| !ignored.contains(f.id().as_str()))
        })
        .flatten()
        .map(card);
    let needs_admin = report
        .checked
        .iter()
        .any(|c| c.status == CheckStatus::NeedsAdmin);
    let took = (report.finished_at - report.started_at).whole_milliseconds();
    let yes_no = |b: bool| label(if b { "helper.yes" } else { "helper.no" });
    let helper = vec![
        Row {
            label: label("helper.version"),
            value: report.bilby_version.clone(),
        },
        Row {
            label: label("helper.windows"),
            value: format!(
                "{} {} {}",
                report.machine.os_name, report.machine.os_version, report.machine.arch
            )
            .trim()
            .to_owned(),
        },
        Row {
            label: label("helper.admin"),
            value: yes_no(report.is_admin),
        },
        Row {
            label: label("helper.started"),
            value: report.started_at.to_string(),
        },
        Row {
            label: label("helper.took"),
            value: copy::tf(
                "helper.millis",
                &BTreeMap::from([("ms".to_owned(), took.to_string())]),
            ),
        },
    ];
    let timings = report
        .timings
        .iter()
        .map(|t| Row {
            label: STEPS
                .iter()
                .find(|s| **s == t.step)
                .map_or_else(|| t.step.clone(), |s| family_name(family_of(s)).to_owned()),
            value: copy::tf(
                "helper.millis",
                &BTreeMap::from([("ms".to_owned(), t.millis.to_string())]),
            ),
        })
        .collect();
    Results {
        light: light_class(report.light),
        headline: light_headline(report.light),
        sub,
        first,
        counts,
        cards,
        notes,
        ignored: ignored_cards,
        areas: areas(report),
        offer_deep_check: can_deep_check && (!report.is_admin || needs_admin),
        helper,
        timings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bilby_core::demo::{DemoKind, demo_report};

    #[test]
    fn attention_demo_has_cards_and_a_first_step() {
        let r = results(&demo_report(DemoKind::NeedsAttention), true);
        assert_eq!(r.light, "attention");
        assert!(!r.cards.is_empty());
        assert!(r.first.is_some());
        let c = &r.cards[0];
        assert_eq!(c.sev, "high");
        assert!(!c.title.is_empty() && !c.what.is_empty() && !c.why.is_empty());
        // Copy keys in variables become words, and full paths stay off the
        // card face.
        assert!(c.what.contains("your Downloads folder"), "{}", c.what);
        assert!(!c.what.contains(":\\"), "{}", c.what);
        assert!(c.evidence.iter().any(|e| e.value.contains(":\\")));
    }

    #[test]
    fn healthy_demo_has_no_first_step() {
        let r = results(&demo_report(DemoKind::Healthy), true);
        assert_eq!(r.light, "healthy");
        assert!(r.first.is_none());
        assert!(r.cards.iter().all(|c| c.sev != "high"));
    }

    #[test]
    fn ignored_findings_move_to_their_own_list() {
        let mut report = demo_report(DemoKind::NeedsAttention);
        let id = report.findings[0].id();
        report.suppressed.push(id.clone());
        let r = results(&report, true);
        assert!(r.cards.iter().all(|c| c.id != id));
        assert!(r.ignored.iter().any(|c| c.id == id));
    }

    #[test]
    fn every_area_and_step_has_words() {
        for s in steps() {
            assert_ne!(s.name, "");
        }
        let r = results(&demo_report(DemoKind::NeedsAttention), true);
        assert!(
            r.areas
                .iter()
                .any(|a| a.state == "partial" || a.state == "failed")
        );
    }

    #[test]
    fn browser_pages_have_no_open_button() {
        let mut f = demo_report(DemoKind::NeedsAttention).findings[0].clone();
        f.next_step = NextStepKind::OpenSetting("browser.extensions".to_owned());
        assert!(action(&f).is_none());
        assert!(setting_for(&f).is_none());
        f.next_step = NextStepKind::OpenSetting("windowsdefender:".to_owned());
        assert_eq!(setting_for(&f), Some("windowsdefender:"));
    }
}
