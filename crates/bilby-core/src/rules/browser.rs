//! Browser extension rules. Store extensions are trusted to the store's own
//! review, so the light only moves for things installed around it:
//! sideloaded, forced by a policy nobody set, loaded through a shortcut, or
//! unsigned in Firefox. See `docs/signals.md`.

use super::{FindingBuilder, Rule, RuleContext};
use crate::browser::{broad_access, official_update_url, shortcut_flags};
use crate::model::{Confidence, Finding, NextStepKind, Severity, SignalFamily, Subject};
use crate::snapshot::{
    BrowserFacts, BrowserPolicy, ExtensionFact, ExtensionSource, SystemSnapshot,
};

/// Opens the browser's extensions page; the app maps this per browser.
pub const SETTING_EXTENSIONS: &str = "browser.extensions";

fn browser_label(browser: &str) -> &str {
    match browser {
        "chrome" => "Google Chrome",
        "edge" => "Microsoft Edge",
        "brave" => "Brave",
        "vivaldi" => "Vivaldi",
        "opera" => "Opera",
        "firefox" => "Firefox",
        other => other,
    }
}

fn ext_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    e: &ExtensionFact,
) -> FindingBuilder {
    let mut b = FindingBuilder::new(
        id,
        SignalFamily::Browser,
        severity,
        confidence,
        // Profile too: the same extension in two profiles is two things to
        // remove.
        Subject::Extension {
            browser: format!("{}/{}", e.browser, e.profile),
            id: e.id.clone(),
        },
    )
    .var("name", e.name.as_deref().unwrap_or(&e.id))
    .var("browser", browser_label(&e.browser))
    .text("evidence.extension_id", &e.id)
    .text(
        "evidence.browser_profile",
        format!("{} / {}", e.browser, e.profile),
    )
    .next(NextStepKind::OpenSetting(SETTING_EXTENSIONS.to_owned()));
    if let Some(l) = &e.raw_location {
        b = b.text("evidence.install_location", l);
    }
    for p in e
        .permissions
        .iter()
        .filter(|p| crate::browser::BROAD_HOSTS.contains(&p.as_str()))
    {
        b = b.text("evidence.permission", p);
    }
    b
}

macro_rules! rule {
    ($name:ident, $id:literal, $fn:ident) => {
        struct $name;
        impl Rule for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::Browser
            }
            fn evaluate(&self, snap: &SystemSnapshot, _: &RuleContext) -> Vec<Finding> {
                snap.browser.as_ref().map(|b| $fn(b)).unwrap_or_default()
            }
        }
    };
}

rule!(SideloadedWide, "browser.sideloaded_wide", sideloaded_wide);
rule!(
    ForcedUnmanaged,
    "browser.forced_unmanaged",
    forced_unmanaged
);
rule!(ForcedManaged, "browser.forced_managed", forced_managed);
rule!(
    ShortcutLoadExtension,
    "browser.shortcut_load_extension",
    shortcut_load_extension
);
rule!(
    FirefoxUnsigned,
    "browser.firefox_unsigned",
    firefox_unsigned
);
rule!(StoreWide, "browser.store_wide", store_wide);

/// Every browser rule.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SideloadedWide),
        Box::new(ForcedUnmanaged),
        Box::new(ForcedManaged),
        Box::new(ShortcutLoadExtension),
        Box::new(FirefoxUnsigned),
        Box::new(StoreWide),
    ]
}

/// From the browser's own store: installed there, or installed by another
/// program (Adobe Acrobat adds its Chrome extension this way) through
/// external preferences with the store as its update URL. That is location
/// 6, `kExternalPrefDownload`, which Chromium downloads from the update URL
/// itself, and on Windows and macOS that URL must be the Chrome Web Store.
/// Locations 2 and 3 carry a local crx whose manifest could name any URL,
/// so they don't count.
fn from_store(e: &ExtensionFact) -> bool {
    e.source == ExtensionSource::Store
        || (e.source == ExtensionSource::External
            && e.raw_location.as_deref() == Some("6")
            && e.update_url
                .as_deref()
                .is_some_and(|u| official_update_url(Some(u))))
}

fn sideloaded_wide(b: &BrowserFacts) -> Vec<Finding> {
    b.extensions
        .iter()
        .filter(|e| {
            e.enabled
                && matches!(
                    e.source,
                    ExtensionSource::Unpacked
                        | ExtensionSource::CommandLine
                        | ExtensionSource::External
                )
                && !from_store(e)
                && broad_access(e)
        })
        .map(|e| {
            ext_finding(
                "browser.sideloaded_wide",
                Severity::Medium,
                Confidence::Medium,
                e,
            )
            .build()
        })
        .collect()
}

fn policy_finding(
    id: &str,
    severity: Severity,
    confidence: Confidence,
    p: &BrowserPolicy,
    b: &BrowserFacts,
) -> Finding {
    let name = b
        .extensions
        .iter()
        .find(|e| e.id == p.id)
        .and_then(|e| e.name.clone())
        .unwrap_or_else(|| p.id.clone());
    let mut f = FindingBuilder::new(
        id,
        SignalFamily::Browser,
        severity,
        confidence,
        Subject::Extension {
            browser: format!("{}/policy", p.browser),
            id: p.id.clone(),
        },
    )
    .var("name", name)
    .var("browser", browser_label(&p.browser))
    .text("evidence.extension_id", &p.id)
    .text("evidence.policy", &p.location)
    .next(NextStepKind::TalkToHelper);
    if let Some(u) = &p.update_url {
        f = f.text("evidence.update_url", u);
    }
    for r in &b.management.reasons {
        f = f.text("evidence.management", r);
    }
    f.build()
}

fn forced_unmanaged(b: &BrowserFacts) -> Vec<Finding> {
    if b.management.managed {
        return Vec::new();
    }
    b.policies
        .iter()
        .map(|p| {
            // A forced extension from somewhere other than the browser's own
            // store can't have gone through store review.
            let confidence = if official_update_url(p.update_url.as_deref()) {
                Confidence::Medium
            } else {
                Confidence::High
            };
            policy_finding("browser.forced_unmanaged", Severity::High, confidence, p, b)
        })
        .collect()
}

fn forced_managed(b: &BrowserFacts) -> Vec<Finding> {
    if !b.management.managed {
        return Vec::new();
    }
    b.policies
        .iter()
        .map(|p| {
            policy_finding(
                "browser.forced_managed",
                Severity::Info,
                Confidence::High,
                p,
                b,
            )
        })
        .collect()
}

fn shortcut_load_extension(b: &BrowserFacts) -> Vec<Finding> {
    b.shortcuts
        .iter()
        .filter(|s| shortcut_flags(&s.arguments).contains(&"load_extension"))
        .map(|s| {
            FindingBuilder::new(
                "browser.shortcut_load_extension",
                SignalFamily::Browser,
                Severity::High,
                Confidence::High,
                Subject::File(s.path.to_lowercase()),
            )
            .var("browser", browser_label(&s.browser))
            .text("evidence.shortcut", &s.path)
            .text("evidence.command", &s.arguments)
            .next(NextStepKind::TalkToHelper)
            .build()
        })
        .collect()
}

fn firefox_unsigned(b: &BrowserFacts) -> Vec<Finding> {
    b.extensions
        .iter()
        .filter(|e| {
            e.browser == "firefox"
                && e.enabled
                && e.source == ExtensionSource::FirefoxProfile
                && e.signed_state.is_some_and(|s| s < 1)
        })
        .map(|e| {
            ext_finding(
                "browser.firefox_unsigned",
                Severity::Medium,
                Confidence::Medium,
                e,
            )
            .build()
        })
        .collect()
}

fn store_wide(b: &BrowserFacts) -> Vec<Finding> {
    b.extensions
        .iter()
        .filter(|e| e.enabled && from_store(e) && broad_access(e))
        .map(|e| {
            ext_finding("browser.store_wide", Severity::Info, Confidence::High, e)
                .next(NextStepKind::Learn)
                .build()
        })
        .collect()
}
