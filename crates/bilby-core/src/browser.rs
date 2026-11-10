//! Pure parsing of browser profile files: Chromium `Local State`,
//! `Preferences` and `Secure Preferences`, extension manifests, Firefox
//! `profiles.ini` and `extensions.json`, and shortcut arguments. Lenient:
//! unknown fields are ignored and a missing field means `None`, because
//! browsers change these files often.
//!
//! Chromium `location` values are `ManifestLocation` in
//! `extensions/common/mojom/manifest.mojom` (checked on 10-11-2026 at
//! chromium/src `main`): 0 invalid, 1 internal, 2 external pref, 3 external
//! registry, 4 unpacked, 5 component, 6 external pref download, 7 external
//! policy download, 8 command line, 9 external policy, 10 external
//! component. New values are only ever appended.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::snapshot::{ExtensionFact, ExtensionSource};

/// Hosts patterns that mean "every website".
pub const BROAD_HOSTS: &[&str] = &["<all_urls>", "*://*/*", "http://*/*", "https://*/*"];

/// Does this extension ask to read or change every website?
pub fn broad_access(e: &ExtensionFact) -> bool {
    e.permissions
        .iter()
        .any(|p| BROAD_HOSTS.contains(&p.as_str()))
}

/// Maps a Chromium `location` number to a source.
pub fn chromium_source(location: i64) -> ExtensionSource {
    match location {
        1 => ExtensionSource::Store,
        2 | 3 | 6 => ExtensionSource::External,
        4 => ExtensionSource::Unpacked,
        5 | 10 => ExtensionSource::Component,
        7 | 9 => ExtensionSource::Policy,
        8 => ExtensionSource::CommandLine,
        _ => ExtensionSource::Other,
    }
}

/// Profile folder names from Chromium's `Local State`
/// (`profile.info_cache` keys). Empty if the file has none, in which case
/// callers try `Default`.
pub fn chromium_profiles(local_state: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(local_state) else {
        return Vec::new();
    };
    let mut names: Vec<String> = v
        .pointer("/profile/info_cache")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}

/// `extensions.settings` from `Preferences` merged with `Secure
/// Preferences`; the secure file wins for any id in both.
pub fn chromium_settings(
    preferences: Option<&str>,
    secure: Option<&str>,
) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for text in [preferences, secure].into_iter().flatten() {
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        if let Some(m) = v.pointer("/extensions/settings").and_then(Value::as_object) {
            for (id, s) in m {
                out.insert(id.clone(), s.clone());
            }
        }
    }
    out
}

/// Everything an extension can reach: permissions, host permissions,
/// optional ones, and content script matches, deduplicated.
pub fn manifest_permissions(manifest: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |v: Option<&Value>| {
        for p in v.and_then(Value::as_array).into_iter().flatten() {
            if let Some(s) = p.as_str()
                && !out.iter().any(|x| x == s)
            {
                out.push(s.to_owned());
            }
        }
    };
    add(manifest.get("permissions"));
    add(manifest.get("host_permissions"));
    add(manifest.get("optional_permissions"));
    add(manifest.get("optional_host_permissions"));
    for cs in manifest
        .get("content_scripts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        add(cs.get("matches"));
    }
    out
}

/// Resolves a `__MSG_name__` placeholder from `_locales/<locale>/messages.json`
/// text. Message names are case-insensitive in Chromium.
pub fn resolve_message(name: &str, messages: Option<&str>) -> String {
    let Some(key) = name
        .strip_prefix("__MSG_")
        .and_then(|r| r.strip_suffix("__"))
    else {
        return name.to_owned();
    };
    let found = messages
        .and_then(|m| serde_json::from_str::<Value>(m).ok())
        .and_then(|v| {
            v.as_object()?.iter().find_map(|(k, entry)| {
                k.eq_ignore_ascii_case(key)
                    .then(|| entry.get("message")?.as_str().map(str::to_owned))
                    .flatten()
            })
        });
    found.unwrap_or_else(|| name.to_owned())
}

/// The highest version folder name, comparing dotted numbers numerically
/// (`10.0_0` beats `9.1_0`). Chromium appends `_0` to version folders.
pub fn highest_version(folders: &[String]) -> Option<&String> {
    let key = |s: &String| -> Vec<u64> {
        s.split(['.', '_'])
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    folders.iter().max_by(|a, b| key(a).cmp(&key(b)))
}

/// One Chromium extension from its settings entry and (if read separately)
/// its manifest and default-locale messages.
pub fn chromium_extension(
    browser: &str,
    profile: &str,
    id: &str,
    settings: &Value,
    manifest_file: Option<&Value>,
    messages: Option<&str>,
) -> ExtensionFact {
    let location = settings.get("location").and_then(Value::as_i64);
    let manifest = settings.get("manifest").or(manifest_file);
    let name = manifest
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .map(|n| resolve_message(n, messages));
    // `state` 1 is enabled in older builds; newer builds use
    // `disable_reasons` (absent or empty or 0 means enabled).
    let disabled_by_reasons = match settings.get("disable_reasons") {
        Some(Value::Number(n)) => n.as_i64().is_some_and(|r| r != 0),
        Some(Value::Array(a)) => !a.is_empty(),
        _ => false,
    };
    let enabled = match settings.get("state").and_then(Value::as_i64) {
        Some(state) => state == 1 && !disabled_by_reasons,
        None => !disabled_by_reasons,
    };
    // Older builds mark store installs with `from_webstore`.
    let mut source = location.map_or(ExtensionSource::Other, chromium_source);
    if source == ExtensionSource::Other
        && settings.get("from_webstore").and_then(Value::as_bool) == Some(true)
    {
        source = ExtensionSource::Store;
    }
    ExtensionFact {
        browser: browser.to_owned(),
        profile: profile.to_owned(),
        id: id.to_owned(),
        name,
        version: manifest
            .and_then(|m| m.get("version"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        source,
        raw_location: location.map(|l| l.to_string()),
        enabled,
        permissions: manifest.map(manifest_permissions).unwrap_or_default(),
        update_url: manifest
            .and_then(|m| m.get("update_url"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        signed_state: None,
    }
}

/// Firefox profile folders from `profiles.ini`: (path, is relative).
pub fn firefox_profiles(profiles_ini: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut path: Option<String> = None;
    let mut relative = true;
    let mut flush = |path: &mut Option<String>, relative: &mut bool| {
        if let Some(p) = path.take() {
            out.push((p, *relative));
        }
        *relative = true;
    };
    for line in profiles_ini.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            flush(&mut path, &mut relative);
        } else if let Some(v) = line.strip_prefix("Path=") {
            path = Some(v.trim().replace('/', "\\"));
        } else if let Some(v) = line.strip_prefix("IsRelative=") {
            relative = v.trim() != "0";
        }
    }
    flush(&mut path, &mut relative);
    out
}

/// Firefox add-ons of type `extension` from `extensions.json`, skipping
/// built-in and system ones.
pub fn firefox_extensions(profile: &str, extensions_json: &str) -> Vec<ExtensionFact> {
    let Ok(v) = serde_json::from_str::<Value>(extensions_json) else {
        return Vec::new();
    };
    v.get("addons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| a.get("type").and_then(Value::as_str) == Some("extension"))
        .filter_map(|a| {
            let location = a
                .get("location")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if location == "app-builtin" || location.starts_with("app-system") {
                return None;
            }
            let mut permissions = Vec::new();
            for key in ["permissions", "origins"] {
                for p in a
                    .pointer(&format!("/userPermissions/{key}"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(s) = p.as_str() {
                        permissions.push(s.to_owned());
                    }
                }
            }
            let active = a.get("active").and_then(Value::as_bool).unwrap_or(false);
            let user_disabled = a
                .get("userDisabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some(ExtensionFact {
                browser: "firefox".to_owned(),
                profile: profile.to_owned(),
                id: a.get("id").and_then(Value::as_str)?.to_owned(),
                name: a
                    .pointer("/defaultLocale/name")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                version: a.get("version").and_then(Value::as_str).map(str::to_owned),
                source: if location == "app-profile" {
                    ExtensionSource::FirefoxProfile
                } else {
                    ExtensionSource::Other
                },
                raw_location: Some(location.to_owned()),
                enabled: active && !user_disabled,
                permissions,
                update_url: a
                    .get("sourceURI")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                signed_state: a.get("signedState").and_then(Value::as_i64),
            })
        })
        .collect()
}

/// A Chromium forcelist value: `<id>;<update_url>` or just `<id>`.
pub fn forcelist_entry(value: &str) -> (String, Option<String>) {
    match value.split_once(';') {
        Some((id, url)) => (
            id.trim().to_owned(),
            Some(url.trim().to_owned()).filter(|u| !u.is_empty()),
        ),
        None => (value.trim().to_owned(), None),
    }
}

/// Is this the Chrome Web Store's or Edge Add-ons' own update service?
pub fn official_update_url(url: Option<&str>) -> bool {
    // No URL in a forcelist entry means the browser's own store.
    let Some(url) = url else { return true };
    let lower = url.to_ascii_lowercase();
    [
        "https://clients2.google.com/service/update2/crx",
        "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
    ]
    .iter()
    .any(|u| lower == *u)
}

/// What's suspicious in a browser shortcut's arguments, if anything.
pub fn shortcut_flags(arguments: &str) -> Vec<&'static str> {
    let lower = arguments.to_ascii_lowercase();
    let mut out = Vec::new();
    if lower.contains("--load-extension=") {
        out.push("load_extension");
    }
    if lower.contains("--disable-extensions-except=") {
        out.push("disable_extensions_except");
    }
    if lower
        .split_whitespace()
        .any(|a| a.starts_with("http://") || a.starts_with("https://"))
    {
        out.push("start_page");
    }
    out
}

/// One subkey of `HKLM\SOFTWARE\Microsoft\Enrollments`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Enrollment {
    /// `ProviderID`.
    pub provider_id: Option<String>,
    /// `DiscoveryServiceFullURL`: where the device enrolled.
    pub discovery_url: Option<String>,
    /// `EnrollmentState`.
    pub state: Option<u32>,
}

/// Windows' own enrolment records, present on unmanaged PCs too. Seen on a
/// windows-2025 runner (10-11-2026) that wasn't enrolled in any MDM.
const BUILT_IN_PROVIDERS: &[&str] = &["Deploy Authority", "Cloud Authority", "Local Authority"];

/// Is this a real enrolment in an organisation's device management?
///
/// It needs a provider that isn't one of Windows' built-in ones, a
/// discovery URL (the server the device enrolled with), and, if a state is
/// recorded, state 1 (enrolled). Requiring the URL errs towards "not
/// managed". A work PC that's also Entra or domain joined is still caught
/// by those checks. This is based on what the runner showed, not on a
/// documented contract: Microsoft doesn't document these registry values.
pub fn real_mdm_enrollment(e: &Enrollment) -> bool {
    let provider = e.provider_id.as_deref().map(str::trim).unwrap_or_default();
    let url = e
        .discovery_url
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    !provider.is_empty()
        && !BUILT_IN_PROVIDERS
            .iter()
            .any(|b| b.eq_ignore_ascii_case(provider))
        && !url.is_empty()
        && e.state.is_none_or(|s| s == 1)
}
