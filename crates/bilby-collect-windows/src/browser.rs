//! Browser extensions, extension policies, device management and browser
//! shortcuts. Read-only: files are read whole with shared access, never
//! written; registry keys use `KEY_READ`; shortcuts are loaded with
//! `STGM_READ` and never resolved.

use std::path::{Path, PathBuf};

use bilby_core::browser::{
    chromium_extension, chromium_profiles, chromium_settings, firefox_extensions, firefox_profiles,
    forcelist_entry, highest_version,
};
use bilby_core::model::CheckStatus;
use bilby_core::paths::KnownFolders;
use bilby_core::snapshot::{
    BrowserFacts, BrowserPolicy, BrowserShortcut, ExtensionFact, ExtensionSource, Management,
};
use serde_json::Value;
use windows::Win32::NetworkManagement::NetManagement::{
    DSREG_DEVICE_JOIN, NETSETUP_JOIN_STATUS, NetApiBufferFree, NetFreeAadJoinInformation,
    NetGetAadJoinInformation, NetGetJoinInformation, NetSetupDomainName,
};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};
use windows::core::{PCWSTR, PWSTR};

use crate::registry::{Data, Key};

/// What the browser collector found, and how reading went.
pub struct Collected {
    /// The facts.
    pub facts: BrowserFacts,
    /// `Ran`, or `Failed` listing profiles that couldn't be read.
    pub status: CheckStatus,
}

/// Chromium browsers and their user data folders, relative to
/// `%LOCALAPPDATA%` (or `%APPDATA%` for Opera, which has one profile).
const CHROMIUM: &[(&str, &str, bool)] = &[
    ("chrome", r"Google\Chrome\User Data", false),
    ("edge", r"Microsoft\Edge\User Data", false),
    ("brave", r"BraveSoftware\Brave-Browser\User Data", false),
    ("vivaldi", r"Vivaldi\User Data", false),
    ("opera", r"Opera Software\Opera Stable", true),
];

/// Reads a file without locking it. `std::fs::read` opens with read access
/// and shares read, write and delete on Windows, so a running browser can
/// keep its files open.
fn read(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    // Some files start with a UTF-8 byte order mark.
    let text = String::from_utf8_lossy(&bytes);
    Some(text.trim_start_matches('\u{feff}').to_owned())
}

/// Every extension, policy, shortcut and the management state.
pub fn collect(folders: &KnownFolders) -> Collected {
    let mut extensions = Vec::new();
    let mut unreadable = Vec::new();
    for (browser, rel, single) in CHROMIUM {
        let base = if *single {
            &folders.roaming_app_data
        } else {
            &folders.local_app_data
        };
        let root = Path::new(base).join(rel);
        if root.is_dir() {
            extensions.extend(chromium(browser, &root, *single, &mut unreadable));
        }
    }
    extensions.extend(firefox(folders, &mut unreadable));
    let facts = BrowserFacts {
        extensions,
        policies: policies(),
        shortcuts: shortcuts(folders),
        management: management(),
    };
    let status = if unreadable.is_empty() {
        CheckStatus::Ran
    } else {
        CheckStatus::Failed(format!("couldn't read: {}", unreadable.join(", ")))
    };
    Collected { facts, status }
}

fn chromium(
    browser: &str,
    root: &Path,
    single: bool,
    unreadable: &mut Vec<String>,
) -> Vec<ExtensionFact> {
    let profiles = if single {
        vec![String::new()]
    } else {
        let names = read(&root.join("Local State"))
            .map(|t| chromium_profiles(&t))
            .unwrap_or_default();
        if names.is_empty() {
            vec!["Default".to_owned()]
        } else {
            names
        }
    };
    let mut out = Vec::new();
    for profile in profiles {
        let dir = if profile.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&profile)
        };
        if !dir.is_dir() {
            continue;
        }
        let prefs = read(&dir.join("Preferences"));
        let secure = read(&dir.join("Secure Preferences"));
        if prefs.is_none() && secure.is_none() {
            // Present but unreadable (locked), not just a fresh profile.
            if dir.join("Preferences").exists() {
                unreadable.push(format!("{browser} {profile}"));
            }
            continue;
        }
        let label = if profile.is_empty() {
            "Default".to_owned()
        } else {
            profile.clone()
        };
        for (id, settings) in chromium_settings(prefs.as_deref(), secure.as_deref()) {
            let location = settings.get("location").and_then(Value::as_i64);
            // Component extensions are part of the browser itself.
            if matches!(location, Some(5 | 10)) {
                continue;
            }
            let (manifest, messages) = if settings.get("manifest").is_some() {
                (None, None)
            } else {
                manifest_from_disk(&dir, &id, &settings)
            };
            let mut fact = chromium_extension(
                browser,
                &label,
                &id,
                &settings,
                manifest.as_ref(),
                messages.as_deref(),
            );
            // Embedded manifests can use __MSG_ names too.
            if fact
                .name
                .as_deref()
                .is_some_and(|n| n.starts_with("__MSG_"))
            {
                let (_, messages) = manifest_from_disk(&dir, &id, &settings);
                fact = chromium_extension(
                    browser,
                    &label,
                    &id,
                    &settings,
                    manifest.as_ref(),
                    messages.as_deref(),
                );
            }
            if fact.source != ExtensionSource::Component {
                out.push(fact);
            }
        }
    }
    out
}

/// The manifest and default-locale messages from the extension's folder:
/// `path` from settings for unpacked ones, otherwise the highest version
/// under `<profile>\Extensions\<id>`.
fn manifest_from_disk(
    profile: &Path,
    id: &str,
    settings: &Value,
) -> (Option<Value>, Option<String>) {
    let dir: Option<PathBuf> = match settings.get("path").and_then(Value::as_str) {
        Some(p) if Path::new(p).is_absolute() => Some(PathBuf::from(p)),
        _ => {
            let base = profile.join("Extensions").join(id);
            let versions: Vec<String> = std::fs::read_dir(&base)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            highest_version(&versions).map(|v| base.join(v))
        }
    };
    let Some(dir) = dir else { return (None, None) };
    let manifest: Option<Value> =
        read(&dir.join("manifest.json")).and_then(|t| serde_json::from_str(&t).ok());
    let messages = manifest
        .as_ref()
        .and_then(|m| m.get("default_locale"))
        .and_then(Value::as_str)
        .and_then(|loc| read(&dir.join("_locales").join(loc).join("messages.json")));
    (manifest, messages)
}

fn firefox(folders: &KnownFolders, unreadable: &mut Vec<String>) -> Vec<ExtensionFact> {
    let root = Path::new(&folders.roaming_app_data).join(r"Mozilla\Firefox");
    let Some(ini) = read(&root.join("profiles.ini")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (path, relative) in firefox_profiles(&ini) {
        let dir = if relative {
            root.join(&path)
        } else {
            PathBuf::from(&path)
        };
        let label = dir
            .file_name()
            .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned());
        let file = dir.join("extensions.json");
        match read(&file) {
            Some(text) => out.extend(firefox_extensions(&label, &text)),
            None if file.exists() => unreadable.push(format!("firefox {label}")),
            None => {}
        }
    }
    out
}

/// Forcelist entries from the policy keys, machine and user.
fn policies() -> Vec<BrowserPolicy> {
    let keys = [
        (
            "chrome",
            r"Software\Policies\Google\Chrome\ExtensionInstallForcelist",
        ),
        (
            "edge",
            r"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
        ),
        (
            "brave",
            r"Software\Policies\BraveSoftware\Brave\ExtensionInstallForcelist",
        ),
    ];
    let mut out = Vec::new();
    for (root, root_name) in [(HKEY_LOCAL_MACHINE, "HKLM"), (HKEY_CURRENT_USER, "HKCU")] {
        for (browser, path) in keys {
            let Some(key) = Key::open(root, path, KEY_WOW64_64KEY) else {
                continue;
            };
            for (_, data) in key.values() {
                if let Data::Text(value) = data {
                    let (id, update_url) = forcelist_entry(&value);
                    if !id.is_empty() {
                        out.push(BrowserPolicy {
                            browser: browser.to_owned(),
                            location: format!(r"{root_name}\{path}"),
                            id,
                            update_url,
                        });
                    }
                }
            }
        }
        // ExtensionSettings is one JSON value; force_installed entries count.
        for (browser, path) in [
            ("chrome", r"Software\Policies\Google\Chrome"),
            ("edge", r"Software\Policies\Microsoft\Edge"),
            ("firefox", r"Software\Policies\Mozilla\Firefox"),
        ] {
            let Some(text) = Key::open(root, path, KEY_WOW64_64KEY)
                .and_then(|k| k.value("ExtensionSettings"))
                .and_then(|d| d.text().map(str::to_owned))
            else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            for (id, s) in v.as_object().into_iter().flatten() {
                let mode = s
                    .get("installation_mode")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if matches!(mode, "force_installed" | "normal_installed") {
                    out.push(BrowserPolicy {
                        browser: browser.to_owned(),
                        location: format!(r"{root_name}\{path}\ExtensionSettings"),
                        id: id.clone(),
                        update_url: s
                            .get("update_url")
                            .or_else(|| s.get("install_url"))
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    });
                }
            }
        }
    }
    out
}

/// Entra joined, domain joined or MDM enrolled.
fn management() -> Management {
    let mut reasons = Vec::new();
    // SAFETY: a null tenant id asks about the device's own join. The
    // returned structure is freed with NetFreeAadJoinInformation.
    if let Ok(info) = unsafe { NetGetAadJoinInformation(PCWSTR::null()) }
        && !info.is_null()
    {
        // SAFETY: non-null pointer returned by the call above.
        if unsafe { (*info).joinType } == DSREG_DEVICE_JOIN {
            reasons.push("entra joined".to_owned());
        }
        // SAFETY: freeing exactly what NetGetAadJoinInformation returned.
        unsafe { NetFreeAadJoinInformation(Some(info)) };
    }
    let mut name = PWSTR::null();
    let mut status = NETSETUP_JOIN_STATUS::default();
    // SAFETY: local machine; both out-parameters are ours. The name buffer
    // is freed with NetApiBufferFree.
    let rc = unsafe { NetGetJoinInformation(PCWSTR::null(), &raw mut name, &raw mut status) };
    if rc == 0 {
        if status == NetSetupDomainName {
            reasons.push("domain joined".to_owned());
        }
        if !name.is_null() {
            // SAFETY: freeing the buffer the call allocated.
            let _ = unsafe { NetApiBufferFree(Some(name.0.cast())) };
        }
    }
    let enrolled = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Enrollments",
        KEY_WOW64_64KEY,
    )
    .is_some_and(|k| {
        k.subkeys().iter().any(|sub| {
            let Some(s) = k.sub(sub, KEY_WOW64_64KEY) else {
                return false;
            };
            let text = |n: &str| s.value(n).and_then(|d| d.text().map(str::to_owned));
            let state = match s.value("EnrollmentState") {
                Some(Data::Dword(v)) => Some(v),
                _ => None,
            };
            // Windows keeps its own enrolment records on unmanaged PCs
            // too; only a real organisation's enrolment counts.
            bilby_core::browser::real_mdm_enrollment(&bilby_core::browser::Enrollment {
                provider_id: text("ProviderID"),
                discovery_url: text("DiscoveryServiceFullURL"),
                state,
            })
        })
    });
    if enrolled {
        reasons.push("mdm enrolled".to_owned());
    }
    Management {
        managed: !reasons.is_empty(),
        reasons,
    }
}

const BROWSER_EXES: &[(&str, &str)] = &[
    ("chrome.exe", "chrome"),
    ("msedge.exe", "edge"),
    ("brave.exe", "brave"),
    ("vivaldi.exe", "vivaldi"),
    ("opera.exe", "opera"),
    ("launcher.exe", "opera"),
    ("firefox.exe", "firefox"),
];

/// Browser shortcuts on the Desktop, Start Menu and pinned taskbar.
fn shortcuts(folders: &KnownFolders) -> Vec<BrowserShortcut> {
    use windows::Win32::UI::Shell::{FOLDERID_CommonPrograms, FOLDERID_Programs};
    crate::defender::init_com();
    let mut roots: Vec<(PathBuf, bool)> = vec![
        (PathBuf::from(&folders.desktop), false),
        (Path::new(&folders.public).join("Desktop"), false),
        (
            Path::new(&folders.roaming_app_data)
                .join(r"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"),
            false,
        ),
    ];
    for id in [&FOLDERID_Programs, &FOLDERID_CommonPrograms] {
        if let Some(p) = crate::paths::known_folder_path(id) {
            roots.push((PathBuf::from(p), true));
        }
    }
    let mut out = Vec::new();
    for (root, recursive) in roots {
        let mut files = Vec::new();
        lnk_files(&root, recursive, 0, &mut files);
        for lnk in files {
            let Ok(Some((target, arguments))) =
                crate::persistence::shortcut_target(&lnk.to_string_lossy())
            else {
                continue;
            };
            let exe = Path::new(&target)
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if let Some((_, browser)) = BROWSER_EXES.iter().find(|(e, _)| *e == exe) {
                out.push(BrowserShortcut {
                    path: lnk.to_string_lossy().into_owned(),
                    browser: (*browser).to_owned(),
                    arguments,
                });
            }
        }
    }
    out
}

fn lnk_files(dir: &Path, recursive: bool, depth: u8, out: &mut Vec<PathBuf>) {
    if depth > 8 {
        return;
    }
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                lnk_files(&path, true, depth + 1, out);
            }
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("lnk"))
        {
            out.push(path);
        }
    }
}
