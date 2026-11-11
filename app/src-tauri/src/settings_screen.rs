//! The settings screen (#25, first part): the online check switches and
//! the user's own API keys. Keys go straight to Windows Credential
//! Manager; this screen only ever shows whether one is saved.

use askama::Template;
use bilby_core::copy;

use crate::commands::filters;
use crate::settings::{self, Switch};

/// One switch.
pub struct SwitchView {
    /// `data-setting`, parsed by [`Switch::parse`].
    pub name: &'static str,
    /// What it does, from copy.
    pub label: &'static str,
    /// Switched on.
    pub on: bool,
}

/// One service card.
pub struct ServiceView {
    /// `circl`, `virustotal`, `abuseipdb` or `crowdsec`.
    pub id: &'static str,
    /// The service's name.
    pub name: &'static str,
    /// Its switches.
    pub switches: Vec<SwitchView>,
    /// Whether it needs a key, and if so whether one is saved.
    pub key_saved: Option<bool>,
    /// A switch is on but the key is missing.
    pub needs_key: bool,
}

/// The settings screen.
#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsScreen {
    pub services: Vec<ServiceView>,
    /// A line to show at the top, for example after a failed save.
    pub message: Option<&'static str>,
}

/// Which key a service uses.
#[cfg(windows)]
fn key_service(id: &str) -> Option<bilby_reputation::key::Service> {
    use bilby_reputation::key::Service;
    match id {
        "virustotal" => Some(Service::VirusTotal),
        "abuseipdb" => Some(Service::AbuseIpDb),
        "crowdsec" => Some(Service::CrowdSec),
        _ => None,
    }
}

fn key_saved(id: &str) -> bool {
    #[cfg(windows)]
    {
        key_service(id).is_some_and(|s| bilby_reputation::key::load(s).is_some())
    }
    #[cfg(not(windows))]
    {
        let _ = id;
        false
    }
}

/// Builds the screen from the saved settings and keys.
pub fn screen(message: Option<&'static str>) -> SettingsScreen {
    let o = settings::load().online;
    let sw = |name, key, on| SwitchView {
        name,
        label: copy::t(key),
        on,
    };
    let service = |id: &'static str, name_key, switches: Vec<SwitchView>, keyed: bool| {
        let saved = keyed.then(|| key_saved(id));
        let any_on = switches.iter().any(|s| s.on);
        ServiceView {
            id,
            name: copy::t(name_key),
            needs_key: any_on && saved == Some(false),
            switches,
            key_saved: saved,
        }
    };
    SettingsScreen {
        services: vec![
            service(
                "circl",
                "settings.service.circl",
                vec![sw("circl", "settings.online.circl", o.circl)],
                false,
            ),
            service(
                "virustotal",
                "settings.service.virustotal",
                vec![
                    sw("virustotal", "settings.online.virustotal", o.virustotal),
                    sw(
                        "virustotal_ips",
                        "settings.online.virustotal_ips",
                        o.virustotal_ips,
                    ),
                ],
                true,
            ),
            service(
                "abuseipdb",
                "settings.service.abuseipdb",
                vec![sw("abuseipdb", "settings.online.abuseipdb", o.abuseipdb)],
                true,
            ),
            service(
                "crowdsec",
                "settings.service.crowdsec",
                vec![sw("crowdsec", "settings.online.crowdsec", o.crowdsec)],
                true,
            ),
        ],
        message,
    }
}

fn render(message: Option<&'static str>) -> Result<String, String> {
    screen(message).render().map_err(|e| e.to_string())
}

/// Renders the settings screen.
#[tauri::command]
pub fn render_settings() -> Result<String, String> {
    render(None)
}

/// Turns one online check on or off and saves it.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn set_online(name: String, on: bool) -> Result<String, String> {
    let Some(switch) = Switch::parse(&name) else {
        return render(Some(copy::t("settings.save_failed")));
    };
    let mut s = settings::load();
    switch.set(&mut s.online, on);
    if let Err(e) = settings::save(s) {
        tracing::info!(error = %e, "settings.json couldn't be saved");
        return render(Some(copy::t("settings.save_failed")));
    }
    tracing::info!(switch = %name, on, "online check switched");
    render(None)
}

/// Saves a key the user pasted. It goes straight to Credential Manager and
/// is never logged.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn save_key(service: String, key: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        use bilby_reputation::key::{ApiKey, save};
        let saved = key_service(&service)
            .zip(ApiKey::new(&key))
            .is_some_and(|(s, k)| save(s, &k).is_ok());
        drop(key);
        if !saved {
            return render(Some(copy::t("settings.key.failed")));
        }
        tracing::info!(service = %service, "key saved");
        render(Some(copy::t("settings.key.done")))
    }
    #[cfg(not(windows))]
    {
        let _ = (service, key);
        render(Some(copy::t("settings.key.failed")))
    }
}

/// Removes a saved key.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn remove_key(service: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        if let Some(s) = key_service(&service) {
            let _ = bilby_reputation::key::delete(s);
            tracing::info!(service = %service, "key removed");
        }
    }
    #[cfg(not(windows))]
    let _ = service;
    render(None)
}

/// Opens the page where a service gives out free keys, in the default
/// browser. Fixed addresses only.
#[tauri::command]
// Tauri hands command arguments over by value.
#[allow(clippy::needless_pass_by_value)]
pub fn open_key_page(service: String) -> Result<(), String> {
    let url = match service.as_str() {
        "virustotal" => "https://www.virustotal.com/gui/join-us",
        "abuseipdb" => "https://www.abuseipdb.com/register",
        "crowdsec" => "https://app.crowdsec.net/signup",
        _ => return Err(copy::t("results.open_failed").to_owned()),
    };
    #[cfg(windows)]
    {
        use bilby_collect_windows::open::{Target, open};
        open(Target::Uri(url)).map_err(|_| copy::t("results.open_failed").to_owned())
    }
    #[cfg(not(windows))]
    {
        tracing::info!(url, "would open a key page");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_service_and_switch_has_words() {
        let s = screen(None);
        assert_eq!(s.services.len(), 4);
        for svc in &s.services {
            assert_ne!(svc.name, "");
            for sw in &svc.switches {
                assert!(Switch::parse(sw.name).is_some(), "{}", sw.name);
                assert_ne!(sw.label, "");
            }
        }
        let html = s.render().expect("renders");
        assert!(html.contains(r#"data-setting="crowdsec""#));
        assert!(html.contains(r#"type="password""#));
    }
}
