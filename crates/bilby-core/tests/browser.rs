//! Browser profile parsing from fixture JSON. Runs on any OS.

use bilby_core::browser::{Enrollment, real_mdm_enrollment};
use bilby_core::browser::{
    broad_access, chromium_extension, chromium_profiles, chromium_settings, firefox_extensions,
    firefox_profiles, forcelist_entry, highest_version, manifest_permissions, official_update_url,
    resolve_message, shortcut_flags,
};
use bilby_core::snapshot::ExtensionSource;
use serde_json::{Value, json};

#[test]
fn local_state_profiles() {
    let ls = r#"{"profile":{"info_cache":{"Default":{"name":"Person 1"},"Profile 2":{"name":"Work"}},"other":1}}"#;
    assert_eq!(chromium_profiles(ls), ["Default", "Profile 2"]);
    assert_eq!(chromium_profiles("{}").len(), 0);
    assert_eq!(chromium_profiles("not json").len(), 0);
}

#[test]
fn secure_preferences_win() {
    let prefs = r#"{"extensions":{"settings":{"a":{"location":4},"b":{"location":1}}}}"#;
    let secure = r#"{"extensions":{"settings":{"a":{"location":1}}}}"#;
    let merged = chromium_settings(Some(prefs), Some(secure));
    assert_eq!(merged["a"]["location"], 1);
    assert_eq!(merged["b"]["location"], 1);
    assert_eq!(chromium_settings(None, None).len(), 0);
    assert_eq!(chromium_settings(Some("garbage"), Some(secure)).len(), 1);
}

#[test]
fn permissions_include_hosts_and_content_scripts() {
    let m = json!({
        "permissions": ["storage", "tabs"],
        "host_permissions": ["<all_urls>"],
        "optional_permissions": ["downloads"],
        "content_scripts": [{"matches": ["https://*/*", "<all_urls>"]}]
    });
    assert_eq!(
        manifest_permissions(&m),
        ["storage", "tabs", "<all_urls>", "downloads", "https://*/*"]
    );
}

#[test]
fn message_names_resolve_case_insensitively() {
    let messages = r#"{"appName":{"message":"uBlock Origin"},"other":{"message":"x"}}"#;
    assert_eq!(
        resolve_message("__MSG_appName__", Some(messages)),
        "uBlock Origin"
    );
    assert_eq!(
        resolve_message("__MSG_APPNAME__", Some(messages)),
        "uBlock Origin"
    );
    assert_eq!(
        resolve_message("__MSG_missing__", Some(messages)),
        "__MSG_missing__"
    );
    assert_eq!(resolve_message("Plain name", None), "Plain name");
}

#[test]
fn version_folders_compare_numerically() {
    let folders = ["9.1_0", "10.0_0", "1.2.3_0"].map(String::from);
    assert_eq!(
        highest_version(&folders).map(String::as_str),
        Some("10.0_0")
    );
    assert_eq!(highest_version(&[]), None);
}

#[test]
fn chromium_extension_fields() {
    let settings = json!({
        "location": 4,
        "state": 1,
        "path": "C:\\\\dev\\\\ext",
        "manifest": {"name": "__MSG_n__", "version": "1.0", "host_permissions": ["<all_urls>"], "permissions": ["webRequest"]}
    });
    let messages = r#"{"n":{"message":"My Dev Extension"}}"#;
    let e = chromium_extension("chrome", "Default", "abc", &settings, None, Some(messages));
    assert_eq!(e.source, ExtensionSource::Unpacked);
    assert_eq!(e.name.as_deref(), Some("My Dev Extension"));
    assert!(e.enabled);
    assert!(broad_access(&e));

    // Newer builds: no state, disable_reasons instead.
    let off = json!({"location": 1, "disable_reasons": [1], "manifest": {"name": "x"}});
    assert!(!chromium_extension("edge", "Default", "d", &off, None, None).enabled);
    let on = json!({"location": 1, "disable_reasons": 0, "manifest": {"name": "x"}});
    assert!(chromium_extension("edge", "Default", "d", &on, None, None).enabled);

    // Older builds: from_webstore and no location.
    let old = json!({"from_webstore": true, "state": 1, "manifest": {"name": "x"}});
    assert_eq!(
        chromium_extension("chrome", "Default", "o", &old, None, None).source,
        ExtensionSource::Store
    );

    // Manifest from the extension folder when the settings have none.
    let manifest: Value = json!({"name": "From file", "version": "2.0"});
    let e = chromium_extension(
        "brave",
        "Default",
        "f",
        &json!({"location": 1}),
        Some(&manifest),
        None,
    );
    assert_eq!(
        (e.name.as_deref(), e.version.as_deref()),
        (Some("From file"), Some("2.0"))
    );
}

#[test]
fn chromium_locations_match_manifest_mojom() {
    use ExtensionSource::{CommandLine, Component, External, Other, Policy, Store, Unpacked};
    let want = [
        (0, Other),
        (1, Store),
        (2, External),
        (3, External),
        (4, Unpacked),
        (5, Component),
        (6, External),
        (7, Policy),
        (8, CommandLine),
        (9, Policy),
        (10, Component),
        (11, Other),
    ];
    for (n, source) in want {
        assert_eq!(
            bilby_core::browser::chromium_source(n),
            source,
            "location {n}"
        );
    }
}

#[test]
fn firefox_profiles_ini() {
    let ini = "[General]\nStartWithLastProfile=1\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abc.default-release\n\n[Profile1]\nName=other\nIsRelative=0\nPath=D:\\FF\\other\n";
    assert_eq!(
        firefox_profiles(ini),
        [
            ("Profiles\\abc.default-release".to_owned(), true),
            ("D:\\FF\\other".to_owned(), false)
        ]
    );
}

#[test]
fn firefox_extensions_json() {
    let j = json!({"addons": [
        {"id": "uBlock0@raymondhill.net", "type": "extension", "location": "app-profile", "active": true,
         "userDisabled": false, "signedState": 2, "version": "1.60",
         "defaultLocale": {"name": "uBlock Origin"},
         "userPermissions": {"permissions": ["storage"], "origins": ["<all_urls>"]}},
        {"id": "builtin@mozilla", "type": "extension", "location": "app-builtin", "active": true},
        {"id": "sys@mozilla", "type": "extension", "location": "app-system-defaults", "active": true},
        {"id": "theme@x", "type": "theme", "location": "app-profile", "active": true},
        {"id": "off@x", "type": "extension", "location": "app-profile", "active": true, "userDisabled": true, "signedState": 0}
    ]});
    let list = firefox_extensions("abc.default", &j.to_string());
    assert_eq!(list.len(), 2, "built-in, system and themes skipped");
    assert_eq!(list[0].name.as_deref(), Some("uBlock Origin"));
    assert_eq!(list[0].signed_state, Some(2));
    assert!(broad_access(&list[0]));
    assert!(!list[1].enabled);
    assert_eq!(firefox_extensions("p", "{}").len(), 0);
}

#[test]
fn forcelist_and_update_urls() {
    assert_eq!(
        forcelist_entry("abcdefghijklmnop;https://clients2.google.com/service/update2/crx"),
        (
            "abcdefghijklmnop".to_owned(),
            Some("https://clients2.google.com/service/update2/crx".to_owned())
        )
    );
    assert_eq!(forcelist_entry("abc"), ("abc".to_owned(), None));
    assert!(official_update_url(Some(
        "https://clients2.google.com/service/update2/crx"
    )));
    assert!(official_update_url(Some(
        "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
    )));
    assert!(official_update_url(None));
    assert!(!official_update_url(Some(
        "https://update.example.test/crx"
    )));
    assert!(!official_update_url(Some(
        "https://clients2.google.com.evil.test/service/update2/crx"
    )));
}

#[test]
fn shortcut_arguments() {
    assert_eq!(shortcut_flags("--load-extension=C:\\x"), ["load_extension"]);
    assert_eq!(
        shortcut_flags("--disable-extensions-except=C:\\x --load-extension=C:\\x").len(),
        2
    );
    assert_eq!(
        shortcut_flags("https://search.example.test"),
        ["start_page"]
    );
    assert_eq!(shortcut_flags("--profile-directory=\"Profile 1\"").len(), 0);
    assert_eq!(shortcut_flags("").len(), 0);
}

#[test]
fn mdm_enrollment_needs_a_real_provider_and_server() {
    let e = |provider: Option<&str>, url: Option<&str>, state: Option<u32>| Enrollment {
        provider_id: provider.map(str::to_owned),
        discovery_url: url.map(str::to_owned),
        state,
    };
    // What a windows-2025 runner with no MDM has: built-in providers only.
    for built_in in ["Deploy Authority", "Cloud Authority", "Local Authority"] {
        assert!(
            !real_mdm_enrollment(&e(Some(built_in), None, Some(1))),
            "{built_in}"
        );
    }
    assert!(!real_mdm_enrollment(&e(None, None, Some(1))));
    // A provider but no server it enrolled with: not counted.
    assert!(!real_mdm_enrollment(&e(
        Some("MS DM Server"),
        None,
        Some(1)
    )));
    // A real enrolment: provider and discovery URL, enrolled.
    let intune = e(
        Some("MS DM Server"),
        Some("https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc"),
        Some(1),
    );
    assert!(real_mdm_enrollment(&intune));
    // No state recorded still counts; any other state doesn't.
    assert!(real_mdm_enrollment(&Enrollment {
        state: None,
        ..intune.clone()
    }));
    assert!(!real_mdm_enrollment(&Enrollment {
        state: Some(0),
        ..intune
    }));
}
