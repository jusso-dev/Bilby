//! The copy catalogue: every user-facing string, loaded once from
//! `copy/en-AU.toml`. See `docs/copy-guide.md`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The raw catalogue file, for the copy lint.
pub const SOURCE: &str = include_str!("copy/en-AU.toml");

/// Every key, flattened with dots (`light.healthy.headline`), and its text.
pub static CATALOGUE: LazyLock<BTreeMap<String, String>> = LazyLock::new(|| {
    let table: toml::Table = SOURCE
        .parse()
        .expect("copy/en-AU.toml is valid TOML, checked by the copy lint");
    let mut out = BTreeMap::new();
    flatten("", &table, &mut out);
    out
});

fn flatten(prefix: &str, table: &toml::Table, out: &mut BTreeMap<String, String>) {
    for (key, value) in table {
        let full = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::String(s) => {
                out.insert(full, s.clone());
            }
            toml::Value::Table(t) => flatten(&full, t, out),
            other => panic!("copy key {full} must be text, found {}", other.type_str()),
        }
    }
}

/// The text for a key.
///
/// # Panics
///
/// In debug builds, if the key doesn't exist. Release builds return the key
/// itself so a missing string never crashes the app.
pub fn t(key: &str) -> &'static str {
    if let Some(text) = CATALOGUE.get(key) {
        text
    } else {
        debug_assert!(false, "missing copy key {key}");
        // Leaked once per missing key in release: rare, and keeps the
        // `&'static str` API.
        Box::leak(key.to_owned().into_boxed_str())
    }
}

/// The text for a key with `{name}` placeholders filled from `vars`. Unknown
/// placeholders are left as they are. Values are inserted raw: templates
/// escape the result.
pub fn tf(key: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = t(key).to_owned();
    for (name, value) in vars {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_nested_keys() {
        assert_eq!(t("light.healthy.headline"), "Looks healthy");
    }

    #[test]
    fn fills_vars() {
        let vars = BTreeMap::from([("days".to_owned(), "9".to_owned())]);
        assert_eq!(
            tf("protection.signatures_stale.what", &vars),
            "The last update was 9 days ago."
        );
    }
}
