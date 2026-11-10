//! WMI event subscriptions in `root\subscription` and `root\default`.
//! Read-only WQL queries. Reading these namespaces usually needs admin; if
//! access is denied the check says so (`NeedsAdmin`) rather than failing.

use std::collections::HashMap;

use bilby_core::model::CheckStatus;
use bilby_core::snapshot::{WmiConsumerKind, WmiFilter, WmiSubscription};
use wmi::{WMIConnection, WMIError};

use crate::defender::{Row, get_string, init_com, is_access_denied};

const NAMESPACES: &[&str] = &[r"root\subscription", r"root\default"];

/// Consumer classes that run nothing: recorded by name only.
const PASSIVE_CONSUMERS: &[&str] = &[
    "NTEventLogEventConsumer",
    "LogFileEventConsumer",
    "SMTPEventConsumer",
];

/// Every subscription consumer in both namespaces, and how reading went.
pub fn collect() -> (Vec<WmiSubscription>, CheckStatus) {
    init_com();
    let mut out = Vec::new();
    let mut denied = false;
    let mut failure = None;
    for ns in NAMESPACES {
        match namespace(ns) {
            Ok(list) => out.extend(list),
            Err(e) if is_access_denied(&e) => denied = true,
            // root\default has no subscription classes on some builds;
            // an invalid class there isn't a failure of the check.
            Err(_) if *ns == r"root\default" => {}
            Err(e) => failure = Some(e.to_string()),
        }
    }
    let status = if denied {
        CheckStatus::NeedsAdmin
    } else if let Some(f) = failure {
        CheckStatus::Failed(f)
    } else {
        CheckStatus::Ran
    };
    (out, status)
}

fn namespace(ns: &str) -> Result<Vec<WmiSubscription>, WMIError> {
    let con = WMIConnection::with_namespace_path(ns)?;
    let filters: HashMap<String, WmiFilter> = con
        .raw_query::<Row>("SELECT __RELPATH, Name, Query FROM __EventFilter")?
        .iter()
        .filter_map(|r| {
            Some((
                normalise_ref(&get_string(r, "__RELPATH")?),
                WmiFilter {
                    name: get_string(r, "Name").unwrap_or_default(),
                    query: get_string(r, "Query"),
                },
            ))
        })
        .collect();
    // Consumer relpath -> filter relpaths bound to it.
    let mut bindings: HashMap<String, Vec<String>> = HashMap::new();
    for r in con.raw_query::<Row>("SELECT Filter, Consumer FROM __FilterToConsumerBinding")? {
        if let (Some(f), Some(c)) = (get_string(&r, "Filter"), get_string(&r, "Consumer")) {
            bindings
                .entry(normalise_ref(&c))
                .or_default()
                .push(normalise_ref(&f));
        }
    }

    let mut out = Vec::new();
    let mut push = |rel: Option<String>, name: Option<String>, consumer: WmiConsumerKind| {
        let rel = rel.map(|r| normalise_ref(&r)).unwrap_or_default();
        let bound = bindings
            .get(&rel)
            .map(|fs| fs.iter().filter_map(|f| filters.get(f).cloned()).collect())
            .unwrap_or_default();
        out.push(WmiSubscription {
            namespace: ns.to_owned(),
            name: name.unwrap_or_default(),
            consumer,
            filters: bound,
        });
    };
    for r in con.raw_query::<Row>(
        "SELECT __RELPATH, Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer",
    )? {
        push(
            get_string(&r, "__RELPATH"),
            get_string(&r, "Name"),
            WmiConsumerKind::CommandLine {
                command_line: get_string(&r, "CommandLineTemplate"),
                executable: get_string(&r, "ExecutablePath"),
            },
        );
    }
    for r in con.raw_query::<Row>(
        "SELECT __RELPATH, Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer",
    )? {
        push(
            get_string(&r, "__RELPATH"),
            get_string(&r, "Name"),
            WmiConsumerKind::ActiveScript {
                engine: get_string(&r, "ScriptingEngine"),
                text: get_string(&r, "ScriptText").map(|t| t.chars().take(2000).collect()),
                file: get_string(&r, "ScriptFileName"),
            },
        );
    }
    for class in PASSIVE_CONSUMERS {
        // A missing class on some editions isn't a failure.
        let Ok(rows) = con.raw_query::<Row>(format!("SELECT __RELPATH, Name FROM {class}")) else {
            continue;
        };
        for r in rows {
            push(
                get_string(&r, "__RELPATH"),
                get_string(&r, "Name"),
                WmiConsumerKind::Other {
                    class: (*class).to_owned(),
                },
            );
        }
    }
    Ok(out)
}

/// Bindings refer to filters and consumers by object path, which can be
/// relative (`__EventFilter.Name="x"`) or full (`\\HOST\root\subscription:
/// __EventFilter.Name="x"`), with varying case. Compare the part after the
/// last colon, lower-cased.
fn normalise_ref(r: &str) -> String {
    r.rsplit(':').next().unwrap_or(r).trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::normalise_ref;

    #[test]
    fn binding_refs_match_relpaths() {
        let relpath = r#"CommandLineEventConsumer.Name="BilbyTest""#;
        for binding in [
            r#"CommandLineEventConsumer.Name="BilbyTest""#,
            r#"\\RUNNERVM\ROOT\subscription:CommandLineEventConsumer.Name="BilbyTest""#,
            r#"\\.\root\subscription:commandlineeventconsumer.name="BilbyTest""#,
        ] {
            assert_eq!(normalise_ref(binding), normalise_ref(relpath), "{binding}");
        }
    }
}
