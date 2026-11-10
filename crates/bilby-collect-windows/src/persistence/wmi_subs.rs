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

/// `WBEM_E_INVALID_NAMESPACE` and `WBEM_E_INVALID_CLASS` (values from Microsoft's
/// WMI error constants page): the namespace or a
/// class doesn't exist on this edition. That's an expected absence, not a
/// failure.
const WBEM_E_INVALID_NAMESPACE: u32 = 0x8004_100E;
const WBEM_E_INVALID_CLASS: u32 = 0x8004_1010;

fn is_absent(e: &WMIError) -> bool {
    matches!(e, WMIError::HResultError { hres }
        if matches!(hres.cast_unsigned(), WBEM_E_INVALID_NAMESPACE | WBEM_E_INVALID_CLASS))
}

/// How reading went, across every query. Each query is judged on its own,
/// so one missing class never hides what the other queries found.
#[derive(Default)]
struct Outcome {
    denied: bool,
    failures: Vec<String>,
}

impl Outcome {
    /// Rows from a query, or none. Records access denied and real failures;
    /// an absent class or namespace is silently empty.
    fn rows(&mut self, con: &WMIConnection, what: &str, query: &str) -> Vec<Row> {
        match con.raw_query::<Row>(query) {
            Ok(rows) => rows,
            Err(e) if is_access_denied(&e) => {
                self.denied = true;
                Vec::new()
            }
            Err(e) if is_absent(&e) => Vec::new(),
            Err(e) => {
                self.failures.push(format!("{what}: {e}"));
                Vec::new()
            }
        }
    }

    fn status(self) -> CheckStatus {
        if self.denied {
            CheckStatus::NeedsAdmin
        } else if self.failures.is_empty() {
            CheckStatus::Ran
        } else {
            CheckStatus::Failed(self.failures.join("; "))
        }
    }
}

/// Every subscription consumer in both namespaces, and how reading went.
pub fn collect() -> (Vec<WmiSubscription>, CheckStatus) {
    init_com();
    let mut out = Vec::new();
    let mut outcome = Outcome::default();
    for ns in NAMESPACES {
        match WMIConnection::with_namespace_path(ns) {
            Ok(con) => out.extend(namespace(&con, ns, &mut outcome)),
            Err(e) if is_access_denied(&e) => outcome.denied = true,
            Err(e) if is_absent(&e) => {}
            Err(e) => outcome.failures.push(format!("{ns}: {e}")),
        }
    }
    (out, outcome.status())
}

fn namespace(con: &WMIConnection, ns: &str, outcome: &mut Outcome) -> Vec<WmiSubscription> {
    let filters: HashMap<String, WmiFilter> = outcome
        .rows(
            con,
            &format!(r"{ns} __EventFilter"),
            "SELECT __RELPATH, Name, Query FROM __EventFilter",
        )
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
    for r in outcome.rows(
        con,
        &format!(r"{ns} __FilterToConsumerBinding"),
        "SELECT Filter, Consumer FROM __FilterToConsumerBinding",
    ) {
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
    for r in outcome.rows(
        con,
        &format!(r"{ns} CommandLineEventConsumer"),
        "SELECT __RELPATH, Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer",
    ) {
        push(
            get_string(&r, "__RELPATH"),
            get_string(&r, "Name"),
            WmiConsumerKind::CommandLine {
                command_line: get_string(&r, "CommandLineTemplate"),
                executable: get_string(&r, "ExecutablePath"),
            },
        );
    }
    for r in outcome.rows(
        con,
        &format!(r"{ns} ActiveScriptEventConsumer"),
        "SELECT __RELPATH, Name, ScriptingEngine, ScriptText, ScriptFileName FROM ActiveScriptEventConsumer",
    ) {
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
        for r in outcome.rows(
            con,
            &format!(r"{ns} {class}"),
            &format!("SELECT __RELPATH, Name FROM {class}"),
        ) {
            push(
                get_string(&r, "__RELPATH"),
                get_string(&r, "Name"),
                WmiConsumerKind::Other {
                    class: (*class).to_owned(),
                },
            );
        }
    }
    out
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
