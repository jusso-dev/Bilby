//! Things set to start by themselves. Read-only: registry keys opened with
//! `KEY_READ`, shortcuts loaded with `STGM_READ` and never resolved.

mod run_keys;
pub mod services;
mod startup_folders;
pub mod tasks;
pub mod wmi_subs;

use bilby_core::cmdline::{Host, resolve};
use bilby_core::model::{Check, CheckStatus, SignalFamily};
use bilby_core::paths::KnownFolders;
use bilby_core::snapshot::{PersistenceFacts, StartupItem, StartupSource};

use crate::cache::FileCache;

pub use run_keys::{appinit, ifeo, winlogon};

/// What the startup collectors found, and how each part went.
pub struct Collected {
    /// The facts.
    pub facts: PersistenceFacts,
    /// One entry per source.
    pub checks: Vec<Check>,
}

/// Collects Run keys, startup folders, Winlogon, IFEO and `AppInit_DLLs`.
pub fn collect(folders: &KnownFolders, cache: &FileCache) -> Collected {
    crate::defender::init_com();
    let mut items = run_keys::run_items();
    let (folder_items, folder_status) = startup_folders::items();
    items.extend(folder_items);
    for item in &mut items {
        fill_target(item, folders);
    }
    let check = |id: &str, status| Check {
        id: id.to_owned(),
        family: SignalFamily::Persistence,
        status,
    };
    let (services, services_status) = match services::collect(folders) {
        Ok(list) => (list, CheckStatus::Ran),
        Err(e) => (Vec::new(), CheckStatus::Failed(e.message())),
    };
    let (tasks, tasks_status) = match tasks::collect(folders) {
        // Some task folders need admin. Say so rather than look complete.
        Ok(c) if c.folders_denied > 0 => (c.tasks, CheckStatus::NeedsAdmin),
        Ok(c) => (c.tasks, CheckStatus::Ran),
        Err(e) => (Vec::new(), CheckStatus::Failed(e.message())),
    };
    let (wmi, wmi_status) = wmi_subs::collect();
    let mut facts = PersistenceFacts {
        wmi,
        items,
        winlogon: Some(winlogon()),
        ifeo: ifeo(folders),
        appinit: appinit(),
        services,
        tasks,
    };
    // All file checks for every source, in parallel, once.
    fill_pending(&mut facts, folders, cache);
    Collected {
        facts,
        checks: vec![
            check("persistence.run_keys", CheckStatus::Ran),
            check("persistence.startup_folders", folder_status),
            check("persistence.winlogon", CheckStatus::Ran),
            check("persistence.services", services_status),
            check("persistence.tasks", tasks_status),
            check("persistence.wmi", wmi_status),
        ],
    }
}

pub(crate) fn host_name(h: Host) -> &'static str {
    match h {
        Host::Rundll32 => "rundll32",
        Host::Cmd => "cmd",
        Host::PowerShell => "powershell",
        Host::ScriptHost => "script_host",
        Host::Mshta => "mshta",
        Host::Regsvr32 => "regsvr32",
        Host::Msiexec => "msiexec",
        Host::Explorer => "explorer",
    }
}

/// Fills every `FileFacts` in the persistence facts whose `path` is set but
/// that hasn't been checked yet, in parallel. Collectors record a
/// placeholder (`pending`) and call this once at the end.
pub(crate) fn fill_pending(
    facts: &mut PersistenceFacts,
    folders: &KnownFolders,
    cache: &FileCache,
) {
    let mut slots: Vec<&mut bilby_core::snapshot::FileFacts> = Vec::new();
    for i in &mut facts.items {
        slots.extend(i.target.as_mut());
    }
    for e in &mut facts.ifeo {
        slots.extend(e.target.as_mut());
    }
    for s in &mut facts.services {
        slots.extend(s.binary.as_mut());
        slots.extend(s.service_dll.as_mut());
    }
    for t in &mut facts.tasks {
        for a in &mut t.actions {
            if let bilby_core::snapshot::TaskAction::Exec {
                target: Some(f), ..
            } = a
            {
                slots.push(f);
            }
        }
    }
    let pending: Vec<&mut bilby_core::snapshot::FileFacts> =
        slots.into_iter().filter(|f| is_pending(f)).collect();
    let mut paths: Vec<String> = pending.iter().map(|f| f.path.clone()).collect();
    paths.sort_unstable();
    paths.dedup();
    let checked: std::collections::HashMap<String, bilby_core::snapshot::FileFacts> = paths
        .iter()
        .cloned()
        .zip(crate::files::file_facts_many(&paths, folders, cache))
        .collect();
    for slot in pending {
        if let Some(f) = checked.get(&slot.path) {
            *slot = f.clone();
        }
    }
}

const PENDING: &str = "pending";

/// A placeholder for a file that will be checked by `fill_pending`.
pub(crate) fn pending(path: &str, folders: &KnownFolders) -> bilby_core::snapshot::FileFacts {
    if is_network(path, folders) {
        return crate::files::not_checked(path, folders, "on a network drive, not checked");
    }
    crate::files::not_checked(path, folders, PENDING)
}

fn is_pending(f: &bilby_core::snapshot::FileFacts) -> bool {
    matches!(&f.signature, bilby_core::snapshot::SignatureStatus::Error { reason } if reason == PENDING)
}

/// Works out what the command runs and gathers facts about that file.
pub(crate) fn fill_target(item: &mut StartupItem, folders: &KnownFolders) {
    // Never touch the network during a scan: a slow or offline share would
    // stall it, and checking a remote file means contacting that server.
    let exists = |p: &str| !is_network(p, folders) && std::path::Path::new(p).is_file();
    let r = resolve(&item.command, folders, &exists);
    item.args = (!r.args.is_empty()).then_some(r.args);
    item.host = r.via.map(|h| host_name(h).to_owned());
    item.host_args = (!r.host_args.is_empty()).then_some(r.host_args);
    item.target = Some(pending(&r.target, folders));
}

/// UNC paths and mapped network drives.
pub(crate) fn is_network(path: &str, folders: &KnownFolders) -> bool {
    bilby_core::paths::classify(path, folders).class == bilby_core::snapshot::PathClass::Network
}

/// A startup item from a registry value, before its target is filled in.
pub(crate) fn registry_item(
    source: StartupSource,
    location: &str,
    name: String,
    command: String,
    enabled: bool,
    last_write: Option<time::OffsetDateTime>,
) -> StartupItem {
    StartupItem {
        source,
        location: location.to_owned(),
        name,
        command,
        target: None,
        args: None,
        host: None,
        host_args: None,
        enabled,
        last_write,
    }
}
