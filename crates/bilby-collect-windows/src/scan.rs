//! Scan orchestration: every collector, in parallel, with timeouts,
//! cancellation and progress. See "Scan orchestration" in
//! `docs/architecture.md`.
//!
//! Each collector runs on its own thread with COM initialised for that
//! thread (MTA). Processes runs first alongside everything that doesn't
//! need it; network starts once processes is in (it keeps only rows owned
//! by known pids), and tamper once network and browser are in (it ties a
//! local proxy to its listening program and needs the device's management
//! state).
//!
//! A collector that takes longer than its limit is reported as
//! `Failed("took too long")`. Its thread is left to finish on its own and
//! whatever it returns is dropped, so a hung COM or WMI call can never hold
//! up the scan or the window.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use bilby_core::model::{Check, CheckStatus, MachineSummary, SignalFamily, Timing};
use bilby_core::paths::KnownFolders;
use bilby_core::scrub::Scrubber;
use bilby_core::snapshot::{
    BrowserFacts, ConnectionFact, DriverFacts, Management, NetworkFacts, PersistenceFacts,
    ProcessFact, ProtectionFacts, SystemSnapshot, TamperFacts,
};
use serde::Serialize;
use time::OffsetDateTime;
use windows::Win32::Foundation::{E_ACCESSDENIED, ERROR_ACCESS_DENIED};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};

use crate::cache::FileCache;
use crate::registry::{Data, Key};
use crate::{browser, defender, drivers, network, persistence, processes, tamper};

/// The reason shown for a collector that ran out of time.
pub const TOOK_TOO_LONG: &str = "took too long";

/// Limits and the cancel switch for one scan.
#[derive(Debug, Clone)]
pub struct CollectOptions {
    /// How long one collector may take. 30 seconds by default.
    pub collector_timeout: Duration,
    /// How long the whole scan may take. 120 seconds by default.
    pub scan_timeout: Duration,
    /// Set to stop the scan. Checked every 100 ms while waiting, and by
    /// file checks between files.
    pub cancel: Arc<AtomicBool>,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            collector_timeout: Duration::from_secs(30),
            scan_timeout: Duration::from_secs(120),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Where one step is up to, for the progress screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepState {
    /// Started.
    Running,
    /// Finished and everything in it ran.
    Done,
    /// Didn't apply on this computer.
    Skipped,
    /// Part of it needs Bilby to run as administrator.
    NeedsAdmin,
    /// Part of it failed or ran out of time.
    Failed,
}

/// One progress update. The app sends it to the window as `scan-progress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Progress {
    /// Collector id, for example `processes`. The window shows the copy
    /// `scan.step.<id>`.
    pub step: &'static str,
    /// Where it's up to.
    pub state: StepState,
    /// Steps finished so far.
    pub done: usize,
    /// Steps in this scan.
    pub total: usize,
}

/// Everything the collectors found, and how each part went.
#[derive(Debug, Clone)]
pub struct Collection {
    /// The facts.
    pub snapshot: SystemSnapshot,
    /// Every check and how it went.
    pub checks: Vec<Check>,
    /// How long each collector took.
    pub timings: Vec<Timing>,
    /// True if Bilby is running as administrator.
    pub is_admin: bool,
    /// Windows edition, version and architecture.
    pub machine: MachineSummary,
    /// When the scan started.
    pub started_at: OffsetDateTime,
    /// When the last collector finished, timed out or the scan was cancelled.
    pub finished_at: OffsetDateTime,
    /// True if the scan was cancelled. The snapshot is then incomplete and
    /// shouldn't be shown as a result.
    pub cancelled: bool,
}

/// What one collector found.
#[derive(Debug, Clone)]
// Each section is moved once per scan, so boxing the big ones buys nothing.
#[allow(clippy::large_enum_variant)]
pub enum Section {
    /// Antivirus, firewall, UAC and updates.
    Protection(ProtectionFacts),
    /// Running programs.
    Processes(Vec<ProcessFact>),
    /// Things that start by themselves.
    Persistence(PersistenceFacts),
    /// Network connections, if any table could be read.
    Network(Option<NetworkFacts>),
    /// Browser extensions and policies.
    Browser(BrowserFacts),
    /// Hosts file, proxy and root certificates.
    Tamper(TamperFacts),
    /// Drivers and boot settings.
    Drivers(DriverFacts),
    /// A test-only collector with nothing to report.
    #[cfg(feature = "slow-collector-test")]
    Nothing,
}

/// A collector's facts plus one status per part it checked.
#[derive(Debug, Clone)]
pub struct Output {
    /// The facts.
    pub section: Section,
    /// One entry per part.
    pub checks: Vec<Check>,
}

/// Why a whole collector couldn't run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectError {
    /// Needs Bilby to run as administrator.
    NeedsAdmin,
    /// Doesn't apply here. The reason is a copy key.
    Skipped(String),
    /// Something went wrong. Technical text for the helper view.
    Failed(String),
}

impl From<CollectError> for CheckStatus {
    fn from(e: CollectError) -> Self {
        match e {
            CollectError::NeedsAdmin => Self::NeedsAdmin,
            CollectError::Skipped(why) => Self::Skipped(why),
            CollectError::Failed(why) => Self::Failed(why),
        }
    }
}

impl From<windows::core::Error> for CollectError {
    fn from(e: windows::core::Error) -> Self {
        if e.code() == E_ACCESSDENIED || e.code() == ERROR_ACCESS_DENIED.to_hresult() {
            Self::NeedsAdmin
        } else {
            Self::Failed(e.message())
        }
    }
}

/// What a collector can read: shared folders and file cache, plus the
/// results of the collectors it waits for.
#[derive(Clone)]
pub struct CollectCtx {
    /// Known folders for classifying paths.
    pub folders: Arc<KnownFolders>,
    /// The scan's shared file cache (signatures and hashes).
    pub cache: Arc<FileCache>,
    /// Running programs, for network and tamper. Empty before processes is in.
    pub processes: Arc<Vec<ProcessFact>>,
    /// Connections, for tamper. Empty before network is in.
    pub connections: Arc<Vec<ConnectionFact>>,
    /// The device's management state, for tamper. Default before browser is in.
    pub management: Management,
}

/// One collector: an id, the family its checks belong to, and a run.
pub trait Collector: Send + Sync {
    /// Step id, for example `processes`.
    fn id(&self) -> &'static str;
    /// The family its checks belong to.
    fn family(&self) -> SignalFamily;
    /// Collects. Runs on its own thread with COM initialised.
    fn run(&self, ctx: &CollectCtx) -> Result<Output, CollectError>;
}

fn check(id: &str, family: SignalFamily, status: CheckStatus) -> Check {
    Check {
        id: id.to_owned(),
        family,
        status,
    }
}

fn tagged(family: SignalFamily, checks: Vec<(&'static str, CheckStatus)>) -> Vec<Check> {
    checks
        .into_iter()
        .map(|(id, status)| check(id, family, status))
        .collect()
}

macro_rules! collector {
    ($name:ident, $id:literal, $family:ident, |$ctx:ident| $body:expr) => {
        struct $name;
        impl Collector for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn family(&self) -> SignalFamily {
                SignalFamily::$family
            }
            fn run(&self, $ctx: &CollectCtx) -> Result<Output, CollectError> {
                $body
            }
        }
    };
}

collector!(Protection, "protection", Protection, |_ctx| {
    let c = defender::collect();
    Ok(Output {
        section: Section::Protection(c.facts),
        checks: c.checks,
    })
});

collector!(Processes, "processes", Processes, |ctx| {
    let list = processes::collect(&ctx.folders, &ctx.cache)?;
    Ok(Output {
        section: Section::Processes(list),
        checks: vec![check(
            "processes.running",
            SignalFamily::Processes,
            CheckStatus::Ran,
        )],
    })
});

collector!(Persistence, "persistence", Persistence, |ctx| {
    let c = persistence::collect(&ctx.folders, &ctx.cache);
    Ok(Output {
        section: Section::Persistence(c.facts),
        checks: c.checks,
    })
});

collector!(Network, "network", Network, |ctx| {
    let pids: HashSet<u32> = ctx.processes.iter().map(|p| p.pid).collect();
    let c = network::collect(&pids);
    Ok(Output {
        section: Section::Network(c.facts),
        checks: vec![check(
            "network.connections",
            SignalFamily::Network,
            c.status,
        )],
    })
});

collector!(Browser, "browser", Browser, |ctx| {
    let c = browser::collect(&ctx.folders);
    Ok(Output {
        section: Section::Browser(c.facts),
        checks: vec![check("browser.extensions", SignalFamily::Browser, c.status)],
    })
});

collector!(Tamper, "tamper", Tamper, |ctx| {
    let c = tamper::collect(
        &ctx.folders,
        &ctx.processes,
        &ctx.connections,
        ctx.management.clone(),
    );
    Ok(Output {
        section: Section::Tamper(c.facts),
        checks: tagged(SignalFamily::Tamper, c.checks),
    })
});

collector!(Drivers, "drivers", Drivers, |ctx| {
    let c = drivers::collect(&ctx.folders, &ctx.cache);
    Ok(Output {
        section: Section::Drivers(c.facts),
        checks: tagged(SignalFamily::Drivers, c.checks),
    })
});

// Test only: a collector that hangs for a minute, to prove the timeout.
#[cfg(feature = "slow-collector-test")]
collector!(Slow, "test.slow", Protection, |_ctx| {
    std::thread::sleep(Duration::from_secs(60));
    Ok(Output {
        section: Section::Nothing,
        checks: Vec::new(),
    })
});

/// Step ids in the order the progress screen lists them.
pub const STEPS: &[&str] = &[
    "protection",
    "processes",
    "persistence",
    "network",
    "browser",
    "tamper",
    "drivers",
];

type Done = (&'static str, Result<Output, CollectError>);

/// Starts `c` on its own thread. Its result arrives on `tx`.
fn spawn(c: Arc<dyn Collector>, ctx: CollectCtx, tx: Sender<Done>) {
    let id = c.id();
    let fail = tx.clone();
    let worker = move || {
        defender::init_com();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.run(&ctx)))
            .unwrap_or_else(|_| {
                Err(CollectError::Failed(
                    "collector stopped unexpectedly".to_owned(),
                ))
            });
        // The scan may have stopped waiting; then nobody is listening.
        let _ = tx.send((id, result));
    };
    if let Err(e) = std::thread::Builder::new()
        .name(format!("bilby-{id}"))
        .spawn(worker)
    {
        let _ = fail.send((
            id,
            Err(CollectError::Failed(format!("couldn't start: {e}"))),
        ));
    }
}

/// Why connections weren't checked when the process list is missing.
pub const NO_PROCESSES: &str =
    "running programs couldn't be read, so connections couldn't be matched to them";
/// Why the proxy check is incomplete without processes or connections.
pub const NO_PROXY_OWNER: &str =
    "proxy settings were read, but the program behind a local proxy couldn't be identified";

/// Marks a check that ran without one of its inputs as failed, with why.
fn incomplete(checks: &mut [Check], id: &str, why: &str) {
    for c in checks.iter_mut().filter(|c| c.id == id) {
        if c.status == CheckStatus::Ran {
            c.status = CheckStatus::Failed(why.to_owned());
        }
    }
}

/// The state shown for a finished step.
fn step_state(checks: &[Check]) -> StepState {
    let any = |f: fn(&CheckStatus) -> bool| checks.iter().any(|c| f(&c.status));
    if !checks.is_empty()
        && checks
            .iter()
            .all(|c| matches!(c.status, CheckStatus::Skipped(_)))
    {
        StepState::Skipped
    } else if any(|s| matches!(s, CheckStatus::NeedsAdmin)) {
        StepState::NeedsAdmin
    } else if any(|s| matches!(s, CheckStatus::Failed(_))) {
        StepState::Failed
    } else {
        StepState::Done
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Runs every collector and returns what they found. `progress` is called
/// from this thread as steps start and finish. Never takes longer than
/// `opts.scan_timeout`, plus up to 100 ms, and returns within 100 ms of
/// `opts.cancel` being set.
pub fn collect(opts: &CollectOptions, progress: &dyn Fn(Progress)) -> Collection {
    // Only the slow-collector-test feature adds to the list.
    #[allow(unused_mut)]
    let mut all: Vec<Arc<dyn Collector>> = vec![
        Arc::new(Protection),
        Arc::new(Processes),
        Arc::new(Persistence),
        Arc::new(Network),
        Arc::new(Browser),
        Arc::new(Tamper),
        Arc::new(Drivers),
    ];
    #[cfg(feature = "slow-collector-test")]
    all.push(Arc::new(Slow));
    run_collectors(all, opts, progress)
}

/// [`collect`] with a chosen set of collectors. Network and tamper, if
/// present, wait for the collectors they depend on.
#[allow(clippy::too_many_lines)]
fn run_collectors(
    all: Vec<Arc<dyn Collector>>,
    opts: &CollectOptions,
    progress: &dyn Fn(Progress),
) -> Collection {
    let started_at = OffsetDateTime::now_utc();
    // Set when this scan stops waiting (finished, cancelled or out of
    // time). Collectors still running then stop opening files, so a
    // timed-out collector doesn't keep the disk busy for the next scan.
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let deadline = start + opts.scan_timeout;
    let total = all.len();
    let folders = Arc::new(crate::paths::known_folders());
    let mut ctx = CollectCtx {
        folders,
        cache: Arc::new(FileCache::with_cancel(Arc::clone(&stop))),
        processes: Arc::new(Vec::new()),
        connections: Arc::new(Vec::new()),
        management: Management::default(),
    };
    let (tx, rx) = mpsc::channel::<Done>();
    let mut waiting: HashMap<&'static str, Arc<dyn Collector>> = HashMap::new();
    let mut running: HashMap<&'static str, (Instant, SignalFamily)> = HashMap::new();
    let mut finished: HashSet<&'static str> = HashSet::new();
    let needs = |id: &str| -> &'static [&'static str] {
        match id {
            "network" => &["processes"],
            "tamper" => &["processes", "network", "browser"],
            _ => &[],
        }
    };
    let present: HashSet<&'static str> = all.iter().map(|c| c.id()).collect();
    for c in all {
        waiting.insert(c.id(), c);
    }
    let mut snapshot = SystemSnapshot::default();
    let mut checks = Vec::new();
    let mut timings = Vec::new();
    let mut cancelled = false;
    // Whether the inputs network and tamper depend on actually arrived,
    // not just whether their collectors finished.
    let mut have_processes = false;
    let mut have_connections = false;

    loop {
        // Start everything whose inputs are in.
        let ready: Vec<&'static str> = waiting
            .keys()
            .copied()
            .filter(|id| {
                needs(id)
                    .iter()
                    .all(|n| !present.contains(n) || finished.contains(n))
            })
            .collect();
        for id in ready {
            let c = waiting.remove(id).expect("listed as waiting");
            running.insert(id, (Instant::now(), c.family()));
            progress(Progress {
                step: id,
                state: StepState::Running,
                done: finished.len(),
                total,
            });
            spawn(c, ctx.clone(), tx.clone());
        }
        if running.is_empty() && waiting.is_empty() {
            break;
        }
        if opts.cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }

        // Anything over its limit is given up on.
        let now = Instant::now();
        let late: Vec<&'static str> = running
            .iter()
            .filter(|(_, (began, _))| now >= deadline || now >= *began + opts.collector_timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in late {
            let (began, family) = running.remove(id).expect("listed as running");
            finished.insert(id);
            checks.push(check(
                id,
                family,
                CheckStatus::Failed(TOOK_TOO_LONG.to_owned()),
            ));
            timings.push(Timing {
                step: id.to_owned(),
                millis: millis(began.elapsed()),
            });
            progress(Progress {
                step: id,
                state: StepState::Failed,
                done: finished.len(),
                total,
            });
        }
        // Past the scan deadline, nothing that's still waiting will start.
        if Instant::now() >= deadline {
            for (id, c) in waiting.drain() {
                finished.insert(id);
                checks.push(check(
                    id,
                    c.family(),
                    CheckStatus::Failed(TOOK_TOO_LONG.to_owned()),
                ));
                progress(Progress {
                    step: id,
                    state: StepState::Failed,
                    done: finished.len(),
                    total,
                });
            }
        }
        if running.is_empty() {
            continue;
        }

        let (id, result) = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(done) => done,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => unreachable!("this function holds a sender"),
        };
        // A late result from a collector already given up on is dropped.
        let Some((began, family)) = running.remove(id) else {
            continue;
        };
        finished.insert(id);
        timings.push(Timing {
            step: id.to_owned(),
            millis: millis(began.elapsed()),
        });
        let mut part = match result {
            Ok(out) => {
                match out.section {
                    Section::Protection(f) => snapshot.protection = Some(f),
                    Section::Processes(list) => {
                        have_processes = true;
                        ctx.processes = Arc::new(list.clone());
                        snapshot.processes = Some(list);
                    }
                    Section::Persistence(f) => snapshot.persistence = Some(f),
                    Section::Network(f) => {
                        have_connections = f.is_some();
                        ctx.connections = Arc::new(
                            f.as_ref()
                                .map(|n| n.connections.clone())
                                .unwrap_or_default(),
                        );
                        snapshot.network = f;
                    }
                    Section::Browser(f) => {
                        ctx.management = f.management.clone();
                        snapshot.browser = Some(f);
                    }
                    Section::Tamper(f) => snapshot.tamper = Some(f),
                    Section::Drivers(f) => snapshot.drivers = Some(f),
                    #[cfg(feature = "slow-collector-test")]
                    Section::Nothing => {}
                }
                out.checks
            }
            Err(e) => vec![check(id, family, e.into())],
        };
        // Network keeps only rows owned by known programs, and tamper ties a
        // local proxy to the program listening on it. Without those inputs
        // the checks are incomplete, so say so rather than report Ran. The
        // rest of tamper (hosts, roots) stands on its own.
        let lost_processes = present.contains("processes") && !have_processes;
        let lost_connections = present.contains("network") && !have_connections;
        if id == "network" && lost_processes {
            snapshot.network = None;
            ctx.connections = Arc::new(Vec::new());
            incomplete(&mut part, "network.connections", NO_PROCESSES);
        }
        if id == "tamper" && (lost_processes || lost_connections) {
            incomplete(&mut part, "tamper.proxy", NO_PROXY_OWNER);
        }
        progress(Progress {
            step: id,
            state: step_state(&part),
            done: finished.len(),
            total,
        });
        checks.extend(part);
    }

    stop.store(true, Ordering::Relaxed);
    Collection {
        snapshot,
        checks,
        timings,
        is_admin: processes::current_is_elevated(),
        machine: machine(),
        started_at,
        finished_at: OffsetDateTime::now_utc(),
        cancelled,
    }
}

/// Windows edition, version and architecture from the registry.
pub fn machine() -> MachineSummary {
    let key = Key::open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        KEY_WOW64_64KEY,
    );
    let text = |name: &str| {
        key.as_ref()
            .and_then(|k| k.value(name))
            .and_then(|d| d.text().map(str::to_owned))
    };
    let build = text("CurrentBuildNumber").or_else(|| text("CurrentBuild"));
    let ubr = key.as_ref().and_then(|k| match k.value("UBR") {
        Some(Data::Dword(v)) => Some(v),
        _ => None,
    });
    let mut os_name = text("ProductName").unwrap_or_else(|| "Windows".to_owned());
    // Windows 11 still says "Windows 10" in ProductName. Build 22000 is
    // the first Windows 11 release.
    if build
        .as_deref()
        .and_then(|b| b.parse::<u32>().ok())
        .is_some_and(|b| b >= 22000)
    {
        os_name = os_name.replacen("Windows 10", "Windows 11", 1);
    }
    let os_version = match (text("DisplayVersion"), build, ubr) {
        (Some(v), Some(b), Some(u)) => format!("{v} ({b}.{u})"),
        (Some(v), Some(b), None) => format!("{v} ({b})"),
        (None, Some(b), _) => b,
        (v, None, _) => v.unwrap_or_default(),
    };
    let arch = std::env::var("PROCESSOR_ARCHITEW6432")
        .or_else(|_| std::env::var("PROCESSOR_ARCHITECTURE"))
        .map(|a| match a.to_ascii_uppercase().as_str() {
            "AMD64" => "x64".to_owned(),
            "ARM64" => "arm64".to_owned(),
            "X86" => "x86".to_owned(),
            _ => a.to_ascii_lowercase(),
        })
        .unwrap_or_default();
    MachineSummary {
        os_name,
        os_version,
        arch,
        hostname: None,
        user: None,
    }
}

/// A scrubber for this computer: the profile folder (long and 8.3 short
/// form), the user name and the computer name.
pub fn scrubber(folders: &KnownFolders) -> Scrubber {
    let short = crate::paths::short_path(&folders.profile);
    let user = std::env::var("USERNAME").ok();
    let computer = std::env::var("COMPUTERNAME").ok();
    Scrubber::new(
        &[folders.profile.as_str(), short.as_str()],
        user.as_deref(),
        computer.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    collector!(Quick, "quick", Protection, |_ctx| {
        Ok(Output {
            section: Section::Protection(ProtectionFacts::default()),
            checks: vec![check("quick", SignalFamily::Protection, CheckStatus::Ran)],
        })
    });
    collector!(Hangs, "hangs", Drivers, |_ctx| {
        std::thread::sleep(Duration::from_secs(60));
        Err(CollectError::Failed("unreachable".to_owned()))
    });
    collector!(Denied, "denied", Persistence, |_ctx| Err(
        CollectError::NeedsAdmin
    ));
    collector!(BrokenProcesses, "processes", Processes, |_ctx| Err(
        CollectError::Failed("snapshot failed".to_owned())
    ));
    collector!(FakeNetwork, "network", Network, |_ctx| Ok(Output {
        section: Section::Network(Some(NetworkFacts::default())),
        checks: vec![check(
            "network.connections",
            SignalFamily::Network,
            CheckStatus::Ran
        )],
    }));
    collector!(FakeTamper, "tamper", Tamper, |_ctx| Ok(Output {
        section: Section::Tamper(TamperFacts::default()),
        checks: vec![
            check("tamper.hosts", SignalFamily::Tamper, CheckStatus::Ran),
            check("tamper.proxy", SignalFamily::Tamper, CheckStatus::Ran),
        ],
    }));

    #[test]
    fn checks_that_lost_an_input_say_so() {
        let c = run_collectors(
            vec![
                Arc::new(BrokenProcesses),
                Arc::new(FakeNetwork),
                Arc::new(FakeTamper),
            ],
            &opts(5, 10),
            &|_| {},
        );
        let status = |id: &str| {
            c.checks
                .iter()
                .find(|ch| ch.id == id)
                .map(|ch| ch.status.clone())
        };
        assert_eq!(
            status("network.connections"),
            Some(CheckStatus::Failed(NO_PROCESSES.to_owned()))
        );
        assert_eq!(c.snapshot.network, None);
        assert_eq!(
            status("tamper.proxy"),
            Some(CheckStatus::Failed(NO_PROXY_OWNER.to_owned()))
        );
        // The parts of tamper that don't need other collectors still stand.
        assert_eq!(status("tamper.hosts"), Some(CheckStatus::Ran));
    }

    fn opts(collector: u64, scan: u64) -> CollectOptions {
        CollectOptions {
            collector_timeout: Duration::from_secs(collector),
            scan_timeout: Duration::from_secs(scan),
            ..CollectOptions::default()
        }
    }

    #[test]
    fn a_hung_collector_times_out_and_the_rest_report() {
        let seen = std::sync::Mutex::new(Vec::new());
        let began = Instant::now();
        let c = run_collectors(
            vec![Arc::new(Quick), Arc::new(Hangs), Arc::new(Denied)],
            &opts(2, 10),
            &|p| seen.lock().unwrap().push(p),
        );
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{:?}",
            began.elapsed()
        );
        let status = |id: &str| {
            c.checks
                .iter()
                .find(|ch| ch.id == id)
                .map(|ch| ch.status.clone())
        };
        assert_eq!(
            status("hangs"),
            Some(CheckStatus::Failed(TOOK_TOO_LONG.to_owned()))
        );
        assert_eq!(status("quick"), Some(CheckStatus::Ran));
        assert_eq!(status("denied"), Some(CheckStatus::NeedsAdmin));
        assert!(c.snapshot.protection.is_some());
        assert!(!c.cancelled);
        let seen = seen.lock().unwrap();
        let last = seen.last().unwrap();
        assert_eq!((last.done, last.total), (3, 3));
        assert!(
            seen.iter()
                .any(|p| p.step == "hangs" && p.state == StepState::Failed)
        );
        assert!(
            seen.iter()
                .any(|p| p.step == "denied" && p.state == StepState::NeedsAdmin)
        );
    }

    #[test]
    fn the_whole_scan_has_a_limit() {
        let began = Instant::now();
        let c = run_collectors(vec![Arc::new(Hangs)], &opts(30, 1), &|_| {});
        assert!(began.elapsed() < Duration::from_secs(3));
        assert_eq!(
            c.checks[0].status,
            CheckStatus::Failed(TOOK_TOO_LONG.to_owned())
        );
    }

    #[test]
    fn cancel_returns_quickly() {
        let o = opts(30, 120);
        let cancel = Arc::clone(&o.cancel);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            cancel.store(true, Ordering::Relaxed);
        });
        let began = Instant::now();
        let c = run_collectors(vec![Arc::new(Hangs)], &o, &|_| {});
        assert!(c.cancelled);
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "{:?}",
            began.elapsed()
        );
    }
}
