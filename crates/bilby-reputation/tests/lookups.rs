//! Lookups with recorded responses. No live network calls.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use bilby_core::settings::OnlineChecks;
use bilby_reputation::allowlist::{HttpError, Reply, Transport, allowed_host};
use bilby_reputation::key::ApiKey;
use bilby_reputation::{Cache, Limits, RateLimiter, check};

const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const NOTEPAD: &str = "da5807bb0997cc6b6e9d8a3f8a2cf7d1e4b5ad80aaaf8f22b0d0d9a3c3a7f0b1";
const UNKNOWN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn recorded(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/responses")
            .join(name),
    )
    .expect("recorded response")
}

/// One request: URL and headers.
type Sent = (String, Vec<(String, String)>);

/// Replays recorded replies and records every request it's asked to send.
#[derive(Default)]
struct Recorded {
    replies: HashMap<String, Reply>,
    sent: Mutex<Vec<Sent>>,
}

impl Recorded {
    fn with(mut self, url: String, status: u16, file: &str) -> Self {
        self.replies.insert(
            url,
            Reply {
                status,
                body: recorded(file),
            },
        );
        self
    }
    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
}

impl Transport for Recorded {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Reply, HttpError> {
        assert!(
            allowed_host(url).is_some(),
            "request to a host off the list: {url}"
        );
        self.sent.lock().unwrap().push((
            url.to_owned(),
            headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        ));
        self.replies
            .get(url)
            .cloned()
            .ok_or_else(|| HttpError::Failed("no recorded reply".to_owned()))
    }
}

fn no_sleep(_: Duration) {}

fn hashes() -> Vec<String> {
    vec![EICAR.to_owned(), NOTEPAD.to_owned(), UNKNOWN.to_owned()]
}

#[test]
fn everything_off_sends_nothing() {
    let http = Recorded::default();
    let out = check(
        OnlineChecks::default(),
        &hashes(),
        ApiKey::new("k").as_ref(),
        &http,
        &Cache::default(),
        Limits::default(),
        &no_sleep,
    );
    assert!(out.is_none());
    assert_eq!(http.sent().len(), 0);
}

#[test]
fn circl_marks_known_software() {
    let http = Recorded::default()
        .with(bilby_reputation::circl::url(NOTEPAD), 200, "circl_hit.json")
        .with(
            bilby_reputation::circl::url(UNKNOWN),
            404,
            "circl_not_found.json",
        )
        .with(
            bilby_reputation::circl::url(EICAR),
            404,
            "circl_not_found.json",
        );
    let (facts, summary) = check(
        OnlineChecks {
            circl: true,
            virustotal: false,
        },
        &hashes(),
        None,
        &http,
        &Cache::default(),
        Limits::default(),
        &no_sleep,
    )
    .unwrap();
    assert_eq!(facts.known_good, vec![NOTEPAD.to_owned()]);
    assert_eq!(facts.virustotal.len(), 0);
    assert_eq!(summary.circl_sent, 3);
    // Only the hash is in the request: the URL path and an accept header.
    for (url, headers) in http.sent() {
        assert!(url.starts_with("https://hashlookup.circl.lu/lookup/sha256/"));
        assert_eq!(
            headers,
            vec![("accept".to_owned(), "application/json".to_owned())]
        );
    }
}

#[test]
fn virustotal_reads_stats_and_404() {
    let http = Recorded::default()
        .with(
            bilby_reputation::virustotal::url(EICAR),
            200,
            "vt_malicious.json",
        )
        .with(
            bilby_reputation::virustotal::url(NOTEPAD),
            404,
            "vt_not_found.json",
        )
        .with(
            bilby_reputation::virustotal::url(UNKNOWN),
            404,
            "vt_not_found.json",
        );
    let key = ApiKey::new("user-key").unwrap();
    let (facts, summary) = check(
        OnlineChecks {
            circl: false,
            virustotal: true,
        },
        &hashes(),
        Some(&key),
        &http,
        &Cache::default(),
        Limits::default(),
        &no_sleep,
    )
    .unwrap();
    assert_eq!(facts.virustotal.len(), 1);
    let r = &facts.virustotal[0];
    assert_eq!(
        (r.sha256.as_str(), r.malicious, r.undetected),
        (EICAR, 62, 8)
    );
    assert_eq!(
        r.analysed.map(time::OffsetDateTime::unix_timestamp),
        Some(1_762_560_000)
    );
    assert_eq!(summary.vt_sent, 3);
    assert_eq!(summary.errors.len(), 0);
    for (_, headers) in http.sent() {
        assert_eq!(
            headers,
            vec![("x-apikey".to_owned(), "user-key".to_owned())]
        );
    }
}

#[test]
fn quota_stops_virustotal_without_failing_the_scan() {
    let http = Recorded::default().with(
        bilby_reputation::virustotal::url(EICAR),
        429,
        "vt_quota.json",
    );
    let key = ApiKey::new("user-key").unwrap();
    let (facts, summary) = check(
        OnlineChecks {
            circl: false,
            virustotal: true,
        },
        &hashes(),
        Some(&key),
        &http,
        &Cache::default(),
        Limits::default(),
        &no_sleep,
    )
    .unwrap();
    assert_eq!(facts.virustotal.len(), 0);
    assert_eq!(summary.vt_sent, 1, "stops asking after a quota error");
    assert_eq!(summary.errors.len(), 1);
    assert!(
        !summary.errors[0].contains("user-key"),
        "errors never hold the key"
    );
}

#[test]
fn virustotal_without_a_key_sends_nothing() {
    let http = Recorded::default();
    let (_, summary) = check(
        OnlineChecks {
            circl: false,
            virustotal: true,
        },
        &hashes(),
        None,
        &http,
        &Cache::default(),
        Limits::default(),
        &no_sleep,
    )
    .unwrap();
    assert_eq!(http.sent().len(), 0);
    assert_eq!(summary.errors, vec!["VirusTotal: no key saved".to_owned()]);
}

#[test]
fn caps_cache_and_bad_hashes() {
    let http = Recorded::default()
        .with(
            bilby_reputation::circl::url(EICAR),
            404,
            "circl_not_found.json",
        )
        .with(bilby_reputation::circl::url(NOTEPAD), 200, "circl_hit.json");
    let cache = Cache::default();
    let limits = Limits {
        circl_max: 2,
        ..Limits::default()
    };
    let mut input = hashes();
    input.insert(0, "../../etc/passwd".to_owned());
    input.insert(0, "C:\\Users\\alex\\a.exe".to_owned());
    let on = OnlineChecks {
        circl: true,
        virustotal: false,
    };
    let (_, first) = check(on, &input, None, &http, &cache, limits, &no_sleep).unwrap();
    assert_eq!(first.circl_sent, 2, "cap applies; paths are never sent");
    let (facts, second) = check(on, &input, None, &http, &cache, limits, &no_sleep).unwrap();
    assert_eq!(
        second.circl_sent, 0,
        "second scan in the session uses the cache"
    );
    assert_eq!(facts.known_good, vec![NOTEPAD.to_owned()]);
    assert!(
        http.sent()
            .iter()
            .all(|(u, _)| !u.contains("passwd") && !u.contains("Users"))
    );
}

#[test]
fn rate_limiter_spaces_virustotal_calls() {
    use std::cell::Cell;
    use std::time::Instant;
    let start = Instant::now();
    let offset = Cell::new(Duration::ZERO);
    let slept = Cell::new(Duration::ZERO);
    let mut rl = RateLimiter::new(4);
    for _ in 0..9 {
        rl.wait(
            || start + offset.get(),
            |d| {
                offset.set(offset.get() + d);
                slept.set(slept.get() + d);
            },
        );
    }
    // Nine calls at four a minute: two full waits of 60 seconds.
    assert_eq!(slept.get(), Duration::from_secs(120));
}
