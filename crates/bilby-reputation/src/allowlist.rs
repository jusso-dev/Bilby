//! The only hosts Bilby ever talks to, and the HTTP client that enforces it.
//!
//! Every request goes through [`Http`]: HTTPS only, hosts on [`ALLOWED`]
//! only, no redirects followed (a redirect anywhere, even to an allowed
//! host, is treated as a failure), no proxy taken from the environment,
//! a 10 second timeout, and a `Bilby/<version>` User-Agent with nothing
//! machine-specific. TLS is rustls with Mozilla's roots (webpki-roots).

use std::time::Duration;

/// Hosts Bilby may connect to. Nothing else, ever.
pub const ALLOWED: &[&str] = &["hashlookup.circl.lu", "www.virustotal.com"];

/// Per-request timeout.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The User-Agent: the app and version only.
pub fn user_agent() -> String {
    format!("Bilby/{}", env!("CARGO_PKG_VERSION"))
}

/// The host of an `https://` URL, if it's on the allowlist.
pub fn allowed_host(url: &str) -> Option<&'static str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    // No user info, no port, no IP literals: just the exact host.
    if host.contains(['@', ':', '[']) {
        return None;
    }
    ALLOWED
        .iter()
        .copied()
        .find(|a| a.eq_ignore_ascii_case(host))
}

/// One HTTP response: status and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status code.
    pub status: u16,
    /// Response body, at most 1 MiB.
    pub body: String,
}

/// Why a request didn't produce a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// The URL isn't HTTPS to an allowed host. Never sent.
    NotAllowed(String),
    /// Network, TLS, timeout or redirect.
    Failed(String),
}

/// Something that can send a GET. The real one is [`Http`]; tests use
/// recorded responses.
pub trait Transport: Send + Sync {
    /// GET `url` with these extra headers.
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Reply, HttpError>;
}

/// The real HTTP client. Only built when the user switched a service on.
pub struct Http {
    agent: ureq::Agent,
}

impl Http {
    /// Builds the client.
    ///
    /// # Panics
    ///
    /// With the `no-network-guard` feature, if `online_on` is false: a scan
    /// with every switch off must never get this far.
    pub fn new(online_on: bool) -> Self {
        assert!(
            !cfg!(feature = "no-network-guard") || online_on,
            "HTTP client built while every online check is switched off"
        );
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(true)
            .http_status_as_error(false)
            .proxy(None)
            .timeout_global(Some(TIMEOUT))
            .user_agent(user_agent())
            .build()
            .new_agent();
        Self { agent }
    }
}

impl Transport for Http {
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Reply, HttpError> {
        if allowed_host(url).is_none() {
            return Err(HttpError::NotAllowed(url.to_owned()));
        }
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut resp = req.call().map_err(|e| HttpError::Failed(e.to_string()))?;
        let status = resp.status().as_u16();
        // 3xx can't come back as a reply with redirects off and erroring,
        // but refuse one anyway rather than trust it.
        if (300..400).contains(&status) {
            return Err(HttpError::Failed(format!("redirect ({status}) refused")));
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_to_string()
            .map_err(|e| HttpError::Failed(e.to_string()))?;
        Ok(Reply { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_to_allowed_hosts() {
        assert_eq!(
            allowed_host("https://hashlookup.circl.lu/lookup/sha256/ab"),
            Some("hashlookup.circl.lu")
        );
        assert_eq!(
            allowed_host("https://www.virustotal.com/api/v3/files/ab"),
            Some("www.virustotal.com")
        );
        for bad in [
            "http://hashlookup.circl.lu/lookup/sha256/ab",
            "https://virustotal.com/api/v3/files/ab",
            "https://www.virustotal.com.evil.test/api",
            "https://evil.test/?u=https://www.virustotal.com/",
            "https://www.virustotal.com:8443/api",
            "https://user@www.virustotal.com/api",
            "https://[::1]/",
        ] {
            assert_eq!(allowed_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn user_agent_has_nothing_machine_specific() {
        let ua = user_agent();
        assert!(ua.starts_with("Bilby/"));
        assert!(!ua.contains(' '));
    }

    #[test]
    fn refuses_a_url_off_the_list_without_sending() {
        let http = Http::new(true);
        assert!(matches!(
            http.get("https://example.com/", &[]),
            Err(HttpError::NotAllowed(_))
        ));
    }
}

#[cfg(all(test, feature = "no-network-guard"))]
mod guard_tests {
    use super::Http;

    #[test]
    #[should_panic(expected = "every online check is switched off")]
    fn guard_panics_when_everything_is_off() {
        let _ = Http::new(false);
    }

    #[test]
    fn guard_allows_a_client_when_a_switch_is_on() {
        let _ = Http::new(true);
    }
}
