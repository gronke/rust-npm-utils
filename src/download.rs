//! HTTP download helpers.

use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;
use ureq::tls::{RootCerts, TlsConfig};

/// HTTP timeouts for downloads; `None` disables a bound.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// Cap on establishing the connection.
    pub connect: Option<Duration>,
    /// Cap on a single request, connect through transfer — applied per fetch, not across the run
    /// (ureq's per-call `timeout_global`).
    pub global: Option<Duration>,
}

impl Default for Timeouts {
    /// 30 s to connect, 120 s per request — enough for a large tarball on a slow link, while a
    /// stalled peer can't hang the build.
    fn default() -> Self {
        Self {
            connect: Some(Duration::from_secs(30)),
            global: Some(Duration::from_secs(120)),
        }
    }
}

impl Timeouts {
    /// Build from the CLI flags: `--no-timeout` removes every bound; `--timeout <secs>` sets the
    /// per-request timeout (connect stays at the default); neither keeps the default.
    pub fn from_cli(timeout_secs: Option<u64>, no_timeout: bool) -> Timeouts {
        if no_timeout {
            Timeouts {
                connect: None,
                global: None,
            }
        } else if let Some(secs) = timeout_secs {
            Timeouts {
                global: Some(Duration::from_secs(secs)),
                ..Timeouts::default()
            }
        } else {
            Timeouts::default()
        }
    }
}

static TIMEOUTS: OnceLock<Timeouts> = OnceLock::new();

/// Override the process-wide download timeouts. Intended to be called once at startup (the CLI
/// derives them from `--timeout` / `--no-timeout`); the library default applies if never set, and a
/// later call is ignored.
pub fn set_timeouts(timeouts: Timeouts) {
    let _ = TIMEOUTS.set(timeouts);
}

fn timeouts() -> Timeouts {
    TIMEOUTS.get().copied().unwrap_or_default()
}

/// The shared HTTP agent — platform-verifier TLS plus the process-wide download timeouts. Used by
/// every request helper here ([`fetch_with_accept`], [`post_json`]) so they share one TLS/timeout
/// policy and honour `--timeout` / `--no-timeout`.
fn agent() -> ureq::Agent {
    let t = timeouts();
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .timeout_connect(t.connect)
            .timeout_global(t.global)
            .build(),
    )
}

/// Download an `https://` URL into memory (100 MB cap), retrying once on transient failure.
///
/// Only `https` is fetched: a non-https URL is refused up front. The tarball URL is advertised
/// by the registry, so this keeps a hostile or redirecting registry from steering us at a
/// plain-http or internal endpoint (the downloaded bytes are sha512-verified regardless — this
/// is defense-in-depth). Per-request connect and transfer timeouts are set so a stalled peer
/// can't hang the build; the 100 MB cap bounds size, the timeouts bound time.
///
/// Some hosts (GitHub in particular) occasionally drop a connection
/// mid-transfer — observed as `io: Peer disconnected` on CI — and the same URL
/// has not been seen to fail twice in a row, so one retry after a short pause is
/// enough.
pub fn fetch(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    fetch_with_accept(url, None)
}

/// Like [`fetch`], but sends an `Accept` header — used to request the npm registry's abbreviated
/// packument (`application/vnd.npm.install-v1+json`), which is far smaller than the full document.
pub fn fetch_with_accept(
    url: &str,
    accept: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if !url.starts_with("https://") {
        return Err(format!(
            "refusing to fetch non-https URL {url:?}: npm-utils downloads over https only"
        )
        .into());
    }
    let agent = agent();

    let attempts = 2;
    for attempt in 1..=attempts {
        match try_fetch(&agent, url, accept) {
            Ok(body) => return Ok(body),
            Err(e) if attempt < attempts => {
                eprintln!(
                    "npm-utils: download attempt {attempt}/{attempts} failed for {url}: {e}; \
                     retrying in 500ms"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

fn try_fetch(
    agent: &ureq::Agent,
    url: &str,
    accept: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let request = match accept {
        Some(accept) => agent.get(url).header("Accept", accept),
        None => agent.get(url),
    };
    let mut response = request.call()?;
    let body = response.body_mut();
    Ok(body.with_config().limit(100 * 1024 * 1024).read_to_vec()?)
}

/// POST `body` to an `https://` URL and return the parsed JSON response, or `None` on **any**
/// failure — a non-https URL, a network error, a non-2xx status, or an unparseable body.
///
/// The single-attempt, error-swallowing contract is deliberate: the audit advisory sources read
/// `None` as "no advisories", so an unreachable endpoint, a 410 (npm's retired legacy paths), or a
/// flaky link degrades to an empty result instead of failing the run — matching `npm audit` /
/// `pnpm audit`, which exit 0 when the advisory endpoint can't be reached.
///
/// `content_encoding` sets the `Content-Encoding` header (`Some("gzip")` when `body` is
/// gzip-compressed, as npm's bulk-advisory endpoint requires); `accept` overrides the `Accept`
/// header (default `application/json`). `Content-Type` is always `application/json`.
pub fn post_json(
    url: &str,
    body: &[u8],
    content_encoding: Option<&str>,
    accept: Option<&str>,
) -> Option<Value> {
    if !url.starts_with("https://") {
        return None;
    }
    let request = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", accept.unwrap_or("application/json"));
    let request = match content_encoding {
        Some(enc) => request.header("Content-Encoding", enc),
        None => request,
    };
    let mut response = request.send(body).ok()?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(100 * 1024 * 1024)
        .read_to_vec()
        .ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

/// URL for a GitHub repository archive (zip) at a ref (branch, tag, or commit).
pub fn github_archive_url(owner: &str, repo: &str, git_ref: &str) -> String {
    format!("https://github.com/{owner}/{repo}/archive/{git_ref}.zip")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_refuses_non_https() {
        // The scheme guard rejects before any network request, so this is offline.
        for url in [
            "http://registry.npmjs.org/x",
            "file:///etc/passwd",
            "ftp://example.com/x",
            "registry.npmjs.org/x",
        ] {
            assert!(fetch(url).is_err(), "{url:?} must be refused");
        }
    }

    #[test]
    fn post_json_refuses_non_https() {
        // The scheme guard rejects before any network request, so this is offline.
        for url in [
            "http://api.example.com/x",
            "ftp://example.com/x",
            "api.example.com/x",
        ] {
            assert!(
                post_json(url, b"{}", None, None).is_none(),
                "{url:?} must be refused"
            );
        }
    }

    #[test]
    fn timeouts_from_cli_flags() {
        let d = Timeouts::default();
        // Neither flag → the library default.
        let unset = Timeouts::from_cli(None, false);
        assert_eq!((unset.connect, unset.global), (d.connect, d.global));
        // --timeout sets the per-request timeout, keeping the default connect.
        let t = Timeouts::from_cli(Some(5), false);
        assert_eq!(t.global, Some(Duration::from_secs(5)));
        assert_eq!(t.connect, d.connect);
        // --no-timeout removes every bound and wins over --timeout.
        let off = Timeouts::from_cli(Some(5), true);
        assert_eq!((off.connect, off.global), (None, None));
    }
}
