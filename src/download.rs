//! HTTP download helpers.

use std::time::Duration;
use ureq::tls::TlsConfig;

/// Download an `https://` URL into memory (100 MB cap), retrying once on transient failure.
///
/// Only `https` is fetched: a non-https URL is refused up front. The tarball URL is advertised
/// by the registry, so this keeps a hostile or redirecting registry from steering us at a
/// plain-http or internal endpoint (the downloaded bytes are sha512-verified regardless — this
/// is defense-in-depth). Connect and overall timeouts are set so a stalled peer can't hang the
/// build; the 100 MB cap bounds size, the timeouts bound time.
///
/// Some hosts (GitHub in particular) occasionally drop a connection
/// mid-transfer — observed as `io: Peer disconnected` on CI — and the same URL
/// has not been seen to fail twice in a row, so one retry after a short pause is
/// enough.
pub fn fetch(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !url.starts_with("https://") {
        return Err(format!(
            "refusing to fetch non-https URL {url:?}: npm-utils downloads over https only"
        )
        .into());
    }
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .tls_config(TlsConfig::builder().build())
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_global(Some(Duration::from_secs(120)))
            .build(),
    );

    let attempts = 2;
    for attempt in 1..=attempts {
        match try_fetch(&agent, url) {
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

fn try_fetch(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut response = agent.get(url).call()?;
    let body = response.body_mut();
    Ok(body.with_config().limit(100 * 1024 * 1024).read_to_vec()?)
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
}
