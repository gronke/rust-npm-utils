//! HTTP download helpers.

use std::time::Duration;
use ureq::tls::TlsConfig;

/// Download a URL into memory (100 MB cap), retrying once on transient failure.
///
/// Some hosts (GitHub in particular) occasionally drop a connection
/// mid-transfer — observed as `io: Peer disconnected` on CI — and the same URL
/// has not been seen to fail twice in a row, so one retry after a short pause is
/// enough.
pub fn fetch(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .tls_config(TlsConfig::builder().build())
            .build(),
    );

    let attempts = 2;
    for attempt in 1..=attempts {
        match try_fetch(&agent, url) {
            Ok(body) => return Ok(body),
            Err(e) if attempt < attempts => {
                eprintln!(
                    "rust-npm-utils: download attempt {attempt}/{attempts} failed for {url}: {e}; \
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
