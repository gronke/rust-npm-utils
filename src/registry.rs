//! npm registry interaction: tarball URLs, package metadata, and version
//! resolution against a semver range.

use crate::download;
use semver::{Version, VersionReq};
use serde_json::Value;

/// An npm-compatible registry. Defaults to the public registry.
pub struct Registry {
    pub base_url: String,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            base_url: "https://registry.npmjs.org".to_string(),
        }
    }
}

/// A resolved package version: the exact version plus the tarball to fetch.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub name: String,
    pub version: Version,
    pub tarball_url: String,
}

impl Registry {
    /// The public npm registry (`https://registry.npmjs.org`).
    pub fn npm() -> Self {
        Self::default()
    }

    /// A registry at a custom base URL (e.g. a private mirror).
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// Conventional tarball URL for an exact `version`. Handles scoped names:
    /// `@scope/pkg` → `<base>/@scope/pkg/-/pkg-<version>.tgz`.
    pub fn tarball_url(&self, name: &str, version: &str) -> String {
        let unscoped = name.rsplit('/').next().unwrap_or(name);
        format!("{}/{}/-/{}-{}.tgz", self.base_url, name, unscoped, version)
    }

    /// Fetch the package metadata document ("packument").
    pub fn packument(&self, name: &str) -> Result<Value, Box<dyn std::error::Error>> {
        // Scoped names are URL-encoded in the path: `@scope/pkg` → `@scope%2fpkg`.
        let encoded = match name.strip_prefix('@') {
            Some(rest) => format!("@{}", rest.replacen('/', "%2f", 1)),
            None => name.to_string(),
        };
        let url = format!("{}/{}", self.base_url, encoded);
        let bytes = download::fetch(&url)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Resolve the newest published version of `name` matching `req`.
    pub fn resolve(
        &self,
        name: &str,
        req: &VersionReq,
    ) -> Result<Resolved, Box<dyn std::error::Error>> {
        let doc = self.packument(name)?;
        let (version, tarball) = select_version(&doc, req)
            .ok_or_else(|| format!("no published version of {name} matches {req}"))?;
        let tarball_url = tarball.unwrap_or_else(|| self.tarball_url(name, &version.to_string()));
        Ok(Resolved {
            name: name.to_string(),
            version,
            tarball_url,
        })
    }
}

/// Pick the newest version in a packument's `versions` map that satisfies `req`,
/// returning it with the `dist.tarball` URL the registry advertises (if any).
/// Factored out for unit testing without network access.
fn select_version(doc: &Value, req: &VersionReq) -> Option<(Version, Option<String>)> {
    let versions = doc.get("versions")?.as_object()?;
    let mut best: Option<(Version, Option<String>)> = None;
    for (ver_str, meta) in versions {
        let Ok(ver) = Version::parse(ver_str) else {
            continue;
        };
        if !req.matches(&ver) {
            continue;
        }
        if best.as_ref().map(|(b, _)| ver > *b).unwrap_or(true) {
            let tarball = meta
                .get("dist")
                .and_then(|d| d.get("tarball"))
                .and_then(|t| t.as_str())
                .map(str::to_string);
            best = Some((ver, tarball));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tarball_url_handles_scoped_and_unscoped() {
        let reg = Registry::npm();
        assert_eq!(
            reg.tarball_url("lit", "3.3.3"),
            "https://registry.npmjs.org/lit/-/lit-3.3.3.tgz"
        );
        assert_eq!(
            reg.tarball_url("@lit/context", "1.1.6"),
            "https://registry.npmjs.org/@lit/context/-/context-1.1.6.tgz"
        );
    }

    #[test]
    fn select_version_picks_newest_matching() {
        let doc = json!({
            "versions": {
                "3.1.0": { "dist": { "tarball": "https://r/lit-3.1.0.tgz" } },
                "3.3.3": { "dist": { "tarball": "https://r/lit-3.3.3.tgz" } },
                "4.0.0": { "dist": { "tarball": "https://r/lit-4.0.0.tgz" } },
                "2.9.9": {}
            }
        });
        let (ver, tarball) = select_version(&doc, &"^3".parse().unwrap()).unwrap();
        assert_eq!(ver, Version::parse("3.3.3").unwrap());
        assert_eq!(tarball.as_deref(), Some("https://r/lit-3.3.3.tgz"));
    }

    #[test]
    fn select_version_none_when_no_match() {
        let doc = json!({ "versions": { "1.0.0": {}, "2.0.0": {} } });
        assert!(select_version(&doc, &"^5".parse().unwrap()).is_none());
    }
}
