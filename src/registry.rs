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

    /// Resolve the transitive dependency graph of `roots` into a **flat** set — one
    /// version per package name (the npm v3+ `node_modules` layout). Each package's
    /// `dependencies` are read straight from the registry metadata (no tarball
    /// extraction), every child resolved to its newest matching version, and the set
    /// de-duplicated by name. Cyclic graphs terminate (a name is resolved once).
    /// Returns the packages sorted by name.
    ///
    /// MVP limitation: a single version per package name. Two *incompatible*
    /// requirements on the same package — a genuine conflict npm would resolve by
    /// nesting — is reported as an error rather than silently mis-resolved.
    pub fn resolve_tree(
        &self,
        roots: &[(String, VersionReq)],
    ) -> Result<Vec<Resolved>, Box<dyn std::error::Error>> {
        self.resolve_tree_from(roots, |name| self.packument(name))
    }

    /// [`resolve_tree`](Self::resolve_tree) with an injectable packument source, so the
    /// graph walk can be unit-tested without the network.
    fn resolve_tree_from<F>(
        &self,
        roots: &[(String, VersionReq)],
        mut get_packument: F,
    ) -> Result<Vec<Resolved>, Box<dyn std::error::Error>>
    where
        F: FnMut(&str) -> Result<Value, Box<dyn std::error::Error>>,
    {
        use std::collections::{HashMap, VecDeque};
        let mut packuments: HashMap<String, Value> = HashMap::new();
        let mut resolved: HashMap<String, Resolved> = HashMap::new();
        let mut queue: VecDeque<(String, VersionReq)> = roots.iter().cloned().collect();

        while let Some((name, req)) = queue.pop_front() {
            if let Some(existing) = resolved.get(&name) {
                if req.matches(&existing.version) {
                    continue; // already resolved to a satisfying version — dedup
                }
                return Err(format!(
                    "version conflict for `{name}`: resolved {} but also required `{req}` \
                     (flat node_modules install resolves one version per package)",
                    existing.version
                )
                .into());
            }
            if !packuments.contains_key(&name) {
                let doc = get_packument(&name)?;
                packuments.insert(name.clone(), doc);
            }
            let doc = &packuments[&name];
            let (version, tarball) = select_version(doc, &req)
                .ok_or_else(|| format!("no published version of {name} matches {req}"))?;
            let deps = dependencies_of(doc, &version);
            let tarball_url =
                tarball.unwrap_or_else(|| self.tarball_url(&name, &version.to_string()));
            for (dep_name, dep_spec) in deps {
                let dep_req = version_req(&dep_spec).map_err(|e| {
                    format!(
                        "{name}@{version} dependency `{dep_name}`: unsupported version \
                         {dep_spec:?}: {e}"
                    )
                })?;
                queue.push_back((dep_name, dep_req));
            }
            resolved.insert(
                name.clone(),
                Resolved {
                    name,
                    version,
                    tarball_url,
                },
            );
        }
        let mut out: Vec<Resolved> = resolved.into_values().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
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

/// Convert an npm dependency spec into a semver [`VersionReq`], npm-faithfully: a bare
/// full version (`"1.2.3"`) is an **exact** pin (`=1.2.3`); `"*"`, empty, `"x"` and
/// `"latest"` mean any; range syntax (`^`, `~`, `>=`, …) parses as written.
pub fn version_req(spec: &str) -> Result<VersionReq, semver::Error> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" || spec == "x" || spec == "latest" {
        return Ok(VersionReq::STAR);
    }
    if Version::parse(spec).is_ok() {
        return VersionReq::parse(&format!("={spec}"));
    }
    VersionReq::parse(spec)
}

/// The `dependencies` of a specific version, read from a packument, as `(name, spec)`
/// pairs. The full packument carries each version's `dependencies` inline, so the
/// transitive walk discovers children without extracting any tarball.
fn dependencies_of(doc: &Value, version: &Version) -> Vec<(String, String)> {
    doc.get("versions")
        .and_then(|v| v.get(version.to_string()))
        .and_then(|meta| meta.get("dependencies"))
        .and_then(|d| d.as_object())
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
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

    #[test]
    fn version_req_pins_bare_versions_and_parses_ranges() {
        assert_eq!(version_req("1.2.3").unwrap(), "=1.2.3".parse().unwrap());
        assert_eq!(version_req("^3.0.0").unwrap(), "^3.0.0".parse().unwrap());
        assert_eq!(version_req("*").unwrap(), VersionReq::STAR);
        assert_eq!(version_req("").unwrap(), VersionReq::STAR);
        // A bare version matches ONLY itself — npm's exact-pin semantics.
        let exact = version_req("1.2.3").unwrap();
        assert!(exact.matches(&Version::parse("1.2.3").unwrap()));
        assert!(!exact.matches(&Version::parse("1.2.4").unwrap()));
    }

    /// A one-version packument carrying a `dependencies` map, mirroring the registry's
    /// shape, so the graph walk can be exercised without the network.
    fn packument_with(version: &str, deps: &[(&str, &str)]) -> Value {
        let dep_map: serde_json::Map<String, Value> = deps
            .iter()
            .map(|(n, s)| (n.to_string(), json!(*s)))
            .collect();
        let mut versions = serde_json::Map::new();
        versions.insert(
            version.to_string(),
            json!({
                "dist": { "tarball": format!("https://r/{version}.tgz") },
                "dependencies": Value::Object(dep_map),
            }),
        );
        json!({ "versions": Value::Object(versions) })
    }

    #[test]
    fn resolve_tree_walks_transitively_dedups_and_handles_cycles() {
        // a@1 → {b ^1, c ^1}; b@1 → {c ^1} (shared); c@1 → {a ^1} (cycle back to root).
        let mut pkgs: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
        pkgs.insert(
            "a".into(),
            packument_with("1.0.0", &[("b", "^1"), ("c", "^1")]),
        );
        pkgs.insert("b".into(), packument_with("1.2.0", &[("c", "^1")]));
        pkgs.insert("c".into(), packument_with("1.5.0", &[("a", "^1")]));

        let roots = vec![("a".to_string(), "^1".parse().unwrap())];
        let resolved = Registry::npm()
            .resolve_tree_from(&roots, |name| {
                pkgs.get(name)
                    .cloned()
                    .ok_or_else(|| format!("no packument for {name}").into())
            })
            .unwrap();

        // Each of a, b, c resolved exactly once (cycle + shared dep deduped), sorted by name.
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
        let ver = |n: &str| {
            resolved
                .iter()
                .find(|r| r.name == n)
                .unwrap()
                .version
                .to_string()
        };
        assert_eq!(ver("b"), "1.2.0");
        assert_eq!(ver("c"), "1.5.0");
    }

    #[test]
    fn resolve_tree_errors_on_version_conflict() {
        // root requires x ^1; root also requires y, and y requires x ^2 → incompatible.
        let mut pkgs: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
        pkgs.insert(
            "x".into(),
            json!({ "versions": {
                "1.0.0": { "dist": { "tarball": "https://r/x1.tgz" } },
                "2.0.0": { "dist": { "tarball": "https://r/x2.tgz" } }
            }}),
        );
        pkgs.insert("y".into(), packument_with("1.0.0", &[("x", "^2")]));

        let roots = vec![
            ("x".to_string(), "^1".parse().unwrap()),
            ("y".to_string(), "^1".parse().unwrap()),
        ];
        let err = Registry::npm()
            .resolve_tree_from(&roots, |name| {
                pkgs.get(name)
                    .cloned()
                    .ok_or_else(|| format!("no packument for {name}").into())
            })
            .unwrap_err();
        assert!(err.to_string().contains("version conflict"), "got: {err}");
    }
}
