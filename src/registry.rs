//! npm registry interaction: tarball URLs, package metadata, and version
//! resolution against a semver range.

use crate::download;
use crate::package_json::spec::Range;
use semver::Version;
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

/// A resolved package version: the exact version, the tarball to fetch, and the
/// registry's `dist.integrity` SRI for that tarball (when the packument publishes one).
///
/// `#[non_exhaustive]` so further fields can be added without a breaking change — this
/// type is only ever *constructed* inside the crate; callers receive and read it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Resolved {
    pub name: String,
    pub version: Version,
    pub tarball_url: String,
    /// The registry's Subresource-Integrity hash (`sha512-<base64>`), when the packument
    /// carries one — verified against the downloaded bytes before extraction. `None` for a
    /// synthesized tarball URL or a packument entry without `dist.integrity`.
    pub integrity: Option<String>,
    /// The version's declared license, normalized to a single SPDX-ish string from the
    /// packument's `license` string / legacy `{ "type": … }` object / `licenses[]` array.
    /// `None` when the packument declares none. Carried so a generated lockfile can record
    /// it for license/compliance tooling (npm's own lockfiles do the same).
    pub license: Option<String>,
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
    pub fn packument(&self, name: &str) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        // Scoped names are URL-encoded in the path: `@scope/pkg` → `@scope%2fpkg`.
        let encoded = match name.strip_prefix('@') {
            Some(rest) => format!("@{}", rest.replacen('/', "%2f", 1)),
            None => name.to_string(),
        };
        let url = format!("{}/{}", self.base_url, encoded);
        let bytes = download::fetch(&url)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Resolve the newest published version of `name` matching the `range`.
    pub fn resolve(
        &self,
        name: &str,
        range: &Range,
    ) -> Result<Resolved, Box<dyn std::error::Error + Send + Sync>> {
        let doc = self.packument(name)?;
        let (version, tarball, integrity, license) = select_version(&doc, range)
            .ok_or_else(|| format!("no published version of {name} matches {range}"))?;
        let tarball_url = tarball.unwrap_or_else(|| self.tarball_url(name, &version.to_string()));
        Ok(Resolved {
            name: name.to_string(),
            version,
            tarball_url,
            integrity,
            license,
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
        roots: &[(String, Range)],
    ) -> Result<Vec<Resolved>, Box<dyn std::error::Error + Send + Sync>> {
        self.resolve_tree_from(roots, |name| self.packument(name))
    }

    /// [`resolve_tree`](Self::resolve_tree) with an injectable packument source, so the
    /// graph walk can be unit-tested without the network.
    fn resolve_tree_from<F>(
        &self,
        roots: &[(String, Range)],
        mut get_packument: F,
    ) -> Result<Vec<Resolved>, Box<dyn std::error::Error + Send + Sync>>
    where
        F: FnMut(&str) -> Result<Value, Box<dyn std::error::Error + Send + Sync>>,
    {
        use std::collections::{HashMap, VecDeque};
        let mut packuments: HashMap<String, Value> = HashMap::new();
        let mut resolved: HashMap<String, Resolved> = HashMap::new();
        let mut queue: VecDeque<(String, Range)> = roots.iter().cloned().collect();

        while let Some((name, range)) = queue.pop_front() {
            if let Some(existing) = resolved.get(&name) {
                if range.matches(&existing.version) {
                    continue; // already resolved to a satisfying version — dedup
                }
                return Err(format!(
                    "version conflict for `{name}`: resolved {} but also required `{range}` \
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
            let (version, tarball, integrity, license) = select_version(doc, &range)
                .ok_or_else(|| format!("no published version of {name} matches {range}"))?;
            let deps = dependencies_of(doc, &version);
            let tarball_url =
                tarball.unwrap_or_else(|| self.tarball_url(&name, &version.to_string()));
            for (dep_name, dep_spec) in deps {
                // Transitive deps routinely use npm `||`/space ranges; parse the full grammar.
                let dep_range = Range::parse(&dep_spec).map_err(|e| {
                    format!(
                        "{name}@{version} dependency `{dep_name}`: unsupported version \
                         {dep_spec:?}: {e}"
                    )
                })?;
                queue.push_back((dep_name, dep_range));
            }
            resolved.insert(
                name.clone(),
                Resolved {
                    name,
                    version,
                    tarball_url,
                    integrity,
                    license,
                },
            );
        }
        let mut out: Vec<Resolved> = resolved.into_values().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// The fields [`select_version`] extracts for the newest matching version:
/// `(version, dist.tarball, dist.integrity, license)`.
type SelectedVersion = (Version, Option<String>, Option<String>, Option<String>);

/// Pick the newest version in a packument's `versions` map that satisfies the `range`,
/// returning it with the `dist.tarball` URL, the `dist.integrity` SRI, and the declared
/// `license` the registry advertises (each `None` if absent). Factored out for unit testing
/// without network access.
fn select_version(doc: &Value, range: &Range) -> Option<SelectedVersion> {
    let versions = doc.get("versions")?.as_object()?;
    let mut best: Option<SelectedVersion> = None;
    for (ver_str, meta) in versions {
        let Ok(ver) = Version::parse(ver_str) else {
            continue;
        };
        if !range.matches(&ver) {
            continue;
        }
        if best.as_ref().map(|(b, ..)| ver > *b).unwrap_or(true) {
            let dist = meta.get("dist");
            let string_at = |key: &str| {
                dist.and_then(|d| d.get(key))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            };
            best = Some((
                ver,
                string_at("tarball"),
                string_at("integrity"),
                license_of(meta),
            ));
        }
    }
    best
}

/// Normalize a packument version entry's license to a single SPDX-ish string. npm uses a
/// `license` string today; older packages used a `{ "type": … }` object or a
/// `licenses: [{ "type": … }]` array — collapse all three (joining a multi-entry array with
/// `" OR "`), returning `None` when none is declared.
fn license_of(meta: &Value) -> Option<String> {
    match meta.get("license") {
        Some(Value::String(s)) => return Some(s.clone()),
        Some(Value::Object(o)) => {
            if let Some(t) = o.get("type").and_then(Value::as_str) {
                return Some(t.to_string());
            }
        }
        _ => {}
    }
    let types: Vec<String> = meta
        .get("licenses")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|l| l.get("type").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    (!types.is_empty()).then(|| types.join(" OR "))
}

/// The npm dependency-spec → [`VersionReq`] parser lives in the [`crate::package_json`] module
/// (the package-spec grammar); re-exported here for back-compat as `registry::version_req`.
pub use crate::package_json::spec::version_req;

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
                "3.3.3": {
                    "license": "BSD-3-Clause",
                    "dist": {
                        "tarball": "https://r/lit-3.3.3.tgz",
                        "integrity": "sha512-deadbeef"
                    }
                },
                "4.0.0": { "dist": { "tarball": "https://r/lit-4.0.0.tgz" } },
                "2.9.9": {}
            }
        });
        let (ver, tarball, integrity, license) =
            select_version(&doc, &"^3".parse().unwrap()).unwrap();
        assert_eq!(ver, Version::parse("3.3.3").unwrap());
        assert_eq!(tarball.as_deref(), Some("https://r/lit-3.3.3.tgz"));
        // The registry's dist.integrity rides along so node_modules can verify the tarball.
        assert_eq!(integrity.as_deref(), Some("sha512-deadbeef"));
        // The declared license rides along too, so a generated lockfile can record it.
        assert_eq!(license.as_deref(), Some("BSD-3-Clause"));
    }

    #[test]
    fn select_version_integrity_is_none_when_absent() {
        // A dist with a tarball but no integrity → integrity None. node_modules then refuses
        // to install it unverified (from_lockfile is likewise strict on a missing sha512).
        let doc = json!({ "versions": {
            "1.0.0": { "dist": { "tarball": "https://r/x-1.0.0.tgz" } }
        }});
        let (_, tarball, integrity, _license) =
            select_version(&doc, &"^1".parse().unwrap()).unwrap();
        assert_eq!(tarball.as_deref(), Some("https://r/x-1.0.0.tgz"));
        assert!(integrity.is_none());
    }

    #[test]
    fn select_version_none_when_no_match() {
        let doc = json!({ "versions": { "1.0.0": {}, "2.0.0": {} } });
        assert!(select_version(&doc, &"^5".parse().unwrap()).is_none());
    }

    #[test]
    fn license_of_normalizes_string_object_and_array_forms() {
        // Modern SPDX string (what nearly every package publishes today).
        assert_eq!(
            license_of(&json!({ "license": "MIT" })).as_deref(),
            Some("MIT")
        );
        // Legacy `{ type }` object.
        assert_eq!(
            license_of(&json!({ "license": { "type": "Apache-2.0", "url": "x" } })).as_deref(),
            Some("Apache-2.0")
        );
        // Legacy `licenses: [{ type }]` array → joined with " OR ".
        assert_eq!(
            license_of(&json!({ "licenses": [{ "type": "MIT" }, { "type": "Apache-2.0" }] }))
                .as_deref(),
            Some("MIT OR Apache-2.0")
        );
        // None declared.
        assert_eq!(license_of(&json!({ "dist": {} })), None);
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
                "dist": {
                    "tarball": format!("https://r/{version}.tgz"),
                    "integrity": format!("sha512-{version}"),
                },
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

        // dist.integrity threads through the transitive walk, ready for verification.
        let integrity = |n: &str| {
            resolved
                .iter()
                .find(|r| r.name == n)
                .unwrap()
                .integrity
                .clone()
        };
        assert_eq!(integrity("b").as_deref(), Some("sha512-1.2.0"));
    }

    #[test]
    fn resolve_tree_resolves_a_transitive_or_range() {
        // Regression: a transitive dep with an npm `||` range (e.g. @lit/context →
        // @lit/reactive-element `^1.6.2 || ^2.1.0`) must resolve, not fail to parse the `||`.
        let mut pkgs: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
        pkgs.insert(
            "ctx".into(),
            packument_with("1.1.6", &[("re", "^1.6.2 || ^2.1.0")]),
        );
        pkgs.insert("re".into(), packument_with("2.1.0", &[]));

        let roots = vec![("ctx".to_string(), "^1".parse().unwrap())];
        let resolved = Registry::npm()
            .resolve_tree_from(&roots, |name| {
                pkgs.get(name)
                    .cloned()
                    .ok_or_else(|| format!("no packument for {name}").into())
            })
            .unwrap();

        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["ctx", "re"],
            "the `||`-ranged transitive dep resolved"
        );
        assert_eq!(
            resolved
                .iter()
                .find(|r| r.name == "re")
                .unwrap()
                .version
                .to_string(),
            "2.1.0"
        );
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
