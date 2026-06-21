//! `package-lock.json` (lockfileVersion 2 or 3) parsing, per
//! <https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json>.
//!
//! [`Lockfile::parse`] reads the flat `packages` map into faithful [`LockedPackage`] data.
//! [`render_v3`] is the inverse: it emits a `lockfileVersion`-3 document for a flat resolved set
//! (what `cargo npm-utils add`/`upgrade` write). Both are pure — they touch no filesystem and
//! resolve no paths: a caller turns a [`LockedPackage::key`] into an install path itself, so this
//! parser stays pure and the path-safety check lives with the installer. lockfileVersion 1 (the
//! legacy hierarchical `dependencies` tree, with no `packages` map) is unsupported.

use std::path::Path;

use serde_json::{Map, Value};

use super::{manifest, spec};
use crate::registry::Registry;

/// A parsed `package-lock.json`.
#[derive(Debug, Clone)]
pub struct Lockfile {
    /// The `lockfileVersion` (always ≥ 2 here).
    pub version: u64,
    /// Every entry of the `packages` map, sorted by key — so install order, and thus
    /// `.bin` name-collision resolution, is deterministic. Includes the root `""` entry.
    pub packages: Vec<LockedPackage>,
}

/// One entry of the `packages` map.
#[derive(Debug, Clone)]
pub struct LockedPackage {
    /// The map key: `""` for the root project, else a `node_modules/…`-relative path.
    pub key: String,
    /// The package name — the segment after the last `node_modules/` (empty for the root).
    pub name: String,
    /// `version` from the entry (empty for the root or a pure link).
    pub version: String,
    /// `resolved` — the registry URL, git source, or `file:` path; `None` if absent.
    pub resolved: Option<String>,
    /// `integrity` — the Subresource-Integrity string (`sha512-…`); `None` if absent.
    pub integrity: Option<String>,
    /// `license` — the package's declared SPDX license string, when the lockfile records one
    /// (npm writes it per package; so does this crate's [`render_v3`]). `None` if absent.
    /// Read so SBOM/compliance output ([`crate::sbom`]) can carry it.
    pub license: Option<String>,
    /// `dev` — strictly in the devDependencies tree.
    pub dev: bool,
    /// `optional` — strictly in the optionalDependencies tree.
    pub optional: bool,
    /// `devOptional` — both a dev and an optional dependency.
    pub dev_optional: bool,
    /// `link: true` — a symlink to a local path; nothing is fetched.
    pub link: bool,
    /// `os` constraints (npm spelling — `darwin`, `linux`, `win32`; `!`-negation allowed).
    pub os: Vec<String>,
    /// `cpu` constraints (npm spelling — `x64`, `arm64`, `ia32`; `!`-negation allowed).
    pub cpu: Vec<String>,
    /// `bin` as `(name, path-within-package)` pairs.
    pub bin: Vec<(String, String)>,
}

impl Lockfile {
    /// Parse a `package-lock.json` document (lockfileVersion 2 or 3).
    pub fn parse(s: &str) -> Result<Lockfile, Box<dyn std::error::Error>> {
        let json: Value = serde_json::from_str(s)?;
        let version = json
            .get("lockfileVersion")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if version < 2 {
            return Err(format!(
                "package-lock.json lockfileVersion {version} is unsupported \
                 (need 2 or 3, which carry the `packages` map)"
            )
            .into());
        }
        let packages = json
            .get("packages")
            .and_then(Value::as_object)
            .ok_or("package-lock.json has no `packages` map")?;
        let mut out: Vec<LockedPackage> = packages
            .iter()
            .filter_map(|(key, entry)| {
                entry
                    .as_object()
                    .map(|entry| LockedPackage::from_entry(key, entry))
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(Lockfile {
            version,
            packages: out,
        })
    }

    /// The entries an npm-tarball installer fetches on the given host: real (non-root)
    /// `node_modules/…` packages that aren't links and whose `os`/`cpu` match. `host_os` and
    /// `host_arch` are Rust's `std::env::consts::{OS, ARCH}` spellings. Whether each entry's
    /// `resolved` is actually an http(s) registry tarball is left to the caller — see
    /// [`LockedPackage::is_registry_tarball`].
    pub fn installable(&self, host_os: &str, host_arch: &str) -> Vec<&LockedPackage> {
        self.packages
            .iter()
            .filter(|p| p.key.starts_with("node_modules/") && !p.link)
            .filter(|p| p.matches_platform(host_os, host_arch))
            .collect()
    }
}

/// A resolved package to record in a generated lockfile — the write-side input mirroring a parsed
/// [`LockedPackage`], kept to the flat-tree fields [`render_v3`] emits.
#[derive(Debug, Clone)]
pub struct LockEntry {
    /// Package name (the `node_modules/<name>` key segment).
    pub name: String,
    /// Exact resolved version.
    pub version: String,
    /// The registry tarball URL — the entry's `resolved`.
    pub resolved: String,
    /// The `sha512-…` Subresource-Integrity, when the registry advertised one.
    pub integrity: Option<String>,
    /// The package's declared SPDX license, recorded for license/compliance tooling
    /// (npm's own lockfiles carry it too).
    pub license: Option<String>,
}

/// Render a `lockfileVersion`-3 `package-lock.json` for a **flat** dependency tree: a root `""`
/// entry (the project `name`/`version` and its direct dependency ranges) plus one
/// `node_modules/<name>` entry per resolved package. Keys are emitted in npm's order
/// (`name`, `version`, `lockfileVersion`, `requires`, `packages`) thanks to `serde_json`'s
/// `preserve_order`.
///
/// Scope (documented, intentional): this is an **npm-compatible v3 lock for the registry/prod
/// tree** that round-trips through [`Lockfile::parse`] and installs via
/// [`crate::install::from_lockfile`] — it is *not* a byte-for-byte npm reproduction. The flat set
/// from [`crate::registry::Registry::resolve_tree`] carries no dev/optional classification, so no
/// `dev`/`optional` flags are emitted, and `peerDependencies`/`bundleDependencies` and per-package
/// `dependencies` back-references are omitted.
pub fn render_v3(
    root_name: &str,
    root_version: &str,
    direct: &[(String, String)],
    entries: &[LockEntry],
) -> String {
    use serde_json::json;

    let mut packages = Map::new();

    // The root project entry, keyed "".
    let mut root = Map::new();
    root.insert("name".into(), json!(root_name));
    root.insert("version".into(), json!(root_version));
    if !direct.is_empty() {
        let mut deps = Map::new();
        for (name, range) in direct {
            deps.insert(name.clone(), json!(range));
        }
        root.insert("dependencies".into(), Value::Object(deps));
    }
    packages.insert(String::new(), Value::Object(root));

    // One node_modules/<name> entry per resolved package, in the order given (resolve_tree
    // returns them sorted by name).
    for entry in entries {
        let mut pkg = Map::new();
        pkg.insert("version".into(), json!(entry.version));
        pkg.insert("resolved".into(), json!(entry.resolved));
        if let Some(integrity) = &entry.integrity {
            pkg.insert("integrity".into(), json!(integrity));
        }
        if let Some(license) = &entry.license {
            pkg.insert("license".into(), json!(license));
        }
        packages.insert(format!("node_modules/{}", entry.name), Value::Object(pkg));
    }

    let doc = json!({
        "name": root_name,
        "version": root_version,
        "lockfileVersion": 3,
        "requires": true,
        "packages": Value::Object(packages),
    });
    let mut out = serde_json::to_string_pretty(&doc).expect("serialize package-lock.json");
    out.push('\n');
    out
}

/// Resolve a `package.json`-shaped manifest's **registry** dependencies into a flat tree and
/// render it as a `lockfileVersion`-3 `package-lock.json` string (with per-package `license`).
/// Talks to `registry` over the network but touches no filesystem and installs no
/// `node_modules/` — the lockfile-only half of `add`/`upgrade`. Non-registry deps (git /
/// `file:`) are skipped: recorded in the manifest, but not resolvable to a registry tarball.
pub fn render_v3_from_manifest(
    doc: &Value,
    registry: &Registry,
) -> Result<String, Box<dyn std::error::Error>> {
    let direct = manifest::dependencies(doc);
    let roots: Vec<(String, spec::Range)> = direct
        .iter()
        .filter(|(_, range)| spec::Spec::parse(range).is_registry())
        .map(
            |(name, range)| -> Result<(String, spec::Range), Box<dyn std::error::Error>> {
                Ok((name.clone(), spec::Range::parse(range)?))
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    let entries: Vec<LockEntry> = registry
        .resolve_tree(&roots)?
        .into_iter()
        .map(|r| LockEntry {
            name: r.name,
            version: r.version.to_string(),
            resolved: r.tarball_url,
            integrity: r.integrity,
            license: r.license,
        })
        .collect();

    let name = doc.get("name").and_then(Value::as_str).unwrap_or("");
    let version = doc
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("0.0.0");
    Ok(render_v3(name, version, &direct, &entries))
}

/// Read a `package.json`-shaped manifest and (re)write its `package-lock.json` from the
/// registry — pure Rust, no Node, no npm, no `node_modules/`. This is the "update the
/// lockfile" primitive for build scripts and vendoring flows (where the lock is a manifest of
/// resolved versions + licenses, not an install); [`render_v3_from_manifest`] is the in-memory
/// core. Resolves against the public npm registry.
pub fn write_from_manifest(
    manifest_path: &Path,
    lockfile_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
    let doc: Value = serde_json::from_str(&text)
        .map_err(|e| format!("parsing {}: {e}", manifest_path.display()))?;
    let lockfile = render_v3_from_manifest(&doc, &Registry::npm())?;
    std::fs::write(lockfile_path, lockfile)
        .map_err(|e| format!("writing {}: {e}", lockfile_path.display()))?;
    Ok(())
}

impl LockedPackage {
    fn from_entry(key: &str, entry: &Map<String, Value>) -> LockedPackage {
        let name = key
            .rsplit_once("node_modules/")
            .map(|(_, n)| n)
            .unwrap_or(key)
            .to_string();
        LockedPackage {
            bin: bin_entries(entry, &name),
            key: key.to_string(),
            name,
            version: string_field(entry, "version"),
            resolved: opt_string(entry, "resolved"),
            integrity: opt_string(entry, "integrity"),
            license: opt_string(entry, "license"),
            dev: bool_field(entry, "dev"),
            optional: bool_field(entry, "optional"),
            dev_optional: bool_field(entry, "devOptional"),
            link: bool_field(entry, "link"),
            os: string_list(entry, "os"),
            cpu: string_list(entry, "cpu"),
        }
    }

    /// Whether `resolved` is an http(s) registry tarball — the only source `npm-utils` fetches.
    pub fn is_registry_tarball(&self) -> bool {
        self.resolved
            .as_deref()
            .is_some_and(|r| r.starts_with("https://") || r.starts_with("http://"))
    }

    /// Whether the host satisfies this entry's `os`/`cpu`. `host_os`/`host_arch` are Rust's
    /// `std::env::consts::{OS, ARCH}`; they are mapped to npm's spelling before comparing.
    pub fn matches_platform(&self, host_os: &str, host_arch: &str) -> bool {
        constraint_allows(&self.os, node_os(host_os))
            && constraint_allows(&self.cpu, node_cpu(host_arch))
    }
}

/// npm `os`/`cpu` matching: a positive list must include `host`; a `!`-prefixed value excludes
/// it; an empty constraint allows everything.
pub fn constraint_allows(constraint: &[String], host: &str) -> bool {
    let mut has_positive = false;
    let mut matched_positive = false;
    for item in constraint {
        if let Some(excluded) = item.strip_prefix('!') {
            if excluded == host {
                return false;
            }
        } else {
            has_positive = true;
            if item == host {
                matched_positive = true;
            }
        }
    }
    !has_positive || matched_positive
}

const OS_MAP: &[(&str, &str)] = &[("macos", "darwin"), ("windows", "win32")];
const CPU_MAP: &[(&str, &str)] = &[("x86_64", "x64"), ("aarch64", "arm64"), ("x86", "ia32")];

/// Map a Rust `std::env::consts::OS` value to npm's `os` spelling (`linux` is shared).
fn node_os(rust: &str) -> &str {
    map_value(rust, OS_MAP)
}

/// Map a Rust `std::env::consts::ARCH` value to npm's `cpu` spelling.
fn node_cpu(rust: &str) -> &str {
    map_value(rust, CPU_MAP)
}

fn map_value<'a>(rust: &'a str, map: &[(&'static str, &'static str)]) -> &'a str {
    map.iter()
        .find(|(r, _)| *r == rust)
        .map(|(_, n)| *n)
        .unwrap_or(rust)
}

fn string_field(entry: &Map<String, Value>, key: &str) -> String {
    entry
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn opt_string(entry: &Map<String, Value>, key: &str) -> Option<String> {
    entry.get(key).and_then(Value::as_str).map(str::to_string)
}

fn bool_field(entry: &Map<String, Value>, key: &str) -> bool {
    entry.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn string_list(entry: &Map<String, Value>, key: &str) -> Vec<String> {
    entry
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The `(bin-name, path-in-package)` pairs an entry exposes. npm allows either an object
/// (`{"foo": "cli.js"}`) or a bare string (the bin takes the package's unscoped name).
fn bin_entries(entry: &Map<String, Value>, name: &str) -> Vec<(String, String)> {
    match entry.get("bin") {
        Some(Value::String(path)) => {
            let bin_name = name.rsplit('/').next().unwrap_or(name).to_string();
            vec![(bin_name, path.clone())]
        }
        Some(Value::Object(map)) => map
            .iter()
            .filter_map(|(n, v)| v.as_str().map(|p| (n.clone(), p.to_string())))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A lockfileVersion-3 fixture exercising the field variety: a runtime dep, a scoped dep,
    // a dev dep with a `bin` map, an off-platform optional native dep, and a `file:` link.
    const SAMPLE_LOCK: &str = r#"{
      "name": "harness",
      "lockfileVersion": 3,
      "packages": {
        "": { "name": "harness", "devDependencies": { "typescript": "^5" } },
        "node_modules/@scope/pkg": {
          "version": "1.2.3",
          "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz",
          "integrity": "sha512-BBBB"
        },
        "node_modules/typescript": {
          "version": "5.9.3",
          "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz",
          "integrity": "sha512-AAAA",
          "dev": true,
          "bin": { "tsc": "bin/tsc", "tsserver": "bin/tsserver" }
        },
        "node_modules/fsevents": {
          "version": "2.3.2",
          "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.2.tgz",
          "integrity": "sha512-CCCC",
          "dev": true,
          "optional": true,
          "os": ["darwin"]
        },
        "node_modules/local-link": { "resolved": "file:../local", "link": true }
      }
    }"#;

    fn names(packages: &[&LockedPackage]) -> Vec<String> {
        packages.iter().map(|p| p.name.clone()).collect()
    }

    #[test]
    fn parses_fields_and_selects_installable_per_host() {
        let lock = Lockfile::parse(SAMPLE_LOCK).unwrap();
        assert_eq!(lock.version, 3);

        // On linux/x86_64: the scoped dep + typescript. The darwin-only optional is skipped;
        // the root "" and the `file:` link are never installable.
        assert_eq!(
            names(&lock.installable("linux", "x86_64")),
            ["@scope/pkg", "typescript"]
        );
        // On macos/aarch64 the darwin-only fsevents joins (sorted by key).
        assert_eq!(
            names(&lock.installable("macos", "aarch64")),
            ["@scope/pkg", "fsevents", "typescript"]
        );

        // Fields parsed: dev flag, integrity, the full bin map.
        let ts = lock
            .packages
            .iter()
            .find(|p| p.name == "typescript")
            .unwrap();
        assert!(ts.dev);
        assert_eq!(ts.integrity.as_deref(), Some("sha512-AAAA"));
        assert!(ts.bin.iter().any(|(n, p)| n == "tsc" && p == "bin/tsc"));
        assert!(ts.bin.iter().any(|(n, _)| n == "tsserver"));
        // The link entry is parsed (faithful) but excluded from installable.
        assert!(lock.packages.iter().any(|p| p.link));
    }

    #[test]
    fn distinguishes_registry_tarballs_from_other_sources() {
        let lock = Lockfile::parse(SAMPLE_LOCK).unwrap();
        let ts = lock
            .packages
            .iter()
            .find(|p| p.name == "typescript")
            .unwrap();
        assert!(
            ts.is_registry_tarball(),
            "https resolved is a registry tarball"
        );
        let link = lock.packages.iter().find(|p| p.link).unwrap();
        assert!(!link.is_registry_tarball(), "a file: link is not");
    }

    #[test]
    fn rejects_lockfile_version_1() {
        // v1 has no `packages` map — the hierarchical `dependencies` tree is unsupported.
        assert!(Lockfile::parse(r#"{"lockfileVersion":1,"dependencies":{}}"#).is_err());
    }

    #[test]
    fn constraint_allows_follows_npm_os_cpu_rules() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(constraint_allows(&[], "linux"), "no constraint allows all");
        assert!(constraint_allows(&v(&["linux"]), "linux"));
        assert!(!constraint_allows(&v(&["darwin"]), "linux"));
        assert!(constraint_allows(&v(&["darwin", "linux"]), "linux"));
        assert!(constraint_allows(&v(&["!win32"]), "linux"));
        assert!(!constraint_allows(&v(&["!linux"]), "linux"));
    }

    #[test]
    fn matches_platform_maps_rust_host_to_npm_spelling() {
        let lock = Lockfile::parse(SAMPLE_LOCK).unwrap();
        let fsevents = lock.packages.iter().find(|p| p.name == "fsevents").unwrap();
        // os:["darwin"] — excluded on a linux host, allowed on macos (rust "macos" → "darwin").
        assert!(!fsevents.matches_platform("linux", "x86_64"));
        assert!(fsevents.matches_platform("macos", "aarch64"));
    }

    #[test]
    fn render_v3_emits_npm_order_and_round_trips_through_parse() {
        let entries = vec![
            LockEntry {
                name: "ms".into(),
                version: "2.1.3".into(),
                resolved: "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz".into(),
                integrity: Some("sha512-MS".into()),
                license: Some("MIT".into()),
            },
            LockEntry {
                name: "@scope/pkg".into(),
                version: "1.0.0".into(),
                resolved: "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz".into(),
                integrity: Some("sha512-SP".into()),
                license: None,
            },
        ];
        let direct = vec![("ms".to_string(), "^2".to_string())];
        let json = render_v3("fixture", "1.0.0", &direct, &entries);

        // Top-level keys come out in npm's order (preserve_order), not alphabetized.
        let doc: Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = doc
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["name", "version", "lockfileVersion", "requires", "packages"]
        );
        // The root "" entry records the direct dependency ranges from package.json.
        assert_eq!(doc["packages"][""]["dependencies"]["ms"], "^2");

        // A declared license is emitted per package; omitted when None.
        assert_eq!(doc["packages"]["node_modules/ms"]["license"], "MIT");
        assert!(doc["packages"]["node_modules/@scope/pkg"]
            .get("license")
            .is_none());

        // It parses back as a v3 lock; the two registry entries are installable (root "" and
        // any link excluded), sorted by key, with integrity + resolved threaded through.
        let lock = Lockfile::parse(&json).unwrap();
        assert_eq!(lock.version, 3);
        let names: Vec<&str> = lock
            .installable("linux", "x86_64")
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, ["@scope/pkg", "ms"]);
        let ms = lock.packages.iter().find(|p| p.name == "ms").unwrap();
        assert_eq!(ms.integrity.as_deref(), Some("sha512-MS"));
        assert!(
            ms.is_registry_tarball(),
            "resolved is an https registry tarball"
        );
    }
}
