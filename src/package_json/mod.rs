//! Pure-Rust npm manifest + lockfile schemas, modeled on the npm specs:
//!
//! - <https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json>
//! - <https://docs.npmjs.com/cli/v8/using-npm/package-spec>
//!
//! A module of `npm-utils` (`npm_utils::package_json`). It parses, resolves, and renders —
//! manifests and lockfiles as pure `Value`/string transforms — but never writes files, hits the
//! network, or resolves untrusted paths, which keeps its strict spec-conformance tests pure and
//! self-contained (the CLI does the file IO).
//!
//! Four pieces:
//!
//! - this module root: `package.json` — its `dependencies` specs and a browser-favoring
//!   conditional-`exports` resolver (enough of Node's algorithm to build an ES-module
//!   import map).
//! - [`spec`] — the npm "package spec" dependency grammar ([`spec::Spec`]) and
//!   [`spec::version_req`].
//! - [`lock`] — `package-lock.json` (v2/v3) parsing into a faithful [`lock::Lockfile`], and
//!   [`lock::render_v3`] for emitting one.
//! - [`manifest`] — pure write-side `package.json` transforms (scaffold / upsert a dependency)
//!   for the CLI's `init`/`add`.

pub mod lock;
pub mod manifest;
pub mod spec;

use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Normalize a `license` declaration to a single SPDX-ish string. Handles npm's modern `license`
/// string, the legacy `{ "type": … }` object, and the legacy `licenses: [{ "type": … }]` array
/// (joined with `" OR "`); `None` when none is declared. Shared by the registry (reading a
/// packument) and the [`License`] readers (a manifest or a lockfile entry).
pub(crate) fn normalize_license(value: &Value) -> Option<String> {
    match value.get("license") {
        Some(Value::String(s)) => return Some(s.clone()),
        Some(Value::Object(o)) => {
            if let Some(t) = o.get("type").and_then(Value::as_str) {
                return Some(t.to_string());
            }
        }
        _ => {}
    }
    let types: Vec<String> = value
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

/// Programmatic access to a declared license, from either a parsed `package.json`
/// ([`PackageJson`]) or a parsed lockfile entry ([`lock::LockedPackage`]). Lets a consumer source
/// a package's license from whichever it has — the lockfile when it records one, the manifest
/// otherwise.
pub trait License {
    /// The declared SPDX-ish license string, if any.
    fn license(&self) -> Option<String>;
}

/// A dependency parsed from a `package.json` `dependencies` map.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    /// True when the spec points at a git/GitHub source rather than a registry
    /// version (e.g. `github:owner/repo#ref`).
    pub is_git: bool,
}

/// Parse the `dependencies` section of a `package.json`.
pub fn parse_dependencies(
    package_json_path: &Path,
) -> Result<HashMap<String, Dependency>, Box<dyn std::error::Error + Send + Sync>> {
    let content = fs::read_to_string(package_json_path)?;
    let json: Value = serde_json::from_str(&content)?;

    let deps = json
        .get("dependencies")
        .and_then(|d| d.as_object())
        .ok_or("no dependencies section found in package.json")?;

    let mut dependencies = HashMap::new();
    for (name, value) in deps {
        if let Some(version_str) = value.as_str() {
            let is_git = version_str.contains("github.com") || version_str.starts_with("git");
            let version = extract_version(version_str);
            validate_package_name(name)?;
            validate_version(&version)?;
            dependencies.insert(
                name.clone(),
                Dependency {
                    name: name.clone(),
                    version,
                    is_git,
                },
            );
        }
    }

    Ok(dependencies)
}

/// Reject npm package names whose characters could escape a path or URL — a path-safety allowlist,
/// not a spec validator. Allowed: ASCII alphanumerics plus `.`, `_`, `-`, `@`, and `/` (scoped);
/// empty, over-long, and any `..` are rejected. Case is intentionally *not* restricted: npm steers
/// new packages to lowercase, but the registry still hosts legacy mixed-case names, and a truly
/// invalid name simply 404s — enforcing case here would only reject valid installs. Anything
/// outside the allowlist is a typo or a crafted entry meant to traverse a path later — fail loudly.
fn validate_package_name(name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if name.is_empty() || name.len() > 200 {
        return Err(format!("package name {name:?} has invalid length").into());
    }
    if name.contains("..") {
        return Err(format!("package name {name:?} contains '..'").into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@' | b'/'))
    {
        return Err(format!("package name {name:?} contains disallowed characters").into());
    }
    Ok(())
}

/// Reject versions outside the semver-adjacent alphabet, before the value ends
/// up in a URL, a cache filename, or a marker — none of which should contain a
/// path separator.
fn validate_version(version: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if version.is_empty() || version.len() > 100 {
        return Err(format!("version {version:?} has invalid length").into());
    }
    if version.contains("..") {
        return Err(format!("version {version:?} contains '..'").into());
    }
    if !version
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(format!("version {version:?} contains disallowed characters").into());
    }
    Ok(())
}

/// Extract a bare version from a spec string. Handles `"1.2.3"`, `"^1.2.3"`,
/// `"~1.2.3"`, and git URLs (`"...#ref"` → `ref`).
fn extract_version(value: &str) -> String {
    if value.contains("github.com") || value.starts_with("git") {
        if let Some(hash_pos) = value.rfind('#') {
            return value[hash_pos + 1..].to_string();
        }
    }
    value
        .trim_start_matches('^')
        .trim_start_matches('~')
        .to_string()
}

/// The `"type"` field of a `package.json` (Node defaults to CommonJS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageType {
    Module,
    CommonJs,
}

/// An import-map-worthy entry derived from a package's `package.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// The bare specifier (`name`) → a target relative path (the `.` export).
    Bare(String),
    /// A concrete subpath (`name/<subpath>`) → a target relative path.
    Subpath { subpath: String, target: String },
    /// A subpath *pattern* (`"./…/*"` export). `subpath` is the prefix before `*`
    /// (e.g. `"helpers/"` or `""`), `dir` the target directory before `*` (e.g.
    /// `"dist/"`).
    Prefix { subpath: String, dir: String },
}

/// Browser-favoring conditional-`exports` resolver over a parsed `package.json`.
///
/// Resolves the bare entry and subpaths to relative file paths using the
/// condition order browsers want — `browser` → `module` → `import` → `default`
/// (never `node`/`require`) — with a `module` → `browser` → `main` fallback when
/// there is no `exports` field. Enough of the Node resolution algorithm to
/// generate an ES-module import map; not a general-purpose resolver.
#[derive(Debug, Clone)]
pub struct PackageJson {
    raw: Value,
}

impl License for PackageJson {
    /// The manifest's declared license (`license` string, or the legacy object / `licenses[]` array).
    fn license(&self) -> Option<String> {
        normalize_license(&self.raw)
    }
}

/// Conditions tried, in order, for a browser ES-module import map.
const BROWSER_CONDITIONS: &[&str] = &["browser", "module", "import", "default"];

impl PackageJson {
    /// Read and parse a `package.json` from disk.
    pub fn from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::from_json(&fs::read_to_string(path)?)
    }

    /// Parse a `package.json` from a JSON string (e.g. read out of a tarball).
    pub fn from_json(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self::from_value(serde_json::from_str(s)?))
    }

    /// Wrap an already-parsed JSON document.
    pub fn from_value(raw: Value) -> Self {
        Self { raw }
    }

    /// The `"name"` field, if present.
    pub fn name(&self) -> Option<&str> {
        self.raw.get("name").and_then(Value::as_str)
    }

    /// The `"version"` field, if present.
    pub fn version(&self) -> Option<&str> {
        self.raw.get("version").and_then(Value::as_str)
    }

    /// `Module` when `"type": "module"`, else `CommonJs` (Node's default).
    pub fn package_type(&self) -> PackageType {
        match self.raw.get("type").and_then(Value::as_str) {
            Some("module") => PackageType::Module,
            _ => PackageType::CommonJs,
        }
    }

    /// Resolve the bare entry (the `.` export) to a relative path, for the browser.
    pub fn resolve_main(&self) -> Option<String> {
        if let Some(exports) = self.raw.get("exports") {
            if let Some(s) = exports.as_str() {
                return safe_target(s);
            }
            if let Some(obj) = exports.as_object() {
                return if is_subpath_map(obj) {
                    obj.get(".")
                        .and_then(select_condition)
                        .and_then(|s| safe_target(&s))
                } else {
                    select_condition(exports).and_then(|s| safe_target(&s))
                };
            }
        }
        // No usable `exports`: fall back to module → browser → main.
        if let Some(s) = self.raw.get("module").and_then(Value::as_str) {
            return safe_target(s);
        }
        if let Some(browser) = self.raw.get("browser") {
            if let Some(s) = browser.as_str() {
                return safe_target(s);
            }
            if let (Some(map), Some(main)) = (
                browser.as_object(),
                self.raw.get("main").and_then(Value::as_str),
            ) {
                let main = safe_target(main)?;
                for (key, value) in map {
                    if safe_target(key).as_deref() == Some(main.as_str()) {
                        if let Some(s) = value.as_str() {
                            return safe_target(s);
                        }
                    }
                }
            }
        }
        self.raw
            .get("main")
            .and_then(Value::as_str)
            .and_then(safe_target)
    }

    /// Resolve a subpath (e.g. `"./helpers/decorate"`; leading `./` optional) via
    /// the `exports` map — exact key first, then the longest `"./…/*"` pattern.
    pub fn resolve_subpath(&self, subpath: &str) -> Option<String> {
        let key = normalize_subpath_key(subpath);
        let exports = self.raw.get("exports")?.as_object()?;
        if !is_subpath_map(exports) {
            return None;
        }
        if let Some(value) = exports.get(&key) {
            return select_condition(value).and_then(|s| safe_target(&s));
        }
        let mut best_len = 0usize;
        let mut best: Option<String> = None;
        for (pattern, value) in exports {
            let Some(star) = pattern.find('*') else {
                continue;
            };
            let (prefix, suffix) = (&pattern[..star], &pattern[star + 1..]);
            if key.len() >= prefix.len() + suffix.len()
                && key.starts_with(prefix)
                && key.ends_with(suffix)
            {
                let matched = &key[prefix.len()..key.len() - suffix.len()];
                if let Some(target) = select_condition(value) {
                    if let Some(resolved) = safe_target(&target.replace('*', matched)) {
                        if best.is_none() || prefix.len() > best_len {
                            best_len = prefix.len();
                            best = Some(resolved);
                        }
                    }
                }
            }
        }
        best
    }

    /// Enumerate the import-map-worthy entries: the bare entry, concrete subpaths,
    /// and `"./*"`-pattern prefixes.
    pub fn entries(&self) -> Vec<Entry> {
        let mut entries = Vec::new();
        match self.raw.get("exports") {
            Some(Value::Object(obj)) if is_subpath_map(obj) => {
                for (key, value) in obj {
                    if key == "." {
                        if let Some(t) = select_condition(value).and_then(|s| safe_target(&s)) {
                            entries.push(Entry::Bare(t));
                        }
                    } else if let Some(sub) = key.strip_prefix("./") {
                        if let Some(star) = sub.find('*') {
                            if let Some(dir) = select_condition(value).and_then(|t| target_dir(&t))
                            {
                                entries.push(Entry::Prefix {
                                    subpath: sub[..star].to_string(),
                                    dir,
                                });
                            }
                        } else if let Some(t) =
                            select_condition(value).and_then(|s| safe_target(&s))
                        {
                            entries.push(Entry::Subpath {
                                subpath: sub.to_string(),
                                target: t,
                            });
                        }
                    }
                }
            }
            // exports as a string or a pure conditions object, or no exports:
            // only the bare entry (via resolve_main's logic + fallbacks).
            _ => {
                if let Some(t) = self.resolve_main() {
                    entries.push(Entry::Bare(t));
                }
            }
        }
        entries
    }

    /// Every relative path the resolution references (concrete targets + pattern
    /// directories) — used to keep the right files when vendoring, even under `src/`.
    pub fn referenced_paths(&self) -> Vec<String> {
        self.entries()
            .into_iter()
            .map(|e| match e {
                Entry::Bare(t) | Entry::Subpath { target: t, .. } => t,
                Entry::Prefix { dir, .. } => dir,
            })
            .collect()
    }
}

/// Whether an `exports` object is a subpath map (keys like `"."`, `"./x"`) rather
/// than a bare conditions map (keys like `"import"`, `"default"`).
fn is_subpath_map(obj: &serde_json::Map<String, Value>) -> bool {
    obj.keys().any(|k| k.starts_with('.'))
}

/// Pick the first target matching the browser condition order, recursing into
/// nested condition objects and `exports` arrays (ordered fallbacks).
fn select_condition(node: &Value) -> Option<String> {
    match node {
        Value::String(s) => Some(s.clone()),
        Value::Array(arr) => arr.iter().find_map(select_condition),
        Value::Object(map) => BROWSER_CONDITIONS
            .iter()
            .find_map(|cond| map.get(*cond).and_then(select_condition)),
        _ => None,
    }
}

/// Normalize a target: strip a leading `./`, reject `..`/empty (path traversal).
fn safe_target(s: &str) -> Option<String> {
    let t = s.strip_prefix("./").unwrap_or(s).trim_start_matches('/');
    if t.is_empty() || t.split('/').any(|seg| seg == "..") {
        return None;
    }
    Some(t.to_string())
}

/// `"./helpers/foo"` / `"helpers/foo"` → the canonical `"./helpers/foo"` key.
fn normalize_subpath_key(subpath: &str) -> String {
    if subpath.starts_with("./") {
        subpath.to_string()
    } else {
        format!("./{}", subpath.trim_start_matches('/'))
    }
}

/// The directory portion of a pattern target before `*` (e.g. `"./dist/*.js"` →
/// `"dist/"`, `"./*.js"` → `""`). `None` if it would escape.
fn target_dir(target: &str) -> Option<String> {
    let star = target.find('*')?;
    let before = target[..star].strip_prefix("./").unwrap_or(&target[..star]);
    if before.split('/').any(|seg| seg == "..") {
        return None;
    }
    Some(before.trim_start_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_pinned_caret_and_git_specs() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("package.json");
        fs::write(
            &p,
            r#"{ "dependencies": {
                "lit": "3.3.3",
                "bootstrap": "^5.3.8",
                "forked": "github:owner/repo#abc123"
            } }"#,
        )
        .unwrap();

        let deps = parse_dependencies(&p).unwrap();
        assert_eq!(deps["lit"].version, "3.3.3");
        assert!(!deps["lit"].is_git);
        assert_eq!(deps["bootstrap"].version, "5.3.8");
        assert_eq!(deps["forked"].version, "abc123");
        assert!(deps["forked"].is_git);
    }

    #[test]
    fn resolve_main_from_exports_and_fallbacks() {
        // exports."." with conditions -> default.
        let a = PackageJson::from_json(
            r#"{"exports":{".":{"types":"./dev.d.ts","default":"./index.js"},"./decorators.js":{"default":"./decorators.js"}}}"#,
        )
        .unwrap();
        assert_eq!(a.resolve_main().as_deref(), Some("index.js"));
        assert_eq!(
            a.resolve_subpath("./decorators.js").as_deref(),
            Some("decorators.js")
        );

        // nested browser condition map under ".".
        let b = PackageJson::from_json(
            r#"{"type":"module","exports":{".":{"browser":{"development":"./development/lit-html.js","default":"./lit-html.js"},"default":"./lit-html.js"}}}"#,
        )
        .unwrap();
        assert_eq!(b.resolve_main().as_deref(), Some("lit-html.js"));

        // no exports -> module wins over main.
        let c = PackageJson::from_json(
            r#"{"main":"dist/js/bootstrap.js","module":"dist/js/bootstrap.esm.js"}"#,
        )
        .unwrap();
        assert_eq!(
            c.resolve_main().as_deref(),
            Some("dist/js/bootstrap.esm.js")
        );
    }

    #[test]
    fn resolve_subpath_picks_import_condition_for_cjs_package() {
        // CommonJS package, no ".", helper subpaths whose "import" condition is the
        // ESM build under src/helpers/esm/.
        let rt = PackageJson::from_json(
            r#"{"type":"commonjs","exports":{"./helpers/decorate":[{"node":"./src/helpers/decorate.js","import":"./src/helpers/esm/decorate.js","default":"./src/helpers/decorate.js"}]}}"#,
        )
        .unwrap();
        assert_eq!(rt.package_type(), PackageType::CommonJs);
        assert!(rt.resolve_main().is_none());
        assert_eq!(
            rt.resolve_subpath("./helpers/decorate").as_deref(),
            Some("src/helpers/esm/decorate.js")
        );
        assert_eq!(
            rt.resolve_subpath("helpers/decorate").as_deref(),
            Some("src/helpers/esm/decorate.js")
        );
        assert!(rt
            .referenced_paths()
            .iter()
            .any(|p| p == "src/helpers/esm/decorate.js"));
    }

    #[test]
    fn condition_order_prefers_browser_and_import_never_node() {
        let x = PackageJson::from_json(
            r#"{"exports":{".":{"node":"./n.js","require":"./r.js","import":"./esm.js","default":"./def.js"}}}"#,
        )
        .unwrap();
        assert_eq!(x.resolve_main().as_deref(), Some("esm.js"));

        let y = PackageJson::from_json(
            r#"{"exports":{".":{"module":"./m.js","browser":"./b.js","default":"./d.js"}}}"#,
        )
        .unwrap();
        assert_eq!(y.resolve_main().as_deref(), Some("b.js"));
    }

    #[test]
    fn subpath_pattern_becomes_prefix_entry() {
        let pkg = PackageJson::from_json(r#"{"exports":{".":"./index.js","./*":"./dist/*.js"}}"#)
            .unwrap();
        assert_eq!(pkg.resolve_subpath("./foo").as_deref(), Some("dist/foo.js"));
        assert!(pkg.entries().iter().any(
            |e| matches!(e, Entry::Prefix { subpath, dir } if subpath.is_empty() && dir == "dist/")
        ));
        assert!(pkg
            .entries()
            .iter()
            .any(|e| matches!(e, Entry::Bare(t) if t == "index.js")));
    }

    #[test]
    fn rejects_path_traversal_targets() {
        let evil = PackageJson::from_json(r#"{"exports":{".":"../escape.js"}}"#).unwrap();
        assert!(evil.resolve_main().is_none());
    }
}
