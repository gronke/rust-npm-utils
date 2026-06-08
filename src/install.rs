//! Install a `package.json`'s transitive dependency tree into a `node_modules/`
//! directory — a minimal, pure-Rust "npm install".
//!
//! [`node_modules`] resolves the dependency graph against the registry (see
//! [`crate::registry::Registry::resolve_tree`]), verifies each downloaded tarball against the
//! registry's advertised `dist.integrity` (sha512, like `npm install`), and extracts every
//! package into the conventional flat `node_modules/<name>/` layout (scoped names land at
//! `node_modules/@scope/<name>/`). It is skip-if-unchanged — a marker keyed on the
//! resolved version set — and safe under concurrent build scripts via a cross-process
//! lock.
//!
//! [`from_lockfile`] is the `npm ci` counterpart: given a committed `package-lock.json`
//! (version 2 or 3) it installs the **exact** pinned tree — `devDependencies` included —
//! with no registry or semver resolution, verifying each tarball's `sha512` integrity,
//! skipping platform-mismatched optional deps, and creating `node_modules/.bin/` shims. That
//! lets a project install its Node *test tooling* (Playwright, `tsc`) without `npm` and then
//! run it with the Node runtime alone.
//!
//! This complements the single-package, import-map-oriented vendoring helpers: it
//! produces a real `node_modules/` tree (CommonJS and all) for tooling (`tsc`) or a
//! downstream bundler to consume — not browser ES modules directly.

use std::path::{Path, PathBuf};

use base64::Engine;
use semver::{Version, VersionReq};
use serde_json::{Map, Value};
use sha2::{Digest, Sha512};

use crate::path_safety::{ensure_within, safe_join};
use crate::registry::{version_req, Registry, Resolved};
use crate::{cache, download, extract};

/// Resolve `package_json`'s dependencies transitively, verify each tarball's registry
/// `dist.integrity` (sha512), and extract the flat tree into `<dest>/node_modules/`. Returns
/// the resolved package set (sorted by name). A package whose registry metadata advertises no
/// sha512 integrity is refused rather than installed unverified.
///
/// Skips all work when the resolved version set is unchanged and `node_modules/` is
/// already populated. Serialized across concurrent invocations by a lock kept beside
/// `node_modules/` (a refresh wipes `node_modules/` itself, so the lock/marker can't
/// live inside it).
pub fn node_modules(
    package_json: &Path,
    dest: &Path,
) -> Result<Vec<Resolved>, Box<dyn std::error::Error>> {
    let roots = root_requirements(package_json)?;
    let resolved = Registry::npm().resolve_tree(&roots)?;

    let node_modules = dest.join("node_modules");
    let lock = dest.join(".node_modules.lock");
    let marker = dest.join(".node_modules.marker");
    let want = resolved
        .iter()
        .map(|r| format!("{}@{}", r.name, r.version))
        .collect::<Vec<_>>()
        .join("\n");

    cache::with_lock(&lock)(|| -> Result<(), Box<dyn std::error::Error>> {
        if cache::dir_has_content(&node_modules) && cache::marker_matches(&marker, &want) {
            return Ok(()); // already up to date
        }
        cache::clear_directory(&node_modules)?;
        for pkg in &resolved {
            let bytes = download::fetch(&pkg.tarball_url)?;
            // Verify the registry-advertised sha512 integrity before trusting the bytes, like
            // `npm install`. A package whose metadata carries no sha512 is refused, not
            // installed unverified (the same strict stance as `from_lockfile`).
            verify_integrity(&pkg.name, &bytes, pkg.integrity.as_deref().unwrap_or(""))?;
            let dir = package_dir(&node_modules, &pkg.name)?;
            // Strip the tarball's first path component whatever it's named: npm's own pack
            // uses `package/`, but some published tarballs (e.g. `@types/react` → `react
            // v18.3/`) don't, and npm strips the top dir by position, not by name.
            extract::tar_gz(
                &bytes,
                &dir,
                None,
                extract::Select::Matching(&strip_top_dir),
            )?;
        }
        cache::write_marker(&marker, &want)?;
        Ok(())
    })?;

    Ok(resolved)
}

/// The root requirements: each `dependencies` entry as `(name, VersionReq)`, npm-faithful
/// (a bare version pins exactly). Registry specs only — a git/URL spec errors here.
fn root_requirements(
    package_json: &Path,
) -> Result<Vec<(String, VersionReq)>, Box<dyn std::error::Error>> {
    let json: Value = serde_json::from_str(&std::fs::read_to_string(package_json)?)?;
    let deps = json
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or("no dependencies section in package.json")?;
    let mut out = Vec::new();
    for (name, value) in deps {
        let Some(spec) = value.as_str() else { continue };
        let req = version_req(spec)
            .map_err(|e| format!("dependency `{name}`: unsupported version {spec:?}: {e}"))?;
        out.push((name.clone(), req));
    }
    Ok(out)
}

/// `node_modules/<name>/` for a (possibly scoped) package name, path-traversal-hardened
/// via [`crate::path_safety`] (scoped `@scope/pkg` joins fine; any escaping name errors).
fn package_dir(node_modules: &Path, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    safe_join(node_modules, name)
}

/// Install the exact dependency tree pinned by a `package-lock.json` into
/// `<dest>/node_modules/` — a pure-Rust, `npm ci`-faithful install.
///
/// Unlike [`node_modules`], this does **no** registry or semver resolution: a lockfile
/// (version 2 or 3) already enumerates every package — `dependencies` *and*
/// `devDependencies`, transitively — with its exact version, tarball URL, `integrity` hash
/// and platform constraints. Each package is downloaded, its `sha512` integrity is verified,
/// and it is extracted to the path the lockfile names. Optional packages whose `os`/`cpu`
/// don't match the host are skipped (e.g. darwin-only `fsevents` on Linux); each package's
/// `bin` entries become `node_modules/.bin/` symlinks (Unix), so the installed CLIs (`tsc`,
/// `playwright`, …) run as they would under npm — no `npm` needed, only the Node runtime.
///
/// Skip-if-unchanged (a marker keyed on the lockfile's contents) and concurrency-safe via a
/// cross-process lock, like [`node_modules`]. Returns the installed set, sorted by install
/// path.
pub fn from_lockfile(
    package_lock: &Path,
    dest: &Path,
) -> Result<Vec<Resolved>, Box<dyn std::error::Error>> {
    let plan = parse_lockfile(package_lock)?;

    let node_modules = dest.join("node_modules");
    let lock = dest.join(".node_modules.lock");
    let marker = dest.join(".node_modules.marker");
    // The lockfile fully determines the tree, so its content hash is the cache key.
    let want = cache::file_hash(package_lock)?;

    cache::with_lock(&lock)(|| -> Result<(), Box<dyn std::error::Error>> {
        if cache::dir_has_content(&node_modules) && cache::marker_matches(&marker, &want) {
            return Ok(()); // already up to date
        }
        cache::clear_directory(&node_modules)?;
        for pkg in &plan {
            let bytes = download::fetch(&pkg.resolved)?;
            verify_integrity(&pkg.name, &bytes, &pkg.integrity)?;
            let dir = pkg.install_dir(dest)?;
            // Strip the tarball's first path component whatever it's named: npm's own pack
            // uses `package/`, but some published tarballs (e.g. `@types/react` → `react
            // v18.3/`) don't, and npm strips the top dir by position, not by name.
            extract::tar_gz(
                &bytes,
                &dir,
                None,
                extract::Select::Matching(&strip_top_dir),
            )?;
        }
        link_bins(&node_modules, &plan)?;
        cache::write_marker(&marker, &want)?;
        Ok(())
    })?;

    plan.into_iter()
        .map(|pkg| {
            let version = Version::parse(&pkg.version).map_err(|e| {
                format!(
                    "package `{}`: invalid version {:?}: {e}",
                    pkg.name, pkg.version
                )
            })?;
            Ok(Resolved {
                name: pkg.name,
                version,
                tarball_url: pkg.resolved,
                integrity: Some(pkg.integrity),
            })
        })
        .collect()
}

/// One installable entry from a `package-lock.json` `packages` map.
struct LockedPackage {
    /// Install path relative to the project dir, e.g. `node_modules/@scope/pkg`.
    key: String,
    /// Package name — the segment after the last `node_modules/`.
    name: String,
    version: String,
    resolved: String,
    integrity: String,
    /// `(bin-name, path-within-package)` pairs to expose under `node_modules/.bin/`.
    bin: Vec<(String, String)>,
}

impl LockedPackage {
    /// The validated install directory for this package under `project_root` (e.g.
    /// `<root>/node_modules/@scope/pkg`). Path-traversal-hardened at the source: a crafted
    /// lockfile `key` can't escape, because deriving the path *is* validating it.
    fn install_dir(&self, project_root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        safe_join(project_root, &self.key)
    }
}

/// Parse a `package-lock.json` (lockfileVersion 2 or 3) into the packages to install on
/// this host: every `node_modules/…` entry with a downloadable `resolved` tarball whose
/// `os`/`cpu` match. Sorted by install path so `.bin` name collisions resolve
/// deterministically (first wins).
fn parse_lockfile(package_lock: &Path) -> Result<Vec<LockedPackage>, Box<dyn std::error::Error>> {
    let json: Value = serde_json::from_str(&std::fs::read_to_string(package_lock)?)?;
    let lockfile_version = json
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if lockfile_version < 2 {
        return Err(format!(
            "package-lock.json lockfileVersion {lockfile_version} is unsupported \
             (need 2 or 3, which carry the `packages` map)"
        )
        .into());
    }
    let packages = json
        .get("packages")
        .and_then(Value::as_object)
        .ok_or("package-lock.json has no `packages` map")?;

    let mut out = Vec::new();
    for (key, entry) in packages {
        // Real installs live under node_modules/; "" is the root project and bare paths
        // (workspace members) are local sources, not fetched.
        if !key.starts_with("node_modules/") {
            continue;
        }
        ensure_within(key)?; // a crafted key must never escape the tree
        let Some(entry) = entry.as_object() else {
            continue;
        };
        // Only registry tarballs are installable here. An entry with no `resolved`, or a
        // non-HTTP one (git / `file:` / workspace link), isn't a fetchable tarball; skip it.
        let Some(resolved) = entry.get("resolved").and_then(Value::as_str) else {
            continue;
        };
        if !(resolved.starts_with("https://") || resolved.starts_with("http://")) {
            continue;
        }
        // Optional native deps for other platforms (e.g. fsevents on Linux): skip, exactly
        // as npm does — installing them is pointless and can fail.
        if !platform_matches(entry) {
            continue;
        }
        let name = key
            .rsplit_once("node_modules/")
            .map(|(_, n)| n)
            .unwrap_or(key)
            .to_string();
        let bin = bin_entries(entry, &name);
        out.push(LockedPackage {
            key: key.clone(),
            name,
            version: string_field(entry, "version"),
            resolved: resolved.to_string(),
            integrity: string_field(entry, "integrity"),
            bin,
        });
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

fn string_field(entry: &Map<String, Value>, key: &str) -> String {
    entry
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Translate a Rust `std::env::consts::{OS,ARCH}` value to npm/node's spelling.
fn node_value(rust: &'static str, map: &[(&'static str, &'static str)]) -> &'static str {
    map.iter()
        .find(|(r, _)| *r == rust)
        .map(|(_, n)| *n)
        .unwrap_or(rust)
}

const OS_MAP: &[(&str, &str)] = &[("macos", "darwin"), ("windows", "win32")];
const CPU_MAP: &[(&str, &str)] = &[("x86_64", "x64"), ("aarch64", "arm64"), ("x86", "ia32")];

/// Whether the host satisfies an entry's `os` and `cpu` constraints.
fn platform_matches(entry: &Map<String, Value>) -> bool {
    constraint_allows(entry.get("os"), node_value(std::env::consts::OS, OS_MAP))
        && constraint_allows(
            entry.get("cpu"),
            node_value(std::env::consts::ARCH, CPU_MAP),
        )
}

/// npm `os`/`cpu` matching: any positive list must include `host`; a `!`-prefixed value
/// excludes it. An absent/empty constraint allows everything.
fn constraint_allows(field: Option<&Value>, host: &str) -> bool {
    let Some(list) = field.and_then(Value::as_array) else {
        return true;
    };
    let mut has_positive = false;
    let mut matched_positive = false;
    for item in list.iter().filter_map(Value::as_str) {
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

/// Verify a tarball against a Subresource-Integrity string — the `dist.integrity` a registry
/// packument advertises (used by [`node_modules`]) or the `integrity` a `package-lock.json`
/// pins (used by [`from_lockfile`]). npm writes `sha512-<base64>` (occasionally several
/// space-separated algorithms); we require and check the sha512 digest, like
/// `npm install` / `npm ci`. An integrity string with no sha512 component is an error.
fn verify_integrity(
    name: &str,
    bytes: &[u8],
    integrity: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = integrity
        .split_whitespace()
        .find_map(|token| token.strip_prefix("sha512-"))
        .ok_or_else(|| format!("package `{name}`: no sha512 integrity to verify against"))?;
    let actual = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
    if actual != expected {
        return Err(format!(
            "package `{name}`: integrity mismatch — the downloaded tarball does not match \
             the expected sha512"
        )
        .into());
    }
    Ok(())
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

/// Drop a tarball entry's first path component (the package's top-level directory),
/// whatever it's named — `package/` for npm's own pack, but e.g. `react v18.3/` for some
/// published `@types` tarballs. Entries with no directory component are skipped (`None`).
/// This is what npm does: it strips the top dir by position, not by the literal name.
fn strip_top_dir(rel: &str) -> Option<String> {
    rel.split_once('/')
        .map(|(_, rest)| rest.to_string())
        .filter(|rest| !rest.is_empty())
}

/// Create `node_modules/.bin/<name>` symlinks for every package `bin`, so the installed
/// CLIs run as under npm. The shims are *relative* (the tree stays relocatable) and their
/// targets are made executable. On a name collision the first package (by sorted install
/// path) wins. Unix only — `.bin` shims elsewhere are out of scope.
#[cfg(unix)]
fn link_bins(
    node_modules: &Path,
    plan: &[LockedPackage],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;
    use std::os::unix::fs::{symlink, PermissionsExt};

    let bin_dir = node_modules.join(".bin");
    let mut linked: BTreeSet<String> = BTreeSet::new();
    for pkg in plan {
        let Some(install_rel) = pkg.key.strip_prefix("node_modules/") else {
            continue;
        };
        for (bin_name, bin_path) in &pkg.bin {
            // A bin name is a single filename under .bin/, never a path.
            if bin_name.is_empty() || bin_name.contains('/') || bin_name == "." || bin_name == ".."
            {
                continue;
            }
            if !linked.insert(bin_name.clone()) {
                continue; // collision: the first (sorted) package keeps the name
            }
            let bin_path = bin_path.trim_start_matches("./");
            std::fs::create_dir_all(&bin_dir)?;
            // Make the real entry file executable (npm does this on extract).
            let target = safe_join(node_modules, &format!("{install_rel}/{bin_path}"))?;
            if let Ok(meta) = std::fs::metadata(&target) {
                let mut perm = meta.permissions();
                perm.set_mode(perm.mode() | 0o111);
                let _ = std::fs::set_permissions(&target, perm);
            }
            let link = bin_dir.join(bin_name);
            let _ = std::fs::remove_file(&link); // idempotent
            symlink(format!("../{install_rel}/{bin_path}"), &link)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn link_bins(
    _node_modules: &Path,
    _plan: &[LockedPackage],
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(()) // `.bin` shims are Unix symlinks; skipped on other platforms
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn package_dir_handles_scoped_and_rejects_escapes() {
        let nm = Path::new("/tmp/nm");
        assert_eq!(package_dir(nm, "react").unwrap(), nm.join("react"));
        assert_eq!(
            package_dir(nm, "@preact/signals").unwrap(),
            nm.join("@preact").join("signals")
        );
        assert!(package_dir(nm, "../escape").is_err());
        assert!(package_dir(nm, "a/../b").is_err());
        assert!(package_dir(nm, "/abs").is_err());
    }

    fn tiny_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, contents) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(contents.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, *path, Cursor::new(*contents))
                .unwrap();
        }
        b.finish().unwrap();
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extracts_a_package_into_the_node_modules_layout() {
        // The per-package extraction step (offline): a scoped package lands under
        // node_modules/@scope/pkg/ with the npm `package/` prefix stripped.
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        let tgz = tiny_tgz(&[
            (
                "package/package.json",
                br#"{"name":"@scope/pkg","version":"1.0.0"}"#,
            ),
            ("package/index.js", b"export default 1;"),
        ]);
        let dir = package_dir(&nm, "@scope/pkg").unwrap();
        extract::tar_gz(&tgz, &dir, Some("package/"), extract::Select::All).unwrap();
        assert!(nm.join("@scope/pkg/package.json").is_file());
        assert!(nm.join("@scope/pkg/index.js").is_file());
    }

    #[test]
    #[ignore = "network: hits the npm registry"]
    fn installs_react_with_transitive_scheduler() {
        // Real install of the React-showcase deps. react-dom depends on scheduler, so a
        // correct transitive resolve produces all three under node_modules/. Each tarball's
        // registry sha512 integrity is also verified end-to-end here — a mismatch would fail
        // the install. (Tamper-rejection itself is covered offline by
        // `verify_integrity_checks_sha512_and_rejects_tampering`, shared by both install paths.)
        let tmp = tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{ "dependencies": { "react": "^19", "react-dom": "^19" } }"#,
        )
        .unwrap();

        let resolved = node_modules(&pkg, tmp.path()).unwrap();
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"react"), "got {names:?}");
        assert!(names.contains(&"react-dom"), "got {names:?}");
        assert!(
            names.contains(&"scheduler"),
            "transitive dep missing: {names:?}"
        );

        let nm = tmp.path().join("node_modules");
        for p in ["react", "react-dom", "scheduler"] {
            assert!(
                nm.join(p).join("package.json").is_file(),
                "node_modules/{p}/package.json missing"
            );
        }
    }

    #[test]
    #[ignore = "network: hits the npm registry"]
    fn downloads_and_extracts_a_commonjs_package() {
        use crate::package_json::{PackageJson, PackageType};
        // `ms` is a tiny, dependency-free, long-frozen CommonJS package — a focused check
        // that we download + extract a real CJS package *intact*. CommonJS is exactly the
        // case a buildless ESM tree can't serve directly, which is why node_modules/ exists.
        let tmp = tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(&pkg, r#"{ "dependencies": { "ms": "^2" } }"#).unwrap();

        let resolved = node_modules(&pkg, tmp.path()).unwrap();
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["ms"], "ms has no runtime dependencies");

        let ms = tmp.path().join("node_modules/ms");
        let manifest = PackageJson::from_path(&ms.join("package.json")).unwrap();
        assert_eq!(manifest.name(), Some("ms"));
        assert_eq!(
            manifest.package_type(),
            PackageType::CommonJs,
            "ms ships CommonJS"
        );
        // The JS itself extracted to disk and really is CommonJS source. (`ms`'s "main"
        // is the extension-less "./index"; the file on disk is index.js per its "files".)
        let entry = ms.join("index.js");
        let source = std::fs::read_to_string(&entry).unwrap();
        assert!(
            source.contains("module.exports"),
            "extracted entry {entry:?} is CommonJS source"
        );
    }

    // A small lockfileVersion-3 fixture exercising selection: a runtime dep, a scoped dep, a
    // dev dep with a `bin` map, an off-platform optional native dep, and a `file:` link.
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

    #[test]
    fn parse_lockfile_selects_installable_entries_and_parses_bins() {
        let tmp = tempdir().unwrap();
        let lock = tmp.path().join("package-lock.json");
        std::fs::write(&lock, SAMPLE_LOCK).unwrap();

        let plan = parse_lockfile(&lock).unwrap();
        let names: Vec<&str> = plan.iter().map(|p| p.name.as_str()).collect();
        // The root "" and the `file:` link are never installed; entries are sorted by path.
        // fsevents is darwin-only, so it's selected only on macOS.
        #[cfg(not(target_os = "macos"))]
        assert_eq!(names, ["@scope/pkg", "typescript"], "got {names:?}");
        #[cfg(target_os = "macos")]
        assert_eq!(
            names,
            ["@scope/pkg", "fsevents", "typescript"],
            "got {names:?}"
        );

        // The `bin` map is parsed (both entries), so .bin shims can be created later.
        let ts = plan.iter().find(|p| p.name == "typescript").unwrap();
        assert!(ts.bin.iter().any(|(n, p)| n == "tsc" && p == "bin/tsc"));
        assert!(ts.bin.iter().any(|(n, _)| n == "tsserver"));
    }

    #[test]
    fn parse_lockfile_rejects_old_versions_and_traversal() {
        assert!(ensure_within("node_modules/@s/p").is_ok());
        assert!(ensure_within("node_modules/../escape").is_err());

        let tmp = tempdir().unwrap();
        // lockfileVersion 1 has no `packages` map → unsupported.
        let v1 = tmp.path().join("v1.json");
        std::fs::write(&v1, r#"{"lockfileVersion":1,"dependencies":{}}"#).unwrap();
        assert!(parse_lockfile(&v1).is_err());

        // A key that would escape node_modules/ is rejected before any download.
        let evil = tmp.path().join("evil.json");
        std::fs::write(
            &evil,
            r#"{"lockfileVersion":3,"packages":{"node_modules/../evil":{"resolved":"https://x/y.tgz","integrity":"sha512-A"}}}"#,
        )
        .unwrap();
        assert!(parse_lockfile(&evil).is_err());
    }

    #[test]
    fn constraint_allows_follows_npm_os_cpu_rules() {
        use serde_json::json;
        assert!(constraint_allows(None, "linux"), "no constraint allows all");
        assert!(constraint_allows(Some(&json!(["linux"])), "linux"));
        assert!(!constraint_allows(Some(&json!(["darwin"])), "linux"));
        assert!(constraint_allows(
            Some(&json!(["darwin", "linux"])),
            "linux"
        ));
        assert!(constraint_allows(Some(&json!(["!win32"])), "linux"));
        assert!(!constraint_allows(Some(&json!(["!linux"])), "linux"));
    }

    #[test]
    fn verify_integrity_checks_sha512_and_rejects_tampering() {
        use base64::Engine;
        use sha2::{Digest, Sha512};

        let tgz = tiny_tgz(&[("package/index.js", b"export default 1;")]);
        let good = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tgz))
        );
        verify_integrity("p", &tgz, &good).expect("matching sha512 passes");

        let mut tampered = tgz.clone();
        tampered[0] ^= 0xff;
        assert!(
            verify_integrity("p", &tampered, &good).is_err(),
            "flipped byte fails"
        );

        // An integrity string without a sha512 component is rejected (npm-ci-strict).
        assert!(verify_integrity("p", &tgz, "sha1-deadbeef").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn link_bins_creates_relative_exec_symlinks_first_wins() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        for rel in [
            "@playwright/test/cli.js",
            "playwright/cli.js",
            "typescript/bin/tsc",
        ] {
            let p = nm.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"#!/usr/bin/env node\n").unwrap();
        }
        // Sorted by install path (as parse_lockfile returns): @playwright/test < playwright.
        let plan = vec![
            LockedPackage {
                key: "node_modules/@playwright/test".into(),
                name: "@playwright/test".into(),
                version: "1.60.0".into(),
                resolved: String::new(),
                integrity: String::new(),
                bin: vec![("playwright".into(), "cli.js".into())],
            },
            LockedPackage {
                key: "node_modules/playwright".into(),
                name: "playwright".into(),
                version: "1.60.0".into(),
                resolved: String::new(),
                integrity: String::new(),
                bin: vec![("playwright".into(), "cli.js".into())],
            },
            LockedPackage {
                key: "node_modules/typescript".into(),
                name: "typescript".into(),
                version: "5.9.3".into(),
                resolved: String::new(),
                integrity: String::new(),
                bin: vec![("tsc".into(), "bin/tsc".into())],
            },
        ];
        link_bins(&nm, &plan).unwrap();

        // Relative, relocatable shims.
        assert_eq!(
            std::fs::read_link(nm.join(".bin/tsc")).unwrap(),
            Path::new("../typescript/bin/tsc")
        );
        // On the `playwright` collision the first (sorted) package keeps the name.
        assert_eq!(
            std::fs::read_link(nm.join(".bin/playwright")).unwrap(),
            Path::new("../@playwright/test/cli.js")
        );
        // The real entry file was made executable.
        let mode = std::fs::metadata(nm.join("typescript/bin/tsc"))
            .unwrap()
            .permissions()
            .mode();
        assert!(mode & 0o111 != 0, "bin target should be executable");
    }

    #[test]
    fn strip_top_dir_drops_first_component_regardless_of_name() {
        assert_eq!(
            strip_top_dir("package/index.js").as_deref(),
            Some("index.js")
        );
        // @types/react ships under "react v18.3/", not "package/".
        assert_eq!(
            strip_top_dir("react v18.3/index.d.ts").as_deref(),
            Some("index.d.ts")
        );
        assert_eq!(
            strip_top_dir("root/sub/file.d.ts").as_deref(),
            Some("sub/file.d.ts")
        );
        assert_eq!(strip_top_dir("toplevel"), None); // no directory component → skipped
    }

    #[test]
    fn extracts_tarballs_whose_root_is_not_named_package() {
        // Regression for the dogfood-found bug: a package whose tarball root is not `package/`
        // (e.g. `@types/react`'s `react v18.3/`) must still extract into the package dir, not a
        // stray subdir — npm strips the top dir by position, not by name.
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("@types/react");
        let tgz = tiny_tgz(&[
            ("react v18.3/index.d.ts", b"export {};"),
            ("react v18.3/package.json", br#"{"name":"@types/react"}"#),
        ]);
        extract::tar_gz(&tgz, &dir, None, extract::Select::Matching(&strip_top_dir)).unwrap();
        assert!(
            dir.join("index.d.ts").is_file(),
            "top dir stripped by position"
        );
        assert!(dir.join("package.json").is_file());
        assert!(
            !dir.join("react v18.3").exists(),
            "no stray top-level dir remains"
        );
    }

    #[test]
    #[ignore = "network: hits the npm registry"]
    #[cfg(not(target_os = "macos"))]
    fn installs_a_locked_tree_and_skips_offplatform_optional() {
        // `ms@2.1.3` is a frozen package with a known sha512 (so integrity is really checked).
        // `darwin-only` carries a bogus URL that MUST NOT be fetched on a non-darwin host —
        // proving the platform skip end to end (a fetch would error on the invalid URL).
        let tmp = tempdir().unwrap();
        let lock = tmp.path().join("package-lock.json");
        std::fs::write(
            &lock,
            r#"{
              "name": "fixture",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "fixture", "dependencies": { "ms": "2.1.3" } },
                "node_modules/ms": {
                  "version": "2.1.3",
                  "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
                  "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="
                },
                "node_modules/darwin-only": {
                  "version": "1.0.0",
                  "resolved": "https://example.invalid/never-fetched.tgz",
                  "integrity": "sha512-AAAA",
                  "optional": true,
                  "os": ["darwin"]
                }
              }
            }"#,
        )
        .unwrap();

        let installed = from_lockfile(&lock, tmp.path()).unwrap();
        let names: Vec<&str> = installed.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["ms"],
            "the darwin-only optional dep is skipped on this host"
        );

        let nm = tmp.path().join("node_modules");
        assert!(
            nm.join("ms/package.json").is_file(),
            "ms downloaded, integrity-verified and extracted"
        );
        assert!(
            !nm.join("darwin-only").exists(),
            "off-platform dep not installed"
        );

        // Idempotent: the lockfile-hash marker short-circuits the second call.
        let again = from_lockfile(&lock, tmp.path()).unwrap();
        assert_eq!(again.len(), 1);
    }
}
