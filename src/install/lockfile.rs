//! `from_lockfile()` — install the exact tree pinned by a `package-lock.json` (pure-Rust
//! `npm ci`), plus `node_modules/.bin/` shims.

use std::path::Path;

use package_json::lock::{LockedPackage, Lockfile};
use semver::Version;

use crate::path_safety::safe_join;
use crate::registry::Resolved;

/// Install the exact dependency tree pinned by a `package-lock.json` into `<dest>/node_modules/`
/// — a pure-Rust, `npm ci`-faithful install.
///
/// The lockfile (v2/v3) is parsed by [`package_json::lock`]; this installs every registry-tarball
/// entry whose `os`/`cpu` match the host (skipping links and off-platform optional deps like
/// darwin-only `fsevents` on Linux), verifies each `sha512` integrity, extracts it to the path the
/// lockfile names, and creates `node_modules/.bin/` symlinks — so installed CLIs (`tsc`,
/// `playwright`, …) run as under npm, with only the Node runtime, no `npm`. Skip-if-unchanged on
/// the lockfile's content hash. Returns the installed set, sorted by install path.
pub fn from_lockfile(
    package_lock: &Path,
    dest: &Path,
) -> Result<Vec<Resolved>, Box<dyn std::error::Error>> {
    let lockfile = Lockfile::parse(&std::fs::read_to_string(package_lock)?)?;
    // What this host installs: platform-matching, non-link entries that are registry tarballs.
    let installable: Vec<&LockedPackage> = lockfile
        .installable(std::env::consts::OS, std::env::consts::ARCH)
        .into_iter()
        .filter(|p| p.is_registry_tarball())
        .collect();
    // The lockfile fully determines the tree, so its content hash is the cache key.
    let want = crate::cache::file_hash(package_lock)?;

    super::run_install(dest, &want, |node_modules| {
        for pkg in &installable {
            // The key (`node_modules/…`) is validated into a contained path under `dest`.
            let dir = safe_join(dest, &pkg.key)?;
            let url = pkg.resolved.as_deref().unwrap_or_default();
            super::fetch_verify_extract(&pkg.name, url, pkg.integrity.as_deref(), &dir)?;
        }
        link_bins(node_modules, &installable)?;
        Ok(())
    })?;

    installable
        .iter()
        .map(|pkg| {
            let version = Version::parse(&pkg.version).map_err(|e| {
                format!(
                    "package `{}`: invalid version {:?}: {e}",
                    pkg.name, pkg.version
                )
            })?;
            Ok(Resolved {
                name: pkg.name.clone(),
                version,
                tarball_url: pkg.resolved.clone().unwrap_or_default(),
                integrity: pkg.integrity.clone(),
            })
        })
        .collect()
}

/// Create `node_modules/.bin/<name>` symlinks for every package `bin`, so the installed CLIs run
/// as under npm. The shims are *relative* (the tree stays relocatable) and their targets are made
/// executable. On a name collision the first package (by sorted install path) wins. Unix only —
/// `.bin` shims elsewhere are out of scope.
#[cfg(unix)]
fn link_bins(
    node_modules: &Path,
    plan: &[&LockedPackage],
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
    _plan: &[&LockedPackage],
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(()) // `.bin` shims are Unix symlinks; skipped on other platforms
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Build a `LockedPackage` for the `.bin` test — only `key`, `name`, and `bin` matter here.
    fn locked(key: &str, bin: &[(&str, &str)]) -> LockedPackage {
        LockedPackage {
            name: key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key)
                .to_string(),
            key: key.to_string(),
            version: "1.0.0".into(),
            resolved: None,
            integrity: None,
            dev: false,
            optional: false,
            dev_optional: false,
            link: false,
            os: Vec::new(),
            cpu: Vec::new(),
            bin: bin
                .iter()
                .map(|(n, p)| (n.to_string(), p.to_string()))
                .collect(),
        }
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
        // Sorted by install path (as Lockfile::installable returns): @playwright/test < playwright.
        let pkgs = [
            locked("node_modules/@playwright/test", &[("playwright", "cli.js")]),
            locked("node_modules/playwright", &[("playwright", "cli.js")]),
            locked("node_modules/typescript", &[("tsc", "bin/tsc")]),
        ];
        let plan: Vec<&LockedPackage> = pkgs.iter().collect();
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
