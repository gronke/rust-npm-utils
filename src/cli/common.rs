//! Helpers shared by the verb submodules: manifest read/write, the lock+install [`sync`] that
//! `add`/`upgrade` share, install reporting, and small parsing utilities.

use std::path::Path;

use serde_json::Value;

use super::Res;
use crate::install::from_lockfile;
use crate::package_json::{lock, manifest, spec};
use crate::registry::{Registry, Resolved};

/// Make `package-lock.json` + `node_modules/` a function of the manifest: resolve the full
/// registry dependency tree, write a fresh v3 lockfile, and install from it (every tarball's
/// sha512 verified). Non-registry deps (git/file) are recorded in the manifest but not resolved.
pub(super) fn sync(dir: &Path, doc: &Value) -> Res {
    let direct = manifest::dependencies(doc);
    let roots: Vec<(String, spec::Range)> = direct
        .iter()
        .filter(|(_, range)| spec::Spec::parse(range).is_registry())
        .map(|(name, range)| -> Res<(String, spec::Range)> {
            Ok((name.clone(), spec::Range::parse(range)?))
        })
        .collect::<Res<Vec<_>>>()?;

    let resolved = Registry::npm().resolve_tree(&roots)?;
    let entries: Vec<lock::LockEntry> = resolved
        .iter()
        .map(|r| lock::LockEntry {
            name: r.name.clone(),
            version: r.version.to_string(),
            resolved: r.tarball_url.clone(),
            integrity: r.integrity.clone(),
        })
        .collect();

    let name = doc.get("name").and_then(Value::as_str).unwrap_or("");
    let version = doc
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("1.0.0");
    write_atomic(
        &dir.join("package-lock.json"),
        &lock::render_v3(name, version, &direct, &entries),
    )?;

    report_installed(&from_lockfile(&dir.join("package-lock.json"), dir)?);
    Ok(())
}

/// Report an install's outcome: a count line plus each `name@version` (sorted by the installer).
pub(super) fn report_installed(installed: &[Resolved]) {
    println!("installed {} package(s)", installed.len());
    for r in installed {
        println!("  {}@{}", r.name, r.version);
    }
}

/// Read + parse `<dir>/package.json`, erroring clearly if it is missing or not a JSON object.
pub(super) fn read_manifest(dir: &Path) -> Res<Value> {
    let path = dir.join("package.json");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let doc: Value =
        serde_json::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    if !doc.is_object() {
        return Err(format!("{} is not a JSON object", path.display()).into());
    }
    Ok(doc)
}

/// Write a manifest back as pretty JSON (npm's two-space indent + trailing newline), atomically.
pub(super) fn write_manifest(dir: &Path, doc: &Value) -> Res {
    write_atomic(&dir.join("package.json"), &manifest::to_pretty(doc))
}

/// Write `contents` to `path` atomically: write a sibling temp file, then rename it over the
/// target — so a crash mid-write can't leave a truncated `package.json` / `package-lock.json`
/// (either the old file or the complete new one is present). The temp shares the target's
/// directory (same filesystem → the rename is atomic) and is cleaned up if the rename fails.
pub(super) fn write_atomic(path: &Path, contents: &str) -> Res {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("package.json");
    let tmp = dir.join(format!(".{file_name}.tmp.{}", std::process::id()));
    std::fs::write(&tmp, contents).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("replacing {}: {e}", path.display())
    })?;
    Ok(())
}

/// Split `name@range` honoring scoped names: the version separator is the *last* `@` (a leading
/// `@` is the scope). `lit@^3` → `("lit", "^3")`; `@lit/context@^1` → `("@lit/context", "^1")`;
/// `lit` → `("lit", None)`.
pub(super) fn split_name_range(pkg: &str) -> (&str, Option<&str>) {
    match pkg.rfind('@') {
        Some(i) if i > 0 => (&pkg[..i], Some(&pkg[i + 1..])),
        _ => (pkg, None),
    }
}

/// For a caret/tilde range, return it with the floor set to `version` (`^3.1.0` + 3.4.2 →
/// `^3.4.2`). `None` for any other shape (exact pin, `*`, comparator range) — left as written.
pub(super) fn bump_floor(range: &str, version: &semver::Version) -> Option<String> {
    match range.chars().next() {
        Some(prefix @ ('^' | '~')) => Some(format!("{prefix}{version}")),
        _ => None,
    }
}

/// The project's default package name: the (canonicalized) directory's file name, else `app`.
pub(super) fn default_name(dir: &Path) -> String {
    std::fs::canonicalize(dir)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "app".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_name_range_handles_scopes_and_bare_names() {
        assert_eq!(split_name_range("lit"), ("lit", None));
        assert_eq!(split_name_range("lit@^3"), ("lit", Some("^3")));
        assert_eq!(
            split_name_range("@lit/context@^1"),
            ("@lit/context", Some("^1"))
        );
        // A bare scoped name keeps its leading `@` (the scope is not a version marker).
        assert_eq!(split_name_range("@scope/pkg"), ("@scope/pkg", None));
    }

    #[test]
    fn bump_floor_only_moves_floating_ranges() {
        let v = semver::Version::parse("3.4.2").unwrap();
        assert_eq!(bump_floor("^3.1.0", &v).as_deref(), Some("^3.4.2"));
        assert_eq!(bump_floor("~3.1.0", &v).as_deref(), Some("~3.4.2"));
        // Exact pins and any non-^/~ shape are left untouched.
        assert_eq!(bump_floor("3.1.0", &v), None);
        assert_eq!(bump_floor("*", &v), None);
        assert_eq!(bump_floor(">=3 <4", &v), None);
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_temp() {
        use tempfile::tempdir;
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("package.json");
        std::fs::write(&target, "OLD").unwrap();
        write_atomic(&target, "NEW").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "NEW");
        let temp_left = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".tmp."));
        assert!(
            !temp_left,
            "no temp file should remain after an atomic write"
        );
    }
}
