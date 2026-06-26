//! Helpers shared by the verb submodules: manifest read/write, the lock+install [`sync`] that
//! `add`/`upgrade` share, install reporting, and small parsing utilities.

use std::path::Path;

use serde_json::Value;

use super::Res;
use crate::install::from_lockfile;
use crate::package_json::{lock, manifest};
use crate::registry::{PackumentDetail, Registry, Resolved};

/// Make `package-lock.json` + `node_modules/` a function of the manifest: write a fresh v3
/// lockfile from the resolved registry dependency tree (via [`lock::render_v3_from_manifest`],
/// licenses and all), then install from it (every tarball's sha512 verified). Non-registry
/// deps (git/`file:`) are recorded in the manifest but not resolved.
pub(super) fn sync(dir: &Path, doc: &Value, detail: PackumentDetail) -> Res {
    let lockfile = dir.join("package-lock.json");
    std::fs::write(
        &lockfile,
        lock::render_v3_from_manifest(doc, &Registry::npm().with_detail(detail))?,
    )?;
    report_installed(&from_lockfile(&lockfile, dir)?);
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

/// Write a manifest back as pretty JSON (npm's two-space indent + trailing newline).
pub(super) fn write_manifest(dir: &Path, doc: &Value) -> Res {
    std::fs::write(dir.join("package.json"), manifest::to_pretty(doc))?;
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
}
