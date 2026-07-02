//! Helpers shared by the verb submodules: the install-report printer, `name@range` splitting, and
//! the project's default name. The manifest read/write helpers and the lock+install `sync` now live
//! in the public [`crate::project`] module (shared with library consumers); the first two are
//! re-exported here so the verb submodules keep their short `common::` paths.

use std::path::Path;

use serde_json::Value;

use super::Res;
use crate::registry::{PackumentDetail, Resolved};

// Manifest read/write moved to `crate::project` (public API); re-export for the verb submodules.
pub(super) use crate::project::{read_manifest, write_manifest};

/// Rewrite the lock from the manifest and install, then print the installed tree. The library
/// [`crate::project::sync`] does the work and returns the packages; this thin wrapper reports them
/// (the `add` / `install` / `upgrade` verbs share it).
pub(super) fn sync(dir: &Path, doc: &Value, detail: PackumentDetail) -> Res {
    report_installed(&crate::project::sync(dir, doc, detail)?);
    Ok(())
}

/// Report an install's outcome: a count line plus each `name@version` (sorted by the installer).
pub(super) fn report_installed(installed: &[Resolved]) {
    println!("installed {} package(s)", installed.len());
    for r in installed {
        println!("  {}@{}", r.name, r.version);
    }
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
}
