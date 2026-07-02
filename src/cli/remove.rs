//! `remove` — drop package(s) from `package.json`, refresh the lock, reinstall, and prune
//! `node_modules/` (= `npm remove`). Thin wrapper over [`crate::project::remove`].

use std::path::Path;

use super::common::report_installed;
use super::Res;
use crate::project;
use crate::registry::PackumentDetail;

/// Remove each named dependency, then refresh the lock + `node_modules/`. Prints what was removed,
/// notes any name that was not a dependency, and reports the reinstalled tree.
pub(super) fn run(packages: &[String], dir: &Path, detail: PackumentDetail) -> Res {
    let (removed, installed) = project::remove(dir, packages, detail)?;
    for name in &removed {
        println!("- {name}");
    }
    for name in packages.iter().filter(|p| !removed.contains(p)) {
        println!("{name}: not a dependency (skipped)");
    }
    report_installed(&installed);
    Ok(())
}
