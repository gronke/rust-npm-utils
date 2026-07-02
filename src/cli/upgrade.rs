//! `upgrade` — re-resolve dependencies within their ranges, refresh the lock, install
//! (= `npm update`). Thin wrapper over [`crate::project::upgrade`].

use std::path::Path;

use super::common::report_installed;
use super::Res;
use crate::project;
use crate::registry::PackumentDetail;

/// Upgrade the selected dependencies (empty = all) and refresh the lock + `node_modules/`, printing
/// each applied `name: from → to` change and the reinstalled tree.
pub(super) fn run(packages: &[String], dir: &Path, detail: PackumentDetail) -> Res {
    let (changes, installed) = project::upgrade(dir, packages, detail)?;
    for change in &changes {
        println!("{}: {} → {}", change.name, change.from, change.to);
    }
    report_installed(&installed);
    Ok(())
}
