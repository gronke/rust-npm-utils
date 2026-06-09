//! `ci` — install the exact tree a `package-lock.json` pins (= `npm ci`).

use std::path::Path;

use super::common::report_installed;
use super::Res;
use crate::install::from_lockfile;

/// Install the exact, integrity-checked tree the lockfile pins into `<dir>/node_modules/`.
pub(super) fn run(dir: &Path) -> Res {
    report_installed(&from_lockfile(&dir.join("package-lock.json"), dir)?);
    Ok(())
}
