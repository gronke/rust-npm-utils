//! `install` — resolve `package.json`'s `dependencies` and install `node_modules/`
//! (= `npm install`).

use std::path::Path;

use super::common::report_installed;
use super::Res;
use crate::install::node_modules;

/// Resolve the manifest's transitive dependencies against the registry and install the flat tree.
pub(super) fn run(dir: &Path) -> Res {
    report_installed(&node_modules(&dir.join("package.json"), dir)?);
    Ok(())
}
