//! `upgrade` — re-resolve dependencies within their ranges, refresh the lock, install
//! (= `npm update`).

use std::path::Path;

use super::common::{bump_floor, read_manifest, sync, write_manifest};
use super::Res;
use crate::package_json::{manifest, spec};
use crate::registry::{PackumentDetail, Registry};

/// For each (selected) registry dependency, re-resolve within its range and bump a floating
/// (`^`/`~`) range's floor to the resolved version; then `sync`. Exact pins and complex ranges are
/// left untouched (npm honors them too).
pub(super) fn run(packages: &[String], dir: &Path, detail: PackumentDetail) -> Res {
    let mut doc = read_manifest(dir)?;
    let registry = Registry::npm();
    for (name, range) in manifest::dependencies(&doc) {
        if !packages.is_empty() && !packages.contains(&name) {
            continue;
        }
        if !spec::Spec::parse(&range).is_registry() {
            continue; // git / file / tarball — nothing to re-resolve from the registry
        }
        let resolved = registry.resolve(&name, &spec::Range::parse(&range)?)?;
        if let Some(bumped) = bump_floor(&range, &resolved.version) {
            if bumped != range {
                manifest::upsert_dependency(&mut doc, &name, &bumped);
                println!("{name}: {range} → {bumped}");
            }
        }
    }
    write_manifest(dir, &doc)?;
    sync(dir, &doc, detail)
}
