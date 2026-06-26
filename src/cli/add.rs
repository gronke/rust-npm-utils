//! `add` — resolve package(s), record them in `package.json`, write `package-lock.json`, install
//! (= `npm install <pkg>`).

use std::path::Path;

use super::common::{default_name, read_manifest, split_name_range, sync, write_manifest};
use super::Res;
use crate::package_json::{manifest, spec};
use crate::registry::{PackumentDetail, Registry};

/// Resolve each package (latest → `^x.y.z` when no range given), record it in `package.json`
/// (scaffolding one if absent), then `sync` the lock + `node_modules/`.
pub(super) fn run(packages: &[String], dir: &Path, detail: PackumentDetail) -> Res {
    let mut doc = if dir.join("package.json").exists() {
        read_manifest(dir)?
    } else {
        manifest::scaffold(&default_name(dir), "1.0.0")
    };

    let registry = Registry::npm();
    for pkg in packages {
        let (name, range) = split_name_range(pkg);
        let range = match range {
            Some(r) => r.to_string(),
            None => format!("^{}", registry.resolve(name, &spec::Range::any())?.version),
        };
        manifest::upsert_dependency(&mut doc, name, &range);
        println!("+ {name}@{range}");
    }
    write_manifest(dir, &doc)?;
    sync(dir, &doc, detail)
}
