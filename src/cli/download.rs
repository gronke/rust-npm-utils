//! `download` — resolve a range, fetch the tarball, write it to a file (no install).

use std::path::{Path, PathBuf};

use super::Res;
use crate::package_json::spec;
use crate::registry::Registry;

/// Resolve `range`, fetch the tarball, and write it to `out` (or `<name>-<version>.tgz`).
pub(super) fn run(name: &str, range: &str, out: Option<&Path>) -> Res {
    let r = Registry::npm().resolve(name, &spec::Range::parse(range)?)?;
    let bytes = crate::download::fetch(&r.tarball_url)?;
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    let path = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(format!("{unscoped}-{}.tgz", r.version)));
    std::fs::write(&path, &bytes)?;
    println!(
        "wrote {} ({} bytes) — {}@{}",
        path.display(),
        bytes.len(),
        r.name,
        r.version
    );
    Ok(())
}
