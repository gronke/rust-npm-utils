//! `init` — scaffold a `package.json` (= `npm init -y`).

use std::path::Path;

use super::common::default_name;
use super::Res;
use crate::package_json::manifest;

/// Write a fresh `package.json` (refusing to clobber an existing one).
pub(super) fn run(dir: &Path, name: Option<&str>) -> Res {
    let path = dir.join("package.json");
    if path.exists() {
        return Err(format!("{} already exists", path.display()).into());
    }
    std::fs::create_dir_all(dir)?;
    let name = name
        .map(str::to_string)
        .unwrap_or_else(|| default_name(dir));
    std::fs::write(
        &path,
        manifest::to_pretty(&manifest::scaffold(&name, "1.0.0")),
    )?;
    println!("wrote {}", path.display());
    Ok(())
}
