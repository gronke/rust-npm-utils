//! `sbom` — render a license summary / CycloneDX / SPDX bill of materials from a
//! `package-lock.json`, pure Rust (no Node, no network).

use std::path::Path;

use clap::ValueEnum;

use super::common::default_name;
use super::Res;
use crate::package_json::lock::Lockfile;
use crate::sbom;

/// Output format for the `sbom` verb.
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum Format {
    /// Human-readable license overview (packages grouped by license).
    Summary,
    /// CycloneDX 1.6 JSON document.
    Cyclonedx,
    /// SPDX 2.3 JSON document.
    Spdx,
}

/// Parse `<dir>/package-lock.json` and print its bill of materials to stdout in `format`. `name`
/// labels the SBOM's root component / document (defaults to the directory name).
pub(super) fn run(dir: &Path, format: Format, name: Option<&str>) -> Res {
    let lock_path = dir.join("package-lock.json");
    let text = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("reading {}: {e}", lock_path.display()))?;
    let components = sbom::components(&Lockfile::parse(&text)?);
    let app = name
        .map(str::to_string)
        .unwrap_or_else(|| default_name(dir));

    let out = match format {
        Format::Summary => sbom::render_summary(&components),
        Format::Cyclonedx => {
            sbom::to_cyclonedx(&components, &app, "0.0.0", Some(&sbom::now_rfc3339()))
        }
        Format::Spdx => {
            let created = sbom::now_rfc3339();
            let namespace = format!("https://spdx.org/spdxdocs/{app}-{created}");
            sbom::to_spdx(&components, &app, &namespace, &created)
        }
    };
    print!("{out}");
    Ok(())
}
