//! `sbom` — render a license summary / CycloneDX / SPDX bill of materials from a
//! `package-lock.json`, pure Rust (no Node, no network).

use std::path::Path;

use clap::ValueEnum;

use super::common::default_name;
use super::Res;
use crate::package_json::lock::Lockfile;
use crate::package_json::{License, PackageJson};
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

/// Where the `sbom` verb reads each package's declared license.
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum LicenseSource {
    /// The lockfile when it records a license, else the installed package.json (the default).
    Auto,
    /// Only the lockfile's recorded license.
    Lockfile,
    /// The installed `node_modules/<name>/package.json`, falling back to the lockfile.
    Package,
}

/// Parse `<dir>/package-lock.json` and print its bill of materials to stdout in `format`. `name`
/// labels the SBOM's root component / document (defaults to the directory name).
pub(super) fn run(
    dir: &Path,
    format: Format,
    name: Option<&str>,
    license_source: LicenseSource,
) -> Res {
    let lock_path = dir.join("package-lock.json");
    let text = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("reading {}: {e}", lock_path.display()))?;
    let mut components = sbom::components(&Lockfile::parse(&text)?);
    enrich_licenses(&mut components, dir, license_source);
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

/// Source each component's license per `source`, reading the installed `package.json` when asked.
/// `Lockfile` keeps the lockfile's value; `Auto` fills only a missing one; `Package` prefers the
/// package.json (keeping the lockfile value when the package isn't installed).
fn enrich_licenses(components: &mut [sbom::Component], dir: &Path, source: LicenseSource) {
    if matches!(source, LicenseSource::Lockfile) {
        return;
    }
    for c in components.iter_mut() {
        let want_pkg = match source {
            LicenseSource::Package => true,
            LicenseSource::Auto => c.license.is_none(),
            LicenseSource::Lockfile => false,
        };
        if want_pkg {
            if let Some(license) = package_license(dir, &c.name) {
                c.license = Some(license);
            }
        }
    }
}

/// A package's declared license from `<dir>/node_modules/<name>/package.json`, if installed.
fn package_license(dir: &Path, name: &str) -> Option<String> {
    let path = dir.join("node_modules").join(name).join("package.json");
    PackageJson::from_path(&path)
        .ok()
        .and_then(|pj| pj.license())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::Component;
    use tempfile::tempdir;

    fn component(name: &str, license: Option<&str>) -> Component {
        Component {
            purl: format!("pkg:npm/{name}@1.0.0"),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            license: license.map(str::to_string),
            resolved: None,
            integrity: None,
        }
    }

    fn write_installed(dir: &Path, name: &str, license: &str) {
        let pkg = dir.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{"name":"{name}","version":"1.0.0","license":"{license}"}}"#),
        )
        .unwrap();
    }

    #[test]
    fn auto_fills_only_a_missing_license_from_package_json() {
        let tmp = tempdir().unwrap();
        write_installed(tmp.path(), "foo", "MIT");
        let mut comps = vec![component("foo", None), component("bar", Some("Apache-2.0"))];
        enrich_licenses(&mut comps, tmp.path(), LicenseSource::Auto);
        assert_eq!(comps[0].license.as_deref(), Some("MIT")); // filled from package.json
        assert_eq!(comps[1].license.as_deref(), Some("Apache-2.0")); // lockfile value kept
    }

    #[test]
    fn lockfile_source_never_reads_package_json() {
        let tmp = tempdir().unwrap();
        write_installed(tmp.path(), "foo", "MIT");
        let mut comps = vec![component("foo", None)];
        enrich_licenses(&mut comps, tmp.path(), LicenseSource::Lockfile);
        assert_eq!(comps[0].license, None);
    }

    #[test]
    fn package_source_prefers_package_json_but_keeps_lockfile_when_uninstalled() {
        let tmp = tempdir().unwrap();
        write_installed(tmp.path(), "foo", "MIT");
        let mut comps = vec![
            component("foo", Some("WTFPL")),
            component("ghost", Some("ISC")),
        ];
        enrich_licenses(&mut comps, tmp.path(), LicenseSource::Package);
        assert_eq!(comps[0].license.as_deref(), Some("MIT")); // overridden from package.json
        assert_eq!(comps[1].license.as_deref(), Some("ISC")); // not installed → lockfile kept
    }
}
