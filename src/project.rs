//! Project-level mutations: operations on a directory that holds a `package.json` — keep the lock
//! and `node_modules/` in step with the manifest ([`sync`]), upgrade dependencies within their
//! ranges ([`upgrade`], previewable with [`plan_upgrade`]), and remove them ([`remove`]).
//!
//! The manifest/lockfile *transforms* stay pure in [`crate::package_json`]; this module is the file
//! IO + orchestration that composes them with [`crate::registry`] resolution and [`crate::install`],
//! the same way the CLI's `add` / `upgrade` verbs do. Each mutating call rewrites `package.json` and
//! a fresh v3 `package-lock.json`, then installs the locked tree (every tarball sha512-verified).

use std::path::Path;

use serde_json::Value;

use crate::install::from_lockfile;
use crate::package_json::{lock, manifest, spec};
use crate::registry::{PackumentDetail, Registry, Resolved};
use crate::Result;

/// A single dependency version-range change — the unit of an [`upgrade`] plan (`from` → `to`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The dependency name.
    pub name: String,
    /// The range as written in `package.json` before the upgrade.
    pub from: String,
    /// The range after bumping its floor to the newly resolved version.
    pub to: String,
}

/// Read and parse `<dir>/package.json`, erroring clearly if it is missing or not a JSON object.
pub fn read_manifest(dir: &Path) -> Result<Value> {
    let path = dir.join("package.json");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let doc: Value =
        serde_json::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    if !doc.is_object() {
        return Err(format!("{} is not a JSON object", path.display()).into());
    }
    Ok(doc)
}

/// Write a manifest back as pretty JSON (npm's two-space indent + trailing newline).
pub fn write_manifest(dir: &Path, doc: &Value) -> Result<()> {
    std::fs::write(dir.join("package.json"), manifest::to_pretty(doc))?;
    Ok(())
}

/// Make `package-lock.json` + `node_modules/` a function of the manifest: write a fresh v3 lockfile
/// from the resolved registry dependency tree (licenses per `detail`), then install from it (every
/// tarball's sha512 verified). Returns the installed packages. Non-registry deps (git/`file:`) are
/// recorded in the manifest but not resolved.
pub fn sync(dir: &Path, doc: &Value, detail: PackumentDetail) -> Result<Vec<Resolved>> {
    let lockfile = dir.join("package-lock.json");
    std::fs::write(
        &lockfile,
        lock::render_v3_from_manifest(doc, &Registry::npm().with_detail(detail))?,
    )?;
    from_lockfile(&lockfile, dir)
}

/// Compute the upgrade plan **without writing anything** (the dry-run): for each selected registry
/// dependency, re-resolve within its range and, when the range floats (`^`/`~`), bump its floor to
/// the resolved version. An empty `packages` means every dependency; exact pins and complex ranges
/// are left untouched (npm honors them too), so they never appear as a [`Change`].
pub fn plan_upgrade(doc: &Value, packages: &[String], registry: &Registry) -> Result<Vec<Change>> {
    plan_upgrade_with(doc, packages, |name, range| registry.resolve(name, range))
}

/// [`plan_upgrade`] with an injectable resolver, so the plan logic can be unit-tested without the
/// network (mirroring [`Registry::resolve_tree`]'s test seam).
fn plan_upgrade_with<F>(doc: &Value, packages: &[String], mut resolve: F) -> Result<Vec<Change>>
where
    F: FnMut(&str, &spec::Range) -> Result<Resolved>,
{
    let mut changes = Vec::new();
    for (name, range) in manifest::dependencies(doc) {
        if !packages.is_empty() && !packages.contains(&name) {
            continue;
        }
        if !spec::Spec::parse(&range).is_registry() {
            continue; // git / file / tarball — nothing to re-resolve from the registry
        }
        let resolved = resolve(&name, &spec::Range::parse(&range)?)?;
        if let Some(bumped) = bump_floor(&range, &resolved.version) {
            if bumped != range {
                changes.push(Change {
                    name,
                    from: range,
                    to: bumped,
                });
            }
        }
    }
    Ok(changes)
}

/// Upgrade dependencies within their ranges (= `npm update`): compute the plan ([`plan_upgrade`]
/// against the public registry), apply each [`Change`] to `package.json`, then [`sync`]. Returns the
/// applied changes and the freshly installed tree. Writes nothing beyond the manifest, lockfile, and
/// `node_modules/`; a run with no floating updates leaves the manifest byte-identical.
pub fn upgrade(
    dir: &Path,
    packages: &[String],
    detail: PackumentDetail,
) -> Result<(Vec<Change>, Vec<Resolved>)> {
    let mut doc = read_manifest(dir)?;
    let changes = plan_upgrade(&doc, packages, &Registry::npm())?;
    for change in &changes {
        manifest::upsert_dependency(&mut doc, &change.name, &change.to);
    }
    write_manifest(dir, &doc)?;
    let installed = sync(dir, &doc, detail)?;
    Ok((changes, installed))
}

/// Remove dependencies (= `npm remove`): drop each named dependency from `package.json`, rewrite the
/// lock, reinstall the remaining tree, and delete each removed package's `node_modules/<name>`
/// directory (best-effort — `sync` reinstalls what remains but does not prune a dropped package).
/// Returns the names actually removed (a name absent from `dependencies` is skipped) and the
/// reinstalled tree.
pub fn remove(
    dir: &Path,
    names: &[String],
    detail: PackumentDetail,
) -> Result<(Vec<String>, Vec<Resolved>)> {
    let mut doc = read_manifest(dir)?;
    let mut removed = Vec::new();
    for name in names {
        if manifest::remove_dependency(&mut doc, name) {
            removed.push(name.clone());
        }
    }
    write_manifest(dir, &doc)?;
    let installed = sync(dir, &doc, detail)?;
    for name in &removed {
        // Scoped names resolve to `node_modules/@scope/pkg`; a missing directory is not an error.
        let _ = std::fs::remove_dir_all(dir.join("node_modules").join(name));
    }
    Ok((removed, installed))
}

/// For a caret/tilde range, return it with the floor set to `version` (`^3.1.0` + 3.4.2 → `^3.4.2`).
/// `None` for any other shape (exact pin, `*`, comparator range) — left as written.
pub fn bump_floor(range: &str, version: &semver::Version) -> Option<String> {
    match range.chars().next() {
        Some(prefix @ ('^' | '~')) => Some(format!("{prefix}{version}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_floor_only_moves_floating_ranges() {
        let v = semver::Version::parse("3.4.2").unwrap();
        assert_eq!(bump_floor("^3.1.0", &v).as_deref(), Some("^3.4.2"));
        assert_eq!(bump_floor("~3.1.0", &v).as_deref(), Some("~3.4.2"));
        // Exact pins and any non-^/~ shape are left untouched.
        assert_eq!(bump_floor("3.1.0", &v), None);
        assert_eq!(bump_floor("*", &v), None);
        assert_eq!(bump_floor(">=3 <4", &v), None);
    }

    /// A `Resolved` at `version` — enough to drive [`plan_upgrade_with`]'s bump decision offline.
    fn resolved_at(version: &str) -> Resolved {
        Resolved {
            name: String::new(),
            version: semver::Version::parse(version).unwrap(),
            tarball_url: String::new(),
            integrity: None,
            license: None,
        }
    }

    #[test]
    fn plan_upgrade_bumps_floating_and_skips_pinned_filtered_and_non_registry() {
        let doc: Value = serde_json::from_str(
            r#"{"name":"app","version":"1.0.0","dependencies":{
                 "lit":"^3.0.0","ms":"~2.1.0","pinned":"1.2.3","gitdep":"github:o/r"
               }}"#,
        )
        .unwrap();

        // Resolve everything to 9.9.9. `dependencies` is sorted (gitdep, lit, ms, pinned): gitdep is
        // non-registry (skipped, never resolved); lit/ms float and bump; pinned is an exact pin, so
        // its floor never moves.
        let all = plan_upgrade_with(&doc, &[], |_n, _r| Ok(resolved_at("9.9.9"))).unwrap();
        assert_eq!(
            all,
            vec![
                Change {
                    name: "lit".into(),
                    from: "^3.0.0".into(),
                    to: "^9.9.9".into()
                },
                Change {
                    name: "ms".into(),
                    from: "~2.1.0".into(),
                    to: "~9.9.9".into()
                },
            ]
        );

        // A package filter narrows the plan to just the named dependency.
        let filtered =
            plan_upgrade_with(&doc, &["lit".into()], |_n, _r| Ok(resolved_at("9.9.9"))).unwrap();
        assert_eq!(
            filtered,
            vec![Change {
                name: "lit".into(),
                from: "^3.0.0".into(),
                to: "^9.9.9".into()
            }]
        );
    }

    #[test]
    fn plan_upgrade_is_empty_when_nothing_floats() {
        // A floating range already at the resolved version yields no change.
        let doc: Value =
            serde_json::from_str(r#"{"name":"app","dependencies":{"lit":"^9.9.9"}}"#).unwrap();
        let changes = plan_upgrade_with(&doc, &[], |_n, _r| Ok(resolved_at("9.9.9"))).unwrap();
        assert!(
            changes.is_empty(),
            "no floor move → empty plan: {changes:?}"
        );
    }
}
