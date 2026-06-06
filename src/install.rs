//! Install a `package.json`'s transitive dependency tree into a `node_modules/`
//! directory — a minimal, pure-Rust "npm install".
//!
//! [`node_modules`] resolves the dependency graph against the registry (see
//! [`crate::registry::Registry::resolve_tree`]) and extracts every package into the
//! conventional flat `node_modules/<name>/` layout (scoped names land at
//! `node_modules/@scope/<name>/`). It is skip-if-unchanged — a marker keyed on the
//! resolved version set — and safe under concurrent build scripts via a cross-process
//! lock.
//!
//! This complements the single-package, import-map-oriented vendoring helpers: it
//! produces a real `node_modules/` tree (CommonJS and all) for tooling (`tsc`) or a
//! downstream bundler to consume — not browser ES modules directly.

use std::path::{Path, PathBuf};

use semver::VersionReq;
use serde_json::Value;

use crate::registry::{version_req, Registry, Resolved};
use crate::{cache, download, extract};

/// Resolve `package_json`'s dependencies transitively and extract the flat tree into
/// `<dest>/node_modules/`. Returns the resolved package set (sorted by name).
///
/// Skips all work when the resolved version set is unchanged and `node_modules/` is
/// already populated. Serialized across concurrent invocations by a lock kept beside
/// `node_modules/` (a refresh wipes `node_modules/` itself, so the lock/marker can't
/// live inside it).
pub fn node_modules(
    package_json: &Path,
    dest: &Path,
) -> Result<Vec<Resolved>, Box<dyn std::error::Error>> {
    let roots = root_requirements(package_json)?;
    let resolved = Registry::npm().resolve_tree(&roots)?;

    let node_modules = dest.join("node_modules");
    let lock = dest.join(".node_modules.lock");
    let marker = dest.join(".node_modules.marker");
    let want = resolved
        .iter()
        .map(|r| format!("{}@{}", r.name, r.version))
        .collect::<Vec<_>>()
        .join("\n");

    cache::with_lock(&lock)(|| -> Result<(), Box<dyn std::error::Error>> {
        if cache::dir_has_content(&node_modules) && cache::marker_matches(&marker, &want) {
            return Ok(()); // already up to date
        }
        cache::clear_directory(&node_modules)?;
        for pkg in &resolved {
            let bytes = download::fetch(&pkg.tarball_url)?;
            let dir = package_dir(&node_modules, &pkg.name)?;
            extract::tar_gz(&bytes, &dir, Some("package/"), extract::Select::All)?;
        }
        cache::write_marker(&marker, &want)?;
        Ok(())
    })?;

    Ok(resolved)
}

/// The root requirements: each `dependencies` entry as `(name, VersionReq)`, npm-faithful
/// (a bare version pins exactly). Registry specs only — a git/URL spec errors here.
fn root_requirements(
    package_json: &Path,
) -> Result<Vec<(String, VersionReq)>, Box<dyn std::error::Error>> {
    let json: Value = serde_json::from_str(&std::fs::read_to_string(package_json)?)?;
    let deps = json
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or("no dependencies section in package.json")?;
    let mut out = Vec::new();
    for (name, value) in deps {
        let Some(spec) = value.as_str() else { continue };
        let req = version_req(spec)
            .map_err(|e| format!("dependency `{name}`: unsupported version {spec:?}: {e}"))?;
        out.push((name.clone(), req));
    }
    Ok(out)
}

/// `node_modules/<name>/`, handling scoped names (`@scope/pkg` → `@scope/pkg`) and
/// rejecting any segment that would escape the tree.
fn package_dir(node_modules: &Path, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut dir = node_modules.to_path_buf();
    for segment in name.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.contains('\\') {
            return Err(format!("unsafe package name {name:?}").into());
        }
        dir.push(segment);
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn package_dir_handles_scoped_and_rejects_escapes() {
        let nm = Path::new("/tmp/nm");
        assert_eq!(package_dir(nm, "react").unwrap(), nm.join("react"));
        assert_eq!(
            package_dir(nm, "@preact/signals").unwrap(),
            nm.join("@preact").join("signals")
        );
        assert!(package_dir(nm, "../escape").is_err());
        assert!(package_dir(nm, "a/../b").is_err());
        assert!(package_dir(nm, "/abs").is_err());
    }

    fn tiny_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, contents) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(contents.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, *path, Cursor::new(*contents))
                .unwrap();
        }
        b.finish().unwrap();
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extracts_a_package_into_the_node_modules_layout() {
        // The per-package extraction step (offline): a scoped package lands under
        // node_modules/@scope/pkg/ with the npm `package/` prefix stripped.
        let tmp = tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        let tgz = tiny_tgz(&[
            (
                "package/package.json",
                br#"{"name":"@scope/pkg","version":"1.0.0"}"#,
            ),
            ("package/index.js", b"export default 1;"),
        ]);
        let dir = package_dir(&nm, "@scope/pkg").unwrap();
        extract::tar_gz(&tgz, &dir, Some("package/"), extract::Select::All).unwrap();
        assert!(nm.join("@scope/pkg/package.json").is_file());
        assert!(nm.join("@scope/pkg/index.js").is_file());
    }

    #[test]
    #[ignore = "network: hits the npm registry"]
    fn installs_react_with_transitive_scheduler() {
        // Real install of the React-showcase deps. react-dom depends on scheduler, so a
        // correct transitive resolve produces all three under node_modules/.
        let tmp = tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{ "dependencies": { "react": "^19", "react-dom": "^19" } }"#,
        )
        .unwrap();

        let resolved = node_modules(&pkg, tmp.path()).unwrap();
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"react"), "got {names:?}");
        assert!(names.contains(&"react-dom"), "got {names:?}");
        assert!(
            names.contains(&"scheduler"),
            "transitive dep missing: {names:?}"
        );

        let nm = tmp.path().join("node_modules");
        for p in ["react", "react-dom", "scheduler"] {
            assert!(
                nm.join(p).join("package.json").is_file(),
                "node_modules/{p}/package.json missing"
            );
        }
    }

    #[test]
    #[ignore = "network: hits the npm registry"]
    fn downloads_and_extracts_a_commonjs_package() {
        use crate::package_json::{PackageJson, PackageType};
        // `ms` is a tiny, dependency-free, long-frozen CommonJS package — a focused check
        // that we download + extract a real CJS package *intact*. CommonJS is exactly the
        // case a buildless ESM tree can't serve directly, which is why node_modules/ exists.
        let tmp = tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(&pkg, r#"{ "dependencies": { "ms": "^2" } }"#).unwrap();

        let resolved = node_modules(&pkg, tmp.path()).unwrap();
        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["ms"], "ms has no runtime dependencies");

        let ms = tmp.path().join("node_modules/ms");
        let manifest = PackageJson::from_path(&ms.join("package.json")).unwrap();
        assert_eq!(manifest.name(), Some("ms"));
        assert_eq!(
            manifest.package_type(),
            PackageType::CommonJs,
            "ms ships CommonJS"
        );
        // The JS itself extracted to disk and really is CommonJS source. (`ms`'s "main"
        // is the extension-less "./index"; the file on disk is index.js per its "files".)
        let entry = ms.join("index.js");
        let source = std::fs::read_to_string(&entry).unwrap();
        assert!(
            source.contains("module.exports"),
            "extracted entry {entry:?} is CommonJS source"
        );
    }
}
