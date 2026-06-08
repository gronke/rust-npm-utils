//! Install a dependency tree into a `node_modules/` directory — a pure-Rust "npm install"
//! ([`node_modules`], from a `package.json`) and "npm ci" ([`from_lockfile`], from a
//! `package-lock.json`). Each downloads, integrity-verifies, and extracts every package; the
//! lockfile path also creates `node_modules/.bin/` shims. Both are skip-if-unchanged (a marker
//! beside `node_modules/`) and concurrency-safe via a cross-process lock.
//!
//! The npm-format *parsing* lives in the [`crate::package_json`] module; this module is the *action* that
//! orchestrates the primitives ([`crate::registry`], [`crate::download`], [`crate::integrity`],
//! [`crate::extract`]) over those parsed structures — and owns the path-safety step that turns a
//! package name or lockfile key into a contained install directory ([`crate::path_safety`]).

use std::path::Path;

use crate::{cache, download, extract, integrity};

mod lockfile;
mod node_modules;

pub use lockfile::from_lockfile;
pub use node_modules::node_modules;

/// The shared skip-if-unchanged install dance: under a cross-process lock, short-circuit when
/// `node_modules/` is populated and `marker_input` is unchanged; otherwise wipe it, run
/// `populate` (which downloads/verifies/extracts into the given `node_modules` dir), and record
/// the marker. The lock/marker live *beside* `node_modules/` (a refresh wipes the dir itself, so
/// they can't live inside it).
fn run_install(
    dest: &Path,
    marker_input: &str,
    populate: impl FnOnce(&Path) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node_modules = dest.join("node_modules");
    let lock = dest.join(".node_modules.lock");
    let marker = dest.join(".node_modules.marker");
    cache::with_lock(&lock)(|| -> Result<(), Box<dyn std::error::Error>> {
        if cache::dir_has_content(&node_modules) && cache::marker_matches(&marker, marker_input) {
            return Ok(()); // already up to date
        }
        cache::clear_directory(&node_modules)?;
        populate(&node_modules)?;
        cache::write_marker(&marker, marker_input)?;
        Ok(())
    })
}

/// Download one package tarball, verify its sha512 integrity, and extract it into `dir`. A
/// package whose metadata carries no sha512 is refused, not installed unverified.
fn fetch_verify_extract(
    name: &str,
    tarball_url: &str,
    integrity_sri: Option<&str>,
    dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = download::fetch(tarball_url)?;
    integrity::verify(name, &bytes, integrity_sri.unwrap_or(""))?;
    // Strip the tarball's first path component whatever it's named: npm's own pack uses
    // `package/`, but some published tarballs (e.g. `@types/react` → `react v18.3/`) don't, and
    // npm strips the top dir by position, not by name.
    extract::tar_gz(&bytes, dir, None, extract::Select::Matching(&strip_top_dir))?;
    Ok(())
}

/// Drop a tarball entry's first path component (the package's top-level directory), whatever it
/// is named. Entries with no directory component are skipped (`None`).
fn strip_top_dir(rel: &str) -> Option<String> {
    rel.split_once('/')
        .map(|(_, rest)| rest.to_string())
        .filter(|rest| !rest.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_safety::safe_join;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;
    use tempfile::tempdir;

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
    fn strip_top_dir_drops_first_component_regardless_of_name() {
        assert_eq!(
            strip_top_dir("package/index.js").as_deref(),
            Some("index.js")
        );
        // @types/react ships under "react v18.3/", not "package/".
        assert_eq!(
            strip_top_dir("react v18.3/index.d.ts").as_deref(),
            Some("index.d.ts")
        );
        assert_eq!(
            strip_top_dir("root/sub/file.d.ts").as_deref(),
            Some("sub/file.d.ts")
        );
        assert_eq!(strip_top_dir("toplevel"), None); // no directory component → skipped
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
        let dir = safe_join(&nm, "@scope/pkg").unwrap();
        extract::tar_gz(&tgz, &dir, Some("package/"), extract::Select::All).unwrap();
        assert!(nm.join("@scope/pkg/package.json").is_file());
        assert!(nm.join("@scope/pkg/index.js").is_file());
    }

    #[test]
    fn extracts_tarballs_whose_root_is_not_named_package() {
        // Regression for the dogfood-found bug: a package whose tarball root is not `package/`
        // (e.g. `@types/react`'s `react v18.3/`) must still extract into the package dir, not a
        // stray subdir — npm strips the top dir by position, not by name.
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("@types/react");
        let tgz = tiny_tgz(&[
            ("react v18.3/index.d.ts", b"export {};"),
            ("react v18.3/package.json", br#"{"name":"@types/react"}"#),
        ]);
        extract::tar_gz(&tgz, &dir, None, extract::Select::Matching(&strip_top_dir)).unwrap();
        assert!(
            dir.join("index.d.ts").is_file(),
            "top dir stripped by position"
        );
        assert!(dir.join("package.json").is_file());
        assert!(
            !dir.join("react v18.3").exists(),
            "no stray top-level dir remains"
        );
    }
}
