//! Archive extraction with path-traversal protection.
//!
//! Both [`tar_gz`] and [`zip`] iterate an archive in memory and write selected
//! entries beneath `dest`. `strip_prefix` (e.g. `Some("package/")` for npm
//! tarballs) is removed from each entry path before [`Select`] is applied.

use flate2::read::GzDecoder;
use std::fs::{create_dir_all, File};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::Archive;

/// Which archive entries to extract, and where each lands (relative to `dest`).
pub enum Select<'a> {
    /// Every file, keeping its (prefix-stripped) path. Directory entries create
    /// directories; symlinks are skipped.
    All,
    /// Only entries whose (prefix-stripped) path equals a listed source; written
    /// to the paired destination.
    Files(&'a [(&'a str, &'a str)]),
    /// Each entry's (prefix-stripped) path is handed to the closure, which
    /// returns the destination path or `None` to skip the entry.
    Matching(&'a dyn Fn(&str) -> Option<String>),
}

impl Select<'_> {
    /// Resolve an entry's (prefix-stripped) archive path to a destination
    /// relative path, or `None` to skip it.
    fn dest_for(&self, rel: &str) -> Option<String> {
        match self {
            Select::All => Some(rel.to_string()),
            Select::Files(files) => files
                .iter()
                .find(|(src, _)| *src == rel)
                .map(|(_, dst)| dst.to_string()),
            Select::Matching(f) => f(rel),
        }
    }
}

/// Extract a gzipped tarball into `dest`. Returns the number of files written.
pub fn tar_gz(
    bytes: &[u8],
    dest: &Path,
    strip_prefix: Option<&str>,
    select: Select<'_>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut archive = Archive::new(GzDecoder::new(Cursor::new(bytes)));
    let mut count = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() {
            continue;
        }
        let path = entry.path()?;
        let path_str = path.to_string_lossy().into_owned();
        let rel = strip(&path_str, strip_prefix);
        if rel.is_empty() {
            continue;
        }
        let is_dir = entry_type.is_dir();
        if is_dir {
            if matches!(select, Select::All) {
                create_dir_all(safe_join(dest, rel)?)?;
            }
            continue;
        }
        let Some(dest_rel) = select.dest_for(rel) else {
            continue;
        };
        let out = safe_join(dest, &dest_rel)?;
        if let Some(parent) = out.parent() {
            create_dir_all(parent)?;
        }
        let mut content = Vec::new();
        entry.read_to_end(&mut content)?;
        File::create(&out)?.write_all(&content)?;
        count += 1;
    }
    Ok(count)
}

/// Extract a zip archive into `dest`. Returns the number of files written.
pub fn zip(
    bytes: &[u8],
    dest: &Path,
    strip_prefix: Option<&str>,
    select: Select<'_>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let mut count = 0;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() || file.is_symlink() {
            continue;
        }
        let name = match file.enclosed_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => return Err("unsafe zip entry name (escapes destination)".into()),
        };
        let rel = strip(&name, strip_prefix);
        if rel.is_empty() {
            continue;
        }
        let Some(dest_rel) = select.dest_for(rel) else {
            continue;
        };
        let out = safe_join(dest, &dest_rel)?;
        if let Some(parent) = out.parent() {
            create_dir_all(parent)?;
        }
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        File::create(&out)?.write_all(&content)?;
        count += 1;
    }
    Ok(count)
}

fn strip<'a>(path: &'a str, prefix: Option<&str>) -> &'a str {
    match prefix {
        Some(p) => path.strip_prefix(p).unwrap_or(path),
        None => path,
    }
}

/// Join `relative` onto `base`, returning an error for an empty path or anything
/// that would escape `base` (`..`, absolute, or a drive/root prefix). Extraction
/// aborts on such an entry rather than silently skipping it, so a malicious or
/// malformed archive fails loudly instead of being partially written.
fn safe_join(base: &Path, relative: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let reject = || -> Box<dyn std::error::Error> {
        format!("unsafe archive entry path: {relative:?}").into()
    };
    if relative.is_empty() || relative.contains("..") {
        return Err(reject());
    }
    let path = Path::new(relative);
    for component in path.components() {
        match component {
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(reject())
            }
            _ => {}
        }
    }
    Ok(base.join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor as IoCursor;
    use tempfile::tempdir;

    /// Build an in-memory `.tar.gz` from `(path, contents)` pairs.
    fn make_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            builder
                .append_data(&mut header, *path, IoCursor::new(*contents))
                .unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn tar_gz_all_strips_prefix() {
        let tgz = make_tar_gz(&[("package/index.js", b"a"), ("package/sub/util.js", b"b")]);
        let tmp = tempdir().unwrap();
        let n = tar_gz(&tgz, tmp.path(), Some("package/"), Select::All).unwrap();
        assert_eq!(n, 2);
        assert!(tmp.path().join("index.js").exists());
        assert!(tmp.path().join("sub/util.js").exists());
    }

    #[test]
    fn tar_gz_files_picks_named_entries() {
        let tgz = make_tar_gz(&[
            ("package/dist/sprite.svg", b"<svg/>"),
            ("package/readme.md", b"x"),
        ]);
        let tmp = tempdir().unwrap();
        let n = tar_gz(
            &tgz,
            tmp.path(),
            Some("package/"),
            Select::Files(&[("dist/sprite.svg", "icons/sprite.svg")]),
        )
        .unwrap();
        assert_eq!(n, 1);
        assert!(tmp.path().join("icons/sprite.svg").exists());
        assert!(!tmp.path().join("readme.md").exists());
    }

    #[test]
    fn tar_gz_matching_predicate_and_prefix() {
        let tgz = make_tar_gz(&[
            ("package/a.js", b"x"),
            ("package/b.css", b"y"),
            ("package/c.mjs", b"z"),
        ]);
        let tmp = tempdir().unwrap();
        let keep_js = |rel: &str| -> Option<String> {
            (rel.ends_with(".js") || rel.ends_with(".mjs")).then(|| format!("lit/{rel}"))
        };
        let n = tar_gz(
            &tgz,
            tmp.path(),
            Some("package/"),
            Select::Matching(&keep_js),
        )
        .unwrap();
        assert_eq!(n, 2);
        assert!(tmp.path().join("lit/a.js").exists());
        assert!(tmp.path().join("lit/c.mjs").exists());
        assert!(!tmp.path().join("lit/b.css").exists());
    }

    #[test]
    fn safe_join_rejects_escapes() {
        let base = Path::new("/tmp/base");
        assert!(safe_join(base, "../escape").is_err());
        assert!(safe_join(base, "/abs").is_err());
        assert!(safe_join(base, "a/../b").is_err());
        assert!(safe_join(base, "").is_err());
        assert!(safe_join(base, "a/b.js").is_ok());
    }

    #[test]
    fn tar_gz_errors_when_selection_escapes_dest() {
        // Benign archive, but the selection maps an entry to a path that escapes
        // `dest` — extraction must abort, not silently skip.
        let tgz = make_tar_gz(&[("package/x.js", b"x")]);
        let tmp = tempdir().unwrap();
        let escape = |_rel: &str| -> Option<String> { Some("../escape.js".to_string()) };
        let result = tar_gz(
            &tgz,
            tmp.path(),
            Some("package/"),
            Select::Matching(&escape),
        );
        assert!(result.is_err(), "extraction must error when a dest escapes");
    }
}
