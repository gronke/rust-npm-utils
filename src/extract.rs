//! Archive extraction, hardened against hostile archives.
//!
//! Both [`tar_gz`] and [`zip`] iterate an archive in memory and write selected entries beneath
//! `dest`. `strip_prefix` (e.g. `Some("package/")` for npm tarballs) is removed from each entry
//! path before [`Select`] is applied.
//!
//! Archive contents are untrusted input, so extraction is defended in layers:
//!
//! - **Entry-type allowlist** — only regular files and directories are written; symlinks,
//!   hardlinks, device nodes, FIFOs and sockets are skipped, so an archive can't plant a link or
//!   special file.
//! - **Structural path check** ([`crate::path_safety::safe_join`]) — reject `..`, absolute,
//!   root/drive, and backslash segments before touching the filesystem.
//! - **Symlink-resolved containment** ([`crate::path_safety::contained_target`]) — each write's
//!   parent is canonicalized and required to stay within the canonicalized `dest`, so even a
//!   symlink already on disk (pre-existing, or from a destination shared across calls) can't
//!   redirect a write outside it.
//! - **Size cap** — entries are streamed (never buffered whole) and the total is bounded, so a
//!   decompression bomb can't exhaust memory or disk.

use flate2::read::GzDecoder;
use std::fs::{create_dir_all, File};
use std::io::{Cursor, Read, Write};
use std::path::Path;
use tar::Archive;

use crate::path_safety::{contained_target, safe_join};

/// Which archive entries to extract, and where each lands (relative to `dest`).
pub enum Select<'a> {
    /// Every file, keeping its (prefix-stripped) path. Directory entries create
    /// directories; non-regular entries (symlinks, hardlinks, devices) are skipped.
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
    let mut total: u64 = 0;
    let mut entries: u64 = 0;
    // The real (symlink-resolved) absolute path every write must stay under.
    create_dir_all(dest)?;
    let root = dest.canonicalize()?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(too_many_entries());
        }
        let entry_type = entry.header().entry_type();
        let is_dir = entry_type.is_dir();
        // Materialize only regular files and (for `Select::All`) directories. Symlinks,
        // hardlinks, device nodes, FIFOs and sockets are skipped — an archive must not create a
        // link or special file that could redirect a later write or otherwise surprise the caller.
        if !is_dir && !entry_type.is_file() {
            continue;
        }
        let path = entry.path()?;
        let path_str = path.to_string_lossy().into_owned();
        let rel = strip(&path_str, strip_prefix);
        // Skip the archive root itself (`.` or empty after the prefix strip): an entry naming
        // the destination directory must never replace it or be written over it.
        if is_root_entry(rel) {
            continue;
        }
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
        let target = contained_target(&root, &out)?;
        let mut file = File::create(&target)?;
        total += copy_capped(&mut entry, &mut file, MAX_TOTAL_BYTES.saturating_sub(total))?;
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
    if archive.len() as u64 > MAX_ENTRIES {
        return Err(too_many_entries());
    }
    let mut count = 0;
    let mut total: u64 = 0;
    // The real (symlink-resolved) absolute path every write must stay under.
    create_dir_all(dest)?;
    let root = dest.canonicalize()?;
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
        // Skip the archive root itself (`.`/empty), as in `tar_gz`.
        if is_root_entry(rel) {
            continue;
        }
        let Some(dest_rel) = select.dest_for(rel) else {
            continue;
        };
        let out = safe_join(dest, &dest_rel)?;
        let target = contained_target(&root, &out)?;
        let mut writer = File::create(&target)?;
        total += copy_capped(
            &mut file,
            &mut writer,
            MAX_TOTAL_BYTES.saturating_sub(total),
        )?;
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

/// Whether a (prefix-stripped) entry path refers to the destination root itself — `.` or the
/// empty string. Such an entry names the package directory, so it is skipped: the root must
/// never be written or linked over.
fn is_root_entry(rel: &str) -> bool {
    rel.is_empty() || rel == "."
}

/// Ceiling on the total bytes one archive may expand to on disk. A compressed archive can
/// inflate enormously (a "decompression bomb"); without a cap a small download could exhaust
/// memory or disk. Generous for real packages — even a large `node_modules` is a few hundred
/// MB — while a bomb is orders of magnitude bigger.
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Ceiling on the number of entries one archive may contain. Bounds inode-exhaustion archives
/// (millions of tiny files or directories) that the byte cap alone wouldn't catch. Far above
/// any real single package, which has at most a few thousand files.
const MAX_ENTRIES: u64 = 200_000;

fn too_many_entries() -> Box<dyn std::error::Error> {
    format!("archive has more than {MAX_ENTRIES} entries (possible archive bomb)").into()
}

/// Stream `reader` into `writer`, writing at most `budget` bytes and erroring if the source
/// has more — i.e. if the archive's running total would exceed [`MAX_TOTAL_BYTES`]. Streaming
/// (rather than buffering the whole entry) means a single huge entry can't OOM the process,
/// and the budget bounds total disk use. Returns the number of bytes written.
fn copy_capped<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    budget: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    // Read one byte past the budget, so an over-budget entry is detected rather than silently
    // truncated to the limit.
    let written = std::io::copy(&mut reader.take(budget.saturating_add(1)), writer)?;
    if written > budget {
        return Err(
            "archive exceeds the extraction size limit (possible decompression bomb)".into(),
        );
    }
    Ok(written)
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

    #[test]
    #[cfg(unix)]
    fn rejects_writing_through_a_preexisting_symlink() {
        use std::os::unix::fs::symlink;
        // The footgun: a symlink already inside `dest` points outside it, and an archive
        // writes a file *through* it. The canonicalized-containment guard must refuse, and
        // nothing may land outside `dest`.
        let tmp = tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dest.join("evil")).unwrap();

        let tgz = make_tar_gz(&[("package/evil/pwned", b"owned")]);
        let result = tar_gz(&tgz, &dest, Some("package/"), Select::All);

        assert!(
            result.is_err(),
            "must refuse to write through an escaping symlink"
        );
        assert!(
            !outside.join("pwned").exists(),
            "nothing may be written outside the extract dir"
        );
    }

    #[test]
    fn odd_but_legal_entry_names_stay_contained() {
        // Scary-looking but non-traversal entry names must land *under* `dest`, never escape:
        // `...` and `~` are ordinary directory names, and `file://` is just part of a filename
        // (we never interpret it as a URL).
        let tmp = tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let tgz = make_tar_gz(&[
            (".../flag.txt", b"a"),
            ("~/flag.txt", b"b"),
            ("file:///tmp/flag.txt", b"c"),
        ]);
        let n = tar_gz(&tgz, &dest, None, Select::All).unwrap();
        assert_eq!(n, 3);
        assert!(dest.join("...").join("flag.txt").is_file());
        assert!(dest.join("~").join("flag.txt").is_file());
        // "file:///tmp/flag.txt" → a dir named "file:", then tmp/flag.txt — all under dest.
        assert!(dest.join("file:").join("tmp").join("flag.txt").is_file());
        // Crucially, nothing escaped to dest's parent (no `/tmp` write, no parent-dir write).
        assert!(!tmp.path().join("flag.txt").exists());
    }

    /// A tarball carrying a symlink entry, a hardlink entry, and one regular file.
    fn tar_with_links() -> Vec<u8> {
        let mut b = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        let mut reg = tar::Header::new_gnu();
        reg.set_size(4);
        reg.set_mode(0o644);
        reg.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut reg, "real.txt", IoCursor::new(&b"data"[..]))
            .unwrap();

        let mut sym = tar::Header::new_gnu();
        sym.set_size(0);
        sym.set_mode(0o777);
        sym.set_entry_type(tar::EntryType::Symlink);
        b.append_link(&mut sym, "evil-symlink", "real.txt").unwrap();

        let mut hard = tar::Header::new_gnu();
        hard.set_size(0);
        hard.set_mode(0o644);
        hard.set_entry_type(tar::EntryType::Link);
        b.append_link(&mut hard, "evil-hardlink", "real.txt")
            .unwrap();

        b.finish().unwrap();
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn skips_symlink_and_hardlink_entries() {
        // Only regular files and directories are materialized; link entries (which could
        // redirect a later write or point outside the tree) are never created.
        let tmp = tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let n = tar_gz(&tar_with_links(), &dest, None, Select::All).unwrap();
        assert_eq!(n, 1, "only the regular file is written");
        assert!(dest.join("real.txt").is_file());
        assert!(!dest.join("evil-symlink").exists());
        assert!(!dest.join("evil-hardlink").exists());
    }

    #[test]
    fn copy_capped_streams_within_budget_and_rejects_a_bomb() {
        let src = vec![7u8; 1000];
        // Within budget: the whole stream is copied.
        let mut ok = Vec::new();
        assert_eq!(
            copy_capped(&mut src.as_slice(), &mut ok, 2000).unwrap(),
            1000
        );
        assert_eq!(ok, src);
        // Over budget (the decompression-bomb case): errors rather than truncating silently.
        let mut overflow = Vec::new();
        assert!(copy_capped(&mut src.as_slice(), &mut overflow, 100).is_err());
    }

    #[test]
    fn is_root_entry_flags_dot_and_empty() {
        // `.` and "" name the destination root itself and are skipped, so no entry — least of
        // all a symlink — can replace or be written over the package directory.
        assert!(is_root_entry("."));
        assert!(is_root_entry(""));
        assert!(!is_root_entry("index.js"));
        assert!(!is_root_entry("./index.js"));
        assert!(!is_root_entry("..."));
    }

    #[test]
    fn refuses_to_write_at_the_destination_root() {
        // A `.`/empty *entry* is skipped (is_root_entry); a selection mapping straight onto the
        // root is caught by the containment check (the root's parent is above it). Either way the
        // destination directory itself is never overwritten.
        let tmp = tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let tgz = make_tar_gz(&[("package/x.js", b"x")]);
        let onto_root = |_rel: &str| -> Option<String> { Some(".".to_string()) };
        let result = tar_gz(&tgz, &dest, Some("package/"), Select::Matching(&onto_root));
        assert!(result.is_err(), "writing onto the root must be refused");
        assert!(
            dest.is_dir(),
            "the destination root remains a real directory"
        );
    }
}
