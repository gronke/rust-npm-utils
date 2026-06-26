//! Path-traversal hardening shared by [`crate::extract`] and [`crate::install`].
//!
//! Archive and lockfile paths are untrusted. Two layers keep every write inside its intended
//! directory:
//!
//! 1. a cheap **structural** check ([`ensure_within`] / [`safe_join`]) that rejects `..`
//!    (`ParentDir`), absolute / root / drive-prefixed paths, and any segment containing a
//!    backslash (a Windows separator Unix would treat as a filename); and
//! 2. a **filesystem** check ([`contained_target`]) that canonicalizes the resolved parent so a
//!    symlink — one planted by the archive or already present on disk — can't redirect a write
//!    out of the destination.
//!
//! Names that *look* dangerous but don't actually traverse — `...`, `~`, or one literally
//! containing `file://` — are ordinary filenames; we never interpret them, so they're allowed
//! and stay contained rather than rejected (rejecting them would break legitimate packages).

use std::path::{Component, Path, PathBuf};

fn unsafe_path(relative: &str) -> Box<dyn std::error::Error + Send + Sync> {
    format!("unsafe path {relative:?}: refuses to escape the destination").into()
}

/// Validate that `relative` cannot escape a base directory. Rejects an empty path, a `..`
/// (`ParentDir`) component, an absolute / root / drive-prefixed path, and any segment
/// containing a backslash. A leading `.` and ordinary segments — including odd-but-legal
/// names like `...`, `~`, or `file:` — are allowed; none of them traverse.
pub fn ensure_within(relative: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if relative.is_empty() {
        return Err(unsafe_path(relative));
    }
    for component in Path::new(relative).components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(unsafe_path(relative));
            }
            Component::Normal(segment) if segment.to_string_lossy().contains('\\') => {
                return Err(unsafe_path(relative));
            }
            _ => {}
        }
    }
    Ok(())
}

/// `base` joined with a `relative` first validated by [`ensure_within`].
pub fn safe_join(
    base: &Path,
    relative: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    ensure_within(relative)?;
    Ok(base.join(relative))
}

/// Resolve where `out`'s parent really points — creating it, then following symlinks — and
/// require it to stay within `root` (which must already be canonicalized). Returns the real,
/// contained path to write to. This is the symlink-traversal guard: neither a link planted by
/// an archive nor one already on disk in the destination can redirect a write outside it.
pub fn contained_target(
    root: &Path,
    out: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let parent = out
        .parent()
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "path has no parent".into()
        })?;
    std::fs::create_dir_all(parent)?;
    let real_parent = parent.canonicalize()?;
    if !real_parent.starts_with(root) {
        return Err(format!(
            "unsafe path {out:?}: parent resolves outside the destination (symlink traversal?)"
        )
        .into());
    }
    let name = out
        .file_name()
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "path has no file name".into()
        })?;
    // Write into the *resolved* directory, so the final write can't be re-redirected.
    let target = real_parent.join(name);
    if let Ok(meta) = std::fs::symlink_metadata(&target) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "unsafe path {out:?}: destination already exists as a symlink \
                 (refuses to write through it)"
            )
            .into());
        }
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_within_rejects_traversal() {
        for bad in [
            "../flag.txt",
            "./../flag.txt",
            "a/../../flag.txt",
            "/etc/passwd",  // absolute
            "..",           // bare parent
            "",             // empty
            "..\\flag.txt", // backslash (a Windows separator) in a single Unix segment
            "a/..\\..\\b",  // backslash-escapes hidden inside a segment
        ] {
            assert!(ensure_within(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn ensure_within_allows_legal_but_unusual_names() {
        // None of these traverse — they're ordinary (if odd) filenames, so they're allowed and
        // stay contained under the base. We never interpret `~` or `file://` specially.
        for ok in [
            "flag.txt",
            "a/b/c.js",
            "@scope/pkg/index.js",
            ".../flag.txt",         // a directory literally named "..."
            "~/flag.txt",           // a directory literally named "~"
            "file:///tmp/flag.txt", // contains "file://" — just a filename to us
            "a..b/c",               // ".." inside a name is not a parent reference
            "./flag.txt",           // a leading "." is fine
        ] {
            assert!(
                ensure_within(ok).is_ok(),
                "{ok:?} is a normal name, must be contained"
            );
        }
    }

    #[test]
    fn safe_join_stays_under_base() {
        let base = Path::new("/srv/node_modules");
        assert_eq!(
            safe_join(base, "@scope/pkg/index.js").unwrap(),
            base.join("@scope/pkg/index.js")
        );
        assert!(safe_join(base, "../escape").is_err());
        assert!(safe_join(base, "a/../b").is_err());
        assert!(safe_join(base, "/abs").is_err());
        assert!(safe_join(base, "").is_err());
    }

    #[test]
    fn contained_target_refuses_the_root_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("pkg");
        std::fs::create_dir_all(&dest).unwrap();
        let root = dest.canonicalize().unwrap();
        // Writing *at* the root (out == root) is refused — its parent is above the root, so a
        // `.`-style entry can never replace the package directory.
        assert!(contained_target(&root, &dest).is_err());
        // A child under the root is allowed.
        assert!(contained_target(&root, &dest.join("file.js")).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn contained_target_refuses_a_preexisting_leaf_symlink() {
        use std::os::unix::fs::symlink;
        // The parent is contained, but the *leaf* itself is a pre-existing symlink pointing
        // outside `root`. `File::create` would follow it, so contained_target must refuse.
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("dest");
        let outside = tmp.path().join("outside.txt");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(&outside, b"original").unwrap();
        let root = dest.canonicalize().unwrap();
        symlink(&outside, dest.join("leaf")).unwrap();
        assert!(
            contained_target(&root, &dest.join("leaf")).is_err(),
            "a pre-existing leaf symlink must be refused"
        );
    }
}
