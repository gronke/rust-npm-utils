//! Skip-if-unchanged cache helpers: content-hash markers, a cross-process build
//! lock, and directory utilities.

use std::fs::{self, create_dir_all};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

/// Run `f` while holding an exclusive cross-process lock on `lock_path`.
///
/// A build script may be invoked concurrently for multiple compile units of the
/// same crate (e.g. the host-profile build-dep unit and the target-profile unit
/// of a `links` crate). This serializes a download/extract block via an
/// atomic-create lock file so concurrent invocations don't race on shared
/// writes; the second waiter typically observes a fresh marker and skips its own
/// work. A lock held longer than 120 s (e.g. a crashed previous holder) is
/// treated as stale, removed, and the wait continues.
pub fn with_lock<F: FnOnce() -> R, R>(lock_path: &Path) -> impl FnOnce(F) -> R {
    let lock_path = lock_path.to_path_buf();
    move |f: F| -> R {
        if let Some(parent) = lock_path.parent() {
            let _ = create_dir_all(parent);
        }
        let start = Instant::now();
        let max_wait = Duration::from_secs(120);
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", std::process::id());
                    drop(file);
                    let result = f();
                    let _ = fs::remove_file(&lock_path);
                    return result;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if start.elapsed() > max_wait {
                        eprintln!(
                            "rust-npm-utils: lock at {} held for {}s — assuming stale and continuing",
                            lock_path.display(),
                            start.elapsed().as_secs()
                        );
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => panic!(
                    "rust-npm-utils: failed to acquire lock at {}: {}",
                    lock_path.display(),
                    e
                ),
            }
        }
    }
}

/// Whether a directory exists and contains at least one entry.
pub fn dir_has_content(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    match std::fs::read_dir(dir) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => false,
    }
}

/// Compute a fast, position-weighted hash of a file's contents.
///
/// Not cryptographically secure — sufficient for cache invalidation (detecting
/// that an input changed), not for integrity verification.
pub fn file_hash(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let mut hash: u64 = 0;
    for (i, byte) in contents.iter().enumerate() {
        hash = hash.wrapping_add((*byte as u64).wrapping_mul((i as u64).wrapping_add(1)));
    }
    Ok(format!("{:016x}", hash))
}

/// Whether a marker file exists and its contents equal `expected_hash`.
pub fn marker_matches(marker_path: &Path, expected_hash: &str) -> bool {
    match fs::read_to_string(marker_path) {
        Ok(content) => content.trim() == expected_hash,
        Err(_) => false,
    }
}

/// Write `hash` to a marker file.
pub fn write_marker(marker_path: &Path, hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::File::create(marker_path)?;
    file.write_all(hash.as_bytes())?;
    Ok(())
}

/// Remove and recreate a directory.
///
/// Retries on `ENOTEMPTY` — observed under CI overlay/tmpfs filesystems where
/// the final `rmdir` races with leftover dentries even after all children are
/// gone. Linux returns 39, macOS/BSD return 66 — match both.
pub fn clear_directory(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if dir.exists() {
        let mut delay_ms: u64 = 50;
        let mut attempts = 0;
        loop {
            match fs::remove_dir_all(dir) {
                Ok(()) => break,
                Err(e) if is_not_empty_error(&e) && attempts < 5 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(delay_ms));
                    delay_ms *= 2;
                }
                Err(e) => return Err(Box::new(e)),
            }
        }
    }
    create_dir_all(dir)?;
    Ok(())
}

fn is_not_empty_error(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(39) | Some(66))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn hash_changes_with_content_and_markers_round_trip() {
        let tmp = tempdir().unwrap();
        let f = tmp.path().join("input");
        fs::write(&f, b"alpha").unwrap();
        let h1 = file_hash(&f).unwrap();
        fs::write(&f, b"alphb").unwrap();
        let h2 = file_hash(&f).unwrap();
        assert_ne!(h1, h2);

        let marker = tmp.path().join(".marker");
        assert!(!marker_matches(&marker, &h2));
        write_marker(&marker, &h2).unwrap();
        assert!(marker_matches(&marker, &h2));
        assert!(!marker_matches(&marker, &h1));
    }

    #[test]
    fn clear_directory_empties_and_recreates() {
        let tmp = tempdir().unwrap();
        let d = tmp.path().join("d");
        fs::create_dir_all(d.join("nested")).unwrap();
        fs::write(d.join("nested/file"), b"x").unwrap();
        assert!(dir_has_content(&d));
        clear_directory(&d).unwrap();
        assert!(d.exists());
        assert!(!dir_has_content(&d));
    }

    #[test]
    fn with_lock_runs_the_closure_and_releases() {
        let tmp = tempdir().unwrap();
        let lock = tmp.path().join(".lock");
        let out = with_lock(&lock)(|| 42);
        assert_eq!(out, 42);
        assert!(!lock.exists(), "lock should be released");
    }
}
