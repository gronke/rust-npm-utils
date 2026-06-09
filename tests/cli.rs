#![cfg(feature = "cli")]
//! End-to-end test of the `npm-utils` CLI, driving the real binary the way a user does. The
//! library unit-tests the pure pieces (manifest/lock writers, arg parsing); this exercises the
//! whole `init → add → ci → upgrade` flow against the live registry, so it is network-gated:
//!
//! ```text
//! cargo test --features cli --test cli -- --include-ignored
//! ```
//!
//! `ms` is a tiny, dependency-free, long-frozen package — a stable target whose tarball carries a
//! known sha512, so integrity is genuinely verified end to end.

use std::process::Command;

/// The CLI binary. Cargo sets `CARGO_BIN_EXE_npm-utils` because the bin's `required-features`
/// (`cli`) are active for this test build.
fn npm_utils() -> Command {
    Command::new(env!("CARGO_BIN_EXE_npm-utils"))
}

fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    assert!(
        out.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "network: fetches ms from the npm registry"]
fn init_add_ci_upgrade_roundtrip() {
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().to_str().unwrap();

    // init → a package.json is scaffolded.
    run(
        npm_utils().args(["init", "--dir", dir, "--name", "demo"]),
        "init",
    );
    assert!(project.path().join("package.json").is_file());

    // add ms@^2 → manifest records the range, a v3 lock pins the resolved version with a real
    // sha512, and node_modules/ is populated.
    let stdout = run(npm_utils().args(["add", "ms@^2", "--dir", dir]), "add");
    assert!(
        stdout.contains("installed"),
        "add reports an install: {stdout}"
    );

    let manifest = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    assert!(
        manifest.contains("\"ms\""),
        "manifest records ms:\n{manifest}"
    );

    let lock = std::fs::read_to_string(project.path().join("package-lock.json")).unwrap();
    assert!(lock.contains("\"lockfileVersion\": 3"), "v3 lock:\n{lock}");
    assert!(lock.contains("node_modules/ms"), "lock pins ms");
    assert!(lock.contains("sha512-"), "lock carries integrity");
    assert!(
        project
            .path()
            .join("node_modules/ms/package.json")
            .is_file(),
        "ms downloaded, integrity-verified, extracted"
    );

    // ci in a FRESH dir from that exact lock reproduces the tree (the lock we wrote is consumable
    // by the npm-ci path).
    let fresh = tempfile::tempdir().unwrap();
    std::fs::copy(
        project.path().join("package-lock.json"),
        fresh.path().join("package-lock.json"),
    )
    .unwrap();
    run(
        npm_utils().args(["ci", fresh.path().to_str().unwrap()]),
        "ci",
    );
    assert!(
        fresh.path().join("node_modules/ms/package.json").is_file(),
        "ci reproduced ms from the generated lock"
    );

    // upgrade re-resolves within `^2` and refreshes the lock/tree without error (it may bump the
    // recorded floor to the latest 2.x — both outcomes are fine; we assert it stays valid).
    run(npm_utils().args(["upgrade", "--dir", dir]), "upgrade");
    let manifest = std::fs::read_to_string(project.path().join("package.json")).unwrap();
    assert!(
        manifest.contains("\"ms\""),
        "ms still present after upgrade"
    );
}
