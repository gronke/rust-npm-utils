//! Pure-Rust utilities for the npm registry and web assets.
//!
//! Building blocks for fetching browser/JS dependencies at build time without
//! Node or npm:
//!
//! - [`registry`] — talk to an npm registry: build tarball URLs, fetch a
//!   package's metadata, and resolve the newest version matching a semver range.
//! - [`download`] — fetch bytes over HTTP (with a retry) and build GitHub
//!   archive URLs.
//! - [`extract`] — unpack `.tar.gz` and `.zip` archives into a destination
//!   directory, selecting all files, an explicit file map, or a predicate, with
//!   path-traversal protection.
//! - [`path_safety`] — the path-traversal hardening shared by `extract` and
//!   `install`: reject `..`/absolute paths and refuse symlink-redirected writes.
//! - [`cache`] — content-hash markers, a cross-process build lock, and directory
//!   helpers for skip-if-unchanged download caches.
//! - [`package_json`] — read pinned dependency versions from a `package.json`, and
//!   resolve its `exports`/`module`/`browser`/`main` to browser entry points (for
//!   generating an ES-module import map).
//! - [`install`] — produce a real `node_modules/` directory, pure Rust, with every tarball
//!   sha512-verified: resolve a `package.json`'s transitive `dependencies` against the registry
//!   ([`install::node_modules`]), or install the exact tree a `package-lock.json` pins —
//!   devDependencies included, `.bin` shims and all — an `npm ci` in Rust
//!   ([`install::from_lockfile`]).
//! - [`integrity`] — verify a downloaded tarball's `sha512` Subresource-Integrity (both
//!   install paths check it before trusting bytes).
//! - [`sbom`] — render the packages a `package-lock.json` pins as a license summary, a CycloneDX
//!   1.6 document, or an SPDX 2.3 document — compliance artifacts, pure Rust, no Node.
//! - [`audit`] — check those same pinned packages against vulnerability advisories from multiple
//!   sources (npm's registry endpoint, OSV) behind a small source trait — `npm audit`, pure Rust.
//!
//! ```no_run
//! use npm_utils::{download, extract, registry::Registry};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let reg = Registry::npm();
//! let lit = reg.resolve("lit", &"^3".parse()?)?;
//! let tgz = download::fetch(&lit.tarball_url)?;
//! extract::tar_gz(&tgz, "dist/lit".as_ref(), Some("package/"), extract::Select::All)?;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

/// The crate's boxed, thread-safe error type. A single alias so the whole crate shares one error
/// spelling, errors cross thread boundaries, and a future switch to a structured enum is one edit.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
/// The crate's result type, defaulting the error to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

// Vulnerability auditing (`npm audit`, pure Rust): check the packages a `package-lock.json` pins
// against multiple advisory sources (npm's registry endpoint, OSV) behind a small source trait.
pub mod audit;
pub mod cache;
// The command-line tool (`npm-utils` / `cargo npm-utils`), behind the `cli` feature so a default
// library build pulls no `clap`. Drives the primitives below — `registry`, `install`, and the
// `package_json` manifest/lock writers — for `install`/`ci`/`add`/`init`/`upgrade`.
#[cfg(feature = "cli")]
pub mod cli;
pub mod download;
pub mod extract;
pub mod install;
pub mod integrity;
// The npm `package.json` / `package-lock.json` schemas — a pure-parsing module (no IO),
// modeled on the npm specs, with strict spec-conformance tests living beside it.
pub mod package_json;
pub mod path_safety;
pub mod registry;
// License/SBOM output (license summary · CycloneDX · SPDX) for a parsed `package-lock.json`.
pub mod sbom;
