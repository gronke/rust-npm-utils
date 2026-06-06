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
//! - [`cache`] — content-hash markers, a cross-process build lock, and directory
//!   helpers for skip-if-unchanged download caches.
//! - [`package_json`] — read pinned dependency versions from a `package.json`, and
//!   resolve its `exports`/`module`/`browser`/`main` to browser entry points (for
//!   generating an ES-module import map).
//! - [`install`] — resolve a `package.json`'s transitive dependency graph and extract
//!   the tree into a `node_modules/` directory (a minimal, pure-Rust "npm install").
//!
//! ```no_run
//! use npm_utils::{download, extract, registry::Registry};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let reg = Registry::npm();
//! let lit = reg.resolve("lit", &"^3".parse()?)?;
//! let tgz = download::fetch(&lit.tarball_url)?;
//! extract::tar_gz(&tgz, "dist/lit".as_ref(), Some("package/"), extract::Select::All)?;
//! # Ok(()) }
//! ```

pub mod cache;
pub mod download;
pub mod extract;
pub mod install;
pub mod package_json;
pub mod registry;
