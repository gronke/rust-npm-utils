# npm-utils

Pure-Rust utilities for the **npm registry** and web assets — resolve a package
version, download npm tarballs and GitHub archives, extract files, and install a
real `node_modules/` from a `package.json` or `package-lock.json`. No Node or npm
at build time; just `ureq` + archive extraction. Handy from a `build.rs` to vendor
browser/JS dependencies into your own asset tree.

## Modules

- **`registry`** — `Registry::npm()`; `tarball_url(name, version)` (handles
  `@scope/pkg`); `packument(name)`; `resolve(name, &VersionReq)` → the newest
  published version matching a semver range.
- **`download`** — `fetch(url)` (one retry, 100 MB cap); `github_archive_url(...)`.
- **`extract`** — `tar_gz(..)` / `zip(..)` into a directory, selecting `All`, an
  explicit `Files` map, or a `Matching` predicate; path-traversal-safe.
- **`cache`** — content-hash markers, a cross-process `with_lock`, and directory
  helpers for skip-if-unchanged download caches.
- **`package_json`** — re-exported from the internal [`package_json`](crates/package_json) crate:
  the rolled-own npm-format schemas — `package.json` (dependency specs + a browser-favoring
  `exports` resolver), the `package-spec` grammar (`spec::Spec`), and `package-lock.json` parsing
  (`lock::Lockfile`) — modeled on the npm specs and held to a strict spec-conformance suite.
- **`integrity`** — verify a downloaded tarball's `sha512` Subresource-Integrity (both install
  paths check it before trusting bytes).
- **`install`** — produce a real `node_modules/` tree, pure Rust, verifying every tarball's
  `sha512` integrity. `node_modules(..)` resolves a `package.json`'s transitive `dependencies`
  against the registry, checking each tarball against the registry's `dist.integrity` like
  `npm install`; `from_lockfile(..)` is an **`npm ci` in Rust** — it installs the *exact* tree
  a `package-lock.json` (v2/v3) pins, **devDependencies included**, with no semver resolution:
  each tarball's pinned `sha512` integrity is verified, platform-mismatched optional deps (e.g.
  darwin-only `fsevents` on Linux) are skipped, and `node_modules/.bin/` shims are created.
  That installs a project's Node test tooling (Playwright, `tsc`) without `npm` — only the Node
  runtime is needed to then run it.

## Workspace

The npm-format schemas live in an internal `package_json` crate
([`crates/package_json`](crates/package_json), re-exported as `npm_utils::package_json`), so its
strict `package.json` / `package-lock.json` spec-conformance tests run on their own CI, independent
of the rest of `npm-utils`.

## Examples

Vendor a single package's browser assets:

```rust,no_run
use npm_utils::{download, extract, registry::Registry};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let reg = Registry::npm();
let lit = reg.resolve("lit", &"^3".parse()?)?;
let tgz = download::fetch(&lit.tarball_url)?;
extract::tar_gz(&tgz, "dist/lit".as_ref(), Some("package/"), extract::Select::All)?;
# Ok(()) }
```

Install a committed lockfile's full tree (an `npm ci`, in Rust):

```rust,no_run
use std::path::Path;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let project = Path::new("examples/app");
npm_utils::install::from_lockfile(&project.join("package-lock.json"), project)?;
// → project/node_modules/ populated + .bin shims; now run `node node_modules/.bin/tsc`.
# Ok(()) }
```

See [`examples/date-converter`](examples/date-converter) for a runnable Lit +
`Temporal` demo that vendors its dependencies with this crate.

## License

MIT — see [LICENSE](LICENSE).
