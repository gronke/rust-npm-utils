# npm-utils

Pure-Rust utilities for the **npm registry** and web assets — resolve a package
version, download npm tarballs and GitHub archives, and extract files. No Node or
npm at build time; just `ureq` + archive extraction. Handy from a `build.rs` to
vendor browser/JS dependencies into your own asset tree.

## Modules

- **`registry`** — `Registry::npm()`; `tarball_url(name, version)` (handles
  `@scope/pkg`); `packument(name)`; `resolve(name, &VersionReq)` → the newest
  published version matching a semver range.
- **`download`** — `fetch(url)` (one retry, 100 MB cap); `github_archive_url(...)`.
- **`extract`** — `tar_gz(..)` / `zip(..)` into a directory, selecting `All`, an
  explicit `Files` map, or a `Matching` predicate; path-traversal-safe.
- **`cache`** — content-hash markers, a cross-process `with_lock`, and directory
  helpers for skip-if-unchanged download caches.
- **`package_json`** — read pinned dependency versions from a `package.json`.

## Example

```rust,no_run
use npm_utils::{download, extract, registry::Registry};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let reg = Registry::npm();
let lit = reg.resolve("lit", &"^3".parse()?)?;
let tgz = download::fetch(&lit.tarball_url)?;
extract::tar_gz(&tgz, "dist/lit".as_ref(), Some("package/"), extract::Select::All)?;
# Ok(()) }
```

See [`examples/date-converter`](examples/date-converter) for a runnable Lit +
`Temporal` demo that vendors its dependencies with this crate.

## License

MIT — see [LICENSE](LICENSE).
