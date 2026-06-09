# npm-utils

Pure-Rust utilities for the **npm registry** and web assets — resolve a package
version, download npm tarballs and GitHub archives, extract files, and install a
real `node_modules/` from a `package.json` or `package-lock.json`. No Node or npm
at build time; just `ureq` + archive extraction. Handy from a `build.rs` to vendor
browser/JS dependencies into your own asset tree.

It's both a **library** (the modules below) and an optional **command-line tool** —
`cargo npm-utils install` / `add` / `ci` / …, a pure-Rust subset of npm's verbs. See
[CLI](#cli).

## Modules

- **`registry`** — `Registry::npm()`; `tarball_url(name, version)` (handles
  `@scope/pkg`); `packument(name)`; `resolve(name, &VersionReq)` → the newest
  published version matching a semver range.
- **`download`** — `fetch(url)` (one retry, 100 MB cap); `github_archive_url(...)`.
- **`extract`** — `tar_gz(..)` / `zip(..)` into a directory, selecting `All`, an
  explicit `Files` map, or a `Matching` predicate; path-traversal-safe.
- **`cache`** — content-hash markers, a cross-process `with_lock`, and directory
  helpers for skip-if-unchanged download caches.
- **`package_json`** — the rolled-own npm-format schemas as a pure-parsing module:
  `package.json` (dependency specs + a browser-favoring `exports` resolver), the `package-spec`
  grammar (`spec::Spec`), and `package-lock.json` parsing (`lock::Lockfile`) — modeled on the npm
  specs and held to a strict spec-conformance suite.
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

## CLI

The same engine ships as a command-line tool behind the `cli` feature — a pure-Rust
subset of npm's verbs, no Node or npm:

```bash
cargo install npm-utils --features cli
```

That installs two binaries — `npm-utils` and `cargo-npm-utils` — so every verb works
standalone *or* as a cargo subcommand (`npm-utils add lit` ≡ `cargo npm-utils add lit`):

| Command | npm | What it does |
|---------|-----|--------------|
| `install [dir]` | `npm install` | resolve `package.json`'s `dependencies` → `node_modules/` |
| `ci [dir]` | `npm ci` | install the exact tree a `package-lock.json` pins |
| `add <pkg…> [--dir d]` | `npm install <pkg>` | resolve, record in `package.json`, write the lock, install |
| `init [--name n]` | `npm init -y` | scaffold a `package.json` |
| `upgrade [pkg…]` | `npm update` | re-resolve within ranges, refresh the lock, install |
| `resolve <pkg> [range]` | — | print the newest matching version (tarball + integrity) |
| `download <pkg> [range]` | `npm pack` | fetch a package tarball |

```bash
cargo npm-utils init --name demo
cargo npm-utils add lit@^3 @lit/context   # resolve, write package.json + lock, install
cargo npm-utils ci                        # reproduce the locked tree, integrity-checked
```

`add`/`upgrade` write a `lockfileVersion`-3 `package-lock.json` that both npm and
`npm-utils ci` read — every tarball pinned with its `sha512`. It is an npm-compatible
lock for the **registry/production tree**, not a byte-for-byte npm reproduction
(dev/optional classification and peer/bundle dependencies are out of scope). The CLI
mirrors npm's vocabulary for the subset it supports; it is **not** a full npm drop-in.

## License

MIT — see [LICENSE](LICENSE).
