# npm-utils

Pure-Rust utilities for the **npm registry** and web assets —
resolve a package version, download npm tarballs and GitHub archives, extract files, and install a real `node_modules/` from a `package.json` or `package-lock.json`.
No Node or npm at build time; just `ureq` + archive extraction.
Handy from a `build.rs` to vendor browser/JS dependencies into your own asset tree.

It's both a **library** (the modules below) and an optional **command-line tool** —
a pure-Rust subset of npm's verbs (`install` / `add` / `ci` / `sbom` / …).
See [CLI](#cli).

## Library

```toml
[dependencies]
npm-utils = "0.5"   # Rust 1.77+
```

Composable modules — the full API is on **[docs.rs](https://docs.rs/npm-utils)**:

| Module | What it does |
|---|---|
| `registry` | Resolve the newest version in a semver range; build tarball URLs; fetch packuments (abbreviated or full). |
| `download` | Fetch over HTTPS with one retry and a 100 MB cap; build GitHub archive URLs. |
| `extract` | Unpack `.tar.gz` / `.zip` — all files, an explicit file map, or a predicate — path-traversal-safe. |
| `integrity` | Verify a tarball's `sha512` Subresource-Integrity before its bytes are trusted. |
| `install` | Build a real `node_modules/`: resolve a `package.json` (`npm install`) or reproduce a `package-lock.json` exactly (`npm ci`), every tarball integrity-checked. |
| `package_json` | Parse `package.json` / `package-lock.json` and the npm version-spec grammar; write npm-faithful manifests and v3 locks. |
| `sbom` | Render a committed lock as a license summary, CycloneDX 1.6, or SPDX 2.3. |
| `cache` | Content-hash markers and a cross-process lock for skip-if-unchanged downloads. |
| `path_safety` | The traversal/symlink hardening shared by `extract` and `install`. |

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

Generate a license summary — or a CycloneDX / SPDX SBOM — from a committed lock:

```rust,no_run
use npm_utils::{package_json::lock::Lockfile, sbom};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let lock = Lockfile::parse(&std::fs::read_to_string("package-lock.json")?)?;
let bom = sbom::components(&lock);
print!("{}", sbom::render_summary(&bom));                              // license overview
std::fs::write("sbom.cdx.json", sbom::to_cyclonedx(&bom, "my-app", "1.0.0", None))?;
# Ok(()) }
```

## CLI

The same engine ships as a command-line tool behind the `cli` feature — a pure-Rust subset of npm's verbs, no Node or npm:

```bash
cargo install npm-utils --features cli
```

That installs two binaries — `npm-utils` and `cargo-npm-utils` —
so every verb works standalone *or* as a cargo subcommand (`npm-utils add lit` ≡ `cargo npm-utils add lit`).

<!-- regenerate: cargo run --features cli --bin npm-utils -- --help -->

```console
$ npm-utils --help
Pure-Rust npm registry tools: install · ci · add · init · upgrade · sbom

Usage: npm-utils [OPTIONS] <COMMAND>

Commands:
  install   Resolve dependencies, write package-lock.json, install node_modules/ (npm install)
  ci        Install the exact tree package-lock.json pins (npm ci)
  add       Add packages to package.json, write the lock, and install (npm add)
  init      Create a package.json (npm init -y)
  upgrade   Re-resolve within ranges, refresh the lock, and install (npm update)
  resolve   Print the newest version matching a range (version, tarball, integrity)
  download  Download a package tarball — resolve and fetch, no install
  sbom      Bill of materials from package-lock.json: license summary, CycloneDX, or SPDX
  help      Print this message or the help of the given subcommand(s)

Options:
      --timeout <SECS>  Per-fetch timeout in seconds (default 120) — caps each registry/tarball request, not the whole run
      --no-timeout      Disable download timeouts entirely (no per-fetch or connect bound)
  -h, --help            Print help
  -V, --version         Print version
```

Run `npm-utils <command> --help` for a verb's flags.

`install` / `add` / `upgrade` write a `lockfileVersion`-3 `package-lock.json` that both npm and `npm-utils ci` read — every tarball pinned with its `sha512`.
It is an npm-compatible lock for the **registry/production tree**, not a byte-for-byte npm reproduction;
the CLI mirrors npm's vocabulary for the subset it supports and is **not** a full npm drop-in.

### License checks

The lockfile-writing verbs default to the fast **abbreviated** packument, which carries no license;
pass `--no-skip-license` to fetch the **full** packument and record each package's license in the lock.
`sbom` then renders the license tree of the whole dependency graph — handy for auditing an external package you don't own:

```console
$ mkdir lit-licenses && cd lit-licenses
$ npm-utils init --name lit-licenses
$ npm-utils add --no-skip-license lit@3.3.3   # resolve, record each license, install
$ npm-utils sbom                              # the transitive license tree, grouped
6 package(s) across 2 license(s)

BSD-3-Clause (5)
  @lit-labs/ssr-dom-shim@1.6.0
  @lit/reactive-element@2.1.2
  lit-element@4.2.2
  lit-html@3.3.3
  lit@3.3.3

MIT (1)
  @types/trusted-types@2.0.7
```

`npm-utils sbom --format cyclonedx` (or `spdx`) emits the same tree as a standards-based compliance document —
each component carrying its purl, declared license, and `sha512`.

## Examples

See [`examples/date-converter`](examples/date-converter) for a runnable Lit + `Temporal` demo that vendors its browser dependencies with this crate —
no Node or bundler in the build.

## Scope

Not a general `npm`:
npm-utils vendors **public-registry** packages and reproduces a committed `package-lock.json` — that's the remit.
So: **no lifecycle scripts** (by design), **public registry only** (no `.npmrc`/auth), and `node_modules()` resolves a **flat, prod-only** tree that errors on a version conflict npm would nest — install from a lockfile (`from_lockfile`/`ci`) for a full tree.
Anything unsupported — a dist-tag like `next`, `overrides`, lockfile v1 — fails with a clear error rather than silently.

## License

MIT — see [LICENSE](LICENSE).
