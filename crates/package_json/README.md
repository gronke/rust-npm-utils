# package_json

Internal crate of [`npm-utils`](../..): pure-Rust, dependency-light schemas for the npm package
formats, modeled on the official npm specs and held to a strict spec-conformance test suite.
Re-exported as `npm_utils::package_json`; **not published separately**.

## Modules

- **root** — `package.json`: `PackageJson`, a browser-favoring conditional-`exports` resolver
  (`resolve_main`/`resolve_subpath`/`entries`) for generating ES-module import maps, plus
  `parse_dependencies`.
- **`spec`** — the npm ["package spec"](https://docs.npmjs.com/cli/v8/using-npm/package-spec)
  dependency grammar: `Spec` classifies a `dependencies` value (registry range/tag, `npm:` alias,
  git, remote tarball, local path) and `is_registry()` reports whether it's a fetchable registry
  tarball; `version_req` turns a registry range into a `semver::VersionReq`.
- **`lock`** — [`package-lock.json`](https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json)
  (lockfileVersion 2/3) parsing into a faithful `Lockfile` / `LockedPackage`, with npm `os`/`cpu`
  matching rules. lockfileVersion 1 is unsupported.

## Design

Pure data + parsing — **no filesystem, network, or path resolution**. Callers (the `npm-utils`
install action) turn a parsed lockfile key into an install path and own the path-traversal check,
keeping this crate trivially testable. Its CI (`.github/workflows/package-json.yml`) runs the spec
suite only when this crate changes.
