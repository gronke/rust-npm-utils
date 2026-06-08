//! Pure-Rust npm manifest + lockfile schemas — `package.json` resolution and
//! `package-lock.json` parsing — modeled on the npm specs:
//!
//! - <https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json>
//! - <https://docs.npmjs.com/cli/v8/using-npm/package-spec>
//!
//! Internal to `npm-utils` (re-exported as `npm_utils::package_json`); not published
//! separately. The crate is pure data + parsing — no filesystem or network — so its
//! strict spec-conformance tests can run in isolation.
