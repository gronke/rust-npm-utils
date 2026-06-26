//! The `npm-utils` / `cargo npm-utils` command-line tool (feature `cli`).
//!
//! Pure-Rust npm verbs over the crate's primitives — it mirrors npm's vocabulary for the subset it
//! supports and is deliberately **not** a full npm drop-in. Each verb lives in its own submodule;
//! the shared helpers they lean on (manifest read/write, the lock+install `sync` that `add` and
//! `upgrade` both run, install reporting) live in the `common` submodule.
//!
//! - `install` — resolve `package.json`'s `dependencies`, write `package-lock.json`, and install
//!   `node_modules/` (= `npm install`); `--lockfile-only` / `--no-lockfile` toggle each half.
//! - `ci` — install the exact tree a `package-lock.json` pins (= `npm ci`).
//! - `add` — resolve package(s), record them in `package.json`, write `package-lock.json`, install.
//! - `init` — scaffold a `package.json` (= `npm init -y`).
//! - `upgrade` — re-resolve within ranges, refresh the lock, install (= `npm update`).
//! - `resolve` / `download` — thin registry probes (print a resolution / fetch a tarball).
//!
//! The library does the heavy lifting ([`crate::registry`], [`crate::install`], and the
//! [`crate::package_json`] manifest/lock writers); this module is the argument parsing + the file
//! IO those pure transforms leave to the caller. Both bins (`npm-utils`, `cargo-npm-utils`) are
//! thin shells over [`main_with`].

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::registry::PackumentDetail;

mod add;
mod ci;
mod common;
mod download;
mod init;
mod install;
mod resolve;
mod sbom;
mod upgrade;

/// This module's ubiquitous fallible return — `()` by default, over the crate [`crate::Error`].
pub(crate) type Res<T = ()> = crate::Result<T>;

#[derive(Parser)]
#[command(
    name = "npm-utils",
    version,
    about = "Pure-Rust npm registry tools: install · ci · add · init · upgrade · sbom"
)]
struct Cli {
    /// Timeout in seconds for each download (default 120): the cap on every individual registry/tarball fetch, not a budget for the whole run.
    #[arg(
        long,
        global = true,
        value_name = "SECS",
        conflicts_with = "no_timeout"
    )]
    timeout: Option<u64>,
    /// Disable download timeouts entirely (no per-fetch or connect bound).
    #[arg(long, global = true)]
    no_timeout: bool,
    #[command(subcommand)]
    command: Command,
}

/// The shared `--skip-license` / `--no-skip-license` knob for the lockfile-writing verbs
/// (`install`, `add`, `upgrade`). The default records license (the full packument); `--skip-license`
/// uses the faster abbreviated packument and omits per-package license from the lockfile.
#[derive(Args)]
struct LicenseOpts {
    /// Record each package's license in package-lock.json (fetches the full packument). The default.
    #[arg(long, conflicts_with = "skip_license")]
    no_skip_license: bool,
    /// Skip per-package license in package-lock.json for faster resolution (abbreviated packument).
    #[arg(long)]
    skip_license: bool,
}

impl LicenseOpts {
    /// Which packument detail the lockfile writer should use. `--skip-license` uses the abbreviated
    /// packument; the default and explicit `--no-skip-license` record license via the full one.
    fn detail(&self) -> PackumentDetail {
        if self.skip_license && !self.no_skip_license {
            PackumentDetail::Abbreviated
        } else {
            PackumentDetail::Full
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Resolve `dependencies`, write `package-lock.json`, and install `node_modules/`
    /// (= `npm install`).
    Install {
        /// Project directory containing package.json.
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Write package-lock.json but skip installing node_modules/
        /// (= npm `--package-lock-only`, pnpm `--lockfile-only`).
        #[arg(
            long,
            visible_alias = "package-lock-only",
            conflicts_with = "no_lockfile"
        )]
        lockfile_only: bool,
        /// Install node_modules/ without writing package-lock.json
        /// (= yarn `--no-lockfile`, npm `--no-package-lock`).
        #[arg(long, visible_alias = "no-package-lock")]
        no_lockfile: bool,
        #[command(flatten)]
        license: LicenseOpts,
    },
    /// Install the exact tree pinned by package-lock.json into `node_modules/` (= `npm ci`).
    Ci {
        /// Project directory containing package-lock.json.
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    /// Resolve + add package(s) to package.json, write package-lock.json, and install (= `npm add`).
    Add {
        /// Packages as `name` or `name@range` (e.g. `lit`, `lit@^3`, `@lit/context@^1`).
        #[arg(required = true)]
        packages: Vec<String>,
        /// Project directory.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[command(flatten)]
        license: LicenseOpts,
    },
    /// Create a package.json in the directory (= `npm init -y`).
    Init {
        /// Project directory.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Package name (defaults to the directory name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Re-resolve dependencies within their ranges, refresh the lock, and install (= `npm update`).
    Upgrade {
        /// Packages to upgrade; empty means all `dependencies`.
        packages: Vec<String>,
        /// Project directory.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[command(flatten)]
        license: LicenseOpts,
    },
    /// Resolve the newest version matching a range and print it (version, tarball, integrity).
    Resolve {
        /// Package name.
        name: String,
        /// Semver range (default: any).
        #[arg(default_value = "*")]
        range: String,
    },
    /// Download a package tarball to a file — resolve + fetch, no install.
    Download {
        /// Package name.
        name: String,
        /// Semver range (default: any).
        #[arg(default_value = "*")]
        range: String,
        /// Write the .tgz here (default: `<name>-<version>.tgz` in the current dir).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Render a bill of materials from package-lock.json: a license summary, CycloneDX, or SPDX.
    Sbom {
        /// Project directory containing package-lock.json.
        #[arg(default_value = ".")]
        dir: PathBuf,
        /// Output format.
        #[arg(long, default_value = "summary")]
        format: sbom::Format,
        /// Name for the SBOM's root component / document (default: the directory name).
        #[arg(long)]
        name: Option<String>,
    },
}

/// Parse `argv` and dispatch to the verb's submodule. `argv` is taken explicitly (not
/// `std::env::args_os()`) so the `cargo-npm-utils` shim can strip the re-passed subcommand name
/// before handing off.
pub fn run(argv: impl IntoIterator<Item = OsString>) -> Res {
    let cli = Cli::parse_from(argv);
    // Apply the download-timeout flags before any fetch happens.
    crate::download::set_timeouts(crate::download::Timeouts::from_cli(
        cli.timeout,
        cli.no_timeout,
    ));
    match cli.command {
        Command::Install {
            dir,
            lockfile_only,
            no_lockfile,
            license,
        } => install::run(&dir, lockfile_only, no_lockfile, license.detail()),
        Command::Ci { dir } => ci::run(&dir),
        Command::Add {
            packages,
            dir,
            license,
        } => add::run(&packages, &dir, license.detail()),
        Command::Init { dir, name } => init::run(&dir, name.as_deref()),
        Command::Upgrade {
            packages,
            dir,
            license,
        } => upgrade::run(&packages, &dir, license.detail()),
        Command::Resolve { name, range } => resolve::run(&name, &range),
        Command::Download { name, range, out } => download::run(&name, &range, out.as_deref()),
        Command::Sbom { dir, format, name } => sbom::run(&dir, format, name.as_deref()),
    }
}

/// Bin entry point: run, then map an error to a tidy message + nonzero exit (instead of the
/// `Result`-returning-`main` `Error: …` Debug dump).
pub fn main_with(argv: impl IntoIterator<Item = OsString>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("npm-utils: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `cargo-npm-utils` entry point: cargo invokes the bin as `cargo-npm-utils npm-utils <verb> …`,
/// re-passing the subcommand name as `argv[1]`; strip it so clap sees the real verb.
pub fn run_as_cargo_subcommand(argv: impl IntoIterator<Item = OsString>) -> ExitCode {
    main_with(strip_cargo_prefix(argv.into_iter().collect()))
}

/// Drop a leading `npm-utils` token at `argv[1]` (cargo's re-passed subcommand name). A no-op when
/// the bin is run directly (`cargo-npm-utils install` → `argv[1]` is the verb, left alone).
fn strip_cargo_prefix(mut args: Vec<OsString>) -> Vec<OsString> {
    if args.get(1).is_some_and(|a| a == "npm-utils") {
        args.remove(1);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn osv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn strip_cargo_prefix_drops_the_repassed_subcommand_name() {
        // `cargo npm-utils add lit` → cargo execs us with the subcommand name re-passed.
        assert_eq!(
            strip_cargo_prefix(osv(&["cargo-npm-utils", "npm-utils", "add", "lit"])),
            osv(&["cargo-npm-utils", "add", "lit"])
        );
        // Run directly: argv[1] is the real verb, untouched.
        assert_eq!(
            strip_cargo_prefix(osv(&["cargo-npm-utils", "install"])),
            osv(&["cargo-npm-utils", "install"])
        );
        // Degenerate argv (no args) is left as-is.
        assert_eq!(
            strip_cargo_prefix(osv(&["cargo-npm-utils"])),
            osv(&["cargo-npm-utils"])
        );
    }

    #[test]
    fn cli_parses_the_verb_set() {
        // A smoke test that the clap grammar accepts each verb (no dispatch/network).
        for argv in [
            osv(&["npm-utils", "install"]),
            osv(&["npm-utils", "install", "web", "--lockfile-only"]),
            osv(&["npm-utils", "install", "--no-lockfile"]),
            osv(&["npm-utils", "ci", "/tmp/x"]),
            osv(&["npm-utils", "add", "lit@^3", "--dir", "/tmp/x"]),
            osv(&["npm-utils", "init", "--name", "demo"]),
            osv(&["npm-utils", "upgrade"]),
            osv(&["npm-utils", "resolve", "lit", "^3"]),
            osv(&["npm-utils", "download", "ms", "--out", "/tmp/ms.tgz"]),
            osv(&["npm-utils", "sbom", "/tmp/x", "--format", "cyclonedx"]),
            osv(&["npm-utils", "sbom", "--format", "spdx", "--name", "demo"]),
        ] {
            assert!(Cli::try_parse_from(argv).is_ok());
        }
        // `add` requires at least one package.
        assert!(Cli::try_parse_from(osv(&["npm-utils", "add"])).is_err());
        // `install` can't both write only the lock and skip the lock.
        assert!(Cli::try_parse_from(osv(&[
            "npm-utils",
            "install",
            "--lockfile-only",
            "--no-lockfile"
        ]))
        .is_err());
    }

    #[test]
    fn cli_accepts_global_timeout_flags() {
        // `--timeout <secs>` and `--no-timeout` are global: accepted before or after the verb.
        assert!(Cli::try_parse_from(osv(&["npm-utils", "--timeout", "5", "install"])).is_ok());
        assert!(Cli::try_parse_from(osv(&["npm-utils", "install", "--no-timeout"])).is_ok());
        assert!(Cli::try_parse_from(osv(&["npm-utils", "--no-timeout", "ci", "/tmp/x"])).is_ok());
        // The two flags conflict, and `--timeout` requires a numeric value.
        assert!(Cli::try_parse_from(osv(&[
            "npm-utils",
            "--timeout",
            "5",
            "--no-timeout",
            "install"
        ]))
        .is_err());
        assert!(Cli::try_parse_from(osv(&["npm-utils", "--timeout", "soon", "install"])).is_err());
    }

    #[test]
    fn cli_accepts_license_flags() {
        // --skip-license / --no-skip-license are accepted on the lockfile-writing verbs.
        assert!(Cli::try_parse_from(osv(&["npm-utils", "install", "--skip-license"])).is_ok());
        assert!(
            Cli::try_parse_from(osv(&["npm-utils", "add", "lit", "--no-skip-license"])).is_ok()
        );
        assert!(Cli::try_parse_from(osv(&["npm-utils", "upgrade", "--skip-license"])).is_ok());
        // The two conflict.
        assert!(Cli::try_parse_from(osv(&[
            "npm-utils",
            "install",
            "--skip-license",
            "--no-skip-license"
        ]))
        .is_err());
    }

    #[test]
    fn license_opts_map_to_packument_detail() {
        let detail = |skip: bool, no_skip: bool| {
            LicenseOpts {
                skip_license: skip,
                no_skip_license: no_skip,
            }
            .detail()
        };
        // The default records license (Full); --skip-license uses the abbreviated packument.
        assert_eq!(detail(false, false), PackumentDetail::Full);
        assert_eq!(detail(false, true), PackumentDetail::Full);
        assert_eq!(detail(true, false), PackumentDetail::Abbreviated);
    }
}
