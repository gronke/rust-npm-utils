//! `audit` — check installed packages against vulnerability advisories from multiple sources.
//!
//! Mirrors `npm audit`: prints a report and exits non-zero only when an advisory at or above the
//! `--audit-level` threshold is found. A missing/garbage lockfile is a real error (nonzero with a
//! message); an unreachable advisory endpoint degrades to "found 0 vulnerabilities" and exit 0.

use std::io::Write as _;
use std::path::Path;

use clap::ValueEnum;

use super::Res;
use crate::audit::npm::NpmRegistrySource;
use crate::audit::osv::OsvSource;
use crate::audit::{self, AdvisorySource, Severity};
use crate::package_json::lock::Lockfile;
use crate::sbom;

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

/// Minimum severity that makes `audit` exit non-zero.
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum AuditLevel {
    Low,
    Moderate,
    High,
    Critical,
}

impl From<AuditLevel> for Severity {
    fn from(level: AuditLevel) -> Severity {
        match level {
            AuditLevel::Low => Severity::Low,
            AuditLevel::Moderate => Severity::Moderate,
            AuditLevel::High => Severity::High,
            AuditLevel::Critical => Severity::Critical,
        }
    }
}

/// Output format for the `audit` verb.
#[derive(Clone, Copy, ValueEnum)]
pub(super) enum Format {
    /// Human-readable summary (the default)
    Summary,
    /// `npm audit --json`-shaped JSON
    Json,
}

/// An advisory source selectable via `--sources`.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum SourceKind {
    Npm,
    Osv,
}

/// Parse `<dir>/package-lock.json`, query the selected advisory sources, and print the report.
/// Exits `1` when an advisory at or above `audit_level` is found (after printing), `0` when clean.
pub(super) fn run(
    dir: &Path,
    audit_level: AuditLevel,
    format: Format,
    sources: Option<&[SourceKind]>,
    registry: Option<&str>,
) -> Res {
    let lock_path = dir.join("package-lock.json");
    let text = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("reading {}: {e}", lock_path.display()))?;
    let components = sbom::components(&Lockfile::parse(&text)?);

    let active = build_sources(sources, registry);
    let report = audit::run_audit(&components, &active);

    let out = match format {
        Format::Summary => audit::render_summary(&report),
        Format::Json => audit::render_json(&report),
    };
    print!("{out}");

    // A finding at/above the threshold is a nonzero *result*, not a tool error: print to stdout and
    // exit directly, bypassing `main_with`'s `npm-utils: <err>` path. Flush first — `process::exit`
    // runs no destructors.
    if report.exceeds(audit_level.into()) {
        let _ = std::io::stdout().flush();
        std::process::exit(1);
    }
    Ok(())
}

/// Assemble the active advisory sources: the subset named by `--sources`, or npm + OSV by default.
///
/// This is the single seam for adding sources. A future, optional, API-key'd source slots in here
/// without touching the [`AdvisorySource`] trait or the orchestrator — e.g. a feature-gated Snyk
/// source (`snyk = []` in `Cargo.toml`, `src/audit/snyk.rs` behind `#[cfg(feature = "snyk")]`):
///
/// ```ignore
/// #[cfg(feature = "snyk")]
/// if let Some(token) = std::env::var("SNYK_TOKEN").ok() {
///     active.push(Box::new(crate::audit::snyk::SnykSource::new(token)));
/// }
/// ```
fn build_sources(
    sources: Option<&[SourceKind]>,
    registry: Option<&str>,
) -> Vec<Box<dyn AdvisorySource>> {
    let registry = registry.unwrap_or(DEFAULT_REGISTRY);
    let selected: &[SourceKind] = match sources {
        Some(s) if !s.is_empty() => s,
        _ => &[SourceKind::Npm, SourceKind::Osv],
    };
    selected
        .iter()
        .map(|kind| -> Box<dyn AdvisorySource> {
            match kind {
                SourceKind::Npm => Box::new(NpmRegistrySource::new(registry)),
                SourceKind::Osv => Box::new(OsvSource),
            }
        })
        .collect()
}
