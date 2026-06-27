//! Vulnerability auditing for a parsed `package-lock.json` — `npm audit`, pure Rust.
//!
//! The packages a lockfile pins ([`crate::sbom::components`]) are checked against one or more
//! **advisory sources** behind a small [`AdvisorySource`] trait, and the hits are distilled into an
//! [`AuditReport`]: which installed components are vulnerable, to which advisories, at what severity.
//!
//! Two sources ship in v1, both keyless and queried by default:
//! - [`npm::NpmRegistrySource`] — npm's native bulk-advisory endpoint (also honours a custom mirror).
//! - [`osv::OsvSource`] — the OSV (osv.dev) database, with structured affected-version ranges.
//!
//! The seam is deliberately open: a new source is one `impl AdvisorySource` plus one line where the
//! active sources are assembled (e.g. a future, feature-gated, API-key'd Snyk source).
//!
//! Everything except the sources' network calls is pure and unit-tested: [`dedup_advisories`]
//! collapses the same vulnerability reported by several sources, and [`build_report`] keeps only the
//! advisories whose vulnerable range actually contains the *installed* version — the guard against
//! the npm endpoint's range over-broadening — then groups and counts them.
//!
//! ```no_run
//! use npm_utils::{audit, package_json::lock::Lockfile, sbom};
//! # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let lock = Lockfile::parse(&std::fs::read_to_string("package-lock.json")?)?;
//! let components = sbom::components(&lock);
//! let sources: Vec<Box<dyn audit::AdvisorySource>> =
//!     vec![Box::new(audit::npm::NpmRegistrySource::new("https://registry.npmjs.org"))];
//! let report = audit::run_audit(&components, &sources);
//! print!("{}", audit::render_summary(&report));
//! # Ok(()) }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use serde_json::{json, Map, Value};

use crate::package_json::spec::Range;
use crate::sbom::Component;

pub mod npm;
pub mod osv;

/// A normalized advisory severity. Ordered `Low < Moderate < High < Critical` so a `--audit-level`
/// threshold is a simple comparison. npm's vocabulary (`moderate`, not `medium`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

impl Severity {
    /// Parse a severity word, case-insensitively, from either source's vocabulary: npm's
    /// `low`/`moderate`/`high`/`critical` and OSV's uppercase `CRITICAL` etc.; `medium` maps to
    /// [`Severity::Moderate`]. Anything else (`info`, `none`, empty, unknown) is `None` — below the
    /// lowest actionable bucket.
    pub fn from_str_loose(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "moderate" | "medium" => Some(Severity::Moderate),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// The lowercase wire/display word for this severity.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Moderate => "moderate",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Map a CVSS base score to a severity bucket (the CVSS v3 qualitative ranges): `<= 0` is `None`,
/// `< 4` Low, `< 7` Moderate, `< 9` High, else Critical. Used when a source gives a numeric score
/// but no severity word.
pub fn severity_from_cvss(score: f64) -> Option<Severity> {
    match score {
        s if s <= 0.0 => None,
        s if s < 4.0 => Some(Severity::Low),
        s if s < 7.0 => Some(Severity::Moderate),
        s if s < 9.0 => Some(Severity::High),
        _ => Some(Severity::Critical),
    }
}

/// One vulnerability advisory, normalized across sources into a single shape.
#[derive(Debug, Clone)]
pub struct Advisory {
    /// The reporting source's name (`"npm"`, `"osv"`, …) — matches [`AdvisorySource::name`].
    pub source: &'static str,
    /// The source-native id — a `GHSA-…` for both v1 sources (npm's numeric id is folded away when a
    /// GHSA is recoverable).
    pub id: String,
    /// Cross-reference ids (`GHSA-…`, `CVE-…`) used to recognize the same vulnerability across
    /// sources — the key [`dedup_advisories`] joins on.
    pub aliases: Vec<String>,
    /// The package name this advisory concerns.
    pub package: String,
    /// The affected version range, as a string the npm/[`Range`] grammar accepts — npm's raw
    /// `vulnerable_versions`, or a `>=`/`<` range synthesized from OSV's structured events.
    pub vulnerable_range: String,
    /// Normalized severity, when the source provides one.
    pub severity: Option<Severity>,
    /// Short human title / summary.
    pub title: String,
    /// A canonical advisory URL, when known.
    pub url: Option<String>,
    /// CWE identifiers (`CWE-79`, …).
    pub cwe: Vec<String>,
    /// CVSS base score, when the source provides a numeric one (npm does; OSV usually doesn't).
    pub cvss_score: Option<f64>,
    /// CVSS vector string, when present.
    pub cvss_vector: Option<String>,
    /// The installed version this advisory was matched against — set by [`build_report`]; empty
    /// until then.
    pub matched_version: String,
}

/// Per-severity advisory counts — the shape of npm's `metadata.vulnerabilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vulnerabilities {
    pub info: u64,
    pub low: u64,
    pub moderate: u64,
    pub high: u64,
    pub critical: u64,
    pub total: u64,
}

/// One vulnerable installed component and the advisories that hit its exact version.
#[derive(Debug, Clone)]
pub struct ComponentAdvisories {
    pub component: Component,
    pub advisories: Vec<Advisory>,
}

/// The result of an audit: the vulnerable components (sorted by name then version) and the
/// per-severity totals across them.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub findings: Vec<ComponentAdvisories>,
    pub vulnerabilities: Vulnerabilities,
}

impl AuditReport {
    /// The highest severity present across all findings, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.advisories().filter_map(|a| a.severity).max()
    }

    /// Whether any advisory's severity is at or above `level` — the `--audit-level` exit test.
    /// Advisories without a severity (below the lowest bucket) never trip it.
    pub fn exceeds(&self, level: Severity) -> bool {
        self.advisories()
            .any(|a| a.severity.is_some_and(|s| s >= level))
    }

    fn advisories(&self) -> impl Iterator<Item = &Advisory> {
        self.findings.iter().flat_map(|f| f.advisories.iter())
    }
}

/// An advisory database that can be queried for the vulnerabilities affecting a set of components.
///
/// Implementations should **degrade gracefully**: a network failure or an unreachable endpoint
/// returns `Ok(vec![])` (no advisories), not an `Err`, so a flaky link never fails the audit run.
/// An `Err` is reserved for a genuinely fatal misconfiguration.
pub trait AdvisorySource {
    /// A short, stable name (`"npm"`, `"osv"`, …) used in [`Advisory::source`] and diagnostics.
    fn name(&self) -> &'static str;
    /// Query advisories affecting `components`.
    fn query(&self, components: &[Component]) -> crate::Result<Vec<Advisory>>;
}

/// Query every source, then dedup across sources and keep only advisories that actually apply to an
/// installed version ([`build_report`]). A source that errors is reported to stderr and skipped — a
/// single failing source never sinks the run.
pub fn run_audit(components: &[Component], sources: &[Box<dyn AdvisorySource>]) -> AuditReport {
    let mut all = Vec::new();
    for source in sources {
        match source.query(components) {
            Ok(advisories) => all.extend(advisories),
            Err(e) => eprintln!(
                "npm-utils: {} advisory source failed: {e}; audit results may be incomplete",
                source.name()
            ),
        }
    }
    let deduped = dedup_advisories(all);
    build_report(&deduped, components)
}

/// The normalized GHSA-/CVE-shaped identity tokens of an advisory (its `id` plus `aliases`),
/// uppercased. A purely numeric npm id is not a stable cross-source key, so it is excluded.
fn advisory_keys(adv: &Advisory) -> Vec<String> {
    std::iter::once(&adv.id)
        .chain(adv.aliases.iter())
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|k| k.starts_with("GHSA-") || k.starts_with("CVE-"))
        .collect()
}

/// Collapse advisories that describe the same vulnerability for the same package across sources,
/// joined by any shared `GHSA-`/`CVE-` token. The first occurrence wins (sources are concatenated in
/// selection order, npm before osv), and a later duplicate's aliases / url / cwe / cvss / severity
/// enrich the survivor where it lacks them — so an OSV record's CVE alias decorates the npm GHSA.
pub fn dedup_advisories(advisories: Vec<Advisory>) -> Vec<Advisory> {
    let mut out: Vec<Advisory> = Vec::new();
    for adv in advisories {
        let keys = advisory_keys(&adv);
        let existing = out.iter_mut().find(|e| {
            e.package == adv.package && advisory_keys(e).iter().any(|k| keys.contains(k))
        });
        match existing {
            Some(into) => merge_advisory(into, adv),
            None => out.push(adv),
        }
    }
    out
}

/// Fold `from` into `into`: union the alias sets (adding `from`'s native id when it is a GHSA/CVE),
/// and fill any field `into` is missing.
fn merge_advisory(into: &mut Advisory, from: Advisory) {
    let add_alias = |into: &mut Advisory, alias: String| {
        let k = alias.trim().to_ascii_uppercase();
        if !into
            .aliases
            .iter()
            .any(|x| x.trim().to_ascii_uppercase() == k)
            && into.id != alias
        {
            into.aliases.push(alias);
        }
    };
    let from_id_upper = from.id.trim().to_ascii_uppercase();
    if from_id_upper.starts_with("GHSA-") || from_id_upper.starts_with("CVE-") {
        add_alias(into, from.id);
    }
    for a in from.aliases {
        add_alias(into, a);
    }
    if into.url.is_none() {
        into.url = from.url;
    }
    if into.cwe.is_empty() {
        into.cwe = from.cwe;
    }
    if into.cvss_score.is_none() {
        into.cvss_score = from.cvss_score;
    }
    if into.cvss_vector.is_none() {
        into.cvss_vector = from.cvss_vector;
    }
    if into.severity.is_none() {
        into.severity = from.severity;
    }
}

/// Match deduped advisories against the installed components and group the hits into an
/// [`AuditReport`].
///
/// A component is a finding when an advisory for its name has a `vulnerable_range` that contains its
/// exact installed version (`Range::matches`) — the guard against the npm endpoint over-broadening
/// ranges and against OSV's multi-package records. Components are de-duplicated by `name@version`
/// first (a lockfile can pin one version at several tree paths), and each stored advisory records
/// the `matched_version` it applied to. A component whose version or an advisory's range won't parse
/// is skipped rather than reported.
pub fn build_report(advisories: &[Advisory], components: &[Component]) -> AuditReport {
    let mut by_name: BTreeMap<&str, Vec<&Advisory>> = BTreeMap::new();
    for a in advisories {
        by_name.entry(a.package.as_str()).or_default().push(a);
    }

    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut findings = Vec::new();
    let mut counts = Vulnerabilities::default();
    for c in components {
        if !seen.insert((c.name.as_str(), c.version.as_str())) {
            continue; // same name@version already considered (duplicate tree path)
        }
        let Ok(version) = Version::parse(&c.version) else {
            continue;
        };
        let Some(candidates) = by_name.get(c.name.as_str()) else {
            continue;
        };
        let mut hits = Vec::new();
        for adv in candidates {
            let Ok(range) = Range::parse(&adv.vulnerable_range) else {
                continue;
            };
            if range.matches(&version) {
                let mut hit = (*adv).clone();
                hit.matched_version = c.version.clone();
                count_one(&mut counts, hit.severity);
                hits.push(hit);
            }
        }
        if !hits.is_empty() {
            findings.push(ComponentAdvisories {
                component: c.clone(),
                advisories: hits,
            });
        }
    }
    AuditReport {
        findings,
        vulnerabilities: counts,
    }
}

fn count_one(v: &mut Vulnerabilities, severity: Option<Severity>) {
    match severity {
        Some(Severity::Low) => v.low += 1,
        Some(Severity::Moderate) => v.moderate += 1,
        Some(Severity::High) => v.high += 1,
        Some(Severity::Critical) => v.critical += 1,
        None => v.info += 1,
    }
    v.total += 1;
}

/// A plain-text audit summary: a one-line count header, then each vulnerable `name@version` with its
/// advisories. `found 0 vulnerabilities` when clean (mirrors `npm audit`).
pub fn render_summary(report: &AuditReport) -> String {
    use std::fmt::Write as _;
    let v = &report.vulnerabilities;
    let mut s = String::new();
    if v.total == 0 {
        s.push_str("found 0 vulnerabilities\n");
        return s;
    }
    let mut info = String::new();
    if v.info > 0 {
        let _ = write!(info, ", {} info", v.info);
    }
    let _ = writeln!(
        s,
        "found {} vulnerabilit{} ({} critical, {} high, {} moderate, {} low{info}) in {} package(s)",
        v.total,
        if v.total == 1 { "y" } else { "ies" },
        v.critical,
        v.high,
        v.moderate,
        v.low,
        report.findings.len(),
    );
    for f in &report.findings {
        let _ = write!(s, "\n{}@{}\n", f.component.name, f.component.version);
        for a in &f.advisories {
            let severity = a.severity.map(Severity::as_str).unwrap_or("info");
            let _ = writeln!(s, "  {:<8} {}  {}", severity.to_uppercase(), a.id, a.title);
            let mut detail = format!("range {}", a.vulnerable_range);
            if !a.cwe.is_empty() {
                let _ = write!(detail, " · {}", a.cwe.join(", "));
            }
            if let Some(url) = &a.url {
                let _ = write!(detail, " · {url}");
            }
            let _ = writeln!(s, "    {detail}");
        }
    }
    s
}

/// An `npm audit --json`-shaped report: a `vulnerabilities` object keyed by package name (each with
/// its affected installed `versions`, the max `severity`, and the advisories under `via`) plus a
/// `metadata.vulnerabilities` per-severity count block.
pub fn render_json(report: &AuditReport) -> String {
    // Group component findings by name — a name can be installed at several versions.
    let mut by_name: BTreeMap<&str, Vec<&ComponentAdvisories>> = BTreeMap::new();
    for f in &report.findings {
        by_name
            .entry(f.component.name.as_str())
            .or_default()
            .push(f);
    }

    let mut vulns = Map::new();
    for (name, group) in &by_name {
        let mut versions: Vec<&str> = group.iter().map(|f| f.component.version.as_str()).collect();
        versions.sort_unstable();
        versions.dedup();
        let max = group
            .iter()
            .flat_map(|f| f.advisories.iter())
            .filter_map(|a| a.severity)
            .max();
        let via: Vec<Value> = group
            .iter()
            .flat_map(|f| f.advisories.iter())
            .map(advisory_json)
            .collect();
        vulns.insert(
            (*name).to_string(),
            json!({
                "name": name,
                "severity": max.map(Severity::as_str).unwrap_or("info"),
                "versions": versions,
                "via": via,
            }),
        );
    }

    let v = &report.vulnerabilities;
    let doc = json!({
        "vulnerabilities": Value::Object(vulns),
        "metadata": {
            "vulnerabilities": {
                "info": v.info,
                "low": v.low,
                "moderate": v.moderate,
                "high": v.high,
                "critical": v.critical,
                "total": v.total,
            },
        },
    });
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize audit report");
    s.push('\n');
    s
}

fn advisory_json(a: &Advisory) -> Value {
    let mut m = Map::new();
    m.insert("source".into(), json!(a.source));
    m.insert("id".into(), json!(a.id));
    if !a.aliases.is_empty() {
        m.insert("aliases".into(), json!(a.aliases));
    }
    m.insert("title".into(), json!(a.title));
    m.insert("vulnerable_range".into(), json!(a.vulnerable_range));
    if !a.matched_version.is_empty() {
        m.insert("matched_version".into(), json!(a.matched_version));
    }
    if let Some(s) = a.severity {
        m.insert("severity".into(), json!(s.as_str()));
    }
    if let Some(u) = &a.url {
        m.insert("url".into(), json!(u));
    }
    if !a.cwe.is_empty() {
        m.insert("cwe".into(), json!(a.cwe));
    }
    if let Some(score) = a.cvss_score {
        m.insert("cvss_score".into(), json!(score));
    }
    if let Some(vector) = &a.cvss_vector {
        m.insert("cvss_vector".into(), json!(vector));
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory(
        source: &'static str,
        id: &str,
        aliases: &[&str],
        range: &str,
        sev: Option<Severity>,
    ) -> Advisory {
        Advisory {
            source,
            id: id.into(),
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            package: "lodash".into(),
            vulnerable_range: range.into(),
            severity: sev,
            title: format!("advisory {id}"),
            url: None,
            cwe: vec![],
            cvss_score: None,
            cvss_vector: None,
            matched_version: String::new(),
        }
    }

    fn component(name: &str, version: &str) -> Component {
        Component {
            name: name.into(),
            version: version.into(),
            purl: format!("pkg:npm/{name}@{version}"),
            license: None,
            resolved: None,
            integrity: None,
        }
    }

    #[test]
    fn severity_buckets_from_cvss() {
        assert_eq!(severity_from_cvss(0.0), None);
        assert_eq!(severity_from_cvss(3.9), Some(Severity::Low));
        assert_eq!(severity_from_cvss(6.9), Some(Severity::Moderate));
        assert_eq!(severity_from_cvss(7.2), Some(Severity::High));
        assert_eq!(severity_from_cvss(9.8), Some(Severity::Critical));
        assert!(Severity::Low < Severity::Critical);
        assert_eq!(
            Severity::from_str_loose("CRITICAL"),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::from_str_loose("medium"), Some(Severity::Moderate));
        assert_eq!(Severity::from_str_loose("info"), None);
    }

    #[test]
    fn dedup_joins_on_shared_alias_and_enriches() {
        let npm = advisory(
            "npm",
            "GHSA-aaaa-bbbb-cccc",
            &["GHSA-aaaa-bbbb-cccc"],
            "<2.0.0",
            Some(Severity::High),
        );
        let mut osv = advisory(
            "osv",
            "GHSA-aaaa-bbbb-cccc",
            &["GHSA-aaaa-bbbb-cccc", "CVE-2021-1"],
            "<2.0.0",
            Some(Severity::High),
        );
        osv.url = Some("https://osv.dev/x".into());
        osv.cwe = vec!["CWE-79".into()];

        let out = dedup_advisories(vec![npm, osv]);
        assert_eq!(out.len(), 1, "the two sources collapse to one advisory");
        assert_eq!(out[0].source, "npm", "first occurrence wins");
        assert!(
            out[0].aliases.iter().any(|a| a == "CVE-2021-1"),
            "CVE alias merged in from osv"
        );
        assert_eq!(
            out[0].url.as_deref(),
            Some("https://osv.dev/x"),
            "url enriched"
        );
        assert_eq!(out[0].cwe, vec!["CWE-79"], "cwe enriched");

        // A different CVE for the same package does NOT collapse.
        let a = advisory("npm", "GHSA-1", &["CVE-1"], "<2.0.0", Some(Severity::Low));
        let b = advisory("osv", "GHSA-2", &["CVE-2"], "<2.0.0", Some(Severity::Low));
        assert_eq!(dedup_advisories(vec![a, b]).len(), 2);
    }

    #[test]
    fn build_report_keeps_only_in_range_installs_and_counts() {
        let advisories = vec![
            advisory(
                "npm",
                "GHSA-old",
                &["GHSA-old"],
                "<4.17.21",
                Some(Severity::High),
            ),
            advisory(
                "npm",
                "GHSA-wide",
                &["GHSA-wide"],
                "<=4.17.23",
                Some(Severity::Moderate),
            ),
        ];
        // 4.17.20 is below both ceilings → two findings, counted.
        let r = build_report(&advisories, &[component("lodash", "4.17.20")]);
        assert_eq!(r.vulnerabilities.total, 2);
        assert_eq!(r.vulnerabilities.high, 1);
        assert_eq!(r.vulnerabilities.moderate, 1);
        assert_eq!(r.findings[0].advisories[0].matched_version, "4.17.20");

        // 4.17.22 clears the <4.17.21 one but is still <=4.17.23.
        let r = build_report(&advisories, &[component("lodash", "4.17.22")]);
        assert_eq!(r.vulnerabilities.total, 1);
        assert!(r.findings[0].advisories.iter().all(|a| a.id == "GHSA-wide"));

        // A package the advisories don't mention is clean; an unparsable version is skipped.
        assert_eq!(
            build_report(&advisories, &[component("left-pad", "1.3.0")])
                .vulnerabilities
                .total,
            0
        );
        assert_eq!(
            build_report(&advisories, &[component("lodash", "not-semver")])
                .vulnerabilities
                .total,
            0
        );
    }

    #[test]
    fn build_report_dedups_same_name_version_across_tree_paths() {
        let advisories = vec![advisory(
            "npm",
            "GHSA-x",
            &["GHSA-x"],
            "<2.0.0",
            Some(Severity::Low),
        )];
        // The same lodash@1.0.0 pinned at two paths must not double-count.
        let r = build_report(
            &advisories,
            &[component("lodash", "1.0.0"), component("lodash", "1.0.0")],
        );
        assert_eq!(r.vulnerabilities.total, 1);
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn exceeds_respects_threshold_and_renders() {
        let advisories = vec![advisory(
            "npm",
            "GHSA-h",
            &["GHSA-h"],
            "<2.0.0",
            Some(Severity::High),
        )];
        let report = build_report(&advisories, &[component("lodash", "1.0.0")]);
        assert!(report.exceeds(Severity::Low));
        assert!(report.exceeds(Severity::High));
        assert!(!report.exceeds(Severity::Critical));
        assert_eq!(report.max_severity(), Some(Severity::High));

        assert!(render_summary(&report).contains("found 1 vulnerability"));
        assert!(render_summary(&report).contains("lodash@1.0.0"));
        let empty = AuditReport {
            findings: vec![],
            vulnerabilities: Vulnerabilities::default(),
        };
        assert_eq!(render_summary(&empty), "found 0 vulnerabilities\n");

        // JSON shape: keyed by name, with a metadata count block.
        let doc: Value = serde_json::from_str(&render_json(&report)).unwrap();
        assert_eq!(doc["vulnerabilities"]["lodash"]["severity"], "high");
        assert_eq!(doc["metadata"]["vulnerabilities"]["high"], 1);
        assert_eq!(doc["metadata"]["vulnerabilities"]["total"], 1);
    }
}
