//! The OSV (osv.dev) advisory source.
//!
//! A batched `POST /v1/querybatch` returns vulnerability ids per query (positionally, one result
//! list per queried component); each id is then hydrated with `GET /v1/vulns/{id}` for the full
//! record — structured `affected` ranges, aliases (CVE/GHSA), and severity. OSV records span many
//! packages and ecosystems, so a record is only relevant when one of its `affected` entries is the
//! npm package we asked about; that entry's SEMVER `events` are turned into a `>=`/`<` range string
//! the shared [`Range`](crate::package_json::spec::Range) matcher can post-filter.

use std::collections::HashMap;

use serde_json::{json, Value};

use super::{Advisory, AdvisorySource, Severity};
use crate::download;
use crate::sbom::Component;

const QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const VULN_URL_BASE: &str = "https://api.osv.dev/v1/vulns";

/// Queries the public OSV database (osv.dev).
pub struct OsvSource;

impl AdvisorySource for OsvSource {
    fn name(&self) -> &'static str {
        "osv"
    }

    fn query(&self, components: &[Component]) -> crate::Result<Vec<Advisory>> {
        if components.is_empty() {
            return Ok(Vec::new());
        }
        let raw = serde_json::to_vec(&querybatch_body(components))?;
        let Some(resp) = download::post_json(QUERYBATCH_URL, &raw, None, Some("application/json"))
        else {
            eprintln!("npm-utils: OSV advisory lookup failed; audit results may be incomplete");
            return Ok(Vec::new());
        };

        // `results` is positional: results[i] holds the vuln ids for components[i].
        let mut wanted: Vec<(String, String)> = Vec::new(); // (component name, vuln id)
        if let Some(results) = resp.get("results").and_then(Value::as_array) {
            for (i, result) in results.iter().enumerate() {
                let Some(name) = components.get(i).map(|c| c.name.clone()) else {
                    continue;
                };
                let Some(vulns) = result.get("vulns").and_then(Value::as_array) else {
                    continue;
                };
                for v in vulns {
                    if let Some(id) = v.get("id").and_then(Value::as_str) {
                        wanted.push((name.clone(), id.to_string()));
                    }
                }
            }
        }

        // Hydrate each distinct id once (a record can apply to several queried packages).
        let mut records: HashMap<String, Option<Value>> = HashMap::new();
        let mut out = Vec::new();
        for (name, id) in wanted {
            let record = records.entry(id.clone()).or_insert_with(|| hydrate(&id));
            if let Some(record) = record {
                if let Some(advisory) = parse_osv_vuln(record, &name) {
                    out.push(advisory);
                }
            }
        }
        Ok(out)
    }
}

/// The querybatch body: one `{ package, version }` query per component, in order.
fn querybatch_body(components: &[Component]) -> Value {
    let queries: Vec<Value> = components
        .iter()
        .map(|c| {
            json!({
                "package": { "name": c.name, "ecosystem": "npm" },
                "version": c.version,
            })
        })
        .collect();
    json!({ "queries": queries })
}

fn hydrate(id: &str) -> Option<Value> {
    let bytes = download::fetch(&format!("{VULN_URL_BASE}/{id}")).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

/// Parse a hydrated OSV record into an [`Advisory`] for the npm package `want_name`, or `None` when
/// the record has no `affected` entry for that npm package. Severity is read from
/// `database_specific.severity` (a bucket word); the CVSS vector, when present, is carried for
/// display but not scored. The vulnerable range is synthesized from the matching entry's SEMVER
/// events.
pub fn parse_osv_vuln(record: &Value, want_name: &str) -> Option<Advisory> {
    let id = record.get("id").and_then(Value::as_str)?.to_string();
    let affected = record.get("affected").and_then(Value::as_array)?;
    let entry = affected.iter().find(|a| {
        let pkg = a.get("package");
        pkg.and_then(|p| p.get("ecosystem")).and_then(Value::as_str) == Some("npm")
            && pkg.and_then(|p| p.get("name")).and_then(Value::as_str) == Some(want_name)
    })?;
    let vulnerable_range = osv_range_string(entry)?;

    let database_specific = record.get("database_specific");
    let severity = database_specific
        .and_then(|d| d.get("severity"))
        .and_then(Value::as_str)
        .and_then(Severity::from_str_loose);
    let cvss_vector = record
        .get("severity")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find_map(|s| s.get("score").and_then(Value::as_str))
        })
        .map(str::to_string);
    let url = record
        .get("references")
        .and_then(Value::as_array)
        .and_then(|refs| {
            refs.iter()
                .find_map(|r| r.get("url").and_then(Value::as_str))
        })
        .map(str::to_string)
        .or_else(|| Some(format!("https://osv.dev/vulnerability/{id}")));

    Some(Advisory {
        source: "osv",
        id,
        aliases: string_array(record.get("aliases")),
        package: want_name.to_string(),
        vulnerable_range,
        severity,
        title: record
            .get("summary")
            .or_else(|| record.get("details"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        url,
        cwe: string_array(database_specific.and_then(|d| d.get("cwe_ids"))),
        cvss_score: None,
        cvss_vector,
        matched_version: String::new(),
    })
}

/// Turn an `affected` entry's SEMVER ranges into an npm-style range string. Within a range the
/// events are an ordered sequence: an `introduced` opens an interval (`>=A`, or nothing for `"0"`),
/// a `fixed`/`last_affected` closes it (`<B` / `<=B`); an interval still open at the end is
/// open-ended. Intervals are ANDed within a range and ORed (`||`) across ranges — so e.g.
/// `[introduced:0, fixed:4.17.12]` → `<4.17.12`, and a two-interval range →
/// `>=1.0.0 <1.2.0 || >=2.0.0 <2.2.0`. `None` if there are no usable SEMVER bounds.
fn osv_range_string(entry: &Value) -> Option<String> {
    let ranges = entry.get("ranges").and_then(Value::as_array)?;
    let mut alternatives: Vec<String> = Vec::new();
    for r in ranges {
        if r.get("type").and_then(Value::as_str) != Some("SEMVER") {
            continue;
        }
        let Some(events) = r.get("events").and_then(Value::as_array) else {
            continue;
        };
        let mut lower: Option<String> = None;
        let mut open = false;
        for e in events {
            if let Some(introduced) = e.get("introduced").and_then(Value::as_str) {
                lower = (introduced != "0").then(|| introduced.to_string());
                open = true;
            } else if let Some(fixed) = e.get("fixed").and_then(Value::as_str) {
                alternatives.push(interval(lower.as_deref(), Some(("<", fixed))));
                lower = None;
                open = false;
            } else if let Some(last) = e.get("last_affected").and_then(Value::as_str) {
                alternatives.push(interval(lower.as_deref(), Some(("<=", last))));
                lower = None;
                open = false;
            }
        }
        if open {
            alternatives.push(interval(lower.as_deref(), None));
        }
    }
    (!alternatives.is_empty()).then(|| alternatives.join(" || "))
}

/// One affected interval as comparators: a lower `>=A` (when bounded) ANDed with an upper `<B`/`<=B`
/// (when present). An interval with neither bound is "all versions" (`*`).
fn interval(lower: Option<&str>, upper: Option<(&str, &str)>) -> String {
    let mut parts = Vec::new();
    if let Some(l) = lower {
        parts.push(format!(">={l}"));
    }
    if let Some((op, v)) = upper {
        parts.push(format!("{op}{v}"));
    }
    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join(" ")
    }
}

fn string_array(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_range_from_simple_introduced_zero_fixed() {
        let entry = json!({
            "package": { "name": "lodash", "ecosystem": "npm" },
            "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": "4.17.12" }] }]
        });
        assert_eq!(osv_range_string(&entry).as_deref(), Some("<4.17.12"));
    }

    #[test]
    fn osv_range_from_bounded_and_multi_interval() {
        let bounded = json!({ "ranges": [{ "type": "SEMVER",
            "events": [{ "introduced": "1.0.0" }, { "fixed": "1.5.0" }] }] });
        assert_eq!(
            osv_range_string(&bounded).as_deref(),
            Some(">=1.0.0 <1.5.0")
        );

        let multi = json!({ "ranges": [{ "type": "SEMVER", "events": [
            { "introduced": "1.0.0" }, { "fixed": "1.2.0" },
            { "introduced": "2.0.0" }, { "fixed": "2.2.0" }
        ] }] });
        assert_eq!(
            osv_range_string(&multi).as_deref(),
            Some(">=1.0.0 <1.2.0 || >=2.0.0 <2.2.0")
        );

        let open =
            json!({ "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "3.0.0" }] }] });
        assert_eq!(osv_range_string(&open).as_deref(), Some(">=3.0.0"));
    }

    #[test]
    fn parse_osv_vuln_matches_npm_package_only() {
        let record = json!({
            "id": "GHSA-jf85-cpcp-j695",
            "summary": "Prototype Pollution in lodash",
            "aliases": ["CVE-2019-10744"],
            "database_specific": { "severity": "CRITICAL", "cwe_ids": ["CWE-1321", "CWE-20"] },
            "references": [{ "type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10744" }],
            "affected": [
                { "package": { "name": "lodash", "ecosystem": "npm" },
                  "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": "4.17.12" }] }] },
                { "package": { "name": "lodash-rails", "ecosystem": "RubyGems" },
                  "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": "4.17.12" }] }] }
            ]
        });
        let adv = parse_osv_vuln(&record, "lodash").expect("npm lodash affected");
        assert_eq!(adv.source, "osv");
        assert_eq!(adv.id, "GHSA-jf85-cpcp-j695");
        assert_eq!(adv.aliases, vec!["CVE-2019-10744"]);
        assert_eq!(adv.severity, Some(Severity::Critical));
        assert_eq!(adv.vulnerable_range, "<4.17.12");
        assert_eq!(adv.cwe, vec!["CWE-1321", "CWE-20"]);
        assert_eq!(
            adv.url.as_deref(),
            Some("https://nvd.nist.gov/vuln/detail/CVE-2019-10744")
        );

        // The RubyGems ecosystem and unrelated names are ignored.
        assert!(parse_osv_vuln(&record, "lodash-rails").is_none());
        assert!(parse_osv_vuln(&record, "express").is_none());
    }
}
