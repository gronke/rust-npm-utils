//! npm's native bulk-advisory source.
//!
//! npm's legacy `audits` / `audits/quick` endpoints are retired (they answer `410`); the live
//! contract is a single `POST` of a gzipped `{ "<name>": ["<version>", …] }` map to
//! `/-/npm/v1/security/advisories/bulk`. The response is keyed by package name; each advisory
//! carries `id` (numeric), `url`, `title`, `severity`, `vulnerable_versions`, `cwe[]`, and sometimes
//! `cvss` — but **no CVE**, so the GHSA is parsed out of the advisory `url` for the alias set.

use std::io::Write as _;

use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::{json, Map, Value};

use super::{severity_from_cvss, Advisory, AdvisorySource, Severity};
use crate::download;
use crate::sbom::Component;

/// Queries npm's bulk security-advisory endpoint. `registry_base` lets the query target a private
/// mirror; the public registry is `https://registry.npmjs.org`.
pub struct NpmRegistrySource {
    pub registry_base: String,
}

impl NpmRegistrySource {
    pub fn new(registry_base: impl Into<String>) -> NpmRegistrySource {
        NpmRegistrySource {
            registry_base: registry_base.into(),
        }
    }
}

impl AdvisorySource for NpmRegistrySource {
    fn name(&self) -> &'static str {
        "npm"
    }

    fn query(&self, components: &[Component]) -> crate::Result<Vec<Advisory>> {
        if components.is_empty() {
            return Ok(Vec::new());
        }
        let gz = gzip(&serde_json::to_vec(&bulk_request_body(components))?)?;
        let url = format!(
            "{}/-/npm/v1/security/advisories/bulk",
            self.registry_base.trim_end_matches('/')
        );
        match download::post_json(&url, &gz, Some("gzip"), Some("application/json")) {
            Some(body) => Ok(parse_npm_bulk(&body)),
            None => {
                eprintln!(
                    "npm-utils: npm advisory lookup failed or returned no data; \
                     audit results may be incomplete"
                );
                Ok(Vec::new())
            }
        }
    }
}

/// The bulk request body — `{ "<name>": ["<version>", …], … }` over the installed components, each
/// name's versions de-duplicated.
fn bulk_request_body(components: &[Component]) -> Value {
    let mut map: Map<String, Value> = Map::new();
    for c in components {
        let versions = map.entry(c.name.clone()).or_insert_with(|| json!([]));
        if let Some(arr) = versions.as_array_mut() {
            let v = Value::from(c.version.clone());
            if !arr.contains(&v) {
                arr.push(v);
            }
        }
    }
    Value::Object(map)
}

fn gzip(raw: &[u8]) -> crate::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(raw)?;
    Ok(encoder.finish()?)
}

/// Parse the bulk endpoint's response: an object keyed by package name, each value an array of
/// advisory objects. The GHSA is recovered from each advisory's `url` (the only cross-source id the
/// payload offers) and used as the native id and an alias; severity comes from the `severity` word,
/// falling back to the CVSS score.
pub fn parse_npm_bulk(body: &Value) -> Vec<Advisory> {
    let mut out = Vec::new();
    let Some(obj) = body.as_object() else {
        return out;
    };
    for (name, advisories) in obj {
        let Some(arr) = advisories.as_array() else {
            continue;
        };
        for adv in arr {
            let url = adv.get("url").and_then(Value::as_str).map(str::to_string);
            let ghsa = url.as_deref().and_then(ghsa_from_url);
            let cvss_score = adv
                .get("cvss")
                .and_then(|c| c.get("score"))
                .and_then(Value::as_f64);
            let severity = adv
                .get("severity")
                .and_then(Value::as_str)
                .and_then(Severity::from_str_loose)
                .or_else(|| cvss_score.and_then(severity_from_cvss));
            let aliases = ghsa.iter().cloned().collect();
            out.push(Advisory {
                source: "npm",
                // Prefer the GHSA as the id; fall back to the numeric advisory id.
                id: ghsa
                    .or_else(|| adv.get("id").map(value_to_id))
                    .unwrap_or_default(),
                aliases,
                package: name.clone(),
                vulnerable_range: adv
                    .get("vulnerable_versions")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                severity,
                title: adv
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                url,
                cwe: string_array(adv.get("cwe")),
                cvss_score,
                cvss_vector: adv
                    .get("cvss")
                    .and_then(|c| c.get("vectorString"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                matched_version: String::new(),
            });
        }
    }
    out
}

/// Extract a `GHSA-…` id from a GitHub advisory URL (`https://github.com/advisories/GHSA-…`).
pub fn ghsa_from_url(url: &str) -> Option<String> {
    let after = url.split("/advisories/").nth(1)?;
    let id: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    id.starts_with("GHSA-").then_some(id)
}

fn value_to_id(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
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
    use crate::sbom::Component;

    #[test]
    fn ghsa_parsed_from_advisory_url() {
        assert_eq!(
            ghsa_from_url("https://github.com/advisories/GHSA-35jh-r3h4-6jhm").as_deref(),
            Some("GHSA-35jh-r3h4-6jhm")
        );
        assert_eq!(
            ghsa_from_url("https://github.com/advisories/GHSA-35jh-r3h4-6jhm?ref=x").as_deref(),
            Some("GHSA-35jh-r3h4-6jhm")
        );
        assert_eq!(ghsa_from_url("https://example.com/whatever"), None);
    }

    #[test]
    fn bulk_request_body_groups_versions_per_name() {
        let comps = [
            Component {
                name: "lodash".into(),
                version: "4.17.20".into(),
                purl: String::new(),
                license: None,
                resolved: None,
                integrity: None,
            },
            Component {
                name: "lodash".into(),
                version: "4.17.21".into(),
                purl: String::new(),
                license: None,
                resolved: None,
                integrity: None,
            },
            Component {
                name: "ms".into(),
                version: "2.0.0".into(),
                purl: String::new(),
                license: None,
                resolved: None,
                integrity: None,
            },
        ];
        let body = bulk_request_body(&comps);
        assert_eq!(body["lodash"], json!(["4.17.20", "4.17.21"]));
        assert_eq!(body["ms"], json!(["2.0.0"]));
    }

    #[test]
    fn parse_npm_bulk_reads_fields_and_severity() {
        let body = json!({
            "lodash": [{
                "id": 1106913,
                "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                "title": "Command Injection in lodash",
                "severity": "high",
                "vulnerable_versions": "<4.17.21",
                "cwe": ["CWE-77", "CWE-94"],
                "cvss": { "score": 7.2, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }
            }]
        });
        let advisories = parse_npm_bulk(&body);
        assert_eq!(advisories.len(), 1);
        let a = &advisories[0];
        assert_eq!(a.source, "npm");
        assert_eq!(a.id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(a.aliases, vec!["GHSA-35jh-r3h4-6jhm"]);
        assert_eq!(a.package, "lodash");
        assert_eq!(a.vulnerable_range, "<4.17.21");
        assert_eq!(a.severity, Some(Severity::High));
        assert_eq!(a.cwe, vec!["CWE-77", "CWE-94"]);
        assert_eq!(a.cvss_score, Some(7.2));
        assert!(a.cvss_vector.is_some());
    }

    #[test]
    fn parse_npm_bulk_falls_back_to_cvss_for_severity() {
        let body = json!({ "x": [{
            "id": 1, "url": "https://example.com/x", "title": "t",
            "vulnerable_versions": "<1.0.0", "cvss": { "score": 9.5 }
        }]});
        let a = &parse_npm_bulk(&body)[0];
        assert_eq!(a.severity, Some(Severity::Critical)); // from cvss score; no GHSA in url
        assert_eq!(a.id, "1"); // numeric id stringified when no GHSA
    }
}
