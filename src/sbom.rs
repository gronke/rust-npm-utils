//! Software bill of materials + license output for a parsed `package-lock.json`.
//!
//! The packages a lockfile pins ([`crate::package_json::lock`]) become a vendor-neutral bill of
//! materials — a set of [`Component`]s — that this module renders three ways:
//!
//! - [`render_summary`] — a plain-text license overview (which packages are under which license).
//! - [`to_cyclonedx`] — a [CycloneDX] 1.6 JSON document.
//! - [`to_spdx`] — an [SPDX] 2.3 JSON document.
//!
//! All three are pure (no IO, no network): a CLI or build script turns a *committed*
//! `package-lock.json` into compliance artifacts with no Node, no npm. The license + integrity a
//! component carries are exactly what the lockfile records (npm writes both per package, and so
//! does this crate's [`crate::package_json::lock::render_v3`]).
//!
//! [CycloneDX]: https://cyclonedx.org
//! [SPDX]: https://spdx.dev
//!
//! ```no_run
//! use npm_utils::{package_json::lock::Lockfile, sbom};
//! # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let lock = Lockfile::parse(&std::fs::read_to_string("package-lock.json")?)?;
//! let bom = sbom::components(&lock);
//! print!("{}", sbom::render_summary(&bom));
//! std::fs::write("sbom.cdx.json", sbom::to_cyclonedx(&bom, "my-app", "1.0.0", None))?;
//! # Ok(()) }
//! ```

use std::collections::BTreeMap;

use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::package_json::lock::Lockfile;

/// The SPDX/compliance sentinel for "no license/value asserted".
const NOASSERTION: &str = "NOASSERTION";

/// One package in the bill of materials, distilled from a
/// [`LockedPackage`](crate::package_json::lock::LockedPackage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Package name (scoped names keep their `@scope/` prefix).
    pub name: String,
    /// Exact version.
    pub version: String,
    /// Package URL, e.g. `pkg:npm/lit@3.3.3` or `pkg:npm/%40lit/context@1.1.6`.
    pub purl: String,
    /// Declared SPDX license string, when the lockfile records one.
    pub license: Option<String>,
    /// Resolved download location (the registry tarball URL), when present.
    pub resolved: Option<String>,
    /// `sha512-<base64>` Subresource-Integrity, when present.
    pub integrity: Option<String>,
}

/// The real (non-root, non-link) packages a lockfile pins, as bill-of-materials components,
/// sorted by name then version. The root `""` project entry and `link: true` workspace/`file:`
/// links are excluded — a link is a local path, not a distributable package.
pub fn components(lock: &Lockfile) -> Vec<Component> {
    let mut out: Vec<Component> = lock
        .packages
        .iter()
        .filter(|p| p.key.starts_with("node_modules/") && !p.link)
        .map(|p| Component {
            purl: npm_purl(&p.name, &p.version),
            name: p.name.clone(),
            version: p.version.clone(),
            license: p.license.clone(),
            resolved: p.resolved.clone(),
            integrity: p.integrity.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    out
}

/// Group component `name@version`s by their declared license. Components with no declared license
/// fall under `NOASSERTION`. Keys (licenses) and values (packages) are both sorted.
pub fn license_summary(components: &[Component]) -> BTreeMap<String, Vec<String>> {
    let mut by_license: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in components {
        let key = c.license.clone().unwrap_or_else(|| NOASSERTION.to_string());
        by_license
            .entry(key)
            .or_default()
            .push(format!("{}@{}", c.name, c.version));
    }
    for pkgs in by_license.values_mut() {
        pkgs.sort();
    }
    by_license
}

/// A plain-text license overview: a header, then each license with the packages under it.
pub fn render_summary(components: &[Component]) -> String {
    use std::fmt::Write as _;
    let by = license_summary(components);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{} package(s) across {} license(s)",
        components.len(),
        by.len()
    );
    for (license, pkgs) in &by {
        let _ = write!(s, "\n{license} ({})\n", pkgs.len());
        for p in pkgs {
            let _ = writeln!(s, "  {p}");
        }
    }
    s
}

/// Render a CycloneDX 1.6 JSON SBOM. `app_name`/`app_version` describe the root component;
/// `timestamp` is an RFC 3339 string for `metadata.timestamp` (or `None` to omit it — useful for
/// reproducible output and tests).
pub fn to_cyclonedx(
    components: &[Component],
    app_name: &str,
    app_version: &str,
    timestamp: Option<&str>,
) -> String {
    let mut metadata = Map::new();
    if let Some(ts) = timestamp {
        metadata.insert("timestamp".into(), json!(ts));
    }
    metadata.insert(
        "tools".into(),
        json!({ "components": [{
            "type": "application",
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
        }] }),
    );
    metadata.insert(
        "component".into(),
        json!({
            "type": "application",
            "bom-ref": format!("{app_name}@{app_version}"),
            "name": app_name,
            "version": app_version,
        }),
    );

    let comps: Vec<Value> = components
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert("type".into(), json!("library"));
            m.insert("bom-ref".into(), json!(c.purl));
            m.insert("name".into(), json!(c.name));
            m.insert("version".into(), json!(c.version));
            if let Some(lic) = &c.license {
                m.insert("licenses".into(), cyclonedx_licenses(lic));
            }
            m.insert("purl".into(), json!(c.purl));
            if let Some(hex) = sri_to_sha512_hex(c.integrity.as_deref()) {
                m.insert(
                    "hashes".into(),
                    json!([{ "alg": "SHA-512", "content": hex }]),
                );
            }
            Value::Object(m)
        })
        .collect();

    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": Value::Object(metadata),
        "components": comps,
    });
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize CycloneDX");
    s.push('\n');
    s
}

/// Render an SPDX 2.3 JSON SBOM. `name`/`namespace` are the document name and its unique
/// `documentNamespace` URI; `created` is the RFC 3339 creation time (SPDX requires it).
pub fn to_spdx(components: &[Component], name: &str, namespace: &str, created: &str) -> String {
    let packages: Vec<Value> = components
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert(
                "SPDXID".into(),
                json!(format!(
                    "SPDXRef-Package-{}-{}",
                    spdx_id_fragment(&c.name),
                    spdx_id_fragment(&c.version)
                )),
            );
            m.insert("name".into(), json!(c.name));
            m.insert("versionInfo".into(), json!(c.version));
            m.insert(
                "downloadLocation".into(),
                json!(c.resolved.as_deref().unwrap_or(NOASSERTION)),
            );
            m.insert("filesAnalyzed".into(), json!(false));
            m.insert("licenseConcluded".into(), json!(NOASSERTION));
            m.insert(
                "licenseDeclared".into(),
                json!(c.license.as_deref().unwrap_or(NOASSERTION)),
            );
            m.insert("copyrightText".into(), json!(NOASSERTION));
            m.insert(
                "externalRefs".into(),
                json!([{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }]),
            );
            if let Some(hex) = sri_to_sha512_hex(c.integrity.as_deref()) {
                m.insert(
                    "checksums".into(),
                    json!([{ "algorithm": "SHA512", "checksumValue": hex }]),
                );
            }
            Value::Object(m)
        })
        .collect();

    let doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": [format!("Tool: {}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))],
        },
        "packages": packages,
    });
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize SPDX");
    s.push('\n');
    s
}

/// The current UTC time as an RFC 3339 timestamp (second precision), for stamping a freshly
/// generated SBOM — via the `time` crate.
pub fn now_rfc3339() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format current time as RFC 3339")
}

/// `pkg:npm/<name>@<version>` — a [Package URL]. A scoped `@scope/name` percent-encodes its
/// leading `@` to `%40`, per the npm purl type.
///
/// [Package URL]: https://github.com/package-url/purl-spec
fn npm_purl(name: &str, version: &str) -> String {
    let path = match name.strip_prefix('@') {
        Some(rest) => format!("%40{rest}"),
        None => name.to_string(),
    };
    format!("pkg:npm/{path}@{version}")
}

/// CycloneDX `licenses` for one declared license string: a single SPDX id becomes
/// `[{ license: { id } }]`; anything that looks like an SPDX *expression* (contains `OR`/`AND`/
/// `WITH`/parens) becomes `[{ expression }]`.
fn cyclonedx_licenses(license: &str) -> Value {
    if is_spdx_expression(license) {
        json!([{ "expression": license }])
    } else {
        json!([{ "license": { "id": license } }])
    }
}

fn is_spdx_expression(license: &str) -> bool {
    license.contains(" OR ")
        || license.contains(" AND ")
        || license.contains(" WITH ")
        || license.contains('(')
}

/// Decode a `sha512-<base64>` Subresource-Integrity into lowercase hex (the form CycloneDX
/// `hashes`/SPDX `checksums` want). `None` for a missing, non-sha512, or malformed value.
fn sri_to_sha512_hex(integrity: Option<&str>) -> Option<String> {
    let b64 = integrity?.strip_prefix("sha512-")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Sanitize a string into the `SPDXRef-` id charset (`[a-zA-Z0-9.-]`): every other character
/// becomes `-`. Keeps SPDXIDs valid for scoped names (`@lit/context` → `-lit-context`).
fn spdx_id_fragment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small v3 lockfile: a scoped + an unscoped package (one licensed with integrity, one
    /// license-less), plus the root and a `link` that must be excluded.
    const SAMPLE: &str = r#"{
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": { "name": "demo", "version": "1.0.0" },
            "node_modules/lit": {
                "version": "3.3.3",
                "resolved": "https://registry.npmjs.org/lit/-/lit-3.3.3.tgz",
                "integrity": "sha512-HP1SZDqaLDPwsNiqRqi5NcP0SSXciX2s9E+RyqJIIqGo+vJeN5AJVM98CXmW/Wux0nQ5L7jeWUdplCEf0Ee+tg==",
                "license": "BSD-3-Clause"
            },
            "node_modules/@lit/context": {
                "version": "1.1.6",
                "resolved": "https://registry.npmjs.org/@lit/context/-/context-1.1.6.tgz",
                "license": "BSD-3-Clause"
            },
            "node_modules/mystery": { "version": "0.0.1" },
            "node_modules/local-link": { "version": "1.0.0", "link": true }
        }
    }"#;

    fn sample_components() -> Vec<Component> {
        components(&Lockfile::parse(SAMPLE).unwrap())
    }

    #[test]
    fn components_skip_root_and_links_and_build_purls() {
        let c = sample_components();
        let names: Vec<&str> = c.iter().map(|x| x.name.as_str()).collect();
        // Root "" and the `link: true` entry are excluded; sorted by name.
        assert_eq!(names, ["@lit/context", "lit", "mystery"]);
        // Scoped purl percent-encodes the leading `@`.
        assert_eq!(c[0].purl, "pkg:npm/%40lit/context@1.1.6");
        assert_eq!(c[1].purl, "pkg:npm/lit@3.3.3");
    }

    #[test]
    fn license_summary_groups_and_marks_unknown_as_noassertion() {
        let summary = license_summary(&sample_components());
        assert_eq!(
            summary.get("BSD-3-Clause").unwrap(),
            &["@lit/context@1.1.6", "lit@3.3.3"]
        );
        // A package with no declared license is grouped under NOASSERTION.
        assert_eq!(summary.get("NOASSERTION").unwrap(), &["mystery@0.0.1"]);
    }

    #[test]
    fn cyclonedx_has_required_shape_purls_licenses_and_sha512_hash() {
        let json: Value =
            serde_json::from_str(&to_cyclonedx(&sample_components(), "demo", "1.0.0", None))
                .unwrap();
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert_eq!(json["specVersion"], "1.6");
        // No timestamp requested → key omitted (reproducible).
        assert!(json["metadata"].get("timestamp").is_none());

        let lit = &json["components"][1];
        assert_eq!(lit["name"], "lit");
        assert_eq!(lit["purl"], "pkg:npm/lit@3.3.3");
        assert_eq!(lit["licenses"][0]["license"]["id"], "BSD-3-Clause");
        // sha512-<base64> decoded to 64 bytes → 128 lowercase hex chars.
        let hex = lit["hashes"][0]["content"].as_str().unwrap();
        assert_eq!(lit["hashes"][0]["alg"], "SHA-512");
        assert_eq!(hex.len(), 128);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        // The license-less package carries neither a licenses nor a hashes key.
        let mystery = &json["components"][2];
        assert_eq!(mystery["name"], "mystery");
        assert!(mystery.get("licenses").is_none());
        assert!(mystery.get("hashes").is_none());
    }

    #[test]
    fn cyclonedx_uses_expression_for_compound_licenses() {
        let comps = vec![Component {
            name: "dual".into(),
            version: "1.0.0".into(),
            purl: "pkg:npm/dual@1.0.0".into(),
            license: Some("MIT OR Apache-2.0".into()),
            resolved: None,
            integrity: None,
        }];
        let json: Value = serde_json::from_str(&to_cyclonedx(&comps, "x", "1", None)).unwrap();
        assert_eq!(
            json["components"][0]["licenses"][0]["expression"],
            "MIT OR Apache-2.0"
        );
    }

    #[test]
    fn spdx_has_required_shape_ids_purls_and_license() {
        let json: Value = serde_json::from_str(&to_spdx(
            &sample_components(),
            "demo-sbom",
            "https://spdx.example/demo",
            "2026-01-01T00:00:00Z",
        ))
        .unwrap();
        assert_eq!(json["spdxVersion"], "SPDX-2.3");
        assert_eq!(json["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(json["creationInfo"]["created"], "2026-01-01T00:00:00Z");

        // Scoped name sanitized into a valid SPDXID.
        let scoped = &json["packages"][0];
        assert_eq!(scoped["SPDXID"], "SPDXRef-Package--lit-context-1.1.6");
        assert_eq!(scoped["licenseDeclared"], "BSD-3-Clause");
        assert_eq!(
            scoped["externalRefs"][0]["referenceLocator"],
            "pkg:npm/%40lit/context@1.1.6"
        );
        // License-less package → NOASSERTION.
        assert_eq!(json["packages"][2]["licenseDeclared"], "NOASSERTION");
    }

    #[test]
    fn sri_decodes_to_64_byte_sha512_hex() {
        let hex = sri_to_sha512_hex(Some(
            "sha512-HP1SZDqaLDPwsNiqRqi5NcP0SSXciX2s9E+RyqJIIqGo+vJeN5AJVM98CXmW/Wux0nQ5L7jeWUdplCEf0Ee+tg==",
        ))
        .unwrap();
        assert_eq!(hex.len(), 128); // 64 bytes
        assert!(sri_to_sha512_hex(Some("sha1-deadbeef")).is_none()); // not sha512
        assert!(sri_to_sha512_hex(None).is_none());
    }
}
