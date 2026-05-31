//! Minimal `package.json` reader for consumers that pin dependency versions
//! there (rather than resolving against the registry).

use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A dependency parsed from a `package.json` `dependencies` map.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    /// True when the spec points at a git/GitHub source rather than a registry
    /// version (e.g. `github:owner/repo#ref`).
    pub is_git: bool,
}

/// Parse the `dependencies` section of a `package.json`.
pub fn parse_dependencies(
    package_json_path: &Path,
) -> Result<HashMap<String, Dependency>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(package_json_path)?;
    let json: Value = serde_json::from_str(&content)?;

    let deps = json
        .get("dependencies")
        .and_then(|d| d.as_object())
        .ok_or("no dependencies section found in package.json")?;

    let mut dependencies = HashMap::new();
    for (name, value) in deps {
        if let Some(version_str) = value.as_str() {
            let is_git = version_str.contains("github.com") || version_str.starts_with("git");
            let version = extract_version(version_str);
            validate_package_name(name)?;
            validate_version(&version)?;
            dependencies.insert(
                name.clone(),
                Dependency {
                    name: name.clone(),
                    version,
                    is_git,
                },
            );
        }
    }

    Ok(dependencies)
}

/// Reject npm package names whose characters could escape a path or URL. npm
/// restricts names to lowercase letters, digits, `.`, `_`, `-`, `@`, and `/`
/// (scoped). Anything else is a typo or a crafted entry meant to traverse a
/// path later — fail loudly.
fn validate_package_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_empty() || name.len() > 200 {
        return Err(format!("package name {name:?} has invalid length").into());
    }
    if name.contains("..") {
        return Err(format!("package name {name:?} contains '..'").into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@' | b'/'))
    {
        return Err(format!("package name {name:?} contains disallowed characters").into());
    }
    Ok(())
}

/// Reject versions outside the semver-adjacent alphabet, before the value ends
/// up in a URL, a cache filename, or a marker — none of which should contain a
/// path separator.
fn validate_version(version: &str) -> Result<(), Box<dyn std::error::Error>> {
    if version.is_empty() || version.len() > 100 {
        return Err(format!("version {version:?} has invalid length").into());
    }
    if version.contains("..") {
        return Err(format!("version {version:?} contains '..'").into());
    }
    if !version
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(format!("version {version:?} contains disallowed characters").into());
    }
    Ok(())
}

/// Extract a bare version from a spec string. Handles `"1.2.3"`, `"^1.2.3"`,
/// `"~1.2.3"`, and git URLs (`"...#ref"` → `ref`).
fn extract_version(value: &str) -> String {
    if value.contains("github.com") || value.starts_with("git") {
        if let Some(hash_pos) = value.rfind('#') {
            return value[hash_pos + 1..].to_string();
        }
    }
    value
        .trim_start_matches('^')
        .trim_start_matches('~')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_pinned_caret_and_git_specs() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("package.json");
        fs::write(
            &p,
            r#"{ "dependencies": {
                "lit": "3.3.3",
                "bootstrap": "^5.3.8",
                "forked": "github:owner/repo#abc123"
            } }"#,
        )
        .unwrap();

        let deps = parse_dependencies(&p).unwrap();
        assert_eq!(deps["lit"].version, "3.3.3");
        assert!(!deps["lit"].is_git);
        assert_eq!(deps["bootstrap"].version, "5.3.8");
        assert_eq!(deps["forked"].version, "abc123");
        assert!(deps["forked"].is_git);
    }
}
