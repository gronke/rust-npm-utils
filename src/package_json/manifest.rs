//! Pure `package.json` *write-side* transforms — the counterpart to this module's readers.
//!
//! Everything here is a `serde_json::Value` → `Value`/`String` transform: nothing touches the
//! filesystem (the CLI reads and writes the file), so [`crate::package_json`]'s "parses and
//! renders, never does IO" invariant holds and these stay trivially testable. The CLI's `add` /
//! `init` verbs compose them.
//!
//! Key order is npm-faithful only because the crate enables `serde_json`'s `preserve_order`
//! feature: a parsed object keeps the user's field order on re-serialize, and [`dependencies`] is
//! re-sorted alphabetically the way npm does on save.

use serde_json::{Map, Value};

/// A fresh `package.json` document (`name`, `version`, empty `dependencies`) for `npm init`.
pub fn scaffold(name: &str, version: &str) -> Value {
    let mut obj = Map::new();
    obj.insert("name".into(), Value::String(name.to_string()));
    obj.insert("version".into(), Value::String(version.to_string()));
    obj.insert("dependencies".into(), Value::Object(Map::new()));
    Value::Object(obj)
}

/// Add or update `dependencies[name] = range` in place, then re-sort the `dependencies` object
/// alphabetically (npm's on-save behavior). All other fields keep their position. A no-op if
/// `doc` is not a JSON object (a malformed `package.json` the caller should have rejected).
pub fn upsert_dependency(doc: &mut Value, name: &str, range: &str) {
    let Some(obj) = doc.as_object_mut() else {
        return;
    };
    let deps = obj
        .entry("dependencies")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(map) = deps.as_object_mut() {
        map.insert(name.to_string(), Value::String(range.to_string()));
        sort_keys(map);
    }
}

/// The `(name, range)` pairs of the `dependencies` object (string values only), sorted by name.
/// Empty when there is no `dependencies` object.
pub fn dependencies(doc: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = doc
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Serialize a manifest as pretty JSON (npm's two-space indent) with a trailing newline.
pub fn to_pretty(doc: &Value) -> String {
    let mut s = serde_json::to_string_pretty(doc).expect("serialize package.json");
    s.push('\n');
    s
}

/// Re-insert a `preserve_order` object's entries in key order. (With `preserve_order`, `Map` keeps
/// insertion order, so clearing and re-inserting sorted yields sorted iteration/serialization.)
fn sort_keys(map: &mut Map<String, Value>) {
    let mut entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in entries {
        map.insert(k, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_has_name_version_and_empty_deps() {
        let doc = scaffold("my-app", "1.0.0");
        assert_eq!(doc["name"], "my-app");
        assert_eq!(doc["version"], "1.0.0");
        assert!(doc["dependencies"].as_object().unwrap().is_empty());
    }

    #[test]
    fn upsert_preserves_other_keys_and_sorts_dependencies() {
        // A manifest whose siblings (scripts) sit AFTER dependencies, and whose deps are
        // out of order — the npm-faithful result keeps name/version/scripts in place and
        // sorts only within dependencies.
        let mut doc: Value = serde_json::from_str(
            r#"{"name":"app","version":"1.0.0","dependencies":{"c":"^1","a":"^1"},"scripts":{"build":"x"}}"#,
        )
        .unwrap();
        upsert_dependency(&mut doc, "b", "^2");

        // Top-level field order is preserved (name, version, dependencies, scripts).
        let keys: Vec<&str> = doc
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["name", "version", "dependencies", "scripts"]);
        // dependencies sorted alphabetically, with the new one inserted in place.
        assert_eq!(
            dependencies(&doc),
            vec![
                ("a".to_string(), "^1".to_string()),
                ("b".to_string(), "^2".to_string()),
                ("c".to_string(), "^1".to_string()),
            ]
        );
        // scripts untouched.
        assert_eq!(doc["scripts"]["build"], "x");
    }

    #[test]
    fn upsert_updates_an_existing_range_in_place() {
        let mut doc = scaffold("app", "1.0.0");
        upsert_dependency(&mut doc, "lit", "^3");
        upsert_dependency(&mut doc, "lit", "^3.2.0");
        assert_eq!(
            dependencies(&doc),
            vec![("lit".to_string(), "^3.2.0".to_string())]
        );
    }

    #[test]
    fn upsert_creates_the_dependencies_object_when_absent() {
        let mut doc: Value = serde_json::from_str(r#"{"name":"app","version":"1.0.0"}"#).unwrap();
        upsert_dependency(&mut doc, "ms", "^2");
        assert_eq!(doc["dependencies"]["ms"], "^2");
    }

    #[test]
    fn to_pretty_is_two_space_indented_with_trailing_newline() {
        let doc = scaffold("app", "1.0.0");
        let text = to_pretty(&doc);
        assert!(text.ends_with("}\n"));
        assert!(
            text.contains("\n  \"name\": \"app\""),
            "two-space indent: {text}"
        );
    }
}
