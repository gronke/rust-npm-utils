//! The npm "package spec" — the dependency-specifier grammar, per
//! <https://docs.npmjs.com/cli/v8/using-npm/package-spec>.
//!
//! A `package.json` `dependencies` *value* is one of these forms. [`Spec::parse`] classifies
//! a value by *form*; [`Spec::is_registry`] reports whether it resolves to a fetchable
//! registry tarball — the only form `npm-utils` installs (git / remote-tarball / local-path /
//! alias-to-non-registry are not). Range *parsing* is deferred to [`version_req`]: classifying
//! never fails, so an npm range we can't fully parse (spaces, `||`) is still a registry spec.

use semver::{Version, VersionReq};

/// A classified npm dependency specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    /// A registry spec — an exact version, a semver range, or a dist-tag (e.g. `latest`) —
    /// held raw. Resolve it with [`version_req`] (the Rust `semver` subset of npm's grammar).
    Registry(String),
    /// An `npm:<name>@<spec>` alias — install `name` (per the inner spec) under the
    /// dependency's own key.
    Alias { name: String, spec: Box<Spec> },
    /// A git source — a full git URL or a `host:owner/repo` / bare `owner/repo` shorthand —
    /// with an optional `#<committish>` (branch, tag, commit, or `semver:<range>`).
    Git {
        source: String,
        committish: Option<String>,
    },
    /// A remote tarball fetched over http(s).
    Tarball(String),
    /// A local path (`file:…`, `./`, `../`, `/abs`, `~/…`), linked or copied in place.
    Path(String),
}

impl Spec {
    /// Classify a `dependencies` value by form. Never fails — an unparseable-but-registry
    /// range is still [`Spec::Registry`]; turning it into a [`VersionReq`] is a later step.
    pub fn parse(spec: &str) -> Spec {
        let s = spec.trim();

        if let Some(rest) = s.strip_prefix("npm:") {
            let (name, inner) = split_alias(rest);
            return Spec::Alias {
                name: name.to_string(),
                spec: Box::new(Spec::parse(inner)),
            };
        }
        if is_git_url(s) {
            return git_spec(s);
        }
        if s.starts_with("http://") || s.starts_with("https://") {
            return Spec::Tarball(s.to_string());
        }
        if is_path(s) {
            return Spec::Path(s.to_string());
        }
        // After ruling out paths, a bare `owner/repo` is a GitHub shorthand.
        if is_git_shorthand(s) {
            return git_spec(s);
        }
        Spec::Registry(s.to_string())
    }

    /// Whether this spec resolves to a registry tarball (the only form `npm-utils` fetches).
    pub fn is_registry(&self) -> bool {
        match self {
            Spec::Registry(_) => true,
            Spec::Alias { spec, .. } => spec.is_registry(),
            Spec::Git { .. } | Spec::Tarball(_) | Spec::Path(_) => false,
        }
    }
}

/// npm-faithful version → [`VersionReq`]: a bare full version (`1.2.3`) is an **exact** pin
/// (`=1.2.3`); `*`, empty, `x`, and `latest` mean any; range syntax (`^`, `~`, `>=`, …) parses
/// as written, within what the Rust `semver` crate accepts (comma-separated comparators; npm's
/// space-separated and `||` ranges are not supported).
pub fn version_req(spec: &str) -> Result<VersionReq, semver::Error> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" || spec == "x" || spec == "latest" {
        return Ok(VersionReq::STAR);
    }
    if Version::parse(spec).is_ok() {
        return VersionReq::parse(&format!("={spec}"));
    }
    VersionReq::parse(spec)
}

/// Build a [`Spec::Git`], splitting off a `#committish` if present.
fn git_spec(s: &str) -> Spec {
    match s.split_once('#') {
        Some((source, c)) => Spec::Git {
            source: source.to_string(),
            committish: Some(c.to_string()),
        },
        None => Spec::Git {
            source: s.to_string(),
            committish: None,
        },
    }
}

/// Whether a spec value starts with an explicit git scheme or host shorthand.
fn is_git_url(s: &str) -> bool {
    const GIT_PREFIXES: &[&str] = &[
        "git+",
        "git://",
        "git@",
        "ssh://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
    ];
    GIT_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// Whether a spec value is a bare `owner/repo` GitHub shorthand. Checked only *after* paths
/// are ruled out: a slash, not scoped (`@`), and no URL scheme. A registry range never
/// contains '/', so this is unambiguous here.
fn is_git_shorthand(s: &str) -> bool {
    let head = s.split('#').next().unwrap_or(s);
    head.contains('/') && !head.starts_with('@') && !head.contains("://")
}

/// Whether a spec value names a local path. `~1.2.3` (a tilde range) is *not* a path — only
/// `~/…` (a home path) is.
fn is_path(s: &str) -> bool {
    s.starts_with("file:")
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('/')
        || s.starts_with("~/")
}

/// Split an `npm:` alias body into `(name, inner-spec)`, honoring scoped names: the version
/// separator is the *last* `@` (a leading `@` is the scope, not a version marker).
fn split_alias(rest: &str) -> (&str, &str) {
    match rest.rfind('@') {
        Some(at) if at > 0 => (&rest[..at], &rest[at + 1..]),
        _ => (rest, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_req_pins_bare_versions_and_parses_ranges() {
        assert_eq!(version_req("1.2.3").unwrap(), "=1.2.3".parse().unwrap());
        assert_eq!(version_req("^3.0.0").unwrap(), "^3.0.0".parse().unwrap());
        assert_eq!(version_req("*").unwrap(), VersionReq::STAR);
        assert_eq!(version_req("").unwrap(), VersionReq::STAR);
        assert_eq!(version_req("latest").unwrap(), VersionReq::STAR);
        // A bare version matches ONLY itself — npm's exact-pin semantics.
        let exact = version_req("1.2.3").unwrap();
        assert!(exact.matches(&Version::parse("1.2.3").unwrap()));
        assert!(!exact.matches(&Version::parse("1.2.4").unwrap()));
    }

    #[test]
    fn classifies_registry_versions_ranges_and_tags() {
        for s in [
            "^1.2.3", "1.2.3", ">=1 <2", "~1.2.3", "*", "", "latest", "next",
        ] {
            assert!(matches!(Spec::parse(s), Spec::Registry(_)), "{s:?}");
            assert!(Spec::parse(s).is_registry(), "{s:?}");
        }
        // The raw spec is preserved (incl. npm space-ranges we don't fully parse).
        assert_eq!(Spec::parse(">=1 <2"), Spec::Registry(">=1 <2".into()));
        assert_eq!(Spec::parse("latest"), Spec::Registry("latest".into()));
    }

    #[test]
    fn classifies_npm_alias_to_its_inner_spec() {
        match Spec::parse("npm:@scope/pkg@^1.2.3") {
            Spec::Alias { name, spec } => {
                assert_eq!(name, "@scope/pkg");
                assert_eq!(*spec, Spec::Registry("^1.2.3".into()));
            }
            other => panic!("expected alias, got {other:?}"),
        }
        // An alias to a registry range is itself a fetchable registry install.
        assert!(Spec::parse("npm:left-pad@1.0.0").is_registry());
    }

    #[test]
    fn classifies_git_sources_with_committish() {
        for s in [
            "git+https://github.com/npm/cli.git",
            "git+ssh://git@github.com/npm/cli.git",
            "git://github.com/npm/cli.git",
            "github:npm/cli",
            "gitlab:owner/repo",
            "bitbucket:owner/repo",
            "npm/cli", // bare owner/repo shorthand
        ] {
            assert!(matches!(Spec::parse(s), Spec::Git { .. }), "{s}");
            assert!(!Spec::parse(s).is_registry(), "{s}");
        }
        match Spec::parse("npm/cli#v6.0.0") {
            Spec::Git { source, committish } => {
                assert_eq!(source, "npm/cli");
                assert_eq!(committish.as_deref(), Some("v6.0.0"));
            }
            other => panic!("expected git, got {other:?}"),
        }
    }

    #[test]
    fn classifies_remote_tarballs_and_local_paths() {
        assert!(matches!(
            Spec::parse("https://registry.npmjs.org/semver/-/semver-1.0.0.tgz"),
            Spec::Tarball(_)
        ));
        for p in ["file:../local", "./pkg", "../pkg", "/abs/pkg", "~/pkg"] {
            assert!(matches!(Spec::parse(p), Spec::Path(_)), "{p}");
            assert!(!Spec::parse(p).is_registry(), "{p}");
        }
    }
}
