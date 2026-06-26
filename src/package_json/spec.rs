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

/// An npm version **range**: `||`-separated alternatives, each a (possibly space-separated) set
/// of comparators. Rust's [`VersionReq`] handles only comma-separated comparators and has no
/// `||`, yet `||` ranges are pervasive in published packages' dependencies (e.g.
/// `@lit/reactive-element`'s `^1.6.2 || ^2.1.0`). A [`Range`] parses npm's grammar into a set of
/// [`VersionReq`]s and is satisfied when **any** alternative is — so transitive resolution works
/// on real-world trees. ([`version_req`] stays for the single-comparator-set case.)
#[derive(Debug, Clone)]
pub struct Range {
    alternatives: Vec<VersionReq>,
}

impl Range {
    /// A range matching any version (`*`).
    pub fn any() -> Range {
        Range {
            alternatives: vec![VersionReq::STAR],
        }
    }

    /// Parse an npm range. `||` separates alternatives; within one, npm's space-separated
    /// comparators are joined with commas for `semver`. A bare full version is an exact pin;
    /// `*`/`x`/empty/`latest` match anything.
    pub fn parse(spec: &str) -> Result<Range, Box<dyn std::error::Error + Send + Sync>> {
        let spec = spec.trim();
        if spec.is_empty() || spec == "*" || spec == "x" || spec == "latest" {
            return Ok(Range::any());
        }
        let alternatives = spec
            .split("||")
            .map(|alt| parse_alternative(alt.trim()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Range { alternatives })
    }

    /// Whether `version` satisfies any alternative.
    pub fn matches(&self, version: &Version) -> bool {
        self.alternatives.iter().any(|req| req.matches(version))
    }
}

impl From<VersionReq> for Range {
    fn from(req: VersionReq) -> Range {
        Range {
            alternatives: vec![req],
        }
    }
}

impl std::str::FromStr for Range {
    type Err = Box<dyn std::error::Error + Send + Sync>;
    fn from_str(s: &str) -> Result<Range, Self::Err> {
        Range::parse(s)
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, req) in self.alternatives.iter().enumerate() {
            if i > 0 {
                write!(f, " || ")?;
            }
            write!(f, "{req}")?;
        }
        Ok(())
    }
}

/// Parse one `||`-free alternative: a bare full version → an exact pin; otherwise npm's
/// space-separated comparators joined with commas (what `semver` expects). A bare alphabetic word
/// is reported as an unsupported npm dist-tag rather than leaking a cryptic semver error.
fn parse_alternative(alt: &str) -> Result<VersionReq, Box<dyn std::error::Error + Send + Sync>> {
    if alt.is_empty() || alt == "*" || alt == "x" {
        return Ok(VersionReq::STAR);
    }
    if Version::parse(alt).is_ok() {
        return Ok(VersionReq::parse(&format!("={alt}"))?);
    }
    // A bare alphabetic word (`next`, `beta`, …) is an npm dist-tag, not a semver range. We don't
    // resolve dist-tags (that needs a `dist-tags` lookup), so say so clearly. (`latest` is mapped
    // to `*` earlier, in `Range::parse`.)
    if looks_like_dist_tag(alt) {
        return Err(format!(
            "version {alt:?} looks like an npm dist-tag, which npm-utils doesn't resolve — pin a \
             semver version or range (e.g. `^1.2.3`), or install from a package-lock.json"
        )
        .into());
    }
    Ok(VersionReq::parse(
        &alt.split_whitespace().collect::<Vec<_>>().join(", "),
    )?)
}

/// Whether `s` has the shape of an npm dist-tag — a bare word `[A-Za-z][A-Za-z0-9-]*` — as opposed
/// to a semver range (which begins with a digit or a comparator like `^`/`~`/`>`/`<`/`=`). Used
/// only to turn an unsupported tag into a clear error.
fn looks_like_dist_tag(s: &str) -> bool {
    matches!(s.chars().next(), Some(c) if c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
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
    fn range_handles_or_and_space_separated_alternatives() {
        let v = |s: &str| Version::parse(s).unwrap();

        // The `||` OR-range that broke transitive resolution (e.g. @lit/reactive-element).
        let r = Range::parse("^1.6.2 || ^2.1.0").unwrap();
        assert!(r.matches(&v("1.6.2")));
        assert!(r.matches(&v("1.9.0")));
        assert!(r.matches(&v("2.1.0")));
        assert!(
            !r.matches(&v("2.0.0")),
            "below the ^2.1.0 alternative's floor"
        );
        assert!(!r.matches(&v("3.0.0")));

        // Space-separated comparators (npm AND) are joined with commas for semver.
        let and = Range::parse(">=1.6.2 <2.0.0").unwrap();
        assert!(and.matches(&v("1.9.0")));
        assert!(!and.matches(&v("2.0.0")));

        // A bare version is an exact pin; `*`/empty/`Range::any` match anything.
        assert!(Range::parse("1.2.3").unwrap().matches(&v("1.2.3")));
        assert!(!Range::parse("1.2.3").unwrap().matches(&v("1.2.4")));
        assert!(Range::any().matches(&v("9.9.9")));
        assert!(Range::parse("*").unwrap().matches(&v("9.9.9")));
    }

    #[test]
    fn rejects_dist_tags_with_a_clear_message() {
        // `latest` resolves (≈ any); other dist-tags aren't supported, and must say so clearly
        // rather than leak a raw semver parse error.
        assert!(Range::parse("latest").is_ok());
        for tag in ["next", "beta", "canary"] {
            let err = Range::parse(tag).unwrap_err().to_string();
            assert!(
                err.contains("dist-tag"),
                "{tag:?} should give a dist-tag error, got: {err}"
            );
        }
        // A real range still parses.
        assert!(Range::parse("^1.2.3").is_ok());
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
