//! `resolve` — print the newest version matching a range (version, tarball, integrity).

use super::Res;
use crate::package_json::spec;
use crate::registry::Registry;

/// Print the newest published version matching `range`, with its tarball URL and integrity.
pub(super) fn run(name: &str, range: &str) -> Res {
    let r = Registry::npm().resolve(name, &spec::Range::parse(range)?)?;
    println!("{}@{}", r.name, r.version);
    println!("  tarball:   {}", r.tarball_url);
    println!(
        "  integrity: {}",
        r.integrity.as_deref().unwrap_or("(none published)")
    );
    Ok(())
}
