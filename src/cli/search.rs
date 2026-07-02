//! `search` — query the registry and print matching packages (npm's `/-/v1/search`).

use super::Res;
use crate::registry::Registry;

/// Search the registry for `query`, printing up to `limit` results as `name@version — description`.
pub(super) fn run(query: &str, limit: usize) -> Res {
    let results = Registry::npm().search(query, limit)?;
    if results.is_empty() {
        println!("no packages found for {query:?}");
        return Ok(());
    }
    for r in &results {
        match &r.description {
            Some(desc) => println!("{}@{} — {desc}", r.name, r.version),
            None => println!("{}@{}", r.name, r.version),
        }
    }
    Ok(())
}
