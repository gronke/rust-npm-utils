//! Vendors this demo's browser dependencies (declared in `web/package.json`) with
//! `npm-utils` — no Node, no npm — then serves the page over a small Axum static server.
//!
//! Resolves each package against the npm registry, downloads its tarball, and
//! extracts the production `.js`/`.mjs` into `web/web_modules/<specifier>/`,
//! which the page's importmap (`web/index.html`) points at.
//!
//! Run from the repo root:
//!
//! ```sh
//! cargo run -p date-converter
//! # then open the printed http://127.0.0.1:8080/
//! ```

use npm_utils::{download, extract, package_json::parse_dependencies, registry::Registry};
use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let web = Path::new(env!("CARGO_MANIFEST_DIR")).join("web");
    vendor(&web)?;

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let app = axum::Router::new().fallback_service(tower_http::services::ServeDir::new(&web));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!(
        "\nServing {} at http://{addr}/  (Ctrl-C to stop)",
        web.display()
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// Resolve + download + extract the browser dependencies declared in
/// `web/package.json` into `web/web_modules/<name>/`.
///
/// The list comes straight from the manifest — read with
/// [`npm_utils::package_json::parse_dependencies`], the same `package.json` npm
/// reads. This demo resolves each dependency *directly*, without walking transitive
/// deps, so the manifest lists lit's family (`lit-html`, `lit-element`,
/// `@lit/reactive-element`) explicitly, alongside the Web Components and `Temporal`
/// polyfills.
fn vendor(web: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let reg = Registry::npm();

    // Keep production browser modules; drop TypeScript sources and the node-only
    // / development build trees some packages ship.
    let keep = |rel: &str| -> Option<String> {
        if rel
            .split('/')
            .any(|seg| matches!(seg, "src" | "node" | "development"))
        {
            return None;
        }
        (rel.ends_with(".js") || rel.ends_with(".mjs")).then(|| rel.to_string())
    };

    // The dependency set lives in web/package.json; sort it for stable output order.
    let mut deps: Vec<_> = parse_dependencies(&web.join("package.json"))?
        .into_values()
        .collect();
    deps.sort_by(|a, b| a.name.cmp(&b.name));

    for dep in &deps {
        let req = dep.version.parse()?;
        let resolved = reg.resolve(&dep.name, &req)?;
        let tarball = download::fetch(&resolved.tarball_url)?;
        let n = extract::tar_gz(
            &tarball,
            &web.join("web_modules").join(&dep.name),
            Some("package/"),
            extract::Select::Matching(&keep),
        )?;
        println!(
            "vendored {} v{} → web/web_modules/{}/ ({n} files)",
            dep.name, resolved.version, dep.name
        );
    }
    Ok(())
}
