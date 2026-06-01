//! Vendors this demo's browser dependencies with `npm-utils` — no Node, no
//! npm — then serves the page over a small Axum static server.
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

use npm_utils::{download, extract, registry::Registry};
use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;

/// `(directory under web_modules/, npm package, semver range)`.
///
/// `lit` pulls in `lit-html`, `lit-element`, and `@lit/reactive-element` via bare
/// specifiers, so the closure is resolved explicitly here (this crate does
/// *direct* resolution — no transitive walking). Plus the Web Components polyfill
/// (loaded as a fallback) and the `Temporal` polyfill.
const DEPS: &[(&str, &str, &str)] = &[
    ("lit", "lit", "^3"),
    ("lit-html", "lit-html", "^3"),
    ("lit-element", "lit-element", "^4"),
    ("@lit/reactive-element", "@lit/reactive-element", "^2"),
    (
        "@webcomponents/webcomponentsjs",
        "@webcomponents/webcomponentsjs",
        "^2",
    ),
    ("temporal-polyfill", "temporal-polyfill", "^0.3"),
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let web = Path::new(env!("CARGO_MANIFEST_DIR")).join("web");
    vendor(&web.join("web_modules"))?;

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

/// Resolve + download + extract the browser dependencies into `vendor_dir`.
fn vendor(vendor_dir: &Path) -> Result<(), Box<dyn Error>> {
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

    for &(dir, pkg, range) in DEPS {
        let req = range.parse()?;
        let resolved = reg.resolve(pkg, &req)?;
        let tarball = download::fetch(&resolved.tarball_url)?;
        let n = extract::tar_gz(
            &tarball,
            &vendor_dir.join(dir),
            Some("package/"),
            extract::Select::Matching(&keep),
        )?;
        println!(
            "vendored {pkg} v{} → web/web_modules/{dir}/ ({n} files)",
            resolved.version
        );
    }
    Ok(())
}
