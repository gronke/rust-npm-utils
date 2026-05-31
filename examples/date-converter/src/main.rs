//! Vendors this demo's browser dependencies with `rust-npm-utils` — no Node, no
//! npm. Resolves each package against the npm registry, downloads its tarball,
//! and extracts the production `.js`/`.mjs` into `web/web_modules/<specifier>/`,
//! which the page's importmap (in `web/index.html`) points at.
//!
//! Run from the repo root:
//!
//! ```sh
//! cargo run -p date-converter
//! ```
//!
//! then serve the `web/` directory and open `index.html` (the command is
//! printed at the end).

use rust_npm_utils::{download, extract, registry::Registry};
use std::error::Error;
use std::path::PathBuf;

/// `(directory under web_modules/, npm package, semver range)`.
///
/// `lit` pulls in `lit-html`, `lit-element`, and `@lit/reactive-element` via
/// bare specifiers, so the closure is resolved explicitly here (this crate does
/// *direct* resolution — no transitive walking). Plus the Web Components
/// polyfill (loaded as a fallback) and the `Temporal` polyfill.
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

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendor = root.join("web").join("web_modules");
    let reg = Registry::npm();

    // Keep production browser modules; drop TypeScript sources and the
    // node-only / development build trees some packages ship.
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
        let dest = vendor.join(dir);
        let n = extract::tar_gz(
            &tarball,
            &dest,
            Some("package/"),
            extract::Select::Matching(&keep),
        )?;
        println!(
            "vendored {pkg} v{} → web/web_modules/{dir}/ ({n} files)",
            resolved.version
        );
    }

    let web = root.join("web");
    println!("\nDone. Serve the web/ directory and open the page, e.g.:");
    println!("    python3 -m http.server -d {} 8080", web.display());
    println!("    # then open http://localhost:8080/");
    Ok(())
}
