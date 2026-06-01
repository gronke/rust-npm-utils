# date-converter

A runnable demo of `npm-utils`: a small [Lit](https://lit.dev) web component
that converts a wall-clock time between time zones using the `Temporal` API. Its
browser dependencies (`lit` and its closure, the Web Components polyfill, and the
`Temporal` polyfill) are vendored straight from the npm registry by
`npm-utils` — **no Node, npm, or bundler**.

## Run

```sh
cargo run -p date-converter
# Vendors the browser deps, then serves the page (Axum) at http://127.0.0.1:8080/
```

## How it works

`src/main.rs` vendors the deps, then serves `web/` over a small Axum `ServeDir`:

- `Registry::npm().resolve(pkg, &req)` picks the newest version matching a semver
  range and returns its tarball URL,
- `download::fetch(url)` pulls the tarball, and
- `extract::tar_gz(.., Select::Matching(..))` writes the production `.js`/`.mjs`
  into `web/web_modules/<specifier>/`.

`web/index.html` maps the bare specifiers (`lit`, `temporal-polyfill`, …) to those
files via an importmap and loads the Web Components polyfill as a fallback.
`web/date-converter.js` is the Lit element (plain JS — `npm-utils` fetches
dependencies, it does not compile TypeScript).
