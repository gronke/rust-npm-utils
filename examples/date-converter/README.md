# date-converter

A runnable demo of `rust-npm-utils`: a small [Lit](https://lit.dev) web component
that converts a wall-clock time between time zones using the `Temporal` API. Its
browser dependencies (`lit` and its closure, the Web Components polyfill, and the
`Temporal` polyfill) are vendored straight from the npm registry by
`rust-npm-utils` — **no Node, npm, or bundler**.

## Run

```sh
# 1. Resolve + download + extract the browser deps into web/web_modules/
cargo run -p date-converter

# 2. Serve the web/ directory (any static server) and open the page
python3 -m http.server -d examples/date-converter/web 8080
# open http://localhost:8080/
```

## How it works

`src/main.rs` is the whole integration:

- `Registry::npm().resolve(pkg, &req)` picks the newest version matching a semver
  range and returns its tarball URL,
- `download::fetch(url)` pulls the tarball, and
- `extract::tar_gz(.., Select::Matching(..))` writes the production `.js`/`.mjs`
  into `web/web_modules/<specifier>/`.

`web/index.html` maps the bare specifiers (`lit`, `temporal-polyfill`, …) to those
files via an importmap and loads the Web Components polyfill as a fallback.
`web/date-converter.js` is the Lit element (plain JS — `rust-npm-utils` fetches
dependencies, it does not compile TypeScript).
