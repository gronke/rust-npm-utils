//! `cargo npm-utils <verb>` — the cargo-subcommand form of the `npm-utils` CLI. Cargo finds this
//! binary by the `cargo-<name>` convention; it re-passes the subcommand name, which the shared
//! entry point strips. Requires the `cli` feature.

fn main() -> std::process::ExitCode {
    npm_utils::cli::run_as_cargo_subcommand(std::env::args_os())
}
