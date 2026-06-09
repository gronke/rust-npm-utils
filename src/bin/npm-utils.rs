//! The `npm-utils` command-line tool. Requires the `cli` feature
//! (`cargo install npm-utils --features cli`).

fn main() -> std::process::ExitCode {
    npm_utils::cli::main_with(std::env::args_os())
}
