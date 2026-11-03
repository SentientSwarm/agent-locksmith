//! Execute the user guide's actual shell blocks with disposable substituted inputs.
use super::{fixture::Fixture, process};

pub const SETUP: &str = include_str!("../../docs/user/getting-started.md");
pub const UPGRADE: &str = include_str!("../../docs/user/concepts/migrating-account-bindings.md");
pub fn block<'a>(document: &'a str, name: &str) -> &'a str {
    document
        .split_once(&format!("<!-- smoke:{name} -->"))
        .unwrap()
        .1
        .split_once('\n')
        .unwrap()
        .1
        .trim_start()
        .split_once('\n')
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0
}
pub fn command(document: &str, name: &str) -> std::process::Command {
    let mut c = process::command("bash");
    c.args(["-euo", "pipefail", "-c", block(document, name)]);
    c.env("LOCKSMITH_BIN", process::CLI)
        .env("LOCKSMITHD_BIN", process::DAEMON);
    c
}
pub fn fixture(f: &Fixture, document: &str, name: &str) -> std::process::Command {
    let mut c = command(document, name);
    c.current_dir(f.path())
        .env("FIXTURE_DIR", f.path())
        .env("CONFIG", &f.config)
        .env("SOCKET", &f.socket)
        .env("DATABASE", &f.db)
        .env("LOCKSMITH_OP_TOKEN", &f.operator)
        .env("UPSTREAM_URL", &f.upstream);
    c
}
