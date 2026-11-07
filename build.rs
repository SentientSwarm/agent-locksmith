use std::{env, path::Path, process::Command};

#[derive(Debug, PartialEq)]
pub(crate) struct Identity {
    revision: String,
    state: &'static str,
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    command.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-C",
    ]);
    command.arg(root).args(args);
    // Git selectors must not make an archive borrow another checkout's identity.
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    let output = command.output().ok()?;
    output.status.success().then_some(())?;
    String::from_utf8(output.stdout).ok()
}

pub(crate) fn known(root: &Path) -> Option<Identity> {
    let root = root.canonicalize().ok()?;
    let top = git(&root, &["rev-parse", "--show-toplevel"])?;
    if Path::new(top.trim()).canonicalize().ok()? != root {
        return None;
    }
    let revision = git(&root, &["rev-parse", "--verify", "HEAD"])?;
    let revision = revision.trim();
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let status = git(
        &root,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )?;
    Some(Identity {
        revision: revision.to_owned(),
        state: if status.is_empty() { "clean" } else { "dirty" },
    })
}

fn main() {
    // ponytail: always ask Git; a partial HEAD/index watcher misses dirty restores.
    // This intentionally absent input makes Cargo rerun us, including cached builds.
    let out = env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR");
    println!(
        "cargo::rerun-if-changed={}",
        Path::new(&out).join("identity-always-check").display()
    );
    let root = env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies package root");
    let identity = known(Path::new(&root)).unwrap_or(Identity {
        revision: String::new(),
        state: "unknown",
    });
    println!(
        "cargo::rustc-env=LOCKSMITH_BUILD_REVISION={}",
        identity.revision
    );
    println!(
        "cargo::rustc-env=LOCKSMITH_BUILD_SOURCE_STATE={}",
        identity.state
    );
}
