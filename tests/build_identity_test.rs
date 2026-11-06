use std::{path::Path, process::Command};

#[path = "../build.rs"]
#[allow(dead_code)]
mod resolver;

#[test]
fn inspection_is_role_specific_and_configuration_free() {
    for (binary, role, options) in [
        (
            env!("CARGO_BIN_EXE_locksmith"),
            "locksmith",
            vec![
                "--admin-url",
                "http://unused.invalid",
                "--ca-bundle",
                "/nonexistent/ca",
                "--socket",
                "/nonexistent/socket",
            ],
        ),
        (
            env!("CARGO_BIN_EXE_locksmithd"),
            "locksmithd",
            vec!["--config", "/nonexistent/config"],
        ),
    ] {
        let cwd = tempfile::tempdir().unwrap();
        let output = Command::new(binary)
            .args(options)
            .arg("--build-info")
            .current_dir(cwd.path())
            .env("LOCKSMITH_BUILD_REVISION", "not-a-runtime-override")
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            agent_locksmith::build_info::document(role)
        );
        assert!(cwd.path().read_dir().unwrap().next().is_none());
        let short = Command::new(binary).arg("--version").output().unwrap();
        assert!(short.status.success());
        assert_eq!(
            short.stdout,
            format!("{role} {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
    }
}

#[test]
fn ordinary_cli_usage_still_requires_a_command() {
    for args in [
        vec![],
        vec!["--socket", "/nonexistent"],
        vec!["--build-info", "status"],
        vec!["not-a-command"],
    ] {
        assert_eq!(
            Command::new(env!("CARGO_BIN_EXE_locksmith"))
                .args(args)
                .output()
                .unwrap()
                .status
                .code(),
            Some(2)
        );
    }
}

#[test]
fn unknown_sources_do_not_borrow_the_parent_checkout() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(resolver::known(root).is_some());
    assert!(resolver::known(&root.join("tests")).is_none());
    assert!(resolver::known(tempfile::tempdir().unwrap().path()).is_none());
}

#[test]
fn inherited_git_selectors_cannot_change_source_root() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resolver_child", "--ignored"])
        .env("GIT_DIR", "/not-a-real/git")
        .env("GIT_WORK_TREE", "/not-a-real/tree")
        .env("GIT_INDEX_FILE", "/not-a-real/index")
        .env("GIT_COMMON_DIR", "/not-a-real/common")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
}

#[test]
#[ignore = "invoked in a child process with poisoned Git selectors"]
fn resolver_child() {
    assert!(resolver::known(Path::new(env!("CARGO_MANIFEST_DIR"))).is_some());
}
