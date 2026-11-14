//! `Cargo.toml` sets `autotests = false`, so a test file that is neither a
//! `[[test]]` target nor included by a suite binary is silently never built.
//! This guard fails instead. See docs/development/local-ci.md#test-binaries.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn tests_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests"))
}

/// `tests/<file>.rs` paths named by `[[test]]` entries.
fn targets(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .filter_map(|l| l.trim().strip_prefix("path = \"tests/"))
        .filter_map(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

/// Files a suite includes with `#[path = "<file>.rs"]`.
fn included(suite: &str) -> Vec<String> {
    suite
        .lines()
        .filter_map(|l| l.trim().strip_prefix("#[path = \""))
        .filter_map(|rest| rest.strip_suffix("\"]"))
        .map(str::to_owned)
        .collect()
}

/// How many times each top-level test file is built: once is the only right answer.
fn coverage(root: &Path) -> BTreeMap<String, usize> {
    let manifest = fs::read_to_string(root.join("../Cargo.toml")).unwrap();
    let mut count: BTreeMap<String, usize> = fs::read_dir(root)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".rs"))
        .map(|n| (n, 0))
        .collect();
    for target in targets(&manifest) {
        *count.entry(target.clone()).or_default() += 1;
        if !target.ends_with("_suite.rs") {
            continue; // standalone files include only helper modules, not test files
        }
        let suite = fs::read_to_string(root.join(&target)).unwrap();
        for file in included(&suite) {
            *count.entry(file).or_default() += 1;
        }
    }
    count
}

#[test]
fn every_top_level_test_file_is_built_exactly_once() {
    let wrong: Vec<_> = coverage(tests_dir())
        .into_iter()
        .filter(|(_, n)| *n != 1)
        .collect();
    assert!(
        wrong.is_empty(),
        "each tests/*.rs must be a [[test]] target or in one suite, once: {wrong:?}"
    );
}

#[test]
fn parsers_read_the_shapes_cargo_and_suites_use() {
    assert_eq!(
        targets("[[test]]\nname = \"a\"\npath = \"tests/a.rs\"\n"),
        ["a.rs"]
    );
    assert_eq!(
        included("#[path = \"b_test.rs\"]\nmod b_test;\n"),
        ["b_test.rs"]
    );
}
