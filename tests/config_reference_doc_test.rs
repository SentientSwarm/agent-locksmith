//! `docs/reference/config.md` stays in step with the config schema: its
//! complete example is a valid configuration, and every field of every
//! strict (`deny_unknown_fields`) config struct is named on the page.

use agent_locksmith::config::parse_config_str;

const PAGE: &str = include_str!("../docs/reference/config.md");
const MARK: &str = "<!-- config-reference:complete -->\n```yaml\n";

/// Files holding the structs the daemon config deserializes into.
const SOURCES: [(&str, &str); 4] = [
    ("src/config.rs", include_str!("../src/config.rs")),
    (
        "src/native/config.rs",
        include_str!("../src/native/config.rs"),
    ),
    (
        "src/inspection/config.rs",
        include_str!("../src/inspection/config.rs"),
    ),
    (
        "src/oauth/consent/config.rs",
        include_str!("../src/oauth/consent/config.rs"),
    ),
];

/// Provider profiles vary by `kind`; the OAuth operator pages document them.
const DOCUMENTED_ELSEWHERE: [&str; 1] = ["Profile"];

fn complete_example() -> &'static str {
    let start = PAGE.find(MARK).expect("complete-example marker") + MARK.len();
    let len = PAGE[start..].find("```").expect("closing fence");
    &PAGE[start..start + len]
}

/// `(struct, field)` for every public field of a strict struct.
fn strict_fields(source: &str) -> Vec<(String, String)> {
    let (mut out, mut strict, mut current) = (Vec::new(), false, None::<String>);
    for line in source.lines().map(str::trim) {
        if line.starts_with("#[serde(") && line.contains("deny_unknown_fields") {
            strict = true;
        } else if let Some(rest) = line.strip_prefix("pub struct ") {
            current = strict.then(|| rest.split([' ', '{']).next().unwrap().to_string());
            strict = false;
        } else if line.starts_with("pub enum ") {
            strict = false;
        } else if line == "}" {
            current = None;
        } else if let (Some(name), Some(field)) = (&current, line.strip_prefix("pub "))
            && let Some((field, _)) = field.split_once(':')
        {
            out.push((name.clone(), field.to_string()));
        }
    }
    out
}

/// The page names a field as a YAML key (`field:`) or in backticks
/// (`` `field` `` or `` `parent.field` ``).
fn page_names(field: &str) -> bool {
    let as_key = PAGE.lines().any(|l| {
        let l = l.trim_start().trim_start_matches("- ");
        l.starts_with(&format!("{field}:"))
    });
    as_key || PAGE.contains(&format!("`{field}`")) || PAGE.contains(&format!(".{field}`"))
}

#[test]
fn the_complete_example_is_a_valid_config() {
    parse_config_str(complete_example()).expect("the page's complete example parses");
}

#[test]
fn every_strict_config_field_is_on_the_page() {
    let mut missing = Vec::new();
    let mut seen = 0;
    for (path, source) in SOURCES {
        for (name, field) in strict_fields(source) {
            seen += 1;
            if !DOCUMENTED_ELSEWHERE.contains(&name.as_str()) && !page_names(&field) {
                missing.push(format!("{path}: {name}.{field}"));
            }
        }
    }
    assert!(
        seen > 60,
        "found only {seen} fields; the struct scan is broken"
    );
    assert!(
        missing.is_empty(),
        "undocumented config fields: {missing:#?}"
    );
}
