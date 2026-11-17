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

/// `(struct, field)` for every field of a strict struct. serde reads
/// private fields too, so visibility does not matter. Attributes may span
/// lines or share a line with the field. A `#[serde(skip)]` field is not
/// read from the file, so it is not a config field.
fn strict_fields(source: &str) -> Vec<(String, String)> {
    let field =
        regex::Regex::new(r"^(?:#\[.*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:")
            .expect("field regex");
    let (mut out, mut strict, mut current) = (Vec::new(), false, None::<String>);
    let mut skip = false;
    let mut attr = String::new();
    for line in source.lines().map(str::trim) {
        if !attr.is_empty() || line.starts_with("#[") && !line.contains(']') {
            attr.push_str(line);
            if line.contains(")]") {
                strict |= attr.starts_with("#[serde(") && attr.contains("deny_unknown_fields");
                attr.clear();
            }
        } else if line.starts_with("#[serde(") && line.contains("deny_unknown_fields") {
            strict = true;
        } else if let Some(rest) = line.strip_prefix("pub struct ") {
            current = strict.then(|| rest.split([' ', '{']).next().unwrap().to_string());
            (strict, skip) = (false, false);
        } else if line.starts_with("pub enum ") || line.starts_with("enum ") {
            strict = false;
        } else if line == "}" {
            (current, skip) = (None, false);
        } else if line == "#[serde(skip)]" {
            skip = current.is_some();
        } else if let Some(name) = &current
            && !line.starts_with("//")
            && let Some(m) = field.captures(line)
            && !std::mem::take(&mut skip)
        {
            out.push((name.clone(), m[1].to_string()));
        }
    }
    out
}

/// A table row or heading on the page documents the field: a backticked
/// key that is the field itself, or ends or starts with it as a path
/// segment (`audit.retention_days`, `routes[].route`, `…scanners`). Two
/// structs sharing a field name can still hide each other's rows.
fn page_documents(field: &str) -> bool {
    let key = regex::Regex::new(&format!(r"`(?:[^`\s]*[.\]…])?{field}(?:[.\[][^`]*)?`"))
        .expect("key regex");
    PAGE.lines()
        .filter(|l| l.starts_with('|') || l.starts_with('#'))
        .any(|l| key.is_match(l))
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
            if !DOCUMENTED_ELSEWHERE.contains(&name.as_str()) && !page_documents(&field) {
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
