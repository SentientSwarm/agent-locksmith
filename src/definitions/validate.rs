use super::{Definition, Error, Level, Verification};
use std::collections::HashSet;

pub fn identity(id: &str, revision: u32) -> Result<(), Error> {
    let suffix = id
        .strip_prefix("local.")
        .or_else(|| id.strip_prefix("builtin."));
    check(
        identifier(id)
            && suffix.is_some_and(|s| !s.is_empty())
            && (1..=i32::MAX as u32).contains(&revision),
    )
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn text(s: &str, max: usize) -> bool {
    !s.trim().is_empty()
        && s.len() <= max
        && !s
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
fn strings(items: &[String], min: usize, max: usize, length: usize) -> bool {
    (min..=max).contains(&items.len())
        && items.iter().all(|s| text(s, length))
        && items.iter().collect::<HashSet<_>>().len() == items.len()
}
pub(super) fn definition(d: &Definition) -> Result<(), Error> {
    identity(&d.id, d.revision)?;
    check(d.schema_version == 1 && d.protocol_profiles == ["mcp_streamable_http"])?;
    check(text(&d.name, 128) && text(&d.summary, 1024) && text(&d.setup, 4096))?;
    check(strings(&d.limits, 1, 32, 1024))?;
    profiles(d)?;
    workflows(d)?;
    verification(&d.verification)
}
fn profiles(d: &Definition) -> Result<(), Error> {
    check((1..=8).contains(&d.auth_profiles.len()))?;
    let mut ids = HashSet::new();
    for a in &d.auth_profiles {
        check(
            identifier(&a.id)
                && ids.insert(&a.id)
                && text(&a.setup, 4096)
                && strings(&a.required_scopes, 0, 32, 128),
        )?;
    }
    Ok(())
}
fn workflows(d: &Definition) -> Result<(), Error> {
    check((1..=16).contains(&d.workflows.len()))?;
    let mut ids = HashSet::new();
    for w in &d.workflows {
        check(
            identifier(&w.id)
                && ids.insert(&w.id)
                && text(&w.summary, 1024)
                && strings(&w.operations, 1, 32, 128),
        )?;
    }
    Ok(())
}
fn verification(v: &Verification) -> Result<(), Error> {
    check(text(&v.evidence_ref, 1024))?;
    match v.level {
        Level::Candidate => check(v.verified_at.is_none() && v.source_revision.is_none()),
        Level::Fixture => check(
            v.verified_at.as_deref().is_some_and(date)
                && v.source_revision.as_deref().is_some_and(|s| {
                    (7..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
                }),
        ),
    }
}
fn date(s: &str) -> bool {
    if s.len() != 10 || !s.is_ascii() || &s[4..5] != "-" || &s[7..8] != "-" {
        return false;
    }
    if !s
        .bytes()
        .enumerate()
        .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return false;
    }
    let parts = (
        s[..4].parse::<i32>(),
        s[5..7].parse::<u8>(),
        s[8..].parse::<u8>(),
    );
    match parts {
        (Ok(y), Ok(m), Ok(d)) if y > 0 => time::Month::try_from(m)
            .ok()
            .is_some_and(|m| time::Date::from_calendar_date(y, m, d).is_ok()),
        _ => false,
    }
}
fn check(valid: bool) -> Result<(), Error> {
    if valid { Ok(()) } else { Err(Error::Invalid) }
}
