//! Per-binding Slack-style upstream method policies. No policy means unrestricted.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

fn method(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

impl MethodPolicy {
    pub fn validate(&self) -> bool {
        self.allow.len() + self.deny.len() <= 256
            && self
                .allow
                .iter()
                .chain(&self.deny)
                .all(|p| p == "*" || method(p.strip_suffix(".*").unwrap_or(p)))
    }

    pub fn allows(&self, value: &str) -> bool {
        // Accept only one literal method segment. Reject encoded aliases,
        // separators and traversal rather than guessing upstream decoding rules.
        method(value)
            && !self.deny.iter().any(|p| matches(p, value))
            && self.allow.iter().any(|p| matches(p, value))
    }
}

fn matches(pattern: &str, value: &str) -> bool {
    pattern == "*"
        || pattern == value
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| value.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deny_wins_and_aliases_fail_closed() {
        let p = MethodPolicy {
            allow: vec!["users.*".into(), "auth.test".into()],
            deny: vec!["users.profile.set".into()],
        };
        assert!(p.validate());
        assert!(p.allows("users.info"));
        assert!(p.allows("auth.test"));
        for value in [
            "users.profile.set",
            "admin.users.list",
            "users%2einfo",
            "users.info/../profile.set",
            "users.info/",
            "",
            "users..info",
        ] {
            assert!(!p.allows(value), "{value}");
        }
        assert!(
            !MethodPolicy {
                allow: vec!["users*".into()],
                deny: vec![]
            }
            .validate()
        );
        assert!(
            !MethodPolicy {
                allow: vec![],
                deny: vec![]
            }
            .allows("auth.test")
        );
    }
}
