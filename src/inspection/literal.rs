//! `literal:<text>` — matches an exact string. Lets an operator block a
//! known marker (a canary token, a project code name) without a regex.

use super::{Direction, Hit, ScanError, Scanner};

pub(super) struct Literal {
    needle: String,
}

impl Literal {
    pub(super) fn new(needle: &str) -> Result<Self, String> {
        if needle.is_empty() {
            return Err("literal scanner needs text: `literal:<text>`".into());
        }
        Ok(Self {
            needle: needle.to_string(),
        })
    }
}

impl Scanner for Literal {
    fn id(&self) -> &str {
        "literal"
    }

    fn max_match_len(&self) -> usize {
        self.needle.len()
    }

    fn scan(&self, text: &str, _: Direction) -> Result<Vec<Hit>, ScanError> {
        Ok(text
            .match_indices(self.needle.as_str())
            .map(|(start, m)| Hit {
                rule: "literal".into(),
                start,
                end: start + m.len(),
                flag_only: false,
            })
            .collect())
    }
}
