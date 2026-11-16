//! Text folding for pattern scanners (AGENT-264).
//!
//! An NFKC-lite pass: zero-width characters are dropped, look-alike
//! letters (Cyrillic, Greek, fullwidth ASCII) fold to ASCII, whitespace
//! becomes a space, and everything is lower-cased. Offsets map back to
//! the original text so a hit can be redacted where it really is.

/// Characters dropped before matching.
const INVISIBLE: [char; 5] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}'];

/// Longest run of invisible characters that is dropped. A longer run is
/// kept (and breaks any phrase it sits in): the scanner reports it on its
/// own, which keeps every match within a fixed number of original bytes.
pub(super) const MAX_DROPPED_RUN: usize = 4;

pub(super) fn is_invisible(c: char) -> bool {
    INVISIBLE.contains(&c)
}

/// Look-alike letters folded to the ASCII letter they imitate.
fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic
        'а' | 'А' => 'a',
        'В' | 'в' => 'b',
        'с' | 'С' => 'c',
        'ԁ' => 'd',
        'е' | 'Е' | 'ё' => 'e',
        'Н' | 'н' => 'h',
        'і' | 'І' | 'ї' => 'i',
        'ј' | 'Ј' => 'j',
        'К' | 'к' => 'k',
        'М' | 'м' => 'm',
        'о' | 'О' => 'o',
        'р' | 'Р' => 'p',
        'ѕ' | 'Ѕ' => 's',
        'Т' | 'т' => 't',
        'у' | 'У' => 'y',
        'х' | 'Х' => 'x',
        // Greek
        'α' | 'Α' => 'a',
        'Β' | 'β' => 'b',
        'ε' | 'Ε' => 'e',
        'Η' => 'h',
        'ι' | 'Ι' => 'i',
        'Κ' | 'κ' => 'k',
        'Μ' => 'm',
        'ν' | 'Ν' => 'n',
        'ο' | 'Ο' => 'o',
        'ρ' | 'Ρ' => 'p',
        'τ' | 'Τ' => 't',
        'υ' | 'Υ' => 'y',
        'χ' | 'Χ' => 'x',
        'Ζ' => 'z',
        _ => return None,
    })
}

fn fold_char(c: char) -> char {
    if c.is_whitespace() {
        return ' ';
    }
    if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        return char::from_u32(c as u32 - 0xFEE0).unwrap_or(c);
    }
    homoglyph(c).unwrap_or(c)
}

fn push(out: &mut String, map: &mut Vec<usize>, at: usize, c: char) {
    let before = out.len();
    out.push(c);
    map.extend(std::iter::repeat_n(at, out.len() - before));
}

/// Fold `text` for matching; the map gives, for each byte of the folded
/// text, the byte offset in `text` of the character it came from.
pub(super) fn fold(text: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len());
    let mut run: Vec<(usize, char)> = Vec::new();
    let flush = |run: &mut Vec<(usize, char)>, out: &mut String, map: &mut Vec<usize>| {
        if run.len() > MAX_DROPPED_RUN {
            for &(at, c) in run.iter() {
                push(out, map, at, c);
            }
        }
        run.clear();
    };
    for (at, c) in text.char_indices() {
        if is_invisible(c) {
            run.push((at, c));
            continue;
        }
        flush(&mut run, &mut out, &mut map);
        for lower in fold_char(c).to_lowercase() {
            push(&mut out, &mut map, at, lower);
        }
    }
    flush(&mut run, &mut out, &mut map);
    (out, map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_and_maps_offsets() {
        let (norm, map) = fold("a\u{200B}b\u{FEFF}c\u{2060}d");
        assert_eq!(norm, "abcd");
        assert_eq!(map, vec![0, 4, 8, 12]);
    }

    #[test]
    fn folds_homoglyphs_fullwidth_and_case() {
        // Cyrillic і and о, Greek Α, fullwidth Ｒ, then plain ASCII.
        assert_eq!(fold("\u{0456}gn\u{043E}\u{0391}\u{FF32}E").0, "ignoare");
        assert_eq!(fold("HeLLo\u{00A0}World").0, "hello world");
    }

    #[test]
    fn long_invisible_runs_are_kept() {
        let padded = format!("a{}b", "\u{200B}".repeat(5));
        assert_eq!(fold(&padded).0, padded);
        let short = format!("a{}b", "\u{200B}".repeat(4));
        assert_eq!(fold(&short).0, "ab");
    }
}
