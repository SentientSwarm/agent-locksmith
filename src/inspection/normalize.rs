//! Text folding for pattern scanners (AGENT-264).
//!
//! An NFKC-lite pass: invisible format characters are dropped, look-alike
//! letters (Cyrillic, Greek, fullwidth ASCII) fold to ASCII, each run of
//! whitespace becomes one space, and everything is lower-cased. Offsets map back to
//! the original text so a hit can be redacted where it really is.

/// Characters that render as nothing and are dropped before matching:
/// zero-width and joiner characters, soft hyphen, bidi controls,
/// invisible operators, fillers, variation selectors and TAG characters.
pub(super) fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5
        | 0x180B..=0x180F | 0x200B..=0x200F | 0x202A..=0x202E
        | 0x2060..=0x2064 | 0x2066..=0x206F | 0x3164 | 0xFE00..=0xFE0F
        | 0xFEFF | 0xFFA0 | 0xFFF9..=0xFFFB | 0x1D173..=0x1D17A
        | 0xE0100..=0xE01EF)
        || is_tag(c)
}

/// The TAG block: invisible copies of ASCII used to smuggle text.
pub(super) fn is_tag(c: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&c)
}

/// Look-alike letters folded to the ASCII letter they imitate.
fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic
        '\u{0430}' | '\u{0410}' => 'a',
        '\u{0412}' | '\u{0432}' => 'b',
        '\u{0441}' | '\u{0421}' => 'c',
        '\u{0501}' => 'd',
        '\u{0435}' | '\u{0415}' | '\u{0451}' => 'e',
        '\u{041D}' | '\u{043D}' => 'h',
        '\u{0456}' | '\u{0406}' | '\u{0457}' => 'i',
        '\u{0458}' | '\u{0408}' => 'j',
        '\u{041A}' | '\u{043A}' => 'k',
        '\u{041C}' | '\u{043C}' => 'm',
        '\u{043E}' | '\u{041E}' => 'o',
        '\u{0440}' | '\u{0420}' => 'p',
        '\u{0455}' | '\u{0405}' => 's',
        '\u{0422}' | '\u{0442}' => 't',
        '\u{0443}' | '\u{0423}' => 'y',
        '\u{0445}' | '\u{0425}' => 'x',
        // Greek
        '\u{03B1}' | '\u{0391}' => 'a',
        '\u{0392}' | '\u{03B2}' => 'b',
        '\u{03B5}' | '\u{0395}' => 'e',
        '\u{0397}' => 'h',
        '\u{03B9}' | '\u{0399}' => 'i',
        '\u{039A}' | '\u{03BA}' => 'k',
        '\u{039C}' => 'm',
        '\u{03BD}' | '\u{039D}' => 'n',
        '\u{03BF}' | '\u{039F}' => 'o',
        '\u{03C1}' | '\u{03A1}' => 'p',
        '\u{03C4}' | '\u{03A4}' => 't',
        '\u{03C5}' | '\u{03A5}' => 'y',
        '\u{03C7}' | '\u{03A7}' => 'x',
        '\u{0396}' => 'z',
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

/// Bytes `c` contributes to folded text, ignoring whitespace-run
/// collapsing (the caller counts a run once).
pub(super) fn folded_width(c: char) -> usize {
    if is_invisible(c) {
        return 0;
    }
    fold_char(c).to_lowercase().map(char::len_utf8).sum()
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
    let mut after_space = false;
    for (at, c) in text.char_indices() {
        if is_invisible(c) {
            continue;
        }
        let folded = fold_char(c);
        if folded == ' ' {
            if after_space {
                continue;
            }
            after_space = true;
        } else {
            after_space = false;
        }
        for lower in folded.to_lowercase() {
            push(&mut out, &mut map, at, lower);
        }
    }
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
    fn invisible_runs_of_any_length_are_dropped() {
        let padded = format!("a{}b", "\u{200B}".repeat(50));
        assert_eq!(fold(&padded).0, "ab");
    }

    #[test]
    fn whitespace_runs_collapse_to_one_space() {
        let (norm, map) = fold("a \t\n  b");
        assert_eq!(norm, "a b");
        assert_eq!(map, vec![0, 1, 6]);
    }
}
