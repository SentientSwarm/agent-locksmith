//! Text folding for pattern scanners (AGENT-264, AGENT-315).
//!
//! Two folds, each dropping invisible format characters, collapsing each
//! whitespace run to one space and lower-casing, with offsets that map
//! back to the original text so a hit can be redacted where it really is:
//!
//! - [`fold`] also drops every combining mark and replaces each letter by
//!   its compatibility decomposition (NFKD) before folding look-alikes
//!   (Cyrillic, Greek, small capitals and others NFKD leaves alone) to
//!   ASCII.
//! - [`fold_strict`] is the fold before AGENT-315: Cyrillic, Greek,
//!   fullwidth and mathematical letters only, and Latin-block marks.
//!
//! The full fold turns some characters that used to be non-word bytes
//! into letters (`é`, `ℹ`, flags), which glue onto a neighbouring word
//! and break a rule's `\b`. [`needs_strict`] says when a text holds one,
//! and the scanner then matches both folds, so no phrase the previous
//! fold caught is missed.

use unicode_normalization::char::{decompose_compatible, is_combining_mark};

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

/// Combining marks (any General_Category M), dropped by the full fold so
/// `i\u{301}gnore` reads as `ignore` (AGENT-270, AGENT-315). Kept out of
/// [`is_invisible`], which also drives the invisible-run detector,
/// because marks are ordinary in decomposed text.
pub(super) fn is_mark(c: char) -> bool {
    is_combining_mark(c)
}

/// The Latin-oriented combining blocks the strict fold drops.
fn is_latin_mark(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF
        | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// Mathematical alphanumerics (bold, italic, script, fraktur,
/// double-struck, sans-serif, monospace) and the letterlike symbols that
/// fill that block's gaps, folded to ASCII (AGENT-270).
fn math_letter(c: char) -> Option<char> {
    let n = c as u32;
    let ascii = |base: u8, off: u32| char::from(base + off as u8);
    Some(match n {
        0x1D400..=0x1D6A3 => {
            let off = (n - 0x1D400) % 52;
            if off < 26 {
                ascii(b'A', off)
            } else {
                ascii(b'a', off - 26)
            }
        }
        0x1D6A4 => 'i',
        0x1D6A5 => 'j',
        0x1D7CE..=0x1D7FF => ascii(b'0', (n - 0x1D7CE) % 10),
        0x210A => 'g',
        0x210B..=0x210E => 'h',
        0x2110 | 0x2111 => 'i',
        0x2112 | 0x2113 => 'l',
        0x2115 => 'n',
        0x2119 => 'p',
        0x211A => 'q',
        0x211B..=0x211D => 'r',
        0x2124 | 0x2128 => 'z',
        0x212C => 'b',
        0x2102 | 0x212D => 'c',
        0x212F | 0x2130 => 'e',
        0x2131 => 'f',
        0x2133 => 'm',
        0x2134 => 'o',
        _ => return None,
    })
}

/// Cyrillic and Greek letters folded to the ASCII letter they imitate.
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

/// Look-alike letters with no compatibility decomposition to ASCII,
/// folded to the ASCII letter they imitate. Everything that has one
/// (fullwidth, mathematical and letterlike, Roman numerals, circled,
/// superscript, accented) is decomposed by [`fold_full`].
fn lookalike(c: char) -> Option<char> {
    let n = c as u32;
    let letter = |first: u32| char::from(b'a' + (n - first) as u8);
    Some(match n {
        // Negative circled, negative squared, regional indicators.
        0x1F150..=0x1F169 => letter(0x1F150),
        0x1F170..=0x1F189 => letter(0x1F170),
        0x1F1E6..=0x1F1FF => letter(0x1F1E6),
        _ => match c {
            // Dotless i and j.
            '\u{0131}' => 'i',
            '\u{0237}' => 'j',
            // Small capitals.
            '\u{1D00}' => 'a',
            '\u{0299}' => 'b',
            '\u{1D04}' => 'c',
            '\u{1D05}' => 'd',
            '\u{1D07}' => 'e',
            '\u{A730}' => 'f',
            '\u{0262}' => 'g',
            '\u{029C}' => 'h',
            '\u{026A}' => 'i',
            '\u{1D0A}' => 'j',
            '\u{1D0B}' => 'k',
            '\u{029F}' => 'l',
            '\u{1D0D}' => 'm',
            '\u{0274}' => 'n',
            '\u{1D0F}' => 'o',
            '\u{1D18}' => 'p',
            '\u{A7AF}' => 'q',
            '\u{0280}' => 'r',
            '\u{A731}' => 's',
            '\u{1D1B}' => 't',
            '\u{1D1C}' => 'u',
            '\u{1D20}' => 'v',
            '\u{1D21}' => 'w',
            '\u{028F}' => 'y',
            '\u{1D22}' => 'z',
            _ => return homoglyph(c),
        },
    })
}

/// Enclosed forms whose expansion wraps the letter in parentheses.
fn is_enclosed(c: char) -> bool {
    matches!(c as u32, 0x2460..=0x24FF | 0x3200..=0x32FF | 0x1F100..=0x1F1FF)
}

/// Most bytes a character's fold may add over its own UTF-8 length.
/// A longer expansion (U+FDFA is eighteen characters) folds to the
/// character itself, so folded text stays within about 1.5 times the
/// input, as it was before decomposition (AGENT-315).
const MAX_EXTRA_BYTES: usize = 1;

/// Characters whose compatibility form is used: letters (including
/// Roman numerals, circled and modifier letters), parenthesized Latin
/// letters, mathematical digits and fullwidth ASCII. Other symbols and
/// numbers (`™`, `²`, `½`) keep their own form, so they stay non-word
/// bytes and cannot glue onto a phrase's last word and break its `\b`.
fn decomposes(c: char) -> bool {
    c.is_alphabetic()
        || matches!(c as u32,
            0xFF01..=0xFF5E | 0x249C..=0x24B5 | 0x1F110..=0x1F129 | 0x1D7CE..=0x1D7FF)
}

/// Emit what non-whitespace `c` folds to in the full fold, lower-cased:
/// for a letter, its compatibility decomposition (NFKD) with look-alikes
/// folded and marks dropped. Spaces in an expansion are dropped too (a
/// spacing accent expands to a space and a mark), and so are an enclosed
/// form's parentheses.
fn fold_full(c: char, mut emit: impl FnMut(char)) {
    if c.is_ascii() {
        emit(c.to_ascii_lowercase());
        return;
    }
    if is_invisible(c) || is_mark(c) {
        return;
    }
    if let Some(a) = lookalike(c) {
        emit(a);
        return;
    }
    if !decomposes(c) {
        c.to_lowercase().for_each(emit);
        return;
    }
    let enclosed = is_enclosed(c);
    let limit = c.len_utf8() + MAX_EXTRA_BYTES;
    let (mut kept, mut len, mut bytes) = (['\0'; 8], 0, 0);
    decompose_compatible(c, |d| {
        if d.is_whitespace()
            || is_mark(d)
            || is_invisible(d)
            || (enclosed && matches!(d, '(' | ')'))
        {
            return;
        }
        for f in lookalike(d).unwrap_or(d).to_lowercase() {
            bytes += f.len_utf8();
            if bytes <= limit {
                kept[len] = f;
                len += 1;
            }
        }
    });
    if bytes > limit {
        c.to_lowercase().for_each(emit);
    } else {
        kept[..len].iter().copied().for_each(emit);
    }
}

/// Emit what non-whitespace `c` folds to in the strict fold.
fn fold_old(c: char, emit: impl FnMut(char)) {
    if is_invisible(c) || is_latin_mark(c) {
        return;
    }
    let c = if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
    } else {
        homoglyph(c).or_else(|| math_letter(c)).unwrap_or(c)
    };
    c.to_lowercase().for_each(emit);
}

/// Whether `c` folds differently in the two folds. Each fold emits at
/// most five characters (`no_character_folds_to_much_more_than_itself`).
fn folds_differ(c: char) -> bool {
    let collect = |fold: fn(char, &mut dyn FnMut(char))| {
        let (mut out, mut len) = (['\0'; 8], 0);
        fold(c, &mut |f| {
            out[len] = f;
            len += 1;
        });
        (out, len)
    };
    collect(|c, emit| fold_full(c, emit)) != collect(|c, emit| fold_old(c, emit))
}

/// Bytes `c` contributes to either folded text, at most: the smaller of
/// the two, ignoring whitespace-run collapsing (the caller counts a run
/// once). A window that keeps this much keeps enough of both.
pub(super) fn folded_width(c: char) -> usize {
    if c.is_whitespace() {
        return 1;
    }
    let (mut full, mut old) = (0, 0);
    fold_full(c, |f| full += f.len_utf8());
    fold_old(c, |f| old += f.len_utf8());
    full.min(old)
}

fn push(out: &mut String, map: &mut Vec<usize>, at: usize, c: char) {
    let before = out.len();
    out.push(c);
    map.extend(std::iter::repeat_n(at, out.len() - before));
}

/// Fold `text` with `fold_char`; the map gives, for each byte of the
/// folded text, the byte offset in `text` of the character it came from.
fn fold_with(text: &str, fold_char: fn(char, &mut dyn FnMut(char))) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len());
    let mut after_space = false;
    for (at, c) in text.char_indices() {
        if c.is_whitespace() {
            if !after_space {
                push(&mut out, &mut map, at, ' ');
            }
            after_space = true;
            continue;
        }
        let before = out.len();
        fold_char(c, &mut |f| push(&mut out, &mut map, at, f));
        // A character that folds to nothing does not end a space run.
        if out.len() > before {
            after_space = false;
        }
    }
    (out, map)
}

/// The full fold of `text`, with its offset map.
pub(super) fn fold(text: &str) -> (String, Vec<usize>) {
    fold_with(text, |c, emit| fold_full(c, emit))
}

/// The strict (pre-AGENT-315) fold of `text`, with its offset map.
pub(super) fn fold_strict(text: &str) -> (String, Vec<usize>) {
    fold_with(text, |c, emit| fold_old(c, emit))
}

/// Whether `text` holds a character the two folds treat differently, so
/// a scan must match [`fold_strict`] as well as [`fold`].
pub(super) fn needs_strict(text: &str) -> bool {
    text.chars().any(|c| !c.is_ascii() && folds_differ(c))
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
    fn math_alphanumerics_fold_to_ascii() {
        // AGENT-270: bold, italic, script, fraktur, double-struck, sans,
        // monospace letters and digits.
        assert_eq!(
            fold("\u{1D422}\u{1D420}\u{1D427}\u{1D428}\u{1D42B}\u{1D41E} \u{1D631}\u{1D633}\u{1D626}\u{1D637}").0,
            "ignore prev"
        );
        assert_eq!(fold("\u{1D400}\u{1D6A3}\u{1D7CE}\u{1D7FF}").0, "az09");
        assert_eq!(fold("\u{210E}\u{2102}\u{1D6A4}").0, "hci");
        // Math Greek folds to Greek, then to the Latin look-alike.
        assert_eq!(fold("\u{1D6A8}\u{1D6B6}").0, "ao");
    }

    #[test]
    fn compatibility_lookalikes_fold_to_ascii() {
        // AGENT-315: each line spells (part of) "ignore" or a letter of it.
        let cases = [
            // Kelvin sign.
            ("\u{212A}", "k"),
            // Double-struck italic.
            ("\u{2145}\u{2146}\u{2147}\u{2148}\u{2149}", "ddeij"),
            // Roman numerals.
            ("\u{2160}\u{2170}\u{216B}", "iixii"),
            // Circled.
            ("\u{24BE}\u{24D6}\u{24DD}", "ign"),
            // Parenthesized.
            ("\u{24A4}\u{24A2}", "ig"),
            // Negative circled, squared, regional.
            ("\u{1F158}\u{1F176}\u{1F1EE}", "igi"),
            // Superscripts.
            ("\u{1D35}\u{1D4D}\u{207F}\u{1D52}\u{02B3}\u{1D49}", "ignore"),
            // Precomposed accents.
            ("\u{00ED}gn\u{00F3}r\u{00E9}", "ignore"),
            // Small capitals.
            ("\u{026A}\u{0262}\u{0274}\u{1D0F}\u{0280}\u{1D07}", "ignore"),
            // Dotless i and j.
            ("\u{0131}\u{0237}", "ij"),
            // Ligature.
            ("\u{FB01}", "fi"),
        ];
        for (text, want) in cases {
            assert_eq!(fold(text).0, want, "{text:?}");
        }
    }

    #[test]
    fn marks_outside_the_latin_blocks_are_dropped() {
        assert_eq!(fold("ig\u{0483}no\u{0951}re").0, "ignore");
    }

    #[test]
    fn a_letter_whose_form_is_a_space_and_a_mark_folds_to_nothing() {
        // U+037A (Greek ypogegrammeni) is a space and a combining mark.
        assert_eq!(fold("a\u{037A}b").0, "ab");
        assert_eq!(folded_width('\u{037A}'), 0);
    }

    #[test]
    fn spacing_accents_keep_their_own_form() {
        assert_eq!(fold("a\u{00B4}b").0, "a\u{00B4}b");
    }

    #[test]
    fn symbols_and_numbers_keep_their_own_form() {
        // AGENT-315: `™` folded to `tm` would glue onto the last word.
        for c in [
            '\u{2122}', '\u{00B2}', '\u{00BD}', '\u{2121}', '\u{2474}', '\u{00B4}',
        ] {
            assert_eq!(
                fold(&c.to_string()).0,
                c.to_lowercase().to_string(),
                "{c:?}"
            );
        }
    }

    #[test]
    fn no_character_folds_to_much_more_than_itself() {
        // AGENT-315: bounds folded text (and its offset map) by the input.
        for c in (0..=0x10FFFF).filter_map(char::from_u32) {
            let (mut full, mut old) = (0, 0);
            fold_full(c, |f| full += f.len_utf8());
            fold_old(c, |f| old += f.len_utf8());
            let most = c.len_utf8() + MAX_EXTRA_BYTES;
            assert!(full <= most && old <= most, "{c:?}: {full} / {old}");
        }
        assert_eq!(fold("\u{FDFA}").0, "\u{FDFA}");
    }

    #[test]
    fn the_strict_fold_is_the_previous_fold() {
        // AGENT-315: accents, Kelvin, regional indicators and non-Latin
        // marks stay; Cyrillic, fullwidth and math letters still fold.
        let text = "\u{00ED}\u{212A}\u{1F1FA}\u{0456}\u{FF29}\u{1D422}\u{0951}\u{0301}";
        assert_eq!(fold_strict(text).0, "\u{00ED}k\u{1F1FA}iii\u{0951}");
    }

    #[test]
    fn the_strict_fold_is_needed_only_where_the_folds_differ() {
        for text in [
            "plain ascii",
            "\u{0456}gnore \u{FF29}",
            "\u{201C}q\u{201D} \u{2014}",
        ] {
            assert!(!needs_strict(text), "{text:?}");
        }
        for text in ["caf\u{00E9}", "\u{1F1FA}\u{1F1F8}", "\u{2139}", "x\u{0951}"] {
            assert!(needs_strict(text), "{text:?}");
        }
    }

    #[test]
    fn folded_width_is_the_smaller_fold() {
        let sample = "Ab\u{212A}\u{216B}\u{24A4}\u{1F158}\u{00ED}\u{1D6A8}\u{FDFA}\u{AC00}\u{00B4}\u{0301}\u{200B}\u{FB01}\u{0130}\u{1D400}\u{1F1FA}\u{0951}";
        for c in sample.chars() {
            let one = c.to_string();
            let want = fold(&one).0.len().min(fold_strict(&one).0.len());
            assert_eq!(folded_width(c), want, "{c:?}");
        }
    }

    #[test]
    fn combining_marks_are_dropped_and_offsets_kept() {
        let (norm, map) = fold("i\u{0307}g\u{0301}nore\u{20DD}");
        assert_eq!(norm, "ignore");
        assert_eq!(map, vec![0, 3, 6, 7, 8, 9]);
        assert_eq!(folded_width('\u{0301}'), 0);
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
