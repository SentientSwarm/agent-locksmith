//! Phase G3/G5 — codex Responses API body fixup.
//!
//! OpenAI's `/backend-api/codex/responses` endpoint (the path that
//! backs codex CLI's Responses API) has stricter body requirements
//! than the generic OpenAI Responses API. Locksmith encodes the
//! upstream-specific quirks so agents can stay generic.
//!
//! ## Phase G3 — required fields
//!
//! - `instructions` (string, required) — the system-prompt analog.
//! - `store: false` — codex rejects `true`; no agent has a legitimate
//!   reason to want server-side storage on this endpoint.
//! - `stream: true` — codex rejects `false`; the endpoint is
//!   fundamentally streaming.
//!
//! ## Phase G5 — forbidden fields (strip on the way out)
//!
//! - `max_output_tokens` — codex returns 400 with body
//!   `{"detail":"Unsupported parameter: max_output_tokens"}` when set
//!   (ChatGPT-plan output is metered server-side, not by the client).
//!   OpenAI SDK clients (e.g. openclaw, embedded `OpenAI/JS`) emit
//!   this from per-model `maxTokens` config without knowing the
//!   codex-specific rejection. Stripping it here lets agents keep
//!   their generic per-model max-tokens configuration without
//!   carving out a special case for codex.
//!
//! Native codex CLI handles all of these because it's codex-aware.
//! Hermes-agent and openclaw, when proxied through locksmith, send a
//! generic OpenAI-compatible body — chatgpt.com 400s. Phase G2 owns
//! the `ChatGPT-Account-ID` header; G3 owns the missing-field quirks;
//! G5 owns the forbidden-field quirks. Same trust-model premise:
//! locksmith encodes upstream-specific behavior so agents stay generic.
//!
//! See agents-stack/docs/spec/v0.2.0.md "Codex body fixup (Phase G3)"
//! for the original formal design and the G3 addendum to ADR-0005.
//! G5 follows the same shape; addendum lives alongside.

use serde_json::value::RawValue;
use std::collections::BTreeMap;

/// The body's top level only. Nested values stay as the bytes the agent sent,
/// so memory stays close to the body size and nested content is forwarded
/// exactly, numbers included (AGENT-355). Keys are ordered as `Value`'s map
/// orders them, so re-serialized bodies keep the shape they had before.
type TopLevel = BTreeMap<String, Box<RawValue>>;

/// Default `instructions` injected when the agent didn't set any.
/// Operators can document an override later if this becomes a
/// soft-API; for now it's neutral phrasing.
const DEFAULT_INSTRUCTIONS: &str = "You are a helpful assistant.";

/// What [`fixup`] changed. `is_noop` returns true when nothing was
/// touched — proxy.rs uses this to decide whether to emit
/// `details.codex_body_fixup` on the audit row.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FixupSummary {
    pub fields_added: Vec<&'static str>,
    pub fields_overridden: Vec<&'static str>,
    /// Phase G5 — fields stripped before forwarding because codex
    /// rejects them outright. Audit emits this so operators can
    /// trace why their request shape was modified.
    pub fields_removed: Vec<&'static str>,
}

impl FixupSummary {
    pub fn is_noop(&self) -> bool {
        self.fields_added.is_empty()
            && self.fields_overridden.is_empty()
            && self.fields_removed.is_empty()
    }
}

/// Inspect a request body destined for codex `/responses` and inject
/// missing required fields. Returns the (possibly-modified) body and
/// a summary of what changed.
///
/// Tolerant of non-JSON inputs — every parse failure path returns
/// `(body.to_vec(), FixupSummary::default())` so we never block a
/// request just because we couldn't munge it. Codex itself will
/// 400 on malformed bodies; that's the right error for the agent to
/// see.
///
/// There is no size cap of its own (AGENT-248): the body has already been
/// read under the route's `body_limit_bytes`, and the proxy answers a
/// codex `/responses` body over that limit with 413 before calling this.
pub fn fixup(body: &[u8]) -> (Vec<u8>, FixupSummary) {
    // Only a JSON object deserializes into the map; arrays, null, scalars and
    // malformed bodies pass through unchanged.
    let Ok(mut map) = serde_json::from_slice::<TopLevel>(body) else {
        return (body.to_vec(), FixupSummary::default());
    };

    let mut summary = FixupSummary::default();
    apply_store_rule(&mut map, &mut summary);
    apply_stream_rule(&mut map, &mut summary);
    apply_instructions_rule(&mut map, &mut summary);
    apply_max_output_tokens_rule(&mut map, &mut summary);

    if summary.is_noop() {
        // Avoid re-serializing when we didn't change anything —
        // preserves the caller's exact bytes (formatting, key order).
        return (body.to_vec(), summary);
    }

    let new_body = serde_json::to_vec(&map).expect("serializing raw JSON values cannot fail");
    (new_body, summary)
}

fn raw(json: &str) -> Box<RawValue> {
    RawValue::from_string(json.to_string()).expect("a fixed JSON literal")
}

/// Force a top-level boolean. JSON spells each boolean one way, so the raw
/// text is compared without parsing whatever value the agent sent.
fn apply_bool_rule(map: &mut TopLevel, key: &'static str, want: bool, summary: &mut FixupSummary) {
    let literal = if want { "true" } else { "false" };
    match map.get(key) {
        Some(v) if v.get() == literal => {} // already correct
        Some(_) => {
            map.insert(key.into(), raw(literal));
            summary.fields_overridden.push(key);
        }
        None => {
            map.insert(key.into(), raw(literal));
            summary.fields_added.push(key);
        }
    }
}

fn apply_store_rule(map: &mut TopLevel, summary: &mut FixupSummary) {
    apply_bool_rule(map, "store", false, summary);
}

fn apply_stream_rule(map: &mut TopLevel, summary: &mut FixupSummary) {
    apply_bool_rule(map, "stream", true, summary);
}

fn apply_instructions_rule(map: &mut TopLevel, summary: &mut FixupSummary) {
    if !map.contains_key("instructions") {
        let value = serde_json::to_string(DEFAULT_INSTRUCTIONS).expect("a string serializes");
        map.insert("instructions".into(), raw(&value));
        summary.fields_added.push("instructions");
    }
}

fn apply_max_output_tokens_rule(map: &mut TopLevel, summary: &mut FixupSummary) {
    // Phase G5 — codex /responses returns 400 with body
    // `{"detail":"Unsupported parameter: max_output_tokens"}` when
    // this is set. Strip it silently; agents stay generic.
    if map.remove("max_output_tokens").is_some() {
        summary.fields_removed.push("max_output_tokens");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn parse(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("output must be valid JSON")
    }

    #[test]
    fn empty_object_gets_all_three_fields() {
        let (out, summary) = fixup(b"{}");
        let v = parse(&out);
        assert_eq!(v["store"], Value::Bool(false));
        assert_eq!(v["stream"], Value::Bool(true));
        assert_eq!(
            v["instructions"],
            Value::String(DEFAULT_INSTRUCTIONS.into())
        );
        assert_eq!(
            summary.fields_added,
            vec!["store", "stream", "instructions"]
        );
        assert!(summary.fields_overridden.is_empty());
    }

    #[test]
    fn store_true_is_overridden_to_false() {
        let body = json!({"store": true}).to_string();
        let (out, summary) = fixup(body.as_bytes());
        let v = parse(&out);
        assert_eq!(v["store"], Value::Bool(false));
        assert!(summary.fields_overridden.contains(&"store"));
        assert!(!summary.fields_added.contains(&"store"));
    }

    #[test]
    fn store_false_is_preserved_no_override() {
        let body = json!({"store": false, "stream": true, "instructions": "x"}).to_string();
        let (_out, summary) = fixup(body.as_bytes());
        assert!(
            summary.is_noop(),
            "store/stream/instructions all valid → noop"
        );
    }

    #[test]
    fn stream_false_is_overridden_to_true() {
        let body = json!({"stream": false}).to_string();
        let (out, summary) = fixup(body.as_bytes());
        let v = parse(&out);
        assert_eq!(v["stream"], Value::Bool(true));
        assert!(summary.fields_overridden.contains(&"stream"));
    }

    #[test]
    fn instructions_user_value_is_preserved() {
        let body = json!({
            "store": false,
            "stream": true,
            "instructions": "be terse",
        })
        .to_string();
        let (out, summary) = fixup(body.as_bytes());
        let v = parse(&out);
        assert_eq!(v["instructions"], Value::String("be terse".into()));
        assert!(summary.is_noop());
    }

    #[test]
    fn fully_valid_body_is_noop_and_bytes_preserved() {
        // Particular formatting (whitespace, key order) survives noop.
        let body = b"{ \"instructions\": \"x\", \"stream\": true, \"store\": false }";
        let (out, summary) = fixup(body);
        assert_eq!(out, body, "noop must preserve exact input bytes");
        assert!(summary.is_noop());
    }

    #[test]
    fn non_json_body_passes_through_unchanged() {
        let body = b"not json at all";
        let (out, summary) = fixup(body);
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn json_array_passes_through_unchanged() {
        let body = b"[1,2,3]";
        let (out, summary) = fixup(body);
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn json_null_passes_through_unchanged() {
        let body = b"null";
        let (out, summary) = fixup(body);
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn malformed_json_passes_through_unchanged() {
        let body = b"{\"store\": tru";
        let (out, summary) = fixup(body);
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    #[test]
    fn body_over_one_mib_is_fixed_up() {
        // AGENT-248: the old 1 MiB cap is gone; a 3 MiB body with none of
        // the required fields gets all of them, and max_output_tokens goes.
        let prefix = b"{\"max_output_tokens\":5,\"input\":\"";
        let suffix = b"\"}";
        let mut body = Vec::with_capacity(3 * 1024 * 1024);
        body.extend_from_slice(prefix);
        body.extend(std::iter::repeat_n(b'x', 3 * 1024 * 1024));
        body.extend_from_slice(suffix);

        let (out, summary) = fixup(&body);
        assert_eq!(
            summary.fields_added,
            vec!["store", "stream", "instructions"]
        );
        assert_eq!(summary.fields_removed, vec!["max_output_tokens"]);
        let v = parse(&out);
        assert_eq!(v["input"].as_str().map(str::len), Some(3 * 1024 * 1024));
    }

    #[test]
    fn non_json_body_over_one_mib_passes_through_unchanged() {
        let body = vec![b'a'; 2 * 1024 * 1024];
        let (out, summary) = fixup(&body);
        assert_eq!(out, body);
        assert!(summary.is_noop());
    }

    // AGENT-355: only the top level is parsed, so nested content is
    // forwarded exactly as sent and memory stays close to the body size.
    #[test]
    fn nested_content_is_forwarded_byte_for_byte() {
        let nested = r#"{"z":1,"a":[1.10,123456789012345678901234567890]}"#;
        let body = format!(r#"{{"input":{nested},"store":true}}"#);
        let (out, summary) = fixup(body.as_bytes());
        assert!(summary.fields_overridden.contains(&"store"));
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains(nested), "nested content was rewritten: {out}");
    }

    #[test]
    fn rules_read_only_the_top_level_values() {
        // A huge or odd value under a rule's key is replaced, never parsed.
        let big = format!(
            r#"{{"store":[{}0],"stream":true,"instructions":"x"}}"#,
            "0,".repeat(1000)
        );
        let (out, summary) = fixup(big.as_bytes());
        assert_eq!(summary.fields_overridden, vec!["store"]);
        assert_eq!(parse(&out)["store"], Value::Bool(false));
    }

    #[test]
    fn fixup_summary_is_noop_recognizes_empty() {
        assert!(FixupSummary::default().is_noop());
        let mut s = FixupSummary::default();
        s.fields_added.push("x");
        assert!(!s.is_noop());
        let mut s = FixupSummary::default();
        s.fields_overridden.push("x");
        assert!(!s.is_noop());
        let mut s = FixupSummary::default();
        s.fields_removed.push("x");
        assert!(!s.is_noop());
    }

    // Phase G5 — codex rejects max_output_tokens; locksmith strips it.
    #[test]
    fn max_output_tokens_is_stripped() {
        let body = json!({
            "store": false,
            "stream": true,
            "instructions": "x",
            "max_output_tokens": 16384,
        })
        .to_string();
        let (out, summary) = fixup(body.as_bytes());
        let v = parse(&out);
        assert!(
            v.get("max_output_tokens").is_none(),
            "max_output_tokens must be stripped from forwarded body"
        );
        assert!(summary.fields_removed.contains(&"max_output_tokens"));
        assert!(summary.fields_added.is_empty());
        assert!(summary.fields_overridden.is_empty());
    }

    #[test]
    fn max_output_tokens_absent_is_noop_for_g5() {
        let body = json!({
            "store": false,
            "stream": true,
            "instructions": "x",
        })
        .to_string();
        let (_out, summary) = fixup(body.as_bytes());
        assert!(
            !summary.fields_removed.contains(&"max_output_tokens"),
            "absent param must not be reported as removed"
        );
    }

    #[test]
    fn max_output_tokens_stripped_alongside_g3_additions() {
        // Empty input gets G3 additions (store/stream/instructions);
        // explicit max_output_tokens still stripped in same pass.
        let body = json!({"max_output_tokens": 0}).to_string();
        let (out, summary) = fixup(body.as_bytes());
        let v = parse(&out);
        assert!(v.get("max_output_tokens").is_none());
        assert_eq!(v["store"], Value::Bool(false));
        assert_eq!(v["stream"], Value::Bool(true));
        assert_eq!(
            v["instructions"],
            Value::String(DEFAULT_INSTRUCTIONS.into())
        );
        assert_eq!(
            summary.fields_added,
            vec!["store", "stream", "instructions"]
        );
        assert_eq!(summary.fields_removed, vec!["max_output_tokens"]);
    }
}
