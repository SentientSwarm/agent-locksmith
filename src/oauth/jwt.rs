//! Phase G2 — JWT payload extraction for OAuth provider claims.
//!
//! Pure-functional helpers for pulling claims out of OAuth JWTs (today
//! the access token issued by `auth.openai.com` for codex). No crypto
//! — we trust the token because we sealed it ourselves at bootstrap.
//! The provider verified the signature when it minted the token; we're
//! just reading data we already have.
//!
//! Tolerant of non-JWT inputs: every helper returns `None` on parse
//! failure, never panics or errors. This matters because the same
//! storage path is shared with non-codex OAuth providers (anthropic-
//! oauth, google-gemini-cli, etc.) whose tokens may not be JWTs at
//! all.
//!
//! See agents-stack/docs/spec/v0.2.0.md "Per-agent credential
//! overrides + OAuth session labels (Phase G)" for the broader Phase
//! G context.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// Path to the `chatgpt_account_id` claim in OpenAI's JWT shape:
/// `payload["https://api.openai.com/auth"]["chatgpt_account_id"]`.
const OPENAI_AUTH_NAMESPACE: &str = "https://api.openai.com/auth";
const CHATGPT_ACCOUNT_ID_CLAIM: &str = "chatgpt_account_id";

/// Decode the JWT payload (middle segment) into a `serde_json::Value`.
/// Returns `None` for any parse failure: not a JWT, malformed base64,
/// non-JSON payload, etc.
pub fn decode_jwt_payload(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        // More than 3 parts — not a JWT.
        return None;
    }
    // Add base64url padding if needed.
    let mut padded = payload_b64.to_string();
    let pad_len = (4 - padded.len() % 4) % 4;
    padded.extend(std::iter::repeat_n('=', pad_len));
    // base64url no-pad doesn't accept '=' padding, but URL_SAFE_NO_PAD
    // tolerates trailing '=' via `decode_strict_padding(false)` —
    // actually we just trim the padding back since URL_SAFE_NO_PAD
    // expects no padding.
    let trimmed = padded.trim_end_matches('=');
    let decoded = URL_SAFE_NO_PAD.decode(trimmed).ok()?;
    serde_json::from_slice::<Value>(&decoded).ok()
}

/// Extract the `chatgpt_account_id` from a codex/OpenAI access-token
/// JWT. Returns `None` when:
///   - input is not a JWT,
///   - JWT payload doesn't include `https://api.openai.com/auth`,
///   - that namespace doesn't include `chatgpt_account_id`,
///   - the value is not a non-empty string.
///
/// Bootstrap and refresh paths call this on every fresh access-token,
/// silently storing `None` for non-codex OAuth providers.
pub fn extract_chatgpt_account_id(access_token: &str) -> Option<String> {
    let payload = decode_jwt_payload(access_token)?;
    let auth = payload.get(OPENAI_AUTH_NAMESPACE)?;
    let account_id = auth.get(CHATGPT_ACCOUNT_ID_CLAIM)?.as_str()?;
    if account_id.is_empty() {
        return None;
    }
    Some(account_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    /// Build a fake JWT with the given JSON payload. Header + signature
    /// are placeholders — we don't verify them, just parse the payload.
    fn jwt_with_payload(payload: &Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{header}.{payload}.{sig}")
    }

    #[test]
    fn extracts_account_id_from_valid_jwt() {
        let token = jwt_with_payload(&json!({
            "sub": "google-oauth2|123",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "83e64542-54c5-4210-bb33-3631c727a27b",
                "chatgpt_plan_type": "pro",
            },
        }));
        assert_eq!(
            extract_chatgpt_account_id(&token),
            Some("83e64542-54c5-4210-bb33-3631c727a27b".to_string()),
        );
    }

    #[test]
    fn returns_none_for_jwt_without_openai_auth_namespace() {
        let token = jwt_with_payload(&json!({
            "sub": "user",
            "iss": "https://example.com",
        }));
        assert_eq!(extract_chatgpt_account_id(&token), None);
    }

    #[test]
    fn returns_none_when_account_id_claim_missing() {
        let token = jwt_with_payload(&json!({
            "https://api.openai.com/auth": {
                "chatgpt_plan_type": "pro",
            },
        }));
        assert_eq!(extract_chatgpt_account_id(&token), None);
    }

    #[test]
    fn returns_none_when_account_id_is_empty_string() {
        let token = jwt_with_payload(&json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "",
            },
        }));
        assert_eq!(extract_chatgpt_account_id(&token), None);
    }

    #[test]
    fn returns_none_for_non_jwt_input() {
        assert_eq!(extract_chatgpt_account_id(""), None);
        assert_eq!(extract_chatgpt_account_id("not-a-jwt"), None);
        assert_eq!(extract_chatgpt_account_id("only.two"), None);
        assert_eq!(extract_chatgpt_account_id("a.b.c.d"), None);
    }

    #[test]
    fn returns_none_for_locksmith_bearer_format() {
        // The locksmith bearer is `lk_<public_id>.<secret>` — exactly
        // two parts, no JWT structure. Hermes/openclaw also gracefully
        // skip the chatgpt-account-id header in this case (their JWT
        // decode fails identically). Locksmith's own decode must too.
        assert_eq!(
            extract_chatgpt_account_id(
                "lk_lb5_TwfeYLh_9E6z9E5IcQ.tANCHDtQawZAdTgGGb0_tLAqgesRynAHRtZ0S1CYpAU",
            ),
            None,
        );
    }

    #[test]
    fn returns_none_for_malformed_base64_payload() {
        // Three parts but middle isn't valid base64url.
        assert_eq!(extract_chatgpt_account_id("hdr.{not_b64$$$}.sig"), None);
    }

    #[test]
    fn returns_none_when_payload_is_not_json() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"plain text not json");
        let sig = URL_SAFE_NO_PAD.encode(b"sig");
        let token = format!("{header}.{payload}.{sig}");
        assert_eq!(extract_chatgpt_account_id(&token), None);
    }

    #[test]
    fn decode_jwt_payload_returns_full_object() {
        let payload = json!({"foo": "bar", "n": 42});
        let token = jwt_with_payload(&payload);
        let decoded = decode_jwt_payload(&token).unwrap();
        assert_eq!(decoded, payload);
    }
}
