//! Structured token type (T1.12 / INF-5).
//!
//! Every credential issued by Locksmith — agent token, bootstrap token,
//! operator token — has the wire shape `<prefix>_<public_id>.<secret>`:
//!
//! - `<prefix>` is a namespace marker. `lk` for agent tokens (this M1
//!   landing); `lk_op` for operators and `lk_bt` for bootstrap tokens
//!   land in M2 with their respective issuance paths.
//! - `<public_id>` is 128 bits of URL-safe-base64-encoded random (22
//!   characters, no padding). It is **not** secret. The database keys
//!   off this value, which means agent lookup at auth time is a fast
//!   indexed read with no timing-leak concern (Q-14).
//! - `<secret>` is 256 bits of URL-safe-base64-encoded random (43
//!   characters). The hash of this is what's stored at rest (M2 argon2id);
//!   verification in the auth path is constant-time.
//!
//! T1.12 lands the type, parser, and generator. Wiring into the auth
//! path is M2 / T2.9.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};

/// Wire prefix per token namespace. M2 adds `Operator` and `Bootstrap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenNamespace {
    Agent,
}

impl TokenNamespace {
    pub fn prefix(&self) -> &'static str {
        match self {
            TokenNamespace::Agent => "lk",
        }
    }

    fn from_prefix(s: &str) -> Option<Self> {
        match s {
            "lk" => Some(TokenNamespace::Agent),
            _ => None,
        }
    }
}

/// 128-bit public identifier (16 bytes random; 22-char URL-safe base64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicId(String);

impl PublicId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 256-bit shared secret (32 bytes random; 43-char URL-safe base64).
/// Wraps `SecretString` so memory is zeroized on drop.
#[derive(Clone)]
pub struct Secret(SecretString);

impl Secret {
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Debug)]
pub struct StructuredToken {
    pub namespace: TokenNamespace,
    pub public_id: PublicId,
    pub secret: Secret,
}

impl StructuredToken {
    /// Generate a fresh token in `namespace` using OS-cryptographic
    /// randomness. Panics only if the OS RNG itself is unavailable
    /// (treat that as unrecoverable; per the threat model in §5 Q6, an
    /// RNG failure precludes safe credential issuance).
    pub fn generate(namespace: TokenNamespace) -> Self {
        let mut id_bytes = [0u8; 16];
        let mut secret_bytes = [0u8; 32];
        getrandom::fill(&mut id_bytes).expect("OS RNG unavailable");
        getrandom::fill(&mut secret_bytes).expect("OS RNG unavailable");
        Self {
            namespace,
            public_id: PublicId(URL_SAFE_NO_PAD.encode(id_bytes)),
            secret: Secret(SecretString::from(URL_SAFE_NO_PAD.encode(secret_bytes))),
        }
    }

    /// `<prefix>_<public_id>.<secret>` — exactly the format an agent
    /// presents in `Authorization: Bearer …`.
    pub fn wire_format(&self) -> String {
        format!(
            "{}_{}.{}",
            self.namespace.prefix(),
            self.public_id.0,
            self.secret.expose()
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Token does not start with a known namespace prefix.
    UnknownNamespace,
    /// Missing the `.` between public id and secret.
    MissingSeparator,
    /// Public id or secret length doesn't match the expected encoding.
    InvalidLength,
    /// Public id or secret contains non-URL-safe-base64 characters.
    InvalidEncoding,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnknownNamespace => f.write_str("token namespace prefix is not recognized"),
            ParseError::MissingSeparator => {
                f.write_str("token is missing the `.` between public id and secret")
            }
            ParseError::InvalidLength => f.write_str("token has invalid length"),
            ParseError::InvalidEncoding => {
                f.write_str("token contains invalid base64url characters")
            }
        }
    }
}

impl std::error::Error for ParseError {}

const PUBLIC_ID_LEN: usize = 22;
const SECRET_LEN: usize = 43;

/// Parse a presented token of the form `<prefix>_<public_id>.<secret>`.
/// Validation is shape-only: no DB lookup, no hash check — those happen
/// in the authentication path (M2). Returns the namespace, public id,
/// and secret as separate values; the namespace is the first thing the
/// auth path uses to decide *which* repository to consult.
pub fn parse(input: &str) -> Result<(TokenNamespace, PublicId, Secret), ParseError> {
    let (prefix_part, rest) = input.split_once('_').ok_or(ParseError::UnknownNamespace)?;
    let namespace = TokenNamespace::from_prefix(prefix_part).ok_or(ParseError::UnknownNamespace)?;

    let (public_id_str, secret_str) = rest.split_once('.').ok_or(ParseError::MissingSeparator)?;

    if public_id_str.len() != PUBLIC_ID_LEN || secret_str.len() != SECRET_LEN {
        return Err(ParseError::InvalidLength);
    }

    if URL_SAFE_NO_PAD.decode(public_id_str).is_err() || URL_SAFE_NO_PAD.decode(secret_str).is_err()
    {
        return Err(ParseError::InvalidEncoding);
    }

    Ok((
        namespace,
        PublicId(public_id_str.to_string()),
        Secret(SecretString::from(secret_str.to_string())),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_well_formed_wire_token() {
        let t = StructuredToken::generate(TokenNamespace::Agent);
        let wire = t.wire_format();
        assert!(wire.starts_with("lk_"));
        let body = &wire["lk_".len()..];
        let (id, sec) = body.split_once('.').expect("`.` separator present");
        assert_eq!(id.len(), PUBLIC_ID_LEN);
        assert_eq!(sec.len(), SECRET_LEN);
    }

    #[test]
    fn parse_roundtrips_a_generated_token() {
        let t = StructuredToken::generate(TokenNamespace::Agent);
        let wire = t.wire_format();
        let (ns, id, sec) = parse(&wire).expect("roundtrip");
        assert_eq!(ns, TokenNamespace::Agent);
        assert_eq!(id, t.public_id);
        assert_eq!(sec.expose(), t.secret.expose());
    }

    #[test]
    fn parse_rejects_missing_separator() {
        assert!(matches!(parse("lk_abc"), Err(ParseError::MissingSeparator)));
    }

    #[test]
    fn parse_rejects_unknown_namespace() {
        let bad = "xx_aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(matches!(parse(bad), Err(ParseError::UnknownNamespace)));
    }

    #[test]
    fn parse_rejects_short_public_id() {
        let bad = "lk_short.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(matches!(parse(bad), Err(ParseError::InvalidLength)));
    }

    #[test]
    fn parse_rejects_invalid_base64_characters() {
        // `!` is not in any base64 alphabet.
        let bad = "lk_!aaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(matches!(parse(bad), Err(ParseError::InvalidEncoding)));
    }

    #[test]
    fn debug_secret_is_redacted() {
        let s = Secret(SecretString::from("super-secret-value".to_string()));
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret-value"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn generate_is_unique_across_calls() {
        // Statistical: 16 + 32 bytes random; collision is astronomically
        // improbable. Fixed run of 100 tokens; assert no two are equal.
        let mut wires = Vec::new();
        for _ in 0..100 {
            wires.push(StructuredToken::generate(TokenNamespace::Agent).wire_format());
        }
        wires.sort();
        wires.dedup();
        assert_eq!(wires.len(), 100, "duplicate token generated (RNG failure?)");
    }
}
