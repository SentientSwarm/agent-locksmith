//! T6.2 — MtlsValidator (verification gate).
//!
//! Validates a peer's leaf certificate against a configured CA bundle:
//!  1. Parse the leaf as DER.
//!  2. Verify the signature chain against the trusted roots.
//!  3. Check the validity window (notBefore ≤ now ≤ notAfter).
//!  4. Optionally check the cert's serial against a CRL (T6.3) and a
//!     local emergency blocklist (T6.4).
//!  5. Extract the identity in priority order: CN → SAN_DNS → SAN_URI.
//!
//! Implementation choice: chain validation defers to `webpki`'s end-entity
//! verifier (the same path rustls uses internally). We do NOT roll our
//! own X.509 verification — webpki has been audited and exercised by
//! every Rust TLS deployment. Identity extraction goes through
//! `x509-parser` because webpki doesn't surface CN/SAN to the caller.

use std::sync::Arc;
use std::time::SystemTime;

use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};
use x509_parser::prelude::FromDer;

use super::{Blocklist, CrlStore};

#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    #[error("untrusted chain")]
    UntrustedChain,
    #[error("certificate expired")]
    Expired,
    #[error("certificate not yet valid")]
    NotYetValid,
    #[error("malformed certificate: {0}")]
    MalformedCert(String),
    #[error("no identity extractable from cert")]
    NoIdentity,
    #[error("revoked by CRL (serial {serial})")]
    RevokedByCRL { serial: String },
    #[error("revoked by local blocklist (serial {serial})")]
    RevokedByBlocklist { serial: String },
}

/// Validated identity extracted from a peer certificate. `kind` says
/// where the identity came from (`cn` / `san_dns` / `san_uri`); audit
/// rows record this so operators can see the binding shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsIdentity {
    pub value: String,
    pub kind: &'static str,
    pub serial_hex: String,
}

/// Composite validator. `crl` and `blocklist` are optional — operators
/// in early M6 deployments may not have a CRL set up; the local
/// blocklist is always available even when empty.
#[derive(Debug)]
pub struct MtlsValidator {
    /// Owned roots (DER). webpki borrows these per-call.
    roots: Vec<Vec<u8>>,
    #[allow(dead_code)]
    crl: Option<Arc<CrlStore>>,
    #[allow(dead_code)]
    blocklist: Option<Arc<Blocklist>>,
}

impl MtlsValidator {
    /// Build a validator from a PEM-encoded CA bundle. Each PEM block
    /// becomes a trust anchor. The validator does NOT consult the
    /// system root store — only the configured CAs.
    pub fn new(ca_bundle_pem: &str) -> Result<Self, MtlsError> {
        let mut roots = Vec::new();
        for pem in pem::parse_many(ca_bundle_pem.as_bytes())
            .map_err(|e| MtlsError::MalformedCert(format!("CA bundle: {e}")))?
        {
            if pem.tag() != "CERTIFICATE" {
                continue;
            }
            roots.push(pem.contents().to_vec());
        }
        if roots.is_empty() {
            return Err(MtlsError::MalformedCert(
                "CA bundle contains no CERTIFICATE blocks".to_string(),
            ));
        }
        Ok(Self {
            roots,
            crl: None,
            blocklist: None,
        })
    }

    pub fn with_crl(mut self, crl: Arc<CrlStore>) -> Self {
        self.crl = Some(crl);
        self
    }

    pub fn with_blocklist(mut self, blocklist: Arc<Blocklist>) -> Self {
        self.blocklist = Some(blocklist);
        self
    }

    /// Validate a peer's leaf cert (DER) and extract the identity.
    pub fn validate(&self, cert_der: &[u8]) -> Result<MtlsIdentity, MtlsError> {
        // Parse with x509-parser for the validity-window + identity bits.
        // webpki handles chain validation but doesn't expose CN/SAN.
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der)
            .map_err(|e| MtlsError::MalformedCert(format!("DER parse: {e}")))?;

        // (1) Validity window — checked here so we get a precise error
        // before invoking webpki, which lumps expiry into a generic
        // "validation failed".
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();
        if now_secs < not_before {
            return Err(MtlsError::NotYetValid);
        }
        if now_secs > not_after {
            return Err(MtlsError::Expired);
        }

        // (2) Chain validation via webpki.
        let cert_der_owned = CertificateDer::from(cert_der.to_vec());
        let ee = EndEntityCert::try_from(&cert_der_owned)
            .map_err(|e| MtlsError::MalformedCert(format!("webpki parse: {e}")))?;
        // Borrow each root's bytes through a CertificateDer that lives
        // for the duration of the call, then derive TrustAnchors from
        // those borrows.
        let root_ders: Vec<CertificateDer<'_>> = self
            .roots
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        let anchors: Vec<TrustAnchor<'_>> = root_ders
            .iter()
            .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
            .collect();
        if anchors.is_empty() {
            return Err(MtlsError::UntrustedChain);
        }
        let now_unix = UnixTime::since_unix_epoch(std::time::Duration::from_secs(now_secs as u64));
        ee.verify_for_usage(
            ALL_SIG_ALGS,
            &anchors,
            &[],
            now_unix,
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|_| MtlsError::UntrustedChain)?;

        // (3) Serial → CRL / blocklist checks.
        let serial_hex = parsed
            .serial
            .to_bytes_be()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if let Some(blocklist) = &self.blocklist
            && blocklist.contains(&serial_hex)
        {
            return Err(MtlsError::RevokedByBlocklist {
                serial: serial_hex.clone(),
            });
        }
        if let Some(crl) = &self.crl
            && crl.contains(&serial_hex)
        {
            return Err(MtlsError::RevokedByCRL {
                serial: serial_hex.clone(),
            });
        }

        // (4) Identity extraction. CN → SAN_DNS → SAN_URI. Empty
        // strings don't count.
        if let Some(cn) = parsed.subject().iter_common_name().next()
            && let Ok(s) = cn.as_str()
            && !s.is_empty()
        {
            return Ok(MtlsIdentity {
                value: s.to_string(),
                kind: "cn",
                serial_hex,
            });
        }
        // SANs.
        if let Ok(Some(ext)) = parsed.subject_alternative_name() {
            for name in &ext.value.general_names {
                use x509_parser::extensions::GeneralName;
                match name {
                    GeneralName::DNSName(s) if !s.is_empty() => {
                        return Ok(MtlsIdentity {
                            value: s.to_string(),
                            kind: "san_dns",
                            serial_hex,
                        });
                    }
                    _ => {}
                }
            }
            for name in &ext.value.general_names {
                use x509_parser::extensions::GeneralName;
                if let GeneralName::URI(s) = name
                    && !s.is_empty()
                {
                    return Ok(MtlsIdentity {
                        value: s.to_string(),
                        kind: "san_uri",
                        serial_hex,
                    });
                }
            }
        }
        Err(MtlsError::NoIdentity)
    }
}

/// All signature algorithms webpki understands. We don't restrict
/// further because rustls's CryptoProvider will already have rejected
/// anything weak before we see the cert.
const ALL_SIG_ALGS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];
