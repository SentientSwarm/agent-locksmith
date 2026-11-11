//! Per-route upstream CA (#135).
//!
//! A registration may carry its own PEM trust anchors. When present, the
//! route's client trusts only those certificates: no public roots and no
//! global `tls.upstream_ca_bundle`. Any certificate may be the anchor, so an
//! intermediate alone is enough (partial-chain trust).
//!
//! The PEM is validated on write. At client-build time a value that no longer
//! parses yields a client with no anchors at all, so the route fails closed
//! instead of falling back to public roots.

use super::{Protocol, RegistrationError};
use sha2::{Digest, Sha256};

/// Upper bound on the stored PEM. A private CA chain is a few KiB.
pub const MAX_PEM_BYTES: usize = 64 * 1024;
/// Upper bound on certificates in one bundle.
pub const MAX_CERTS: usize = 16;

/// DER certificates from `pem`, or `None` when the bundle is unusable:
/// non-certificate blocks, no certificates, too many, too large, or a
/// certificate that does not parse as X.509.
pub fn der_certificates(pem: &str) -> Option<Vec<Vec<u8>>> {
    if pem.len() > MAX_PEM_BYTES {
        return None;
    }
    let blocks = pem::parse_many(pem).ok()?;
    if blocks.is_empty() || blocks.len() > MAX_CERTS {
        return None;
    }
    blocks
        .into_iter()
        .map(|b| {
            let ok = b.tag() == "CERTIFICATE"
                && x509_parser::parse_x509_certificate(b.contents())
                    .is_ok_and(|(rest, _)| rest.is_empty());
            ok.then(|| b.into_contents())
        })
        .collect()
}

/// Write-time validation. A CA only makes sense on an HTTPS upstream of an
/// HTTP-protocol route (native MCP uses its own client and would ignore it).
pub fn validate(
    pem: Option<&str>,
    upstream: &str,
    protocol: Protocol,
) -> Result<(), RegistrationError> {
    let Some(pem) = pem else { return Ok(()) };
    let https = upstream
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"));
    if !https || protocol != Protocol::Http || der_certificates(pem).is_none() {
        return Err(RegistrationError::InvalidUpstreamCa);
    }
    Ok(())
}

/// Stable fingerprint for client caching and operator display.
pub fn sha256_hex(pem: &str) -> String {
    format!("{:x}", Sha256::digest(pem.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_pem() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(vec!["ca.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem()
    }

    #[test]
    fn accepts_one_or_more_certificates() {
        let one = cert_pem();
        assert_eq!(der_certificates(&one).map(|c| c.len()), Some(1));
        let two = format!("{one}{}", cert_pem());
        assert_eq!(der_certificates(&two).map(|c| c.len()), Some(2));
        assert!(validate(Some(&two), "https://10.0.0.1/v1", Protocol::Http).is_ok());
    }

    #[test]
    fn rejects_unusable_bundles() {
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        for pem in ["", "not pem", key, junk] {
            assert!(der_certificates(pem).is_none(), "{pem:?}");
        }
        let mixed = format!("{}{key}", cert_pem());
        assert!(
            der_certificates(&mixed).is_none(),
            "private key block mixed in"
        );
        let many = cert_pem().repeat(MAX_CERTS + 1);
        assert!(der_certificates(&many).is_none(), "too many certificates");
    }

    #[test]
    fn requires_https_http_protocol_route() {
        let pem = cert_pem();
        let bad = |u: &str, p| validate(Some(&pem), u, p).is_err();
        assert!(bad("http://10.0.0.1/v1", Protocol::Http));
        assert!(bad("https://10.0.0.1/mcp", Protocol::McpStreamableHttp));
        assert!(validate(None, "http://x", Protocol::Http).is_ok());
        assert!(validate(Some(&pem), "HTTPS://10.0.0.1", Protocol::Http).is_ok());
    }
}
