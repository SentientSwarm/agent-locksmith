//! T6.2 — MtlsValidator: chain validation + identity extraction.
//!
//! Builds a CA + leaf at test time with rcgen, walks the leaf DER
//! through `MtlsValidator::validate`, and asserts the extracted
//! identity. Edge cases:
//! - chain validation against a CA bundle that doesn't issue the leaf
//! - expired cert
//! - identity extraction priority: CN → SAN_DNS → SAN_URI

use agent_locksmith::mtls::{MtlsError, MtlsValidator};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use time::OffsetDateTime;
use time::macros::datetime;

struct TestCa {
    ca_pem: String,
    ca_key: KeyPair,
    ca_cert: rcgen::Certificate,
}

fn mint_ca() -> TestCa {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-ca");
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let pem = cert.pem();
    TestCa {
        ca_pem: pem,
        ca_key: key,
        ca_cert: cert,
    }
}

fn mint_leaf(
    ca: &TestCa,
    cn: Option<&str>,
    san_dns: &[&str],
    san_uri: &[&str],
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
) -> Vec<u8> {
    let mut params =
        CertificateParams::new(san_dns.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    // rcgen seeds a default CN; clear it before optionally setting our own
    // so the no-CN test path actually has no CN.
    let mut dn = DistinguishedName::new();
    if let Some(name) = cn {
        dn.push(DnType::CommonName, name);
    }
    params.distinguished_name = dn;
    for u in san_uri {
        params
            .subject_alt_names
            .push(SanType::URI((*u).try_into().unwrap()));
    }
    if let Some(nb) = not_before {
        params.not_before = nb;
    }
    if let Some(na) = not_after {
        params.not_after = na;
    }
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.ca_cert, &ca.ca_key).unwrap();
    cert.der().to_vec()
}

#[test]
fn validate_extracts_cn_when_no_san_uri() {
    let ca = mint_ca();
    let leaf = mint_leaf(&ca, Some("agent-7"), &["agent-7.local"], &[], None, None);
    let v = MtlsValidator::new(&ca.ca_pem).expect("ca loads");
    let identity = v.validate(&leaf).expect("validate ok");
    // CN takes priority per SPEC §6.2 T6.2 ("CN / SAN_DNS / SAN_URI").
    assert_eq!(identity.value, "agent-7");
    assert_eq!(identity.kind, "cn");
}

#[test]
fn validate_falls_back_to_san_dns_when_no_cn() {
    let ca = mint_ca();
    let leaf = mint_leaf(&ca, None, &["agent-7.local"], &[], None, None);
    let v = MtlsValidator::new(&ca.ca_pem).unwrap();
    let identity = v.validate(&leaf).unwrap();
    assert_eq!(identity.value, "agent-7.local");
    assert_eq!(identity.kind, "san_dns");
}

#[test]
fn validate_falls_back_to_san_uri_when_no_cn_no_dns() {
    let ca = mint_ca();
    let leaf = mint_leaf(
        &ca,
        None,
        &[],
        &["spiffe://example.org/agent/7"],
        None,
        None,
    );
    let v = MtlsValidator::new(&ca.ca_pem).unwrap();
    let identity = v.validate(&leaf).unwrap();
    assert_eq!(identity.value, "spiffe://example.org/agent/7");
    assert_eq!(identity.kind, "san_uri");
}

#[test]
fn validate_rejects_expired_cert() {
    let ca = mint_ca();
    let leaf = mint_leaf(
        &ca,
        Some("agent-old"),
        &["agent-old.local"],
        &[],
        Some(datetime!(2020-01-01 0:00 UTC)),
        Some(datetime!(2020-01-02 0:00 UTC)),
    );
    let v = MtlsValidator::new(&ca.ca_pem).unwrap();
    let err = v.validate(&leaf).unwrap_err();
    assert!(matches!(err, MtlsError::Expired), "got: {err:?}");
}

#[test]
fn validate_rejects_chain_against_unrelated_ca() {
    let ca_a = mint_ca();
    let ca_b = mint_ca();
    let leaf = mint_leaf(&ca_a, Some("agent-7"), &["a.local"], &[], None, None);
    // Validator trusts ca_b; leaf was issued by ca_a.
    let v = MtlsValidator::new(&ca_b.ca_pem).unwrap();
    let err = v.validate(&leaf).unwrap_err();
    assert!(matches!(err, MtlsError::UntrustedChain), "got: {err:?}");
}

#[test]
fn validate_rejects_malformed_cert() {
    let ca = mint_ca();
    let v = MtlsValidator::new(&ca.ca_pem).unwrap();
    let err = v.validate(b"not a der cert").unwrap_err();
    assert!(matches!(err, MtlsError::MalformedCert(_)), "got: {err:?}");
}

#[test]
fn validate_rejects_when_no_identity_extractable() {
    let ca = mint_ca();
    // No CN, no SANs at all.
    let leaf = mint_leaf(&ca, None, &[], &[], None, None);
    let v = MtlsValidator::new(&ca.ca_pem).unwrap();
    let err = v.validate(&leaf).unwrap_err();
    assert!(matches!(err, MtlsError::NoIdentity), "got: {err:?}");
}

#[test]
fn validator_load_rejects_malformed_ca_pem() {
    let err = MtlsValidator::new("this is not a PEM").unwrap_err();
    assert!(matches!(err, MtlsError::MalformedCert(_)), "got: {err:?}");
}
