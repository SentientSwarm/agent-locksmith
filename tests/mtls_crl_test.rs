//! T6.3 — CRL store + apply_pem.
//!
//! Mints a CA, revokes one cert, builds a PEM CRL via rcgen, and
//! verifies the store applies it. Refresh failure preservation is
//! covered structurally: `apply_pem` failure does not change the
//! snapshot.

use agent_locksmith::mtls::CrlStore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams,
    SerialNumber,
};
use time::macros::datetime;

fn build_ca() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-crl-ca");
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

fn build_pem_crl(ca: &rcgen::Certificate, ca_key: &KeyPair, revoked_serial: u64) -> String {
    let revoked = RevokedCertParams {
        serial_number: SerialNumber::from(revoked_serial),
        revocation_time: datetime!(2026-04-30 0:00 UTC),
        reason_code: Some(RevocationReason::KeyCompromise),
        invalidity_date: None,
    };
    let crl_params = CertificateRevocationListParams {
        this_update: datetime!(2026-04-30 0:00 UTC),
        next_update: datetime!(2027-04-30 0:00 UTC),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![revoked],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = crl_params.signed_by(ca, ca_key).unwrap();
    crl.pem().unwrap()
}

#[test]
fn apply_pem_populates_revoked_serials() {
    let (ca, key) = build_ca();
    // serial 0x42 = 66 decimal
    let pem = build_pem_crl(&ca, &key, 0x42);

    let store = CrlStore::new();
    assert!(!store.contains("42"));
    let n = store.apply_pem(pem.as_bytes()).expect("apply ok");
    assert_eq!(n, 1, "one revoked serial");
    assert!(store.contains("42"));
}

#[test]
fn apply_pem_with_garbage_returns_error_and_preserves_snapshot() {
    let (ca, key) = build_ca();
    let pem = build_pem_crl(&ca, &key, 0xab);
    let store = CrlStore::new();
    store.apply_pem(pem.as_bytes()).unwrap();
    assert!(store.contains("ab"));

    let err = store.apply_pem(b"not a PEM CRL");
    assert!(err.is_err(), "garbage rejected");

    // Prior snapshot is intact.
    assert!(store.contains("ab"));
}

#[test]
fn age_is_max_until_first_apply() {
    let store = CrlStore::new();
    assert_eq!(store.age_secs(), i64::MAX);
}

#[test]
fn note_failure_increments_counter() {
    let store = CrlStore::new();
    assert_eq!(store.refresh_failures_total(), 0);
    store.note_failure();
    store.note_failure();
    assert_eq!(store.refresh_failures_total(), 2);
}
