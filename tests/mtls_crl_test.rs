//! T6.3 — CRL store + apply_pem.
//!
//! Mints a CA, revokes one cert, builds a PEM CRL via rcgen, and
//! verifies the store applies it only when the trusted CA signed it, it
//! is not past `nextUpdate`, and its CRL number does not go backwards.
//! Refresh failure preservation is covered structurally: `apply_pem`
//! failure does not change the snapshot.

use agent_locksmith::mtls::CrlStore;
use agent_locksmith::mtls::crl::CrlParseError;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CrlIssuingDistributionPoint, CrlScope, DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use time::OffsetDateTime;
use time::macros::datetime;
use x509_parser::prelude::FromDer;

fn build_ca() -> (rcgen::Certificate, KeyPair) {
    ca_named("test-crl-ca", true)
}

fn ca_named(name: &str, crl_sign: bool) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    (ca_cert(name, crl_sign, &key), key)
}

fn ca_cert(name: &str, crl_sign: bool, key: &KeyPair) -> rcgen::Certificate {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    if crl_sign {
        params.key_usages.push(KeyUsagePurpose::CrlSign);
    }
    params.self_signed(key).unwrap()
}

fn build_pem_crl(ca: &rcgen::Certificate, ca_key: &KeyPair, revoked_serial: u64) -> String {
    crl_with(
        ca,
        ca_key,
        revoked_serial,
        1,
        datetime!(2036-04-30 0:00 UTC),
    )
}

fn crl_with(
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
    revoked_serial: u64,
    number: u64,
    next_update: OffsetDateTime,
) -> String {
    crl_scoped(ca, ca_key, revoked_serial, number, next_update, None)
}

fn crl_scoped(
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
    revoked_serial: u64,
    number: u64,
    next_update: OffsetDateTime,
    idp: Option<(Option<CrlScope>, &str)>,
) -> String {
    let revoked = RevokedCertParams {
        serial_number: SerialNumber::from(revoked_serial),
        revocation_time: datetime!(2026-04-30 0:00 UTC),
        reason_code: Some(RevocationReason::KeyCompromise),
        invalidity_date: None,
    };
    let crl_params = CertificateRevocationListParams {
        this_update: datetime!(2026-04-30 0:00 UTC),
        next_update,
        crl_number: SerialNumber::from(number),
        issuing_distribution_point: idp.map(|(scope, uri)| CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint {
                uris: vec![uri.into()],
            },
            scope,
        }),
        revoked_certs: vec![revoked],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = crl_params.signed_by(ca, ca_key).unwrap();
    crl.pem().unwrap()
}

fn trusting(ca: &rcgen::Certificate) -> CrlStore {
    CrlStore::trusting(&ca.pem()).expect("trusted bundle")
}

/// step-ca's default IDP: `https://<dnsName>/1.0/crl`, no port, and not
/// the URL locksmith is configured to fetch.
const STEP_IDP: &str = "https://ca.example.test/1.0/crl";

const NEXT: OffsetDateTime = datetime!(2036-04-30 0:00 UTC);

#[test]
fn apply_pem_populates_revoked_serials() {
    let (ca, key) = build_ca();
    // serial 0x42 = 66 decimal
    let pem = build_pem_crl(&ca, &key, 0x42);

    let store = trusting(&ca);
    assert!(!store.contains("42"));
    let n = store.apply_pem(pem.as_bytes()).expect("apply ok");
    assert_eq!(n, 1, "one revoked serial");
    assert!(store.contains("42"));
}

#[test]
fn apply_pem_with_garbage_returns_error_and_preserves_snapshot() {
    let (ca, key) = build_ca();
    let pem = build_pem_crl(&ca, &key, 0xab);
    let store = trusting(&ca);
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

#[test]
fn crl_signed_by_another_ca_is_refused() {
    let (trusted, _) = build_ca();
    let (other, other_key) = build_ca();
    let store = trusting(&trusted);
    let err = store.apply_pem(build_pem_crl(&other, &other_key, 0x42).as_bytes());
    assert!(
        matches!(err, Err(CrlParseError::Untrusted(_))),
        "foreign-signed CRL refused"
    );
    assert!(!store.contains("42"));
}

#[test]
fn store_without_trusted_issuers_refuses_every_crl() {
    let (ca, key) = build_ca();
    let store = CrlStore::new();
    assert!(
        store
            .apply_pem(build_pem_crl(&ca, &key, 0x42).as_bytes())
            .is_err()
    );
}

#[test]
fn crl_past_next_update_is_refused() {
    let (ca, key) = build_ca();
    let store = trusting(&ca);
    let stale = crl_with(&ca, &key, 0x42, 1, datetime!(2026-05-01 0:00 UTC));
    assert!(
        matches!(store.apply_pem(stale.as_bytes()), Err(CrlParseError::Stale)),
        "stale CRL refused"
    );
}

#[test]
fn lower_crl_number_is_refused_and_keeps_snapshot() {
    let (ca, key) = build_ca();
    let store = trusting(&ca);
    let next = datetime!(2036-04-30 0:00 UTC);
    store
        .apply_pem(crl_with(&ca, &key, 0x42, 5, next).as_bytes())
        .unwrap();
    let replay = crl_with(&ca, &key, 0x43, 4, next);
    assert!(
        matches!(
            store.apply_pem(replay.as_bytes()),
            Err(CrlParseError::Rollback)
        ),
        "rollback refused"
    );
    assert!(store.contains("42") && !store.contains("43"));
    store
        .apply_pem(crl_with(&ca, &key, 0x44, 5, next).as_bytes())
        .expect("same number reapplies");
}

#[test]
fn one_issuer_crl_never_removes_another_issuers_revocations() {
    let (a, a_key) = ca_named("issuer-a", true);
    let (b, b_key) = ca_named("issuer-b", true);
    let store = CrlStore::trusting(&format!("{}{}", a.pem(), b.pem())).unwrap();
    store
        .apply_pem(crl_with(&a, &a_key, 0x42, 1, NEXT).as_bytes())
        .unwrap();
    store
        .apply_pem(crl_with(&b, &b_key, 0x99, 7, NEXT).as_bytes())
        .unwrap();
    assert!(store.contains("42"), "issuer A revocation survives B's CRL");
    assert!(store.contains("99"));
    // Issuer B's lower number is a rollback even though A's is lower still.
    assert!(matches!(
        store.apply_pem(crl_with(&b, &b_key, 0x98, 6, NEXT).as_bytes()),
        Err(CrlParseError::Rollback)
    ));
}

#[test]
fn signer_without_crl_sign_is_refused() {
    // Same name and key; the trusted copy lacks cRLSign.
    let key = KeyPair::generate().unwrap();
    let signer = ca_cert("no-crl-sign", true, &key);
    let store = trusting(&ca_cert("no-crl-sign", false, &key));
    let err = store.apply_pem(build_pem_crl(&signer, &key, 0x42).as_bytes());
    assert!(matches!(err, Err(CrlParseError::Untrusted(_))), "{err:?}");
}

#[test]
fn der_body_applies_like_pem() {
    let (ca, key) = build_ca();
    let store = trusting(&ca);
    let pem = build_pem_crl(&ca, &key, 0x42);
    let der = pem::parse(pem.as_bytes()).unwrap().into_contents();
    store.apply(&der).expect("DER CRL applies");
    assert!(store.contains("42"));
}

#[test]
fn exported_pem_reapplies_to_a_fresh_store() {
    let (a, a_key) = ca_named("issuer-a", true);
    let (b, b_key) = ca_named("issuer-b", true);
    let bundle = format!("{}{}", a.pem(), b.pem());
    let store = CrlStore::trusting(&bundle).unwrap();
    store
        .apply_pem(crl_with(&a, &a_key, 0x42, 1, NEXT).as_bytes())
        .unwrap();
    store
        .apply_pem(crl_with(&b, &b_key, 0x99, 1, NEXT).as_bytes())
        .unwrap();
    let cached = store.to_pem().expect("state to cache");
    let restarted = CrlStore::trusting(&bundle).unwrap();
    assert_eq!(restarted.apply(cached.as_bytes()).unwrap(), 2);
    assert!(restarted.contains("42") && restarted.contains("99"));
}

#[test]
fn ca_only_crl_is_refused_but_user_only_crl_applies() {
    let (ca, key) = build_ca();
    let store = trusting(&ca);
    let scoped =
        |scope, number| crl_scoped(&ca, &key, 0x42, number, NEXT, Some((Some(scope), STEP_IDP)));
    assert!(
        matches!(
            store.apply_pem(scoped(CrlScope::CaCertsOnly, 1).as_bytes()),
            Err(CrlParseError::Untrusted(_))
        ),
        "partial CRL refused"
    );
    store
        .apply_pem(scoped(CrlScope::UserCertsOnly, 2).as_bytes())
        .expect("end-entity CRL covers agent certs");
    assert!(store.contains("42"));
}

#[test]
fn step_ca_shaped_crl_applies_and_its_distribution_point_is_pinned() {
    let (ca, key) = build_ca();
    let store = trusting(&ca);
    let step = |serial, number, uri| crl_scoped(&ca, &key, serial, number, NEXT, Some((None, uri)));
    store
        .apply_pem(step(0x42, 1, STEP_IDP).as_bytes())
        .expect("IDP with only a distribution point applies");
    assert!(store.contains("42"));
    // Validly signed and newer, but for another partition of the CA.
    let other = step(0x43, 9, "https://ca.example.test/partition-2.crl");
    assert!(matches!(
        store.apply_pem(other.as_bytes()),
        Err(CrlParseError::ScopeChanged)
    ));
    let unscoped = crl_with(&ca, &key, 0x43, 9, NEXT);
    assert!(matches!(
        store.apply_pem(unscoped.as_bytes()),
        Err(CrlParseError::ScopeChanged)
    ));
    assert!(store.contains("42") && !store.contains("43"));
    store
        .apply_pem(step(0x44, 2, STEP_IDP).as_bytes())
        .expect("same distribution point refreshes");
    assert!(store.contains("44"));
}

#[test]
fn ca_sharing_a_name_cannot_mask_another_cas_revocation() {
    // Rotation overlap: two trusted CAs, one name, different keys.
    let old_key = KeyPair::generate().unwrap();
    let new_key = KeyPair::generate().unwrap();
    let old = ca_cert("rotating-ca", true, &old_key);
    let new = ca_cert("rotating-ca", true, &new_key);
    let store = CrlStore::trusting(&format!("{}{}", old.pem(), new.pem())).unwrap();
    store
        .apply_pem(crl_with(&old, &old_key, 0x42, 1, NEXT).as_bytes())
        .unwrap();
    // The new CA's CRL numbers from 1 again; it must be neither a
    // rollback nor a replacement of the old CA's list.
    store
        .apply_pem(crl_with(&new, &new_key, 0x99, 1, NEXT).as_bytes())
        .expect("separate state per key");
    let leaf = |ca: &rcgen::Certificate, ca_key: &KeyPair| {
        let mut params = CertificateParams::new(vec!["agent.local".to_string()]).unwrap();
        params.serial_number = Some(SerialNumber::from(0x42u64));
        params
            .signed_by(&KeyPair::generate().unwrap(), ca, ca_key)
            .unwrap()
            .der()
            .to_vec()
    };
    let from_old = leaf(&old, &old_key);
    let from_new = leaf(&new, &new_key);
    let revoked = |der: &[u8]| {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).unwrap();
        store.revokes(&cert)
    };
    assert!(revoked(&from_old), "old CA revoked 42");
    assert!(
        !revoked(&from_new),
        "new CA's serial 42 is a different cert"
    );
}

#[test]
fn cached_crl_past_next_update_still_denies_but_fetched_one_is_refused() {
    let (ca, key) = build_ca();
    let expired = crl_with(&ca, &key, 0x42, 1, datetime!(2026-05-01 0:00 UTC));
    let fetched = trusting(&ca);
    assert!(matches!(
        fetched.apply(expired.as_bytes()),
        Err(CrlParseError::Stale)
    ));
    let restarted = trusting(&ca);
    assert_eq!(restarted.apply_cached(expired.as_bytes()), 1);
    assert!(restarted.contains("42"));
    assert_eq!(
        restarted.age_secs(),
        i64::MAX,
        "a cache load is not a fetch"
    );
}

#[test]
fn cached_blocks_apply_independently() {
    let (a, a_key) = ca_named("issuer-a", true);
    let (b, b_key) = ca_named("issuer-b", true);
    let cache = format!(
        "{}{}",
        crl_with(&b, &b_key, 0x99, 1, NEXT),
        crl_with(&a, &a_key, 0x42, 1, NEXT)
    );
    // Issuer B's CA was removed from the bundle since the cache was written.
    let store = trusting(&a);
    assert_eq!(store.apply_cached(cache.as_bytes()), 1);
    assert!(store.contains("42") && !store.contains("99"));
}

#[test]
fn listed_serial_whose_issuer_cannot_be_told_apart_fails_closed() {
    // The leaf's signature verifies under no trusted key (as with a leaf
    // algorithm x509-parser cannot check); the CA's CRL lists its serial.
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_cert("only-ca", true, &ca_key);
    let store = trusting(&ca);
    store
        .apply_pem(crl_with(&ca, &ca_key, 0x42, 1, NEXT).as_bytes())
        .unwrap();
    let unverifiable_key = KeyPair::generate().unwrap();
    let lookalike = ca_cert("only-ca", true, &unverifiable_key);
    let mut params = CertificateParams::new(vec!["agent.local".to_string()]).unwrap();
    params.serial_number = Some(SerialNumber::from(0x42u64));
    let der = params
        .signed_by(&KeyPair::generate().unwrap(), &lookalike, &unverifiable_key)
        .unwrap()
        .der()
        .to_vec();
    let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
    assert!(store.revokes(&leaf));
}
