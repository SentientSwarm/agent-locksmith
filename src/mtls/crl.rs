//! T6.3 — CRL fetcher and serial-set store.
//!
//! `CrlStore` is the in-memory snapshot the validator consults. It
//! holds:
//!  - The current set of revoked serials (lowercase hex).
//!  - The unix timestamp at which we last successfully refreshed.
//!  - A "fetch failures since last success" counter for metrics.
//!
//! A CRL is applied only when every block is signed by a CA certificate
//! in the trusted bundle whose subject matches the CRL issuer and that may
//! sign CRLs; it is complete (not delta or scope-limited); it carries a CRL
//! number and an unexpired `nextUpdate`; and neither its number nor its
//! `thisUpdate` goes backwards for that issuer. State is kept per issuer,
//! so an unauthenticated, replayed or foreign-issuer CRL cannot strip
//! revocations.
//!
//! The refresher (`mtls::Revocation`) runs as a background tokio task.
//! On refresh failure the prior snapshot stands (SPEC "CRL refresh
//! failure handling"): stale-but-up beats fresh-and-down. Callers observe
//! staleness via
//! `age_secs()`; production deployments typically alert on
//! `age_secs() > 24 * crl_refresh_interval_seconds` or similar.

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};
use x509_parser::extensions::ParsedExtension;
use x509_parser::num_bigint::BigUint;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

/// One issuer's current complete CRL.
#[derive(Debug, Clone)]
pub struct IssuerCrl {
    /// Lowercase hex serials.
    pub revoked_serials: HashSet<String>,
    pub crl_number: BigUint,
    pub this_update_unix_secs: i64,
    /// Raw issuing-distribution-point extension value, if any. Pinned per
    /// issuer: a CRL for another scope of the same CA cannot replace it.
    pub idp: Option<Vec<u8>>,
    /// The signed CRL as fetched, kept so the last good state can be
    /// persisted and re-verified after a restart.
    pub der: Vec<u8>,
}

/// (raw issuer DN, raw SubjectPublicKeyInfo of the signing CA).
pub type IssuerKey = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, Default)]
pub struct CrlState {
    /// Complete CRLs keyed by the issuer's raw distinguished name and the
    /// signing CA's raw SubjectPublicKeyInfo. A
    /// response replaces only the issuers it carries, so one issuer's
    /// CRL can never remove another issuer's revocations.
    pub issuers: HashMap<IssuerKey, IssuerCrl>,
    pub last_success_unix_secs: i64,
}

#[derive(Debug)]
struct TrustedCa {
    der: Vec<u8>,
    subject: Vec<u8>,
    spki: Vec<u8>,
}

#[derive(Debug)]
pub struct CrlStore {
    state: ArcSwap<CrlState>,
    failures: AtomicU64,
    /// The CA certificates trusted to sign CRLs, parsed once.
    issuers: Vec<TrustedCa>,
}

impl Default for CrlStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CrlStore {
    /// A store that trusts no issuer: every CRL is refused.
    pub fn new() -> Self {
        Self {
            state: ArcSwap::from_pointee(CrlState::default()),
            failures: AtomicU64::new(0),
            issuers: Vec::new(),
        }
    }

    /// A store that accepts CRLs signed by a certificate in `ca_bundle_pem`.
    pub fn trusting(ca_bundle_pem: &str) -> Result<Self, CrlParseError> {
        let mut store = Self::new();
        for block in
            pem::parse_many(ca_bundle_pem).map_err(|e| CrlParseError::Pem(e.to_string()))?
        {
            if block.tag() == "CERTIFICATE" {
                let der = block.contents().to_vec();
                let Ok((_, ca)) = x509_parser::certificate::X509Certificate::from_der(&der) else {
                    continue;
                };
                let (subject, spki) =
                    (ca.subject().as_raw().to_vec(), ca.public_key().raw.to_vec());
                store.issuers.push(TrustedCa { der, subject, spki });
            }
        }
        if store.issuers.is_empty() {
            return Err(CrlParseError::Untrusted(
                "no CA certificates in the trusted bundle".into(),
            ));
        }
        Ok(store)
    }

    /// Returns the raw SubjectPublicKeyInfo of the trusted CA that signed
    /// `crl`.
    fn verify(&self, crl: &CertificateRevocationList<'_>) -> Result<Vec<u8>, CrlParseError> {
        let mut cause = "no trusted CA matches the CRL issuer".to_string();
        for trusted in &self.issuers {
            let Ok((_, ca)) = x509_parser::certificate::X509Certificate::from_der(&trusted.der)
            else {
                continue;
            };
            if ca.subject().as_raw() != crl.issuer().as_raw() {
                continue;
            }
            if !may_sign_crls(&ca) {
                cause = "the matching CA may not sign CRLs".into();
                continue;
            }
            // x509-parser cannot verify RSASSA-PSS or P-521 signatures;
            // those CRLs are refused with the error named here.
            match crl.verify_signature(ca.public_key()) {
                Ok(()) => return Ok(ca.public_key().raw.to_vec()),
                Err(e) => cause = format!("signature does not verify: {e}"),
            }
        }
        Err(CrlParseError::Untrusted(cause))
    }

    /// Whether any issuer's CRL revokes `serial_hex`.
    pub fn contains(&self, serial_hex: &str) -> bool {
        let serial = serial_hex.to_ascii_lowercase();
        self.state
            .load()
            .issuers
            .values()
            .any(|c| c.revoked_serials.contains(&serial))
    }

    /// Whether `leaf` is revoked. Serials are unique only within one CA,
    /// and two trusted CAs may share a name (during a key rotation), so
    /// state is per name and key. When a same-name CA's CRL lists the
    /// serial, the cert is refused unless its signature verifies under a
    /// same-name CA whose CRL does not: an issuer that cannot be told
    /// apart (say, a leaf signature algorithm x509-parser cannot check)
    /// fails closed.
    pub fn revokes(&self, leaf: &x509_parser::certificate::X509Certificate<'_>) -> bool {
        let state = self.state.load();
        if state.issuers.is_empty() {
            return false;
        }
        let serial = serial_hex(&leaf.serial);
        let issuer = leaf.issuer().as_raw();
        let listed = |ca: &TrustedCa| {
            state
                .issuers
                .get(&(ca.subject.clone(), ca.spki.clone()))
                .is_some_and(|c| c.revoked_serials.contains(&serial))
        };
        let candidates: Vec<&TrustedCa> = self
            .issuers
            .iter()
            .filter(|ca| ca.subject == issuer)
            .collect();
        if !candidates.iter().any(|ca| listed(ca)) {
            return false;
        }
        !candidates
            .iter()
            .any(|ca| !listed(ca) && signed_by(leaf, ca))
    }

    pub fn snapshot(&self) -> Arc<CrlState> {
        self.state.load_full()
    }

    /// Seconds since the last successful refresh. `i64::MAX` if we
    /// have never succeeded. Drives the `mtls_crl_age_seconds` metric.
    pub fn age_secs(&self) -> i64 {
        let last = self.state.load().last_success_unix_secs;
        if last == 0 {
            return i64::MAX;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now - last
    }

    /// Cumulative fetch failures since process start. Drives the
    /// `mtls_crl_refresh_failures_total` counter.
    pub fn refresh_failures_total(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Apply a freshly-fetched PEM CRL. Replaces the snapshot
    /// atomically. Any parse error increments the failure counter and
    /// preserves the prior snapshot.
    pub fn apply_pem(&self, pem_bytes: &[u8]) -> Result<usize, CrlParseError> {
        self.apply(pem_bytes)
    }

    /// Apply a fetched CRL body: PEM (one or more `X509 CRL` blocks) or
    /// a single DER CRL, as CAs such as step-ca serve by default. All
    /// blocks must pass or nothing changes.
    pub fn apply(&self, body: &[u8]) -> Result<usize, CrlParseError> {
        let len = self.apply_ders(split_body(body)?, Source::Fetched)?;
        info!(revoked_count = len, "CRL applied");
        Ok(len)
    }

    /// Reload the last-good cache written by `to_pem`. Each issuer's
    /// block is applied on its own, so one unusable block does not
    /// discard the others. An expired CRL is still applied (with a
    /// warning): it only adds denials, and a running daemon keeps an
    /// expired CRL in force too. Does not count as a successful fetch.
    pub fn apply_cached(&self, body: &[u8]) -> usize {
        let ders = match split_body(body) {
            Ok(ders) => ders,
            Err(e) => {
                warn!(error = %e, "cached CRL unreadable");
                return 0;
            }
        };
        let mut total = 0;
        for der in ders {
            match self.apply_ders(vec![der], Source::Cached) {
                Ok(n) => total += n,
                Err(e) => warn!(error = %e, "cached CRL block refused"),
            }
        }
        total
    }

    fn apply_ders(&self, ders: Vec<Vec<u8>>, source: Source) -> Result<usize, CrlParseError> {
        let mut fetched: HashMap<IssuerKey, IssuerCrl> = HashMap::new();
        for der in ders {
            let (_, crl) = CertificateRevocationList::from_der(&der)
                .map_err(|e| CrlParseError::Der(e.to_string()))?;
            let signer = self.verify(&crl)?;
            let issuer = (crl.issuer().as_raw().to_vec(), signer);
            let entry = complete_crl(&crl, der.clone(), source)?;
            if fetched.insert(issuer, entry).is_some() {
                return Err(CrlParseError::Untrusted(
                    "more than one CRL for the same issuer".into(),
                ));
            }
        }
        if fetched.is_empty() {
            // No CRL blocks at all → treat as parse error so callers
            // know the snapshot was NOT replaced. Otherwise a garbage
            // PEM (or HTML error page from a misconfigured URL) would
            // silently empty out our revocation set.
            return Err(CrlParseError::Pem(
                "no `X509 CRL` PEM blocks in input".to_string(),
            ));
        }
        let current = self.state.load();
        for (issuer, new) in &fetched {
            let Some(old) = current.issuers.get(issuer) else {
                continue;
            };
            if new.idp != old.idp {
                return Err(CrlParseError::ScopeChanged);
            }
            if new.crl_number < old.crl_number
                || new.this_update_unix_secs < old.this_update_unix_secs
            {
                return Err(CrlParseError::Rollback);
            }
        }
        let mut issuers = current.issuers.clone();
        let len: usize = fetched.values().map(|c| c.revoked_serials.len()).sum();
        issuers.extend(fetched);
        let last_success_unix_secs = match source {
            Source::Fetched => unix_now(),
            Source::Cached => current.last_success_unix_secs,
        };
        self.state.store(Arc::new(CrlState {
            issuers,
            last_success_unix_secs,
        }));
        Ok(len)
    }

    /// Every applied issuer CRL as PEM, for the last-good cache.
    /// Whether any CRL has been applied (fetched or reloaded from cache).
    pub fn in_force(&self) -> bool {
        !self.state.load().issuers.is_empty()
    }

    pub fn to_pem(&self) -> Option<String> {
        let state = self.state.load();
        if state.issuers.is_empty() {
            return None;
        }
        Some(
            state
                .issuers
                .values()
                .map(|c| pem::encode(&pem::Pem::new("X509 CRL", c.der.clone())))
                .collect(),
        )
    }

    pub fn note_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Source {
    Fetched,
    Cached,
}

fn split_body(body: &[u8]) -> Result<Vec<Vec<u8>>, CrlParseError> {
    if body.trim_ascii_start().starts_with(b"-----BEGIN") {
        Ok(pem::parse_many(body)
            .map_err(|e| CrlParseError::Pem(e.to_string()))?
            .into_iter()
            .filter(|b| b.tag() == "X509 CRL")
            .map(|b| b.contents().to_vec())
            .collect())
    } else {
        Ok(vec![body.to_vec()])
    }
}

/// The signer must be a CA allowed to sign CRLs when it says so.
fn may_sign_crls(ca: &x509_parser::certificate::X509Certificate<'_>) -> bool {
    let is_ca = matches!(ca.basic_constraints(), Ok(Some(bc)) if bc.value.ca);
    let crl_sign = match ca.key_usage() {
        Ok(Some(ku)) => ku.value.crl_sign(),
        Ok(None) => true,
        Err(_) => false,
    };
    is_ca && crl_sign
}

const OID_CRL_NUMBER: &str = "2.5.29.20";
const OID_DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const OID_ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
const OID_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const OID_FRESHEST_CRL: &str = "2.5.29.46";

/// The issuing distribution point (step-ca always includes one) is pinned
/// per issuer by the caller: a later CRL naming another scope of the same
/// CA is refused, so a CA that partitions its CRL cannot have one
/// partition replace another. Partitioned CRLs are unsupported; configure
/// the single full CRL. `freshestCRL` is tolerated but delta CRLs are
/// never fetched.
///
/// Accept only a complete, current CRL covering end-entity certs: it must
/// carry a CRL number and an unexpired `nextUpdate`, must not be a delta
/// CRL, must not be limited to CA or attribute certs, some reasons, or
/// another issuer's certs, and may carry no unknown critical extension.
fn complete_crl(
    crl: &CertificateRevocationList<'_>,
    der: Vec<u8>,
    source: Source,
) -> Result<IssuerCrl, CrlParseError> {
    let mut idp_raw = None;
    let scoped = || CrlParseError::Untrusted("CRL is not a complete CRL".into());
    for ext in crl.extensions() {
        let oid = ext.oid.to_id_string();
        match oid.as_str() {
            OID_DELTA_CRL_INDICATOR => return Err(scoped()),
            OID_ISSUING_DISTRIBUTION_POINT => match ext.parsed_extension() {
                ParsedExtension::IssuingDistributionPoint(idp)
                    if !idp.only_contains_ca_certs
                        && !idp.only_contains_attribute_certs
                        && idp.only_some_reasons.is_none()
                        && !idp.indirect_crl =>
                {
                    idp_raw = Some(ext.value.to_vec());
                }
                _ => return Err(scoped()),
            },
            OID_CRL_NUMBER | OID_AUTHORITY_KEY_IDENTIFIER | OID_FRESHEST_CRL => {}
            _ if ext.critical => return Err(scoped()),
            _ => {}
        }
    }
    let crl_number = crl
        .crl_number()
        .cloned()
        .ok_or_else(|| CrlParseError::Untrusted("CRL has no CRL number".into()))?;
    match crl.next_update() {
        Some(next) if next.timestamp() >= unix_now() => {}
        Some(_) if source == Source::Cached => {
            warn!("cached CRL is past nextUpdate; keeping its revocations until a fetch succeeds");
        }
        _ => return Err(CrlParseError::Stale),
    }
    let revoked_serials = crl
        .iter_revoked_certificates()
        .map(|entry| serial_hex(&entry.user_certificate))
        .collect();
    Ok(IssuerCrl {
        revoked_serials,
        crl_number,
        this_update_unix_secs: crl.last_update().timestamp(),
        idp: idp_raw,
        der,
    })
}

fn signed_by(leaf: &x509_parser::certificate::X509Certificate<'_>, ca: &TrustedCa) -> bool {
    x509_parser::x509::SubjectPublicKeyInfo::from_der(&ca.spki)
        .is_ok_and(|(_, key)| leaf.verify_signature(Some(&key)).is_ok())
}

fn serial_hex(serial: &BigUint) -> String {
    serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum CrlParseError {
    #[error("PEM parse: {0}")]
    Pem(String),
    #[error("DER parse: {0}")]
    Der(String),
    #[error("untrusted CRL: {0}")]
    Untrusted(String),
    #[error("CRL has no nextUpdate or it has passed")]
    Stale,
    #[error("CRL is older than the one already applied for its issuer")]
    Rollback,
    #[error("CRL distribution point differs from the one pinned for its issuer")]
    ScopeChanged,
    #[error("fetch: {0}")]
    Fetch(String),
}

/// Largest CRL body accepted; the body is read before its signature can
/// be checked, so it is capped.
pub const MAX_CRL_BYTES: usize = 8 * 1024 * 1024;

/// Fetch and apply the CRL at `url` once with `client`. Returns whether a
/// new snapshot was applied. On any failure the prior snapshot stands and
/// the failure counter is bumped.
pub async fn refresh_once(store: &CrlStore, client: &reqwest::Client, url: &str) -> bool {
    let outcome = match fetch(client, url).await {
        Ok(body) => store.apply(&body),
        Err(e) => Err(CrlParseError::Fetch(e)),
    };
    match outcome {
        Ok(_) => true,
        Err(e @ (CrlParseError::Rollback | CrlParseError::ScopeChanged)) => {
            // Persistent until fixed: a CA that restarts numbering or moves
            // its distribution point under the same name and key needs the
            // CRL cache removed (see the revocation runbook).
            error!(reason = %e, "CRL refused; new revocations are not applied");
            store.note_failure();
            false
        }
        Err(reason) => {
            warn!(%reason, "CRL refresh failed; prior snapshot retained");
            store.note_failure();
            false
        }
    }
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("send failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("non-success status {}", resp.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("read body failed: {e}"))?
    {
        if body.len() + chunk.len() > MAX_CRL_BYTES {
            return Err(format!("CRL body exceeds {MAX_CRL_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A client for CRL fetches: 10s timeout, trusting the built-in roots plus
/// each PEM bundle in `extra_roots` (a private step-ca root, say).
pub fn fetch_client(extra_roots: &[std::path::PathBuf]) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
    for path in extra_roots {
        builder = crate::client_pool::add_ca_bundle(builder, path);
    }
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}
