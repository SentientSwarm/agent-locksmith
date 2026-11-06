use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use std::{os::unix::fs::PermissionsExt, path::Path};

pub struct Pki {
    pub ca: String,
    pub identity: String,
}
impl Pki {
    pub fn write(dir: &Path) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap();
        let (cert, server_key) = issue("localhost", &ca, &key);
        private(dir, "server.pem", &cert);
        private(dir, "server.key", &server_key);
        private(dir, "ca.pem", &ca.pem());
        let (cert, client_key) = issue("native-client", &ca, &key);
        Self {
            ca: ca.pem(),
            identity: format!("{cert}{client_key}"),
        }
    }
}
fn issue(name: &str, ca: &rcgen::Certificate, key: &KeyPair) -> (String, String) {
    let mut params = CertificateParams::new(vec![name.into(), "127.0.0.1".into()]).unwrap();
    params.use_authority_key_identifier_extension = true;
    params.distinguished_name.push(DnType::CommonName, name);
    let pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&pair, ca, key).unwrap();
    (cert.pem(), pair.serialize_pem())
}
fn private(dir: &Path, name: &str, value: &str) {
    let path = dir.join(name);
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
