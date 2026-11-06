//! Real CLI/daemon recovery, using the public SQLite snapshot recipe.
use super::{docs, fixture::Fixture, migration, oauth_setup, process, safety, setup, upstream};
use base64::Engine;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, process::Stdio};

pub struct Keys {
    dir: tempfile::TempDir,
}
impl Keys {
    pub fn new() -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        for (name, byte) in [("stored", 17), ("oauth", 29), ("wrong", 41)] {
            std::fs::write(
                dir.path().join(name),
                base64::engine::general_purpose::STANDARD.encode([byte; 32]),
            )
            .unwrap();
            std::fs::set_permissions(
                dir.path().join(name),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        Self { dir }
    }
    pub fn read(&self, name: &str) -> String {
        let p = self.dir.path().join(name);
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::read_to_string(p).unwrap()
    }
    pub async fn start(&self, f: &mut Fixture, stored: Option<&str>, oauth: Option<&str>) {
        let mut values = Vec::new();
        if let Some(name) = stored {
            values.push(("LOCKSMITH_CREDENTIAL_SEALING_KEY", self.read(name)));
        }
        if let Some(name) = oauth {
            values.push(("LOCKSMITH_OAUTH_SEALING_KEY", self.read(name)));
        }
        f.start_with_env(
            &values
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        )
        .await;
    }
    pub fn safe(&self, f: &Fixture, extra: &[&str]) {
        let mut values = vec![
            self.read("stored"),
            self.read("oauth"),
            self.read("wrong"),
            f.operator.clone(),
        ];
        values.extend(f.tokens.borrow().iter().cloned());
        values.extend(extra.iter().map(|s| s.to_string()));
        let refs: Vec<_> = values.iter().map(String::as_str).collect();
        for n in 0..f.starts {
            safety::no_values(
                &std::fs::read_to_string(f.path().join(format!("daemon-{n}.log"))).unwrap(),
                &refs,
            );
        }
        for args in [
            vec!["audit", "query", "--limit", "1000"],
            vec!["agent", "list", "--include-revoked"],
        ] {
            safety::no_values(&f.op(&args).to_string(), &refs);
        }
    }
}

pub struct Snapshot {
    dir: tempfile::TempDir,
    bytes: Vec<u8>,
    config: serde_json::Value,
    operators: Vec<u8>,
    operator: String,
}
impl Snapshot {
    pub fn take(f: &Fixture) -> Self {
        assert!(f.daemon.is_none(), "snapshot only after source stop/join");
        let dir = tempfile::TempDir::new().unwrap();
        let recipe = include_str!("../../docs/user/operator/sealed-state-recovery.md");
        let command = |database: &std::path::Path| {
            // Execute exactly the public block: no hidden shell error flags.
            let mut c = process::command("sh");
            c.args(["-c", docs::block(recipe, "sealed-backup")]);
            c.current_dir(dir.path()).env("DATABASE", database);
            c
        };
        assert!(
            !process::run(command(&dir.path().join("absent.db")))
                .status
                .success()
        );
        assert!(!dir.path().join("absent.db").exists());
        assert!(!dir.path().join("sealed-state.db").exists());
        assert!(process::run(command(&f.db)).status.success());
        let bytes = std::fs::read(dir.path().join("sealed-state.db")).unwrap();
        assert!(
            !process::run(command(&f.db)).status.success(),
            "snapshot overwrite refused"
        );
        assert!(bytes == std::fs::read(dir.path().join("sealed-state.db")).unwrap());
        for secret in [
            upstream::X,
            upstream::Y,
            "synthetic-first-refresh",
            "synthetic-rotation-1",
        ] {
            assert!(
                !bytes.windows(secret.len()).any(|s| s == secret.as_bytes()),
                "snapshot exposes synthetic token"
            );
        }
        assert_eq!(
            std::fs::metadata(dir.path().join("sealed-state.db"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        Self {
            dir,
            bytes,
            config: serde_yaml::from_str(&std::fs::read_to_string(&f.config).unwrap()).unwrap(),
            operators: std::fs::read(f.path().join("operators.yaml")).unwrap(),
            operator: f.operator.clone(),
        }
    }
    pub fn restore(&self, upstream: &str) -> Fixture {
        let mut f = Fixture::new(upstream);
        std::fs::write(&f.db, &self.bytes).unwrap();
        std::fs::write(f.path().join("operators.yaml"), &self.operators).unwrap();
        f.operator.clone_from(&self.operator);
        let mut config = self.config.clone();
        config["listen"]["port"] = f.port.into();
        config["listen"]["admin_socket"]["path"] = f.socket.to_str().unwrap().into();
        config["database"]["path"] = f.db.to_str().unwrap().into();
        config["operator_credentials_path"] =
            f.path().join("operators.yaml").to_str().unwrap().into();
        std::fs::write(&f.config, serde_yaml::to_string(&config).unwrap()).unwrap();
        assert_eq!(
            migration::sqlite(&f, &f.db, "PRAGMA integrity_check;").trim(),
            "ok"
        );
        assert!(
            self.bytes == std::fs::read(&f.db).unwrap(),
            "entire restored image unchanged before launch"
        );
        f
    }
    pub fn unchanged(&self) {
        assert!(self.bytes == std::fs::read(self.dir.path().join("sealed-state.db")).unwrap());
    }
}

pub fn stored(f: &Fixture) -> setup::Agent {
    setup::put(f, "stored", "bearer=SMOKE_Y"); // Deliberately different template: never fallback.
    let a = f.op(&[
        "agent",
        "register",
        "--name",
        "stored-reader",
        "--allowlist",
        "stored",
    ]);
    let agent = setup::Agent {
        id: a["public_id"].as_str().unwrap().into(),
        token: a["token"].as_str().unwrap().into(),
    };
    let value = f.path().join("private-value");
    std::fs::write(&value, upstream::X).unwrap();
    std::fs::set_permissions(&value, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut c = f.cli(&[
        "agent",
        "set-credential",
        &agent.id,
        "stored",
        "--stored-bearer-stdin",
    ]);
    c.stdin(Stdio::from(std::fs::File::open(&value).unwrap()));
    let out = process::run(c);
    assert!(out.status.success(), "stored ingest");
    safety::no_values(&String::from_utf8_lossy(&out.stdout), &[&agent.token]);
    std::fs::remove_file(value).unwrap();
    f.tokens.borrow_mut().push(agent.token.clone());
    agent
}
pub fn authority(f: &Fixture, agents: &[&setup::Agent]) -> Vec<serde_json::Value> {
    agents
        .iter()
        .flat_map(|a| oauth_setup::authority(f, a))
        .collect()
}
pub fn ciphertext(f: &Fixture) -> String {
    migration::sqlite(
        f,
        &f.db,
        "SELECT hex(sealed_value),hex(nonce) FROM credential_secrets ORDER BY secret_ref;",
    ) + &super::recovery_common::state(f)
}
pub fn kill(f: &mut Fixture) {
    let mut child = f.daemon.take().unwrap();
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
}
pub fn wal(f: &Fixture) -> PathBuf {
    PathBuf::from(format!("{}-wal", f.db.display()))
}
