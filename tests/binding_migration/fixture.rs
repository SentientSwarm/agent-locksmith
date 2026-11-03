use agent_locksmith::{
    migrations::open_and_migrate,
    registrations::{AuthSpec, Kind, Registration, RegistrationRepository},
    repo::{AgentCredentialRepository, AgentRepository},
};
use secrecy::ExposeSecret;
use serde_json::Value;
use sqlx::SqlitePool;
use std::{
    path::PathBuf,
    process::{Command, Output},
};
use tempfile::TempDir;

pub struct Fixture {
    pub dir: TempDir,
    pub db: PathBuf,
    pub pool: SqlitePool,
    pub bearers: Vec<String>,
    pub bindings: AgentCredentialRepository,
    pub registrations: RegistrationRepository,
    pub ids: Vec<i64>,
}
impl Fixture {
    pub async fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("fixture.db");
        let pool = open_and_migrate(&db).await.unwrap();
        let agents = AgentRepository::new(pool.clone());
        let (ids, bearers) = create_agents(&agents).await;
        let registrations = RegistrationRepository::new(pool.clone());
        let bindings = AgentCredentialRepository::new(pool.clone());
        initial_routes(&registrations, &bindings, ids[2]).await;
        // Historical unrestricted policy is inventory input, never live authority.
        sqlx::query("UPDATE agents SET grants_reviewed=0, tool_allowlist=NULL")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO registrations_meta VALUES ('seed_version','keep'), ('unrelated','keep-too')").execute(&pool).await.unwrap();
        Self {
            dir,
            db,
            pool,
            bearers,
            bindings,
            registrations,
            ids,
        }
    }
    pub fn command(&self, mode: &str) -> Command {
        let mut command = offline(mode, &self.db);
        command
            .env("PATH", self.dir.path())
            .env("OP_MARKER", self.dir.path().join("called"));
        command
    }

    pub fn preview(&self) -> Value {
        let output = self.command("preview").output().unwrap();
        success(&output);
        serde_json::from_slice(&output.stdout).unwrap()
    }
    pub fn apply(&self, plan: &Value) -> Output {
        let p = self.dir.path().join("reviewed.json");
        std::fs::write(&p, serde_json::to_vec_pretty(plan).unwrap()).unwrap();
        self.command("apply").arg("--plan").arg(p).output().unwrap()
    }
    pub async fn exec(&self, sql: &str) {
        sqlx::query(sql).execute(&self.pool).await.unwrap();
    }
    pub async fn count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_credential_overrides")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}
pub fn env_spec() -> AuthSpec {
    AuthSpec::Bearer {
        env_var: "MIGRATION_X".into(),
    }
}
pub fn select(plan: &mut Value, id: i64) {
    let row = plan["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["agent_id"] == id && r["registration"] == "api")
        .unwrap();
    assert_eq!(row["action"], "propose");
    row["selected"] = true.into();
}
pub fn success(o: &Output) {
    assert!(
        o.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}
pub fn conflict(o: &Output) {
    assert_eq!(
        o.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("migration_conflict"));
}

async fn create_agents(agents: &AgentRepository) -> (Vec<i64>, Vec<String>) {
    let mut ids = Vec::new();
    let mut bearers = Vec::new();
    for name in ["shared-a", "shared-b", "distinct", "unmapped"] {
        let (pid, secret) = agents
            .create(name, None, None, None, None, None)
            .await
            .unwrap();
        ids.push(agents.get_by_name(name).await.unwrap().unwrap().id);
        bearers.push(format!("Bearer lk_{pid}.{}", secret.expose_secret()));
    }
    (ids, bearers)
}
pub fn offline(mode: &str, db: &std::path::Path) -> Command {
    let bin = std::env::var_os("MIGRATION_TEST_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_locksmith").into());
    let mut c = Command::new(bin);
    c.args(["migrate-bindings", mode, "--database"])
        .arg(db)
        .env("LOCKSMITH_ADMIN_URL", "invalid-offline-must-ignore")
        .env("LOCKSMITH_OP_TOKEN", "PRIVATE_OPERATOR_SENTINEL")
        .env("MIGRATION_X", "PRIVATE_ENV_SENTINEL")
        .env("LOCKSMITH_CREDENTIAL_SEALING_KEY", "invalid-do-not-read");
    c
}

async fn initial_routes(
    registrations: &RegistrationRepository,
    bindings: &AgentCredentialRepository,
    distinct: i64,
) {
    registrations
        .create(&Registration::new(
            "api".into(),
            Kind::Tool,
            "test".into(),
            "http://127.0.0.1:1".into(),
            env_spec(),
        ))
        .await
        .unwrap();
    bindings
        .set(
            distinct,
            "api",
            &AuthSpec::Bearer {
                env_var: "MIGRATION_Y".into(),
            },
        )
        .await
        .unwrap();
}
