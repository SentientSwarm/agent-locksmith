//! Phase E.7 — first-boot seed catalog loader.
//!
//! TS-160..TS-165. See artifact at
//! `~/.kz-eng-mp/devloop/agents-stack/loop-states/phase-e-catalog-substrate-artifact.md`.

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Kind, RegistrationRepository, seed_loader};
use tempfile::TempDir;

const SEED_V200: &str = r#"
version: "2.0.0"
entries:
  - name: anthropic
    kind: model
    description: "Anthropic"
    upstream: "https://api.anthropic.com"
    auth:
      kind: header
      header: x-api-key
      env_var: ANTHROPIC_API_KEY
    metadata:
      modality: text

  - name: tavily
    kind: tool
    description: "Tavily"
    upstream: "https://api.tavily.com"
    auth:
      kind: bearer
      env_var: TAVILY_API_KEY

  - name: duckduckgo
    kind: tool
    description: "DuckDuckGo (authless)"
    upstream: "https://api.duckduckgo.com"
    auth:
      kind: none

  - name: lf-scan
    kind: infra
    description: "Layer8 scanner"
    upstream: "http://lf-scan:8080"
    auth:
      kind: header
      header: X-Internal-Token
      env_var: LF_SCAN_INTERNAL_TOKEN
"#;

const SEED_V210_ADDS_OPENAI: &str = r#"
version: "2.1.0"
entries:
  - name: anthropic
    kind: model
    description: "Anthropic Messages API"   # description updated
    upstream: "https://api.anthropic.com"
    auth:
      kind: header
      header: x-api-key
      env_var: ANTHROPIC_API_KEY
    metadata:
      modality: text

  - name: tavily
    kind: tool
    description: "Tavily"
    upstream: "https://api.tavily.com"
    auth:
      kind: bearer
      env_var: TAVILY_API_KEY

  - name: openai
    kind: model
    description: "OpenAI"
    upstream: "https://api.openai.com"
    auth:
      kind: bearer
      env_var: OPENAI_API_KEY
    metadata:
      modality: text

  - name: duckduckgo
    kind: tool
    description: "DuckDuckGo (authless)"
    upstream: "https://api.duckduckgo.com"
    auth:
      kind: none

  - name: lf-scan
    kind: infra
    description: "Layer8 scanner"
    upstream: "http://lf-scan:8080"
    auth:
      kind: header
      header: X-Internal-Token
      env_var: LF_SCAN_INTERNAL_TOKEN
"#;

async fn fresh() -> (TempDir, RegistrationRepository) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    (dir, RegistrationRepository::new(pool))
}

// ─── TS-160: Loader populates 4 rows on fresh DB ───────────────────────────
#[tokio::test]
async fn ts160_populates_fresh_db() {
    let (_dir, repo) = fresh().await;
    seed_loader::apply_catalog(&repo, SEED_V200).await.unwrap();

    let all = repo.list(None).await.unwrap();
    assert_eq!(all.len(), 4);

    // Spot-check kinds.
    let by_name: std::collections::HashMap<_, _> =
        all.iter().map(|r| (r.name.clone(), r.kind)).collect();
    assert_eq!(by_name["anthropic"], Kind::Model);
    assert_eq!(by_name["tavily"], Kind::Tool);
    assert_eq!(by_name["duckduckgo"], Kind::Tool);
    assert_eq!(by_name["lf-scan"], Kind::Infra);

    // All loaded with seed=true.
    for r in &all {
        assert!(r.seed, "{} should be marked seed=true", r.name);
        assert!(!r.disabled);
    }

    // Version recorded.
    assert_eq!(
        repo.get_seed_version().await.unwrap().as_deref(),
        Some("2.0.0")
    );
}

// ─── TS-161: Loader is idempotent on the same version ─────────────────────
#[tokio::test]
async fn ts161_idempotent_same_version() {
    let (_dir, repo) = fresh().await;
    seed_loader::apply_catalog(&repo, SEED_V200).await.unwrap();
    let before = repo.list(None).await.unwrap();

    seed_loader::apply_catalog(&repo, SEED_V200).await.unwrap();
    let after = repo.list(None).await.unwrap();

    assert_eq!(before.len(), after.len());
    // No fields should have shifted.
    for (b, a) in before.iter().zip(after.iter()) {
        assert_eq!(b.name, a.name);
        assert_eq!(b.created_at, a.created_at);
        assert_eq!(b.updated_at, a.updated_at);
    }
}

// ─── TS-162: Upgrade adds new entries, updates seed=1, preserves seed=0 ───
#[tokio::test]
async fn ts162_upgrade_diff_preserves_overrides() {
    let (_dir, repo) = fresh().await;
    seed_loader::apply_catalog(&repo, SEED_V200).await.unwrap();

    // Operator overrides anthropic — flips seed=0.
    let mut anth = repo.get("anthropic").await.unwrap().unwrap();
    anth.upstream = "https://anthropic.example.internal".to_string();
    anth.description = "Operator override description".to_string();
    anth.seed = false;
    repo.upsert(&anth).await.unwrap();

    // Now upgrade catalog from 2.0.0 → 2.1.0. New entry: openai.
    // Updated entry: anthropic's description (in seed catalog).
    seed_loader::apply_catalog(&repo, SEED_V210_ADDS_OPENAI)
        .await
        .unwrap();

    // openai inserted as seed=true.
    let openai = repo.get("openai").await.unwrap().unwrap();
    assert!(openai.seed);
    assert_eq!(openai.kind, Kind::Model);

    // anthropic preserved with operator's override (seed=0, override fields).
    let anth_after = repo.get("anthropic").await.unwrap().unwrap();
    assert!(!anth_after.seed);
    assert_eq!(anth_after.upstream, "https://anthropic.example.internal");
    assert_eq!(anth_after.description, "Operator override description");

    // tavily was unchanged in the new catalog — fields stable.
    let tavily = repo.get("tavily").await.unwrap().unwrap();
    assert_eq!(tavily.upstream, "https://api.tavily.com");
    assert!(tavily.seed);

    // Version bumped.
    assert_eq!(
        repo.get_seed_version().await.unwrap().as_deref(),
        Some("2.1.0")
    );
}

// ─── TS-163: Disabled flag preserved across version bump ───────────────────
#[tokio::test]
async fn ts163_disabled_preserved_across_upgrade() {
    let (_dir, repo) = fresh().await;
    seed_loader::apply_catalog(&repo, SEED_V200).await.unwrap();

    // Operator disables a seed row (does NOT flip seed=0; just disabled=1).
    repo.set_disabled("tavily", true).await.unwrap();

    // Upgrade.
    seed_loader::apply_catalog(&repo, SEED_V210_ADDS_OPENAI)
        .await
        .unwrap();

    let tavily = repo.get("tavily").await.unwrap().unwrap();
    assert!(tavily.disabled, "disabled flag must survive image upgrade");
    assert!(tavily.seed, "still a seed row");
}

// ─── TS-164: Loader rejects malformed catalog at startup ──────────────────
#[tokio::test]
async fn ts164_malformed_catalog_aborts() {
    let (_dir, repo) = fresh().await;

    // kind=tool without auth → AuthRequired (catalog bug).
    let bad = r#"
version: "2.0.0"
entries:
  - name: forgot-auth
    kind: tool
    upstream: "https://example.com"
"#;
    let err = seed_loader::apply_catalog(&repo, bad).await.unwrap_err();
    assert!(
        err.to_string().contains("forgot-auth") || err.to_string().contains("auth"),
        "expected auth error mentioning entry; got: {err}"
    );

    // Note: kind=model with auth: none is NOT a catalog bug. The catalog
    // ships ollama/lmstudio with `auth: none` for LAN-local inference;
    // see api.rs `op_put` for the validator's rationale.

    // Reserved name → ReservedName.
    let bad_reserved = r#"
version: "2.0.0"
entries:
  - name: skill
    kind: tool
    upstream: "https://example.com"
    auth:
      kind: none
"#;
    let err = seed_loader::apply_catalog(&repo, bad_reserved)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("skill") || err.to_string().contains("reserved"));

    // Invalid YAML → Parse error.
    let garbage = "not: valid:\n  - yaml";
    assert!(seed_loader::apply_catalog(&repo, garbage).await.is_err());
}

// ─── TS-165: Cross-kind change between versions rejected ───────────────────
#[tokio::test]
async fn ts165_cross_kind_change_rejected() {
    let (_dir, repo) = fresh().await;
    seed_loader::apply_catalog(&repo, SEED_V200).await.unwrap();

    // Build a v2.1.0 that flips lf-scan from infra → tool. Catalog bug.
    let cross_kind = r#"
version: "2.1.0"
entries:
  - name: lf-scan
    kind: tool
    upstream: "http://lf-scan:8080"
    auth:
      kind: header
      header: X-Internal-Token
      env_var: LF_SCAN_INTERNAL_TOKEN
"#;
    let err = seed_loader::apply_catalog(&repo, cross_kind)
        .await
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("kind"),
        "expected kind-change error; got: {err}"
    );
}

// ─── TS-165b: shipped catalog file lints + parses ──────────────────────────
#[tokio::test]
async fn ts165b_shipped_catalog_parses() {
    let (_dir, repo) = fresh().await;
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("seed/catalog.yaml");
    let yaml =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    seed_loader::apply_catalog(&repo, &yaml).await.unwrap();

    let all = repo.list(None).await.unwrap();
    assert!(all.len() >= 11, "shipped catalog has at least 11 entries");

    // The 11 SHIP names from E.5 must all be present.
    let names: std::collections::HashSet<&str> = all.iter().map(|r| r.name.as_str()).collect();
    for expected in [
        "anthropic",
        "openai",
        "openrouter",
        "ai-gateway",
        "ollama",
        "lmstudio",
        "tavily",
        "github",
        "duckduckgo",
        "wikipedia",
        "lf-scan",
    ] {
        assert!(
            names.contains(expected),
            "shipped catalog missing entry: {expected}"
        );
    }
}

// ─── TS-165c: empty / missing catalog is non-fatal ─────────────────────────
#[tokio::test]
async fn ts165c_missing_file_is_skip() {
    let (dir, repo) = fresh().await;
    let missing = dir.path().join("does-not-exist.yaml");
    seed_loader::load_or_skip(&repo, &missing).await.unwrap();
    let all = repo.list(None).await.unwrap();
    assert!(all.is_empty(), "missing seed file = no rows loaded");
    assert!(repo.get_seed_version().await.unwrap().is_none());
}
