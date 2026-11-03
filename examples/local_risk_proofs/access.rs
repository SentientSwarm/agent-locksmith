//! Request-time lifecycle checks and the proposed explicit-grant migration risk.
use super::{denied, forwarded, record};
use crate::fixture::{Fixture, env_auth, register};
use agent_locksmith::registrations::AuthSpec;
use serde_json::Value;

async fn policy(h: &Fixture, allow: Vec<String>) {
    h.store
        .agents
        .update_policy(&h.public_id, Some(Some(allow)), None, None, None)
        .await
        .unwrap();
}

async fn policy_and_revocation(rows: &mut Vec<Value>) {
    let h = Fixture::new(false, false).await;
    h.store
        .overrides
        .set(
            h.agent_id,
            "proof",
            &env_auth(false, "LOCKSMITH_LOCAL_PROOF_SELECTED"),
        )
        .await
        .unwrap();
    record(
        rows,
        "before policy change",
        h.request("proof").await,
        forwarded("selected"),
    );
    policy(&h, vec![]).await;
    record(
        rows,
        "empty allowlist denies next request",
        h.request("proof").await,
        denied(403),
    );
    policy(&h, vec!["proof".into()]).await;
    record(
        rows,
        "restored grant permits request",
        h.request("proof").await,
        forwarded("selected"),
    );
    h.store.agents.revoke(&h.public_id).await.unwrap();
    record(
        rows,
        "revoked agent denies next request",
        h.request("proof").await,
        denied(401),
    );
}

async fn catalog_growth(rows: &mut Vec<Value>, unrestricted: bool) {
    let h = Fixture::new(false, unrestricted).await;
    register(
        &h.store.registrations,
        "new-connection",
        &h.mock.uri(),
        AuthSpec::None,
    )
    .await;
    // Isolate D4's existing ACL expansion independently of D1 account selection.
    // Both agents explicitly select no-auth; only one currently allows this name.
    h.store
        .overrides
        .set(h.agent_id, "new-connection", &AuthSpec::None)
        .await
        .unwrap();
    h.refresh_catalog().await;
    let name = if unrestricted {
        "migration target: legacy unrestricted agent gains new entry"
    } else {
        "explicit allowlist excludes new catalog entry"
    };
    record(rows, name, h.request("new-connection").await, denied(403));
}

async fn disabled_snapshot(rows: &mut Vec<Value>) {
    let h = Fixture::new(false, false).await;
    h.store
        .overrides
        .set(
            h.agent_id,
            "proof",
            &env_auth(false, "LOCKSMITH_LOCAL_PROOF_SELECTED"),
        )
        .await
        .unwrap();
    h.store
        .registrations
        .set_disabled("proof", true)
        .await
        .unwrap();
    // Fault model: persistence completed, but activation did not. This bypasses
    // the admin API deliberately; it is not a normal disable-endpoint test.
    record(
        rows,
        "activation fault model: disabled DB row, stale snapshot",
        h.request("proof").await,
        denied(404),
    );
    h.refresh_catalog().await;
    record(
        rows,
        "disabled entry after catalog activation",
        h.request("proof").await,
        denied(404),
    );
}

pub async fn run(rows: &mut Vec<Value>) {
    policy_and_revocation(rows).await;
    catalog_growth(rows, false).await;
    catalog_growth(rows, true).await;
    disabled_snapshot(rows).await;
}
