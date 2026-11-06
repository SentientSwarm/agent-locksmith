use super::support::{Setup, tool};
use serde_json::json;

#[tokio::test]
async fn unchanged_contract_survives_unrelated_drift_removed_returned_needs_regrant() {
    let s = Setup::new().await;
    let first = s.publish(vec![tool("one"), tool("two")]).await;
    let one = s.review(&first, "one").await;
    let two = s.review(&first, "two").await;
    s.grant_for(
        &s.agent,
        &first,
        json!([
        {"name":"one","contract_digest":one["contract_digest"]},
        {"name":"two","contract_digest":two["contract_digest"]}]),
    )
    .await;
    let mut changed = tool("two");
    changed["description"] = "Changed".into();
    let drift = s.publish(vec![tool("one"), changed]).await;
    assert_eq!(drift["tools"].as_array().unwrap().len(), 1);
    assert_eq!(drift["tools"][0]["name"], "one");
    s.publish(vec![]).await;
    let returned = s.publish(vec![tool("one"), tool("two")]).await;
    assert_eq!(returned["tools"], json!([]));
    assert!(
        s.rt.replace(&s.agent, "native", Setup::replace(&first, json!([])))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rotating_one_shared_reference_keeps_other_agents_source_and_grant() {
    use agent_locksmith::{registrations::AuthSpec, repo::CredentialSecretsRepository};
    let s = Setup::new().await;
    let secrets = CredentialSecretsRepository::new(s.f.pool.clone());
    let (reference, public) = shared(&s, &secrets).await;
    let snapshot = s.publish(vec![tool("one")]).await;
    let reviewed = s.review(&snapshot, "one").await;
    let other_snapshot = s.rt.snapshot(&public, "native").await.unwrap();
    s.grant_for(
        &public,
        &other_snapshot,
        json!([{"name":"one","contract_digest":reviewed["contract_digest"]}]),
    )
    .await;
    let before = s.rt.snapshot(&public, "native").await.unwrap();
    s.f.bindings
        .set(s.f.agent_id, "native", &AuthSpec::None)
        .await
        .unwrap();
    assert!(!secrets.tombstone_if_unreferenced(&reference).await.unwrap());
    assert_eq!(s.rt.snapshot(&public, "native").await.unwrap(), before);
    secrets.tombstone(&reference).await.unwrap();
    assert!(s.rt.snapshot(&public, "native").await.is_err());
}
async fn shared(
    s: &Setup,
    secrets: &agent_locksmith::repo::CredentialSecretsRepository,
) -> (String, String) {
    use agent_locksmith::{registrations::AuthSpec, secret::CredentialSealingKey};
    let key = CredentialSealingKey::generate().unwrap();
    let (bytes, nonce) = key.seal(b"synthetic-account-x").unwrap();
    let reference = secrets.insert(&bytes, &nonce).await.unwrap();
    let shared = AuthSpec::StoredBearer {
        secret_ref: reference.clone(),
    };
    s.f.bindings
        .set(s.f.agent_id, "native", &shared)
        .await
        .unwrap();
    let (public, _) =
        s.f.agents
            .create("second", None, Some(&["native".into()]), None, None, None)
            .await
            .unwrap();
    let other = s.f.agents.get_by_name("second").await.unwrap().unwrap();
    s.f.bindings.set(other.id, "native", &shared).await.unwrap();
    (reference, public)
}
