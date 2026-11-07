use super::{flow, support as s};
use serde_json::json;

// A deliberately labeled DB-tamper challenge, not a supported rotation route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_reference_ciphertext_tamper_still_screens_merged_context_before_network() {
    let (mut f, receiver, a) = s::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let reference = s::stored(&f, id, "fixture-account-x");
    let r = s::review(
        &f,
        id,
        json!({"workspace":"tampered-selected-value"}),
        "read_record",
    );
    s::grant(&f, id, &r);
    let session = s::open(&f, &a).await;
    let before = flow::show(&f, id);
    let counts = std::fs::read(f.path().join("counts.json")).unwrap();
    tamper(&f, &reference).await;
    assert_eq!(
        flow::show(&f, id)["grant_revision"],
        before["grant_revision"]
    );
    let r = s::call(&f, &a, &session, 2, json!({"key":"read"})).await;
    assert_eq!(r["error"]["data"]["code"], "upstream_secret_echo", "{r}");
    refused(&f, &counts).await;
    f.stop();
    receiver.stop();
}

async fn tamper(f: &super::fixture::Fixture, reference: &str) {
    let key = agent_locksmith::secret::CredentialSealingKey::from_b64(
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    )
    .unwrap();
    let (sealed, nonce) = key.seal(b"tampered-selected-value").unwrap();
    let pool = s::pool(f).await;
    sqlx::query("UPDATE credential_secrets SET sealed_value=?,nonce=? WHERE secret_ref=?")
        .bind(sealed)
        .bind(nonce)
        .bind(reference)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn refused(f: &super::fixture::Fixture, counts: &[u8]) {
    assert!(s::effects(f).is_empty());
    assert!(s::audit(f, "mcp_admitted").await.is_empty());
    assert_eq!(std::fs::read(f.path().join("counts.json")).unwrap(), counts);
    let denied = s::audit(f, "native_tool_denied").await;
    assert_eq!(denied[0]["reason"], "upstream_secret_echo");
    assert!(
        !serde_json::to_string(&denied)
            .unwrap()
            .contains("tampered-selected-value")
    );
}
