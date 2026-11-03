use super::*;

#[tokio::test]
async fn selected_empty_stored_value_never_dispatches() {
    for header in [false, true] {
        let h = setup_with_sealed(b"", |secret_ref| {
            if header {
                AuthSpec::StoredHeader {
                    header: "x-api-key".into(),
                    secret_ref,
                }
            } else {
                AuthSpec::StoredBearer { secret_ref }
            }
        })
        .await;
        let response = h
            .server
            .get("/api/store-api/v1/ping")
            .add_header("authorization", &h.agent_bearer)
            .await;
        response.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(h.mock.received_requests().await.unwrap().is_empty());
    }
}

fn spec(header: bool, secret_ref: String) -> AuthSpec {
    if header {
        AuthSpec::StoredHeader {
            header: "x-api-key".into(),
            secret_ref,
        }
    } else {
        AuthSpec::StoredBearer { secret_ref }
    }
}

async fn sealed(
    store: &CredentialSecretsRepository,
    key: &CredentialSealingKey,
    value: &[u8],
) -> String {
    let (ct, nonce) = key.seal(value).unwrap();
    store.insert(&ct, &nonce).await.unwrap()
}

async fn fixture(header: bool, failure: &str) -> Harness {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("selected.db"))
        .await
        .unwrap();
    let key = CredentialSealingKey::generate().unwrap();
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let template = sealed(&secrets, &key, b"private-template-Y").await;
    let selected = match failure {
        "missing" => "cs_missing".into(),
        "wrong_key" => {
            sealed(
                &secrets,
                &CredentialSealingKey::generate().unwrap(),
                b"private-X",
            )
            .await
        }
        "empty" => sealed(&secrets, &key, b"").await,
        _ => sealed(&secrets, &key, b"private-X").await,
    };
    let h = build_harness_on(
        dir,
        pool,
        key,
        spec(header, template),
        failure != "key_unset",
    )
    .await;
    let id = h.bindings.list_all().await.unwrap()[0].agent_id;
    h.bindings
        .set(id, "store-api", &spec(header, selected.clone()))
        .await
        .unwrap();
    if failure == "tombstone" {
        h.secrets.tombstone(&selected).await.unwrap();
    }
    if failure == "read_failed" {
        sqlx::query("DROP TABLE credential_secrets")
            .execute(&h.pool)
            .await
            .unwrap();
    }
    h
}

#[tokio::test]
async fn selected_stored_failures_never_use_healthy_template() {
    for header in [false, true] {
        for failure in [
            "missing",
            "wrong_key",
            "empty",
            "key_unset",
            "tombstone",
            "read_failed",
        ] {
            let h = fixture(header, failure).await;
            let response = h
                .server
                .get("/api/store-api/v1/ping")
                .add_header("authorization", &h.agent_bearer)
                .await;
            response.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                h.mock.received_requests().await.unwrap().is_empty(),
                "{failure}"
            );
            assert!(!response.text().contains("private-"));
        }
    }
}

#[tokio::test]
async fn selected_stored_value_wins_over_healthy_template_and_reads_are_safe() {
    for header in [false, true] {
        let h = fixture(header, "healthy").await;
        let (name, value) = if header {
            ("x-api-key", "private-X")
        } else {
            ("authorization", "Bearer private-X")
        };
        Mock::given(method("GET"))
            .and(wiremock::matchers::header(name, value))
            .respond_with(ResponseTemplate::new(200).set_body_string("X"))
            .mount(&h.mock)
            .await;
        let response = h
            .server
            .get("/api/store-api/v1/ping")
            .add_header("authorization", &h.agent_bearer)
            .add_header("x-api-key", "caller-sentinel")
            .await;
        response.assert_status_ok();
        assert_eq!(response.text(), "X");
        let rows = h
            .audit
            .query(
                &agent_locksmith::repo::audit::AuditFilter::default(),
                agent_locksmith::repo::audit::AuditPage::default(),
            )
            .await
            .unwrap();
        assert!(!format!("{rows:?}").contains("private-"));
        assert!(!format!("{rows:?}").contains(&h.agent_bearer));
        assert_eq!(
            rows[0].details.as_ref().unwrap()["auth_source"],
            "agent_override"
        );
        assert_eq!(h.mock.received_requests().await.unwrap().len(), 1);
        let reads = format!("{:?}", h.bindings.list_all().await.unwrap());
        assert!(!reads.contains("private-"));
        assert!(!reads.contains("caller-sentinel"));
    }
}
