use super::*;

#[tokio::test]
async fn selected_empty_op_value_never_dispatches() {
    for header in [false, true] {
        let reference = "op://vault/selected/empty";
        let auth = if header {
            AuthSpec::OpHeader {
                header: "x-api-key".into(),
                reference: reference.into(),
            }
        } else {
            AuthSpec::OpBearer {
                reference: reference.into(),
            }
        };
        let h = setup(auth, Some((reference, ""))).await;
        let calls = h.op_calls.load(Ordering::Relaxed);
        assert_eq!(calls, 1);
        let response = h
            .server
            .get("/api/op-api/v1/ping")
            .add_header("authorization", &h.agent_bearer)
            .await;
        response.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(h.mock.received_requests().await.unwrap().is_empty());
        assert_eq!(h.op_calls.load(Ordering::Relaxed), calls);
    }
}

#[tokio::test]
async fn selected_op_cache_miss_never_uses_healthy_template() {
    for header in [false, true] {
        let template = "op://vault/template/field";
        let selected = "op://vault/selected/missing";
        let auth = if header {
            AuthSpec::OpHeader {
                header: "x-api-key".into(),
                reference: template.into(),
            }
        } else {
            AuthSpec::OpBearer {
                reference: template.into(),
            }
        };
        let h = setup(auth, Some((template, "private-template"))).await;
        let id = h.bindings.list_all().await.unwrap()[0].agent_id;
        let auth = if header {
            AuthSpec::OpHeader {
                header: "x-api-key".into(),
                reference: selected.into(),
            }
        } else {
            AuthSpec::OpBearer {
                reference: selected.into(),
            }
        };
        h.bindings.set(id, "op-api", &auth).await.unwrap();
        let response = h
            .server
            .get("/api/op-api/v1/ping")
            .add_header("authorization", &h.agent_bearer)
            .await;
        response.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(h.mock.received_requests().await.unwrap().is_empty());
        assert_eq!(h.op_calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn selected_cached_op_value_wins_over_healthy_template() {
    for is_header in [false, true] {
        let template = "op://vault/template/field";
        let selected = "op://vault/selected/field";
        let h = setup_sources(
            op_spec(is_header, template),
            &[(template, "private-template"), (selected, "private-X")],
        )
        .await;
        let id = h.bindings.list_all().await.unwrap()[0].agent_id;
        h.bindings
            .set(id, "op-api", &op_spec(is_header, selected))
            .await
            .unwrap();
        let (key, value) = if is_header {
            ("x-api-key", "private-X")
        } else {
            ("authorization", "Bearer private-X")
        };
        Mock::given(method("GET"))
            .and(header(key, value))
            .respond_with(ResponseTemplate::new(200).set_body_string("X"))
            .mount(&h.mock)
            .await;
        let response = h
            .server
            .get("/api/op-api/check")
            .add_header("authorization", &h.agent_bearer)
            .add_header("x-api-key", "caller-private")
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
        assert_eq!(h.op_calls.load(Ordering::Relaxed), 2);
    }
}

fn op_spec(is_header: bool, reference: &str) -> AuthSpec {
    if is_header {
        AuthSpec::OpHeader {
            header: "x-api-key".into(),
            reference: reference.into(),
        }
    } else {
        AuthSpec::OpBearer {
            reference: reference.into(),
        }
    }
}
