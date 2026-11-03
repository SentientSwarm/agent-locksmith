use super::*;

#[tokio::test]
async fn selected_oauth_refresh_ignores_template_endpoint_and_coalesces() {
    for pkce in [false, true] {
        let h = setup().await;
        select(&h, Some("selected"), pkce).await;
        h.sessions
            .create(
                &h.sealing_key,
                "codex",
                "selected",
                "private-refresh-X",
                Some("expired-X"),
                Some(unix_now() - 60),
                "",
            )
            .await
            .unwrap();
        seed_session(
            &h,
            "private-refresh-default",
            Some("private-default"),
            Some(unix_now() + 3600),
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/selected-token"))
            .and(wiremock::matchers::body_string_contains(
                "client_id=selected-client",
            ))
            .and(wiremock::matchers::body_string_contains(
                "refresh_token=private-refresh-X",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(50))
                    .set_body_json(json!({"access_token":"private-access-X","expires_in":3600})),
            )
            .expect(1)
            .mount(&h.mock)
            .await;
        Mock::given(method("GET"))
            .and(header("authorization", "Bearer private-access-X"))
            .respond_with(ResponseTemplate::new(200).set_body_string("X"))
            .expect(6)
            .mount(&h.mock)
            .await;
        let responses = futures_util::future::join_all((0..6).map(|_| call(&h))).await;
        for response in responses {
            response.assert_status_ok();
            assert_eq!(response.text(), "X");
        }
        let requests = h.mock.received_requests().await.unwrap();
        assert_eq!(requests.iter().filter(|r| r.method == "POST").count(), 1);
        assert_eq!(requests.iter().filter(|r| r.method == "GET").count(), 6);
        assert!(requests.iter().all(|r| r.url.path() != "/token"));
    }
}

#[tokio::test]
async fn selected_refresh_rejection_never_uses_default() {
    for pkce in [false, true] {
        let capture = crate::logs::Capture::default();
        let _guard = capture.start();
        let h = setup().await;
        select(&h, Some("selected"), pkce).await;
        seed_session(
            &h,
            "private-default-refresh",
            Some("private-default"),
            Some(unix_now() + 3600),
        )
        .await;
        h.sessions
            .create(
                &h.sealing_key,
                "codex",
                "selected",
                "private-refresh-X",
                Some("expired-X"),
                Some(unix_now() - 60),
                "",
            )
            .await
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/selected-token"))
            .respond_with(ResponseTemplate::new(401).set_body_string("private-provider-echo"))
            .expect(1)
            .mount(&h.mock)
            .await;
        let response = call(&h).await;
        response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.text().contains("private-provider-echo"));
        assert!(!capture.text().contains("private-provider-echo"));
        let rows = h
            .audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap();
        assert!(!format!("{rows:?}").contains("private-"));
        let requests = h.mock.received_requests().await.unwrap();
        assert_eq!(requests.iter().filter(|r| r.method == "POST").count(), 1);
        assert_eq!(requests.iter().filter(|r| r.method == "GET").count(), 0);
        let selected = h
            .sessions
            .get(&h.sealing_key, "codex", "selected")
            .await
            .unwrap()
            .unwrap();
        let default = h
            .sessions
            .get(&h.sealing_key, "codex", "default")
            .await
            .unwrap()
            .unwrap();
        assert!(selected.degraded);
        assert!(!default.degraded);
    }
}

#[tokio::test]
async fn empty_refresh_response_is_not_dispatched_or_persisted() {
    for pkce in [false, true] {
        let h = setup().await;
        select(&h, Some("selected"), pkce).await;
        h.sessions
            .create(
                &h.sealing_key,
                "codex",
                "selected",
                "private-refresh-X",
                Some("expired-X"),
                Some(unix_now() - 60),
                "",
            )
            .await
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/selected-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"", "expires_in":3600})),
            )
            .expect(1)
            .mount(&h.mock)
            .await;
        call(&h)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let requests = h.mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        let selected = h
            .sessions
            .get(&h.sealing_key, "codex", "selected")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.access_token.unwrap().expose_secret(), "expired-X");
        assert!(selected.degraded);
    }
}
