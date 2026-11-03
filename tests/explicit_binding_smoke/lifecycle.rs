//! Existing identity lifecycle, verified through real CLI/UDS/HTTP processes.
use super::{fixture::Fixture, process, setup, upstream};
use agent_locksmith::admin::uds_client::UdsClient;
use serde_json::{Value, json};

async fn request(f: &Fixture, token: &str, method: &str, path: &str, body: Value) -> (u16, Value) {
    let (status, bytes) = UdsClient::new(&f.socket)
        .request(
            method,
            path,
            &[
                ("authorization", &format!("Bearer {token}")),
                ("content-type", "application/json"),
            ],
            Some(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn status(f: &Fixture, token: &str) -> Value {
    let mut c = f.cli(&["status"]);
    c.env_remove("LOCKSMITH_OP_TOKEN")
        .env("LOCKSMITH_AGENT_TOKEN", token);
    process::json(process::run(c))
}

pub async fn exercise() {
    let r = upstream::Receiver::start().await;
    let mut f = Fixture::new(&r.server.uri());
    f.start().await;
    setup::put(&f, "accounts", "bearer=SMOKE_X");
    let issued = setup::register(&f, "operator-issued");
    setup::bind(&f, &issued, "bearer=SMOKE_Y");

    let bootstrap = f.op(&["bootstrap", "mint", "--allowlist", "accounts"]);
    let enrollment = json!({"bootstrap_token": bootstrap["token"], "name": "enrolled"});
    let (code, enrolled) = request(
        &f,
        "unused",
        "POST",
        "/admin/agent/register",
        enrollment.clone(),
    )
    .await;
    assert_eq!(code, 200);
    let a = setup::Agent {
        id: enrolled["public_id"].as_str().unwrap().into(),
        token: enrolled["token"].as_str().unwrap().into(),
    };
    let mut replay = enrollment;
    replay["name"] = "bootstrap-replay".into();
    assert_eq!(
        request(&f, "unused", "POST", "/admin/agent/register", replay)
            .await
            .0,
        401
    );
    setup::bind(&f, &a, "bearer=SMOKE_X");
    upstream::allowed(&f, &r, &a.token, "accounts/check", "X").await;

    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let policy = format!("/admin/operator/agents/{}", a.id);
    assert_eq!(
        request(
            &f,
            &f.operator,
            "PATCH",
            &policy,
            json!({"expires_at": expiry})
        )
        .await
        .0,
        204
    );
    let before = status(&f, &a.token);
    let bindings = f.op(&["agent", "credentials", "list", &a.id]);

    // The authenticated principal, not a caller-supplied other secret/id, owns rotation.
    let mut wrong = f.cli(&[
        "rotate",
        "--current-secret",
        issued.token.split_once('.').unwrap().1,
    ]);
    wrong
        .env_remove("LOCKSMITH_OP_TOKEN")
        .env("LOCKSMITH_AGENT_TOKEN", &a.token);
    assert!(!process::run(wrong).status.success());
    let mut rotate = f.cli(&["rotate"]);
    rotate
        .env_remove("LOCKSMITH_OP_TOKEN")
        .env("LOCKSMITH_AGENT_TOKEN", &a.token);
    let rotated = process::json(process::run(rotate));
    assert_eq!(rotated["public_id"], a.id);
    let token = rotated["token"].as_str().unwrap();
    assert!(token != a.token, "rotation changes the secret");
    let after = status(&f, token);
    for key in ["public_id", "allowlist", "denylist", "expires_at"] {
        assert_eq!(before[key], after[key], "rotation preserves {key}");
    }
    assert_eq!(after["expires_at"], expiry);
    assert_eq!(bindings, f.op(&["agent", "credentials", "list", &a.id]));
    upstream::denied(
        &f,
        &r,
        Some(&a.token),
        "accounts/check",
        401,
        "invalid_credential",
    )
    .await;
    upstream::allowed(&f, &r, token, "accounts/check", "X").await;
    upstream::allowed(&f, &r, &issued.token, "accounts/check", "Y").await;

    let arrivals = r.snapshot().await;
    for (method, path, body) in [
        ("GET", "/admin/operator/agents".to_string(), Value::Null),
        (
            "POST",
            format!("/admin/operator/agents/{}/revoke", issued.id),
            Value::Null,
        ),
        (
            "PUT",
            format!("/admin/operator/agents/{}/credentials/accounts", issued.id),
            json!({"auth_spec":{"kind":"bearer", "env_var":"SMOKE_X"}}),
        ),
    ] {
        assert_eq!(request(&f, token, method, &path, body).await.0, 401);
    }
    assert_eq!(r.snapshot().await, arrivals);
    upstream::allowed(&f, &r, &issued.token, "accounts/check", "Y").await;

    assert_eq!(
        request(&f, &f.operator, "PATCH", &policy, json!({"expires_at": 1}))
            .await
            .0,
        204
    );
    upstream::denied(&f, &r, Some(token), "accounts/check", 401, "expired").await;
    let mut expired_rotate = f.cli(&["rotate"]);
    expired_rotate.env("LOCKSMITH_AGENT_TOKEN", token);
    assert_eq!(process::run(expired_rotate).status.code(), Some(3));
    f.op(&["agent", "revoke", &issued.id]);
    upstream::denied(
        &f,
        &r,
        Some(&issued.token),
        "accounts/check",
        401,
        "invalid_credential",
    )
    .await;
    let address = *r.server.address();
    f.cleanup();
    drop(r);
    upstream::closed(address).await;
    println!(
        "LIFECYCLE PASS: CLI issuance/bootstrap enrollment/replay denial; own rotation preserves grants, binding, expiry and identity; old token/expired/revoked/cross-agent admin denied; account X/Y verified; denied arrivals=0; fixture cleanup"
    );
}
