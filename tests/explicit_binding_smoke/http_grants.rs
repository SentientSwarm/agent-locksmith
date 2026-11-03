//! D4 actual-process finite migration, activation failure and name lifecycle.
use super::{fixture::Fixture, migration, process, setup, upstream};
use serde_json::Value;

pub async fn exercise() {
    let r = upstream::Receiver::start().await;
    let mut f = Fixture::new(&r.server.uri());
    f.start().await;
    let agents = setup::enroll(&f).await;
    f.stop();
    // Exact historical policies, constructed only in this disposable stopped DB.
    migration::sqlite(
        &f,
        &f.db,
        "UPDATE agents SET grants_reviewed=0, tool_allowlist=CASE name WHEN 'shared-a' THEN NULL WHEN 'shared-b' THEN '[\"accounts\",\"future-private\",\"future-public\"]' ELSE '[]' END WHERE name IN ('shared-a','shared-b','unmapped');",
    );
    f.start().await;
    for agent in [&agents[0], &agents[1], &agents[3]] {
        upstream::denied(
            &f,
            &r,
            Some(&agent.token),
            "accounts/check",
            403,
            "tool_not_allowed",
        )
        .await;
    }
    f.stop();
    let mut plan = migration::preview(&f);
    assert_eq!(plan["format_version"], 2);
    for row in plan["grants"].as_array_mut().unwrap() {
        let id = row["agent_id"].clone();
        let name = migration::sqlite(
            &f,
            &f.db,
            &format!("SELECT name FROM agents WHERE id={id};"),
        );
        if name.trim() == "unmapped" {
            assert_eq!(row["allowlist"], serde_json::json!([]));
        } else {
            assert_eq!(row["allowlist"], serde_json::json!(["accounts"]));
        }
        row["selected"] = true.into();
    }
    assert!(
        plan["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["action"] != "propose")
    );
    std::fs::write(
        f.path().join("bindings-reviewed.json"),
        serde_json::to_vec_pretty(&plan).unwrap(),
    )
    .unwrap();
    assert_eq!(migration::apply(&f, 0)["inserted"], 0);
    assert_eq!(migration::apply(&f, 0)["inserted"], 0);
    f.start().await;
    for (agent, label) in agents[..3].iter().zip(["X", "X", "Y"]) {
        upstream::allowed(&f, &r, &agent.token, "accounts/check", label).await;
    }
    upstream::denied(
        &f,
        &r,
        Some(&agents[3].token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
    for (name, auth, route) in [
        ("future-private", "bearer=SMOKE_Y", "check"),
        ("future-public", "none", "noauth"),
    ] {
        setup::put(&f, name, auth);
        for agent in &agents[..2] {
            if auth == "none" {
                f.op(&["agent", "set-credential", &agent.id, name, "--no-auth"]);
            } else {
                f.op(&["agent", "set-credential", &agent.id, name, "--auth", auth]);
            }
            upstream::denied(
                &f,
                &r,
                Some(&agent.token),
                &format!("{name}/{route}"),
                403,
                "tool_not_allowed",
            )
            .await;
        }
    }
    println!(
        "D4 finite cutover: restricted/unrestricted/empty reviewed; all bindings preserved, apply/repeat=0; future authless/credentialed zero-dispatch"
    );

    setup::put(&f, "healthy", "bearer=SMOKE_X");
    f.op(&[
        "agent",
        "modify",
        &agents[0].id,
        "--allowlist",
        "accounts,healthy",
    ]);
    f.op(&[
        "agent",
        "set-credential",
        &agents[0].id,
        "healthy",
        "--auth",
        "bearer=SMOKE_X",
    ]);
    setup::put(&f, "poison", "none");
    migration::sqlite(
        &f,
        &f.db,
        "UPDATE registrations SET auth_json='invalid' WHERE name='poison';",
    );
    let output = process::run(f.cli(&[
        "tool",
        "put",
        "accounts",
        "--upstream",
        &r.server.uri(),
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
        "--description",
        "changed after fault",
    ]));
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("connection_activation_failed"));
    let row = f.op(&["tool", "get", "accounts"]);
    assert_eq!(row["description"], "changed after fault");
    assert_eq!(row["activation"], "pending");
    assert_eq!(row["credential_readiness"], "not_checked");
    upstream::denied(
        &f,
        &r,
        Some(&agents[0].token),
        "accounts/check",
        503,
        "connection_not_active",
    )
    .await;
    upstream::allowed(&f, &r, &agents[0].token, "healthy/check", "X").await;
    let catalog: Value = f
        .http
        .get(f.url("/tools"))
        .bearer_auth(&agents[0].token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = catalog["tools"].as_array().unwrap();
    assert!(rows.iter().any(|r| r["name"] == "healthy"));
    assert!(!rows.iter().any(|r| r["name"] == "accounts"));
    assert_eq!(
        f.http.get(f.url("/readyz")).send().await.unwrap().status(),
        200
    );
    // Repair the isolated fault while stopped, then load persisted desired state.
    f.stop();
    migration::sqlite(&f, &f.db, "DELETE FROM registrations WHERE name='poison';");
    migration::apply(&f, 5); // Old reviewed plan cannot restore later decisions.
    f.start().await;
    assert_eq!(f.op(&["tool", "get", "accounts"])["activation"], "active");
    upstream::allowed(&f, &r, &agents[0].token, "accounts/check", "X").await;
    println!(
        "D4 activation: saved CLI exit1; pending route503/zero arrivals; unrelated route200; ready is not credential attestation; restart activates saved state"
    );

    // Seed delete is disable, not hard deletion; choices survive re-enable.
    migration::sqlite(
        &f,
        &f.db,
        "UPDATE registrations SET seed=1 WHERE name='accounts';",
    );
    f.op(&["tool", "delete", "accounts"]);
    upstream::denied(
        &f,
        &r,
        Some(&agents[0].token),
        "accounts/check",
        404,
        "tool_not_found",
    )
    .await;
    f.op(&["tool", "enable", "accounts"]);
    upstream::allowed(&f, &r, &agents[0].token, "accounts/check", "X").await;

    let destination = upstream::Receiver::start().await;
    f.op(&[
        "tool",
        "put",
        "accounts",
        "--upstream",
        &destination.server.uri(),
        "--auth",
        "bearer=SMOKE_Y",
        "--egress",
        "direct",
    ]);
    let old = r.snapshot().await;
    upstream::denied(
        &f,
        &destination,
        Some(&agents[0].token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
    assert_eq!(r.snapshot().await, old);
    assert!(
        !f.op(&["agent", "credentials", "list", &agents[0].id])
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["registration"] == "accounts")
    );
    f.op(&[
        "agent",
        "modify",
        &agents[0].id,
        "--allowlist",
        "accounts,healthy",
    ]);
    setup::bind(&f, &agents[0], "bearer=SMOKE_Y");
    upstream::allowed(&f, &destination, &agents[0].token, "accounts/check", "Y").await;
    f.op(&["tool", "delete", "accounts"]);
    setup::put(&f, "accounts", "bearer=SMOKE_X");
    upstream::denied(
        &f,
        &r,
        Some(&agents[0].token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
    f.op(&[
        "agent",
        "modify",
        &agents[0].id,
        "--allowlist",
        "accounts,healthy",
    ]);
    setup::bind(&f, &agents[0], "bearer=SMOKE_X");
    upstream::allowed(&f, &r, &agents[0].token, "accounts/check", "X").await;
    f.op(&["agent", "revoke", &agents[0].id]);
    upstream::denied(
        &f,
        &r,
        Some(&agents[0].token),
        "accounts/check",
        401,
        "invalid_credential",
    )
    .await;
    println!(
        "D4 destination replacement/delete-recreate: grants and selections cleared, deliberate reapproval required; next revoked admission zero-dispatch"
    );
    f.cleanup();
}
