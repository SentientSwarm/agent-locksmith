use super::{
    fixture::Fixture,
    setup::{self, Agent},
    upstream::{self, Receiver},
};

pub async fn shared(f: &Fixture, r: &Receiver, agents: &[Agent]) {
    for (a, account) in agents.iter().zip(["X", "X", "Y"]) {
        upstream::allowed(f, r, &a.token, "accounts/check", account).await;
    }
    println!(
        "SM02 explicit accounts X/X/Y; received_delta=3 operations=X:2,Y:1; caller auth stripped"
    );
}
pub async fn exercise(f: &Fixture, r: &Receiver, a: &[Agent]) {
    shared(f, r, a).await;
    for (caller, code) in [
        (None, "invalid_credential"),
        (Some("synthetic-invalid-agent"), "invalid_credential"),
    ] {
        upstream::denied(f, r, caller, "accounts/check", 401, code).await;
    }
    upstream::denied(
        f,
        r,
        Some(&a[3].token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
    super::guidance::repair(f, r, &a[3]).await;
    clear_and_repair(f, r, a).await;
    revoked(f, r).await;
    setup::put(f, "accounts", "bearer=SMOKE_Y");
    shared(f, r, a).await;
    setup::put(f, "public", "none");
    f.op(&[
        "agent",
        "modify",
        &a[0].id,
        "--allowlist",
        "accounts,public",
    ]);
    f.op(&["agent", "set-credential", &a[0].id, "public", "--no-auth"]);
    upstream::allowed(f, r, &a[0].token, "public/noauth", "NONE").await;
    println!("SM03 clear/broken/repaired/replaced/revoked/template/noauth controls PASS");
}
async fn clear_and_repair(f: &Fixture, r: &Receiver, a: &[Agent]) {
    setup::clear(f, &a[0]);
    upstream::denied(
        f,
        r,
        Some(&a[0].token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
    for source in ["bearer=SMOKE_MISSING", "bearer=SMOKE_EMPTY"] {
        setup::bind(f, &a[1], source);
        upstream::denied(
            f,
            r,
            Some(&a[1].token),
            "accounts/check",
            503,
            "credential_unresolved",
        )
        .await;
    }
    setup::bind(f, &a[0], "bearer=SMOKE_Y");
    upstream::allowed(f, r, &a[0].token, "accounts/check", "Y").await;
    for agent in &a[..2] {
        setup::bind(f, agent, "bearer=SMOKE_X");
    }
    shared(f, r, a).await;
}
async fn revoked(f: &Fixture, r: &Receiver) {
    let a = setup::register(f, "revoked-after-use");
    setup::bind(f, &a, "bearer=SMOKE_X");
    upstream::allowed(f, r, &a.token, "accounts/check", "X").await;
    f.op(&["agent", "revoke", &a.id, "--reason", "smoke"]);
    upstream::denied(
        f,
        r,
        Some(&a.token),
        "accounts/check",
        401,
        "invalid_credential",
    )
    .await;
}
