use super::{
    fixture::Fixture,
    oauth_setup as setup, process, recovery_common as common,
    recovery_provider::Provider,
    sealed_recovery::{self as recovery, Keys, Snapshot},
    upstream,
};

pub async fn pending() {
    let r = upstream::Receiver::start().await;
    let p = Provider::start().await;
    let keys = Keys::new();
    let mut source = Fixture::new(&r.server.uri());
    keys.start(&mut source, Some("stored"), Some("oauth")).await;
    let a = setup::enroll_url(&source, &p.url).await;
    common::connect(&source, "synthetic-first-refresh");
    let authority = setup::authority(&source, &a);
    p.hold();
    // Test clock forcing only; the refresh claim/token exchange use production entrypoints.
    common::expiry(&source, 1);
    let request = common::attempt(&source, &a.token, false);
    p.arrived().await;
    common::pending(&source);
    common::expiry(&source, i64::MAX); // Old unexpired access cannot bypass uncertainty.
    let state = common::state(&source);
    recovery::kill(&mut source);
    request.await.unwrap();
    assert!(
        std::fs::metadata(recovery::wal(&source)).unwrap().len() > 0,
        "retain committed WAL"
    );
    let snapshot = Snapshot::take(&source);
    p.release();
    // The source disconnect can cancel this fixture handler after token consumption.
    // Issuance is deliberately not equated with arrival/consumption.
    assert_eq!((p.counts().0, p.counts().1), (2, 2));
    let mut f = snapshot.restore(&r.server.uri());
    for _ in 0..2 {
        keys.start(&mut f, Some("stored"), Some("oauth")).await;
        common::pending(&f);
        common::denied(&f, &a.token).await;
        assert!(common::state(&f) == state, "pending pair/identity retained");
        assert!(setup::authority(&f, &a) == authority);
        assert_eq!((p.counts().0, p.counts().1), (2, 2));
        assert_eq!(r.snapshot().await, ([0, 0, 0], 0));
        keys.safe(
            &f,
            &[
                &a.token,
                "synthetic-first-refresh",
                "synthetic-rotation-1",
                "synthetic-rotation-2",
            ],
        );
        f.stop();
    }
    keys.start(&mut f, Some("stored"), Some("oauth")).await;
    setup::revoke(&f);
    common::connect(&f, "synthetic-fresh-reconnect");
    upstream::allowed(&f, &r, &a.token, "accounts/check", "Y").await;
    f.stop();
    keys.start(&mut f, Some("stored"), Some("oauth")).await;
    upstream::allowed(&f, &r, &a.token, "accounts/check", "Y").await;
    assert_eq!((p.counts().0, p.counts().1), (3, 3));
    assert!((2..=3).contains(&p.counts().2));
    println!("pending provider arrivals/consumed/issued={:?}", p.counts());
    keys.safe(
        &f,
        &[
            &a.token,
            "synthetic-fresh-reconnect",
            "synthetic-rotation-3",
        ],
    );
    f.cleanup();
    snapshot.unchanged();
    p.stop().await;
    let address = *r.server.address();
    drop(r);
    upstream::closed(address).await;
    println!(
        "SEALED pending snapshot from killed source/WAL: restore+restart token replay0/API0, fresh reconnect Y2/token1; all owned processes joined"
    );
}

pub async fn quarantine() {
    let r = upstream::Receiver::start().await;
    let p = Provider::start().await;
    let keys = Keys::new();
    let mut source = Fixture::new(&r.server.uri());
    keys.start(&mut source, Some("stored"), Some("oauth")).await;
    let stored = recovery::stored(&source);
    let old = setup::enroll_url(&source, &p.url).await;
    common::connect(&source, "synthetic-first-refresh");
    source.op(&["agent", "revoke", &old.id]);
    source.stop();
    // Model an old snapshot whose access token has expired by recovery time.
    common::expiry(&source, 1);
    let snapshot = Snapshot::take(&source);
    // Real post-snapshot decision in source custody, with OAuth still quarantined.
    keys.start(&mut source, None, None).await;
    source.op(&["agent", "revoke", &stored.id]);
    assert!(!source.op(&["agent", "get", "stored-reader"])["revoked_at"].is_null());
    source.stop();
    let mut f = snapshot.restore(&r.server.uri());
    keys.start(&mut f, None, None).await;
    assert!(
        f.op(&["agent", "get", &stored.id])["revoked_at"].is_null(),
        "old snapshot predates revocation"
    );
    let inventory = f.op(&["agent", "list", "--include-revoked"]);
    assert!(
        inventory
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["public_id"] == old.id)
    );
    assert!(
        !process::run(f.cli(&["agent", "credentials", "list", &old.id]))
            .status
            .success(),
        "known revoked-id lookup limit"
    );
    assert_eq!(f.op(&["agent", "get", "oauth-reader"])["public_id"], old.id);
    // Revoking removed the agent's bindings in the same write (#157).
    assert!(
        f.op(&["agent", "credentials", "list", "oauth-reader"])
            .as_array()
            .unwrap()
            .is_empty()
    );
    // An externally retained post-snapshot revocation is deliberately reconciled.
    f.op(&["agent", "revoke", &stored.id]);
    assert_eq!(p.counts(), (1, 1, 1));
    f.stop();
    keys.start(&mut f, Some("stored"), Some("oauth")).await;
    assert_eq!(f.op(&["oauth", "list"]).as_array().unwrap().len(), 1);
    setup::revoke(&f);
    for (token, route) in [
        (&old.token, "accounts/check"),
        (&stored.token, "stored/check"),
    ] {
        upstream::denied(&f, &r, Some(token), route, 401, "invalid_credential").await;
    }
    assert_eq!(
        p.counts(),
        (1, 1, 1),
        "no startup refresh from revoked-only recovered binding"
    );
    assert_eq!(r.snapshot().await, ([0, 0, 0], 0));
    common::connect(&f, "synthetic-fresh-reconnect");
    let fresh = super::setup::register(&f, "fresh-reader");
    f.op(&[
        "agent",
        "set-credential",
        &fresh.id,
        "accounts",
        "--oauth-session",
        "reader",
    ]);
    upstream::allowed(&f, &r, &fresh.token, "accounts/check", "Y").await;
    f.stop();
    keys.start(&mut f, Some("stored"), Some("oauth")).await;
    upstream::allowed(&f, &r, &fresh.token, "accounts/check", "Y").await;
    assert_eq!(p.counts(), (2, 2, 2));
    keys.safe(
        &f,
        &[
            &old.token,
            &stored.token,
            &fresh.token,
            "synthetic-first-refresh",
            "synthetic-fresh-reconnect",
            "synthetic-rotation-1",
            "synthetic-rotation-2",
        ],
    );
    f.cleanup();
    snapshot.unchanged();
    p.stop().await;
    let address = *r.server.address();
    drop(r);
    upstream::closed(address).await;
    println!(
        "SEALED old unmarked snapshot: key-omitted/revoked-owner inventory/clear/key-present revoke token0/API0; fresh provision Y2/token1; post-snapshot revoke reconciled"
    );
}
