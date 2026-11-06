use super::{
    fixture::Fixture,
    oauth_setup, recovery_common,
    recovery_provider::Provider,
    sealed_recovery::{self as recovery, Keys, Snapshot},
    upstream,
};

pub async fn exercise() {
    let r = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let keys = Keys::new();
    let mut source = Fixture::new(&r.server.uri());
    keys.start(&mut source, Some("stored"), Some("oauth")).await;
    let stored = recovery::stored(&source);
    let oauth = oauth_setup::enroll_url(&source, &provider.url).await;
    recovery_common::connect(&source, "synthetic-first-refresh");
    upstream::allowed(&source, &r, &stored.token, "stored/check", "X").await;
    upstream::allowed(&source, &r, &oauth.token, "accounts/check", "Y").await;
    let authority = recovery::authority(&source, &[&stored, &oauth]);
    let sealed = recovery::ciphertext(&source);
    let audit = source.op(&["audit", "query", "--limit", "1000"]);
    for (agent, tool) in [(&stored.id, "stored"), (&oauth.id, "accounts")] {
        assert!(
            audit
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["agent_public_id"] == *agent
                    && row["tool"] == tool
                    && row["decision"] == "allowed"
                    && row["details"]["auth_source"] == "agent_override"),
            "receiving call has selected-agent audit attribution"
        );
    }

    keys.safe(
        &source,
        &[
            &stored.token,
            &oauth.token,
            "synthetic-first-refresh",
            "synthetic-rotation-1",
        ],
    );
    source.stop();
    let snapshot = Snapshot::take(&source);
    for (stored_key, oauth_key, stored_error, oauth_error) in [
        (Some("stored"), Some("oauth"), None, None),
        (None, Some("oauth"), Some("credential_unresolved"), None),
        (
            Some("wrong"),
            Some("oauth"),
            Some("credential_unresolved"),
            None,
        ),
        (Some("stored"), None, None, Some("oauth_sealing_key_unset")),
        (
            Some("stored"),
            Some("wrong"),
            None,
            Some("oauth_session_read_failed"),
        ),
    ] {
        let mut f = snapshot.restore(&r.server.uri());
        keys.start(&mut f, stored_key, oauth_key).await;
        assert!(
            recovery::authority(&f, &[&stored, &oauth]) == authority,
            "authority retained"
        );
        assert!(
            recovery::ciphertext(&f) == sealed,
            "sealed rows/identity/version retained"
        );
        let restored = f.op(&["audit", "query", "--limit", "1000"]);
        for row in audit.as_array().unwrap() {
            assert!(
                restored.as_array().unwrap().contains(row),
                "audit row retained"
            );
        }
        for _ in 0..2 {
            match stored_error {
                Some(code) => {
                    upstream::denied(&f, &r, Some(&stored.token), "stored/check", 503, code).await
                }
                None => upstream::allowed(&f, &r, &stored.token, "stored/check", "X").await,
            }
            match oauth_error {
                Some(code) => {
                    upstream::denied(&f, &r, Some(&oauth.token), "accounts/check", 503, code).await
                }
                None => upstream::allowed(&f, &r, &oauth.token, "accounts/check", "Y").await,
            }
            assert_eq!(
                provider.counts(),
                (1, 1, 1),
                "restore/key test caused no token exchange"
            );
            keys.safe(
                &f,
                &[
                    &stored.token,
                    &oauth.token,
                    "synthetic-first-refresh",
                    "synthetic-rotation-1",
                ],
            );
            f.stop();
            keys.start(&mut f, stored_key, oauth_key).await;
        }
        f.cleanup();
        snapshot.unchanged();
    }
    assert_eq!(r.snapshot().await, ([7, 7, 0], 14));
    provider.stop().await;
    let address = *r.server.address();
    drop(r);
    upstream::closed(address).await;
    println!(
        "SEALED restore: correct/absent/wrong independent keys, distinct directories, restart; X7/Y7, token1/consumed1/issued1; all refusals zero arrivals; sealed authority/audit preserved"
    );
}
