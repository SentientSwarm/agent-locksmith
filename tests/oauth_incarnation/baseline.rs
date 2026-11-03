use super::support::*;

#[tokio::test]
async fn late_update_must_not_replace_recreated_account() -> Result<(), Error> {
    let (_dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old-fixture").await?;
    repo.delete("fixture", "reader").await?;
    seed(&repo, &key, "replacement-fixture").await?;
    let result = repo
        .update_tokens(&key, &old, "late-fixture", 7200, None)
        .await;
    let current = repo
        .get(&key, "fixture", "reader")
        .await?
        .ok_or("missing")?;
    let preserved = current.access_token.unwrap().expose_secret() == "replacement-fixture";
    println!(
        "late_write_rejected={} replacement_preserved={preserved}",
        result.is_err()
    );
    assert!(
        result.is_err() && preserved,
        "stale write was accepted or replacement changed"
    );
    Ok(())
}

#[tokio::test]
async fn absent_row_update_must_report_conflict() -> Result<(), Error> {
    let (_dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old-fixture").await?;
    repo.delete("fixture", "reader").await?;
    let result = repo
        .update_tokens(&key, &old, "late-fixture", 7200, None)
        .await;
    println!("zero_row_write_rejected={}", result.is_err());
    assert!(result.is_err(), "zero-row update reported success");
    Ok(())
}

#[tokio::test]
async fn old_failure_must_not_degrade_recreated_account() -> Result<(), Error> {
    let (_dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old-fixture").await?;
    repo.delete("fixture", "reader").await?;
    seed(&repo, &key, "replacement-fixture").await?;
    let result = repo.mark_degraded(&old).await;
    let current = repo
        .get(&key, "fixture", "reader")
        .await?
        .ok_or("missing")?;
    println!(
        "stale_failure_rejected={} replacement_healthy={}",
        result.is_err(),
        !current.degraded
    );
    assert!(
        result.is_err() && !current.degraded,
        "stale failure affected replacement"
    );
    Ok(())
}
