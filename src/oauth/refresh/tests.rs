use super::*;

#[test]
fn safety_margin_uses_five_minutes_for_long_lifetime() {
    // 1-hour token: lifetime/4 = 900s; capped at 300s.
    assert_eq!(refresh_safety_margin_secs(3600), 300);
    // 24-hour token: lifetime/4 = 21600s; capped at 300s.
    assert_eq!(refresh_safety_margin_secs(86400), 300);
}

#[test]
fn safety_margin_uses_quarter_for_short_lifetime() {
    // 15-min token: lifetime/4 = 225s; floor at 60s; chosen 225.
    assert_eq!(refresh_safety_margin_secs(900), 225);
}

#[test]
fn safety_margin_floors_at_sixty() {
    // 2-min token: lifetime/4 = 30s; floored to 60s.
    assert_eq!(refresh_safety_margin_secs(120), 60);
    // 30-second token (pathological): lifetime/4 = 7s; floor 60s.
    assert_eq!(refresh_safety_margin_secs(30), 60);
}

#[tokio::test]
async fn lock_map_returns_same_lock_for_same_name_and_label() {
    let map = RefreshLockMap::new();
    let l1 = map.get("codex", "default").await;
    let l2 = map.get("codex", "default").await;
    assert!(Arc::ptr_eq(&l1, &l2));

    let l3 = map.get("anthropic-oauth", "default").await;
    assert!(!Arc::ptr_eq(&l1, &l3));
}

// Phase G: distinct labels under the same registration name get
// distinct locks, so two labels can refresh concurrently without
// serializing on each other.
#[tokio::test]
async fn lock_map_distinguishes_labels_under_same_name() {
    let map = RefreshLockMap::new();
    let l_default = map.get("codex", "default").await;
    let l_hermes = map.get("codex", "hermes").await;
    let l_openclaw = map.get("codex", "openclaw").await;
    assert!(!Arc::ptr_eq(&l_default, &l_hermes));
    assert!(!Arc::ptr_eq(&l_hermes, &l_openclaw));
    assert!(!Arc::ptr_eq(&l_default, &l_openclaw));
}
