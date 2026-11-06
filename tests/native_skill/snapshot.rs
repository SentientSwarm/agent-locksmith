use super::{fixture::Fixture, support as s};

pub async fn authority(f: &Fixture) -> Vec<(String, Vec<String>)> {
    let pool = s::pool(f).await;
    let mut snapshot = Vec::new();
    // Excludes expected authentication last-used touches and request audit writes.
    for table in [
        "registrations",
        "agent_credential_overrides",
        "credential_secrets",
        "native_observations",
        "native_reviews",
        "native_grant_sets",
        "native_tool_grants",
    ] {
        let columns: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?)")
            .bind(table)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(!columns.is_empty(), "missing snapshot table {table}");
        let quoted = columns
            .iter()
            .map(|c| format!("quote(\"{c}\")"))
            .collect::<Vec<_>>()
            .join(",");
        let mut rows: Vec<String> =
            sqlx::query_scalar(&format!("SELECT json_array({quoted}) FROM {table}"))
                .fetch_all(&pool)
                .await
                .unwrap();
        rows.sort();
        snapshot.push((table.to_owned(), rows));
    }
    pool.close().await;
    snapshot
}
