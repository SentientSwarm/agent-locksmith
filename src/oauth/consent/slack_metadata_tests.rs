use super::*;

fn valid() -> Value {
    json!({"ok":true,"access_token":"invented-access-canary","token_type":"user",
        "team":{"id":"TTEST001"},"authed_user":{"id":"UTEST001",
        "scope":"channels:history,search:read.public"}})
}

fn reason(v: &Value) -> &'static str {
    match token::decode(&profile(), &serde_json::to_vec(v).unwrap()) {
        Ok(_) => "accepted",
        Err(e) => e.0,
    }
}

#[test]
fn metadata_optional_echoes_are_categorical_and_reveal_no_values() {
    let mut results = Vec::new();
    for key in [
        "issuer",
        "iss",
        "resource",
        "client_id",
        "scope",
        "team_id",
        "user_id",
    ] {
        for (value, suffix) in [
            (Value::Null, "null"),
            (json!([]), "type"),
            (json!("invented-private-canary"), "mismatch"),
        ] {
            let mut v = valid();
            v[key] = value;
            let field = root_field(key);
            results.push((
                reason(&v).to_string(),
                format!("slack_token_{field}_{suffix}"),
            ));
        }
    }
    assert!(
        results.iter().all(|(got, expected)| got == expected),
        "{results:?}"
    );
}

#[test]
fn metadata_required_container_and_leaf_categories() {
    let mut results = Vec::new();
    containers(&mut results);
    for (parent, leaf) in [
        ("team", "id"),
        ("authed_user", "id"),
        ("authed_user", "scope"),
    ] {
        for (value, suffix) in [
            (None, "missing"),
            (Some(Value::Null), "null"),
            (Some(json!(false)), "type"),
            (Some(json!("invented-private-canary")), "mismatch"),
        ] {
            let mut v = valid();
            v[parent].as_object_mut().unwrap().remove(leaf);
            if let Some(value) = value {
                v[parent][leaf] = value;
            }
            results.push((
                reason(&v).to_string(),
                format!("slack_token_{parent}_{leaf}_{suffix}"),
            ));
        }
    }
    assert!(
        results.iter().all(|(got, expected)| got == expected),
        "{results:?}"
    );
}

#[test]
fn metadata_nested_conflicts_keep_absence_null_and_types_distinct() {
    let mut results = Vec::new();
    for key in ["access_token", "refresh_token", "expires_in", "token_type"] {
        for (value, suffix) in [
            (Value::Null, "null"),
            (json!([]), "type"),
            (
                if key == "expires_in" {
                    json!(10)
                } else {
                    json!("other-canary")
                },
                "conflict",
            ),
        ] {
            let mut v = valid();
            v["authed_user"][key] = value;
            results.push((
                reason(&v).to_string(),
                format!("slack_token_nested_{key}_{suffix}"),
            ));
        }
    }
    assert!(
        results.iter().all(|(got, expected)| got == expected),
        "{results:?}"
    );
}

#[test]
fn metadata_supported_variants_and_equal_nested_values_stay_accepted() {
    let p = profile();
    let mut v = valid();
    assert_eq!(reason(&v), "accepted");
    for (key, value) in [
        ("issuer", &p.issuer),
        ("iss", &p.issuer),
        ("resource", &p.resource),
        ("client_id", &p.client_id),
        ("team_id", &p.expected_workspace),
        ("user_id", &p.expected_user),
    ] {
        v[key] = json!(value);
    }
    v["scope"] = json!("search:read.public,channels:history");
    for (refresh, expiry) in [
        (Value::Null, Value::Null),
        (json!("invented-refresh-canary"), json!(3600)),
    ] {
        v["refresh_token"] = refresh;
        v["expires_in"] = expiry;
        for key in ["access_token", "refresh_token", "expires_in", "token_type"] {
            v["authed_user"][key] = v[key].clone();
        }
        assert_eq!(reason(&v), "accepted");
    }
}

#[test]
fn metadata_duplicate_and_invalid_json_remain_closed() {
    let p = profile();
    for bytes in [
        br#"{"ok":true,"ok":true}"#.as_slice(),
        br#"{"team":{"id":"one","id":"two"}}"#,
        br#"{"ok":true,"\u006fk":true}"#,
    ] {
        assert_eq!(token::decode(&p, bytes).err().unwrap().0, "json_refused");
    }
    let mut v = valid();
    v["access_token"] = json!("x".repeat(8193));
    assert_eq!(reason(&v), "token_invalid");
    for scope in [
        "channels:history,channels:history",
        "channels:history, search:read.public",
        "channels:history,search:read.public,extra",
    ] {
        v = valid();
        v["authed_user"]["scope"] = json!(scope);
        assert_ne!(reason(&v), "accepted");
    }
}

fn root_field(key: &str) -> String {
    if ["scope", "team_id", "user_id"].contains(&key) {
        format!("root_{key}")
    } else {
        key.to_string()
    }
}

fn containers(results: &mut Vec<(String, String)>) {
    for parent in ["team", "authed_user"] {
        for (value, suffix) in [
            (None, "missing"),
            (Some(Value::Null), "null"),
            (Some(json!([])), "type"),
        ] {
            let mut v = valid();
            v.as_object_mut().unwrap().remove(parent);
            if let Some(value) = value {
                v[parent] = value;
            }
            results.push((
                reason(&v).to_string(),
                format!("slack_token_{parent}_{suffix}"),
            ));
        }
    }
}
