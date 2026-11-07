use super::*;

pub(super) fn configure_contract(f: &Fixture, t: &Twin, service: bool, slack: bool) {
    let port = configure(f, t);
    let path = f.path().join("config.yaml");
    let mut c: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let p = &mut c["oauth_consent"]["profiles"][0];
    p["kind"] = json!("custom-oauth-v1");
    p["authorization_endpoint"] = json!(t.url("/authorize/custom"));
    p["token_endpoint"] = json!(t.url("/token/custom"));
    p["resource"] = json!(t.url("/resource/custom"));
    p["redirect_uri"] = json!(format!(
        "https://127.0.0.1:{port}/oauth/callback/custom/loopback"
    ));
    p.as_object_mut().unwrap().remove("expected_workspace");
    p.as_object_mut().unwrap().remove("expected_user");
    p["contract"] = contract(t, service, slack);
    std::fs::write(path, c.to_string()).unwrap();
}
fn contract(t: &Twin, service: bool, slack: bool) -> Value {
    let subject = if service {
        json!({"kind":"service_principal","subject_id":"service-invented"})
    } else {
        json!({"kind":"user_workspace","workspace_id":"workspace-invented","user_id":"user-invented"})
    };
    json!({"version":1,"grant":"authorization_code_s256","registration":"pre_registered",
        "client_auth":if service {"none"} else {"client_secret_post"},"approved_origins":[t.url("")],
        "mcp_endpoint":t.url("/mcp/custom"),"callback":"distinct_redirect","subject":subject,
        "scope":{"required":["catalog:inspect","records:read"],"request_separator":"space","response_separator":"space_or_comma"},
        "token_response":if slack {"slack-user-v2"} else {"oauth2-bearer-v1"},
        "identity":{"endpoint":t.url("/identity/custom"),"method":if slack {"post"} else {"get"},"response":if slack {"slack-auth-test-v1"} else if service {"service-principal-v1"} else {"workspace-user-v1"}}})
}
pub(super) fn promote(f: &Fixture, t: &Twin) {
    import(f);
    f.op(&[
        "tool",
        "from-definition",
        "fixture",
        "--definition",
        "local.declared-service",
        "--revision",
        "1",
        "--auth-profile",
        "controlled",
        "--upstream",
        &t.url("/mcp/custom"),
        "--allow-private-destination",
    ]);
    activate(f);
    assert!(!f.path().join("counts.json").exists());
}
pub(super) fn connect_contract(f: &Fixture, label: &str) -> Value {
    let status = f.op(&["oauth", "account-status", "fixture", "--label", label]);
    f.op(&[
        "oauth",
        "connect",
        "fixture",
        "--label",
        label,
        "--profile",
        "fixture",
        "--client-generation",
        "1",
        "--redirect-profile",
        "loopback",
        "--expected-config-revision",
        &status["config_revision"].to_string(),
        "--scopes",
        "catalog:inspect,records:read",
    ])
}

fn import(f: &Fixture) {
    let mut d: Value = serde_json::from_str(include_str!(
        "../../../definitions/customer-controlled.example.json"
    ))
    .unwrap();
    d["id"] = json!("local.declared-service");
    d["auth_profiles"][0]["required_scopes"] = json!(["catalog:inspect", "records:read"]);
    let path = f.path().join("definition.json");
    std::fs::write(&path, d.to_string()).unwrap();
    f.op(&["integration", "import", "--file", path.to_str().unwrap()]);
}

fn activate(f: &Fixture) {
    let before = f.op(&["tool", "get", "fixture"]);
    f.op(&[
        "tool",
        "activate-definition",
        "fixture",
        "--if-match",
        before["definition_control"]["revision"].as_str().unwrap(),
        "--compact",
        "--oauth-profile",
        "fixture",
        "--contract-policy",
        "finite-v2",
        "--selected-tool",
        "search_messages",
        "--selected-tool",
        "read_thread",
    ]);
}
