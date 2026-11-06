use super::*;
pub(super) fn grant_policy(f: &fixture::Fixture, id: &str) -> Value {
    let state = flow::observe(f, id);
    let entries = state["observation"]["manifest"]["tools"]
        .as_array()
        .unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(
        state["observation"]["manifest"]["projection"],
        json!({"policy":"explicit_registration_tools_v1","total":41,"selected":4,"omitted":37})
    );
    let grants = entries
        .iter()
        .map(|entry| review_one(f, id, &state, entry))
        .collect::<Vec<_>>();
    let file = flow::write(
        f,
        json!({"source":state["source"],"generation":state["observation"]["generation"],"revision":state["grant_revision"],"tools":grants}),
    );
    f.op(&[
        "agent",
        "mcp-grants",
        "replace",
        "native",
        "--agent",
        id,
        "--file",
        &file,
    ])
}
fn review_one(f: &fixture::Fixture, id: &str, state: &Value, entry: &Value) -> Value {
    let mut request = json!({"source":state["source"],"generation":state["observation"]["generation"],"name":entry["tool"]["name"],"observed_digest":entry["observed_digest"],"effect":"read","contract_policy":"finite-v2"});
    if entry["tool"]["name"] == "empty_record" {
        request["input_restriction"] = "empty-arguments".into();
    }
    refuse_forged(f, id, &request);
    let file = flow::write(f, request);
    let review = f.op(&[
        "tool", "mcp", "review", "native", "--agent", id, "--file", &file,
    ]);
    assert_eq!(review["contract"]["tool"], entry["tool"]);
    if entry["tool"]["name"] == "empty_record" {
        assert!(
            review["contract"]["tool"]["inputSchema"]
                .get("additionalProperties")
                .is_none()
        );
        assert_eq!(
            review["callable_input_schema"]["additionalProperties"],
            false
        );
    }
    json!({"name":entry["tool"]["name"],"contract_digest":review["contract_digest"]})
}
fn refuse_forged(f: &fixture::Fixture, id: &str, request: &Value) {
    let mut forged = request.clone();
    forged["contract_policy"] = "finite-v1".into();
    let file = flow::write(f, forged);
    assert!(
        !process::run(f.command(&[
            "tool", "mcp", "review", "native", "--agent", id, "--file", &file
        ]))
        .status
        .success()
    );
}
