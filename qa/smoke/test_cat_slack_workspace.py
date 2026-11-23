"""F-002: docs/reference/cli-reference.md#slack-workspace-check.

Real CLI/daemon and local auth.test upstream; no Slack account or writes needed.
"""
import json

import pytest
from fakes.agt_support import audit, enrol, put_tool, sealing_key
from fakes.agt_upstream import Reply, Upstream

case = pytest.mark.case
PUT = "admin.PUT./admin/operator/tools/{name}"
KEY = "admin.PUT./admin/operator/tools/{name}/credential"
STORED = "admin.PUT./admin/operator/agents/{public_id}/credentials/{registration}/credential"
TOKEN_A = "slack-synthetic-workspace-token-a"
TOKEN_B = "slack-synthetic-workspace-token-b"
TEAM = "TQA123"


@pytest.fixture
def workspace(target_factory):
    up = Upstream()
    t = target_factory(label="cat-slack-workspace", upstream=False,
                       env={"LOCKSMITH_CREDENTIAL_SEALING_KEY": sealing_key()})
    for value in (TOKEN_A, TOKEN_B):
        t.canaries.add(value, "slack-synthetic-token")
    put_tool(t, "slack-ws", f"{up.url}/api", "none", "--egress", "direct",
             "--broker", "--slack-team-id", TEAM)
    put_tool(t, "slack-agent", f"{up.url}/api", "none", "--egress", "direct",
             "--slack-team-id", TEAM)
    a = enrol(t, "qa-slack-workspace", ["slack-ws", "slack-agent"],
              {"slack-ws": ["--broker"], "slack-agent": ["--no-auth"]})
    yield t, up, a
    up.close()
    raw = t.log_text() + str(audit(t, "slack-ws")) + str(audit(t, "slack-agent"))
    assert TOKEN_A not in raw and TOKEN_B not in raw


def reply(up, team=TEAM, **extra):
    up.routes["/api/auth.test"] = Reply(content_type="application/json",
        body=json.dumps({"ok": True, "team_id": team, **extra}).encode())


def set_key(t, a, value, binding=False):
    args = ("agent", "set-credential", a["id"], "slack-agent", "--stored-bearer-stdin") if binding else ("tool", "set-key", "slack-ws")
    result = t.cli(*args, stdin=value + "\n")
    assert value not in result.out + result.err
    return result


def reference(t, a, binding):
    if not binding:
        return t.cli("tool", "get", "slack-ws").json["auth"]
    return t.cli("agent", "credentials", "list", a["id"]).json


@case("SMK-CAT-100", area="CAT", kind="positive",
      covers=[PUT, KEY, STORED, "cli.tool.put", "cli.tool.set-key", "cli.agent.set-credential"])
def test_slack_workspace_accepts_and_rechecks_live(workspace):
    t, up, a = workspace
    for binding in (False, True):
        reply(up)
        saved = set_key(t, a, TOKEN_A, binding)
        assert saved.code == 0, saved.err
        assert up.last("/api/auth.test").header("authorization") == f"Bearer {TOKEN_A}"
        first = reference(t, a, binding)
        reply(up)
        rotated = set_key(t, a, TOKEN_B, binding)
        assert rotated.code == 0, rotated.err
        assert reference(t, a, binding) != first
        route = "slack-agent" if binding else "slack-ws"
        assert t.http("POST", f"/api/{route}/chat.postMessage", token=a["token"]).status == 200
        assert up.last("/api/chat.postMessage").header("authorization") == f"Bearer {TOKEN_B}"
    events = audit(t, "slack-ws", "proxy_request")
    assert TOKEN_A not in str(events) and TOKEN_B not in str(events)


@case("SMK-CAT-101", area="CAT", kind="refusal", covers=[KEY, STORED],
      codes=["slack_workspace_mismatch", "slack_workspace_check_failed"])
def test_slack_workspace_refuses_without_replacing(workspace):
    t, up, a = workspace
    for binding in (False, True):
        # First refusal stores no key; later refusals preserve the accepted one.
        reply(up, "TOTHER")
        before = reference(t, a, binding)
        refused = set_key(t, a, TOKEN_A, binding)
        assert refused.code != 0 and "slack_workspace_mismatch" in refused.err
        assert TEAM in refused.err and "TOTHER" in refused.err
        assert reference(t, a, binding) == before
        reply(up)
        assert set_key(t, a, TOKEN_A, binding).code == 0
        before = reference(t, a, binding)
        for response in (
            Reply(body=b'{"ok":true,"team_id":"TOTHER"}'),
            Reply(body=json.dumps({"ok": False, "error": TOKEN_B}).encode()),
            Reply(body=json.dumps({"ok": True, "team_id": TOKEN_B}).encode()),
            Reply(body=b'{"ok":true}'), Reply(body=b'not-json'),
            Reply(body=b'x' * 17000),
            Reply(status=302, headers={"Location": f"{up.url}/leaked"}),
            Reply(status=429, body=TOKEN_B.encode()),
            Reply(delay=5.3, body=b'{"ok":true,"team_id":"TQA123"}'),
        ):
            up.routes["/api/auth.test"] = response
            sent = len(up.records)
            refused = set_key(t, a, TOKEN_B, binding)
            assert refused.code != 0
            assert len(up.records) == sent + 1  # No redirects or retries.
            assert reference(t, a, binding) == before
        assert up.count("/leaked") == 0
        route = "slack-agent" if binding else "slack-ws"
        assert t.http("POST", f"/api/{route}/chat.postMessage", token=a["token"]).status == 200
        assert up.last("/api/chat.postMessage").header("authorization") == f"Bearer {TOKEN_A}"


@case("SMK-CAT-102", area="CAT", kind="refusal", covers=[PUT], codes=["invalid_metadata"])
def test_slack_workspace_declaration_is_valid_and_immutable(workspace):
    t, up, _ = workspace
    for team in ("TOTHER", "bad-team", "", "T" + "X" * 64):
        r = t.cli("tool", "put", "slack-ws", "--upstream", f"{up.url}/api",
                  "--auth", "none", "--egress", "direct", "--broker", "--slack-team-id", team)
        assert r.code != 0 and "invalid_metadata" in r.err
    r = t.cli("tool", "put", "slack-ws", "--upstream", f"{up.url}/api",
              "--auth", "none", "--egress", "direct", "--broker")
    assert r.code != 0  # Omitting the declaration cannot silently clear it.
    assert up.count() == 0
    assert t.cli("tool", "get", "slack-ws").json["metadata"]["slack_team_id"] == TEAM
    # Unconfigured routes still ingest keys offline, without auth.test.
    put_tool(t, "plain-ws", up.url, "none", "--egress", "direct")
    assert t.cli("tool", "set-key", "plain-ws", stdin=TOKEN_A).code == 0
    assert up.count() == 0


@case("SMK-CAT-103", area="CAT", kind="corner", covers=[KEY, STORED])
def test_slack_workspace_concurrent_route_change_cannot_store_unchecked_key(workspace):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    t, up, a = workspace
    for binding in (False, True):
        reply(up)
        assert set_key(t, a, TOKEN_A, binding).code == 0
        before = reference(t, a, binding)
        entered, release = threading.Event(), threading.Event()

        def paused(_path, _body):
            entered.set()
            assert release.wait(15)
            return Reply(body=json.dumps({"ok": True, "team_id": TEAM}).encode())

        up.routes["/api/auth.test"] = paused
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(set_key, t, a, TOKEN_B, binding)
            try:
                assert entered.wait(10)
                route = "slack-agent" if binding else "slack-ws"
                flags = ["--auth", "none"] if binding else ["--broker"]
                changed = t.cli("tool", "put", route, "--upstream", f"{up.url}/api",
                    "--egress", "direct", "--slack-team-id", TEAM,
                    "--description", "concurrent edit", *flags)
                assert changed.code == 0, changed.err
            finally:
                release.set()
            assert pending.result().code != 0
        assert reference(t, a, binding) == before


@case("SMK-CAT-104", area="CAT", kind="refusal", covers=[KEY],
      codes=["slack_workspace_check_failed"])
def test_slack_workspace_verification_cannot_bypass_required_egress(workspace):
    t, up, _ = workspace
    put_tool(t, "slack-proxied", f"{up.url}/api", "none", "--egress", "proxied",
             "--slack-team-id", TEAM)
    reply(up)
    r = t.cli("tool", "set-key", "slack-proxied", stdin=TOKEN_A)
    assert r.code != 0 and "slack_workspace_check_failed" in r.err
    assert up.count() == 0


@case("SMK-CAT-105", area="CAT", kind="refusal",
      covers=["admin.PUT./admin/operator/agents/{public_id}/credentials/{registration}", STORED, PUT],
      codes=["slack_workspace_selection_unsupported", "invalid_metadata"])
def test_slack_workspace_refuses_unverified_selections(workspace):
    from fakes.cat_uds import uds
    t, up, a = workspace
    # A live secret from another, undeclared route is not proof of workspace.
    put_tool(t, "source-ref", up.url, "none", "--egress", "direct")
    assert t.cli("tool", "set-key", "source-ref", stdin=TOKEN_B).code == 0
    ref = t.cli("tool", "get", "source-ref").json["auth"]["secret_ref"]
    reply(up)
    assert set_key(t, a, TOKEN_A, True).code == 0
    before = reference(t, a, True)
    sent = up.count()
    for auth in ({"kind": "stored_bearer", "secret_ref": ref},
                 {"kind": "stored_header", "secret_ref": ref, "header": "X-Slack-Key"}):
        r = uds(t, "PUT", f"/admin/operator/agents/{a['id']}/credentials/slack-agent",
                {"auth_spec": auth})
        assert r.status == 400 and r.code == "slack_workspace_selection_unsupported", r.text
        assert reference(t, a, True) == before
    r = t.cli("agent", "set-credential", a["id"], "slack-agent", "--stored-bearer-ref", ref)
    assert r.code != 0 and "slack_workspace_selection_unsupported" in r.err
    assert reference(t, a, True) == before
    assert up.count() == sent  # Refused locally, with no provider call.
    # Direct route-auth reference attachment is also unverified.
    r = uds(t, "PUT", "/admin/operator/tools/slack-agent", {
        "upstream": f"{up.url}/api", "auth": {"kind": "stored_bearer", "secret_ref": ref},
        "metadata": {"slack_team_id": TEAM}, "egress": "direct"})
    assert r.status == 400 and r.code == "invalid_metadata", r.text
    # Custom-header stdin selections, explicit and inferred, store nothing.
    for body, status, code in (
        ({"value": TOKEN_B, "header": "X-Slack-Key"}, 502, "slack_workspace_check_failed"),
        ({"value": TOKEN_B, "stored_header": True}, 400, "invalid_stored_credential"),
    ):
        r = uds(t, "PUT", f"/admin/operator/agents/{a['id']}/credentials/slack-agent/credential", body)
        assert r.status == status and r.code == code, r.text
        assert reference(t, a, True) == before
    # Same selections still work on undeclared routes.
    put_tool(t, "plain-ref", up.url, "none", "--egress", "direct")
    for auth in ({"kind": "stored_bearer", "secret_ref": ref},
                 {"kind": "stored_header", "secret_ref": ref, "header": "X-Slack-Key"}):
        r = uds(t, "PUT", f"/admin/operator/agents/{a['id']}/credentials/plain-ref", {"auth_spec": auth})
        assert r.status == 200, r.text
    reply(up)
    assert t.http("POST", "/api/slack-agent/auth.test", token=a["token"]).status == 200
    assert up.last("/api/auth.test").header("authorization") == f"Bearer {TOKEN_A}"


@case("SMK-CAT-106", area="CAT", kind="refusal",
      covers=["admin.PUT./admin/operator/routes/{route}/backends/{backend}/credential",
              "admin.POST./admin/operator/routes/{route}/switch"],
      codes=["slack_workspace_backend_unsupported"])
def test_slack_workspace_refuses_backend_credentials_and_switch(workspace):
    from fakes.cat_uds import uds
    t, up, a = workspace
    reply(up)
    assert set_key(t, a, TOKEN_A).code == 0
    put = t.cli("route", "backend", "put", "slack-ws", "other", "--upstream", up.url,
                "--auth", "none", "--egress", "direct", "--broker")
    assert put.code == 0, put.err
    ref = t.cli("tool", "get", "slack-ws").json["auth"]["secret_ref"]
    assert uds(t, "PUT", "/admin/operator/routes/slack-ws/backends/other", {
        "upstream": up.url, "egress": "direct", "broker": t.cli("tool", "get", "slack-ws").json["broker"],
        "auth": {"kind": "stored_bearer", "secret_ref": ref}}).status == 200
    before = t.cli("route", "backend", "list", "slack-ws").json
    sent = up.count()
    path = "/admin/operator/routes/slack-ws"
    for value in (TOKEN_A, TOKEN_B):
        r = uds(t, "PUT", path + "/backends/other/credential", {"value": value})
        assert r.status == 409 and r.code == "slack_workspace_backend_unsupported", r.text
        assert value not in r.text
    r = uds(t, "POST", path + "/switch", {"backend": "other"},
            headers={"If-Match": str(before["revision"])})
    assert r.status == 409 and r.code == "slack_workspace_backend_unsupported", r.text
    assert t.cli("route", "backend", "list", "slack-ws").json == before
    assert up.count() == sent
    assert t.http("POST", "/api/slack-ws/auth.test", token=a["token"]).status == 200
    assert up.last("/api/auth.test").header("authorization") == f"Bearer {TOKEN_A}"
