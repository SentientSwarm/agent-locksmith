"""F-001: docs/reference/cli-reference.md#upstream-method-policy.

Real daemon + operator CLI + recording Slack upstream, with no Slack writes.
"""
import pytest
from fakes.agt_support import audit, enrol, put_tool
from fakes.agt_upstream import Upstream
from fakes.cat_uds import uds

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
PUT = "admin.PUT./admin/operator/agents/{public_id}/credentials/{registration}/method-policy"
DELETE = "admin.DELETE./admin/operator/agents/{public_id}/credentials/{registration}/method-policy"
CLI = "cli.agent.method-policy"


@pytest.fixture(scope="module")
def mp(target_factory):
    up = Upstream()
    t = target_factory(label="agt-method-policy")
    put_tool(t, "slack-policy", f"{up.url}/api", "none", "--egress", "direct")
    a = enrol(t, "qa-policy-a", ["slack-policy"], {"slack-policy": ["--no-auth"]})
    b = enrol(t, "qa-policy-b", ["slack-policy"], {"slack-policy": ["--no-auth"]})
    yield t, up, a, b
    up.close()


def policy(t, a, *args):
    r = t.cli("agent", "method-policy", a["id"], "slack-policy", *args)
    assert r.code == 0, r.err
    return r.json


def call(t, a, method):
    return t.http("POST", f"/api/slack-policy/{method}", token=a["token"])


@case("SMK-AGT-090", area="AGT", kind="positive", covers=[PUT, DELETE, CLI, API])
def test_method_policy_lifecycle(mp):
    """Policies apply live, are binding-specific, and survive credential replacement."""
    t, up, a, b = mp
    assert call(t, a, "admin.users.list").status == 200
    saved = policy(t, a, "--allow", "conversations.*,chat.*,users.*,auth.test",
                   "--deny", "admin.*,team.*,users.profile.set,apps.*")
    assert "users.profile.set" in saved["method_policy"]["deny"]
    for method in ("chat.postMessage", "conversations.history", "auth.test", "users.info"):
        sent = len(up.records)
        assert call(t, a, method).status == 200
        assert len(up.records) == sent + 1
        assert up.records[-1].path == f"/api/{method}"
    # Another binding on the same route is unaffected.
    assert call(t, b, "admin.users.list").status == 200
    reset = t.cli("agent", "set-credential", a["id"], "slack-policy", "--no-auth")
    assert reset.code == 0, reset.err
    sent = len(up.records)
    assert call(t, a, "users.profile.set").status == 403
    assert len(up.records) == sent
    policy(t, a, "--allow", "auth.test")
    assert call(t, a, "chat.postMessage").status == 403
    policy(t, a, "--clear")
    assert call(t, a, "chat.postMessage").status == 200
    policy(t, a)  # Explicit empty policy denies everything.
    assert call(t, a, "auth.test").status == 403
    # Policy belongs to the binding, and cannot reappear on a new binding.
    unset = t.cli("agent", "unset-credential", a["id"], "slack-policy")
    assert unset.code == 0, unset.err
    reset = t.cli("agent", "set-credential", a["id"], "slack-policy", "--no-auth")
    assert reset.code == 0, reset.err
    assert call(t, a, "auth.test").status == 200
    changes = audit(t, "slack-policy", "method_policy_changed")
    assert len(changes) >= 4
    assert all(r["agent_public_id"] == a["id"] for r in changes)
    assert a["token"] not in str(changes)
    assert b["token"] not in str(changes)


@case("SMK-AGT-091", area="AGT", kind="refusal", covers=[API], codes=["method_not_allowed"])
def test_method_policy_denies_without_dispatch(mp):
    """Deny wins, unlisted and nonliteral paths fail closed, including encoded aliases."""
    t, up, a, _ = mp
    policy(t, a, "--allow", "*", "--deny", "admin.*,team.*,users.profile.set,apps.*")
    for method in ("admin.users.list", "users.profile.set", "apps.connections.open", "team.info"):
        sent = len(up.records)
        r = call(t, a, method)
        assert r.status == 403 and r.code == "method_not_allowed", (method, r.text)
        assert len(up.records) == sent
    policy(t, a, "--allow", "chat.*")
    for method in ("search.all", "chat%2epostMessage", "chat%252epostMessage",
                   "chat.postMessage/", "chat.postMessage/../users.profile.set",
                   "chat.postMessage%2f..%2fusers.profile.set"):
        sent = len(up.records)
        r = call(t, a, method)
        assert r.status == 403 and r.code == "method_not_allowed", (method, r.text)
        assert len(up.records) == sent
    refusals = audit(t, "slack-policy", "method_policy_denied")
    assert len(refusals) >= 10
    assert all(r["agent_public_id"] == a["id"] for r in refusals)
    assert a["token"] not in str(refusals)


@case("SMK-AGT-092", area="AGT", kind="refusal", covers=[PUT, DELETE],
      codes=["invalid_method_policy", "invalid_credential", "agent_not_found", "grant_target_invalid"])
def test_method_policy_admin_refusals(mp):
    """Only operators may write valid policies on existing HTTP bindings."""
    t, up, a, _ = mp
    path = f'/admin/operator/agents/{a["id"]}/credentials/slack-policy/method-policy'
    for method in ("PUT", "DELETE"):
        r = uds(t, method, path, {"allow": [], "deny": []} if method == "PUT" else None,
                token=a["token"])
        assert r.status == 401 and r.code == "invalid_credential"
    for bad in ("chat*", "chat.*/oops", "chat.%2e", "chat..postMessage"):
        r = uds(t, "PUT", path, {"allow": [bad], "deny": []})
        assert r.status == 400 and r.code == "invalid_method_policy"
    r = uds(t, "PUT", path.replace(a["id"], "qa-no-agent"), {"allow": [], "deny": []})
    assert r.status == 404 and r.code == "agent_not_found"
    r = uds(t, "PUT", path.replace("slack-policy", "no-binding"), {"allow": [], "deny": []})
    assert r.status == 400 and r.code == "grant_target_invalid", r.text
