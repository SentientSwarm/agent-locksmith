"""One proxied HTTP call with its refusals (docs/user/getting-started.md)."""
import pytest

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"


@pytest.fixture(scope="module")
def caller(t1, accounts):
    reg = t1.cli("agent", "register", "--name", "qa-caller", "--allowlist", "accounts")
    assert reg.code == 0, reg.err
    bind = t1.cli("agent", "set-credential", reg.json["public_id"], "accounts", "--auth", "bearer=SMOKE_X")
    assert bind.code == 0, bind.err
    return {"id": reg.json["public_id"], "token": reg.json["token"]}


def unchanged(t1, before):
    assert t1.upstream_counts() == before, "a refused request reached the upstream"


@case("SMK-PROXY-001", area="PROXY", kind="positive", covers=[API, "cli.tool.put", "cli.agent.set-credential"])
def test_selected_account_reaches_upstream(t1, caller):
    before = t1.upstream_counts()
    response = t1.http("GET", "/api/accounts/check", token=caller["token"])
    assert response.status == 200
    assert response.text == "X"
    after = t1.upstream_counts()
    assert after["received"] == before["received"] + 1
    assert after["X"] == before["X"] + 1


@case("SMK-PROXY-002", area="PROXY", kind="refusal", covers=[API], codes=["invalid_credential"])
def test_missing_bearer_is_401(t1, caller):
    before = t1.upstream_counts()
    response = t1.http("GET", "/api/accounts/check")
    assert response.status == 401
    assert response.code == "invalid_credential"
    unchanged(t1, before)


@case("SMK-PROXY-003", area="PROXY", kind="refusal", covers=[API], codes=["invalid_credential"])
def test_wrong_bearer_is_401(t1, caller):
    before = t1.upstream_counts()
    response = t1.http("GET", "/api/accounts/check", token="qa-wrong.not-a-real-agent-token-000")
    assert response.status == 401
    assert response.code == "invalid_credential"
    unchanged(t1, before)


@case("SMK-PROXY-004", area="PROXY", kind="refusal", covers=[API], codes=["tool_not_allowed"])
def test_unallowlisted_tool_is_403(t1, caller):
    before = t1.upstream_counts()
    response = t1.http("GET", "/api/elsewhere/check", token=caller["token"])
    assert response.status == 403
    assert response.code == "tool_not_allowed"
    unchanged(t1, before)


@case("SMK-PROXY-005", area="PROXY", kind="refusal", covers=[API, "cli.agent.unset-credential"], codes=["tool_not_allowed"])
def test_cleared_selection_is_403_without_dispatch(t1, caller):
    clear = t1.cli("agent", "unset-credential", caller["id"], "accounts")
    assert clear.code == 0, clear.err
    try:
        before = t1.upstream_counts()
        response = t1.http("GET", "/api/accounts/check", token=caller["token"])
        assert response.status == 403
        assert response.code == "tool_not_allowed"
        unchanged(t1, before)
    finally:
        assert t1.cli("agent", "set-credential", caller["id"], "accounts", "--auth", "bearer=SMOKE_X").code == 0


@case("SMK-PROXY-006", area="PROXY", kind="refusal", covers=[API, "cli.agent.revoke"], codes=["invalid_credential"])
def test_revoked_agent_is_401(t1, caller):
    revoke = t1.cli("agent", "revoke", caller["id"], "--reason", "qa")
    assert revoke.code == 0, revoke.err
    before = t1.upstream_counts()
    response = t1.http("GET", "/api/accounts/check", token=caller["token"])
    assert response.status == 401
    assert response.code == "invalid_credential"
    unchanged(t1, before)
