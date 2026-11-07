"""Operator enrols an agent through the CLI (docs/user/cli-reference.md)."""
import pytest

case = pytest.mark.case


@pytest.fixture(scope="module")
def agent(t1, accounts):
    return t1.cli("agent", "register", "--name", "qa-enrol", "--allowlist", accounts)


@case("SMK-ENROL-001", area="ENROL", kind="positive", covers=["cli.agent.register", "admin.POST./admin/operator/agents"])
def test_register_returns_identity_and_one_time_token(agent):
    assert agent.code == 0, agent.err
    assert agent.json["public_id"]
    assert agent.json["token"]


@case("SMK-ENROL-002", area="ENROL", kind="refusal", covers=["cli.agent.register", "admin.POST./admin/operator/agents"],
      codes=["agent_name_conflict"])
def test_duplicate_name_conflicts(t1, agent):
    again = t1.cli("agent", "register", "--name", "qa-enrol", "--allowlist", "accounts")
    assert again.code == 5
    assert "agent_name_conflict" in again.err + again.out


@case("SMK-ENROL-003", area="ENROL", kind="refusal", covers=["cli.agent.list", "admin.GET./admin/operator/agents"],
      codes=["invalid_credential"])
def test_wrong_operator_token_is_auth_failure(t1):
    result = t1.cli("agent", "list", op_token="qa-wrong.not-a-real-operator-token")
    assert result.code == 3


@case("SMK-ENROL-004", area="ENROL", kind="positive", covers=["cli.agent.list", "admin.GET./admin/operator/agents"])
def test_list_shows_agent_without_secrets(t1, agent):
    result = t1.cli("agent", "list")
    assert result.code == 0, result.err
    assert "qa-enrol" in result.out
    assert agent.json["token"] not in result.out
    assert "token_hash" not in result.out


@case("SMK-ENROL-005", area="ENROL", kind="refusal", covers=["cli.agent.register", "admin.POST./admin/operator/agents"],
      codes=["grant_target_invalid"])
def test_allowlist_must_name_a_current_connection(t1, accounts):
    result = t1.cli("agent", "register", "--name", "qa-no-target", "--allowlist", "not-a-connection")
    assert result.code == 1
    assert "grant_target_invalid" in result.err
    assert "qa-no-target" not in t1.cli("agent", "list").out
