"""Agent-listener health surfaces (docs/user/getting-started.md)."""
import pytest

case = pytest.mark.case


@case("SMK-HEALTH-001", area="HEALTH", kind="positive", covers=["agent.GET./livez"])
def test_livez(t1):
    assert t1.http("GET", "/livez").status == 200


@case("SMK-HEALTH-002", area="HEALTH", kind="positive", covers=["agent.GET./health"])
def test_health_is_livez_alias(t1):
    health, livez = t1.http("GET", "/health"), t1.http("GET", "/livez")
    assert health.status == 200
    assert health.text == livez.text


@case("SMK-HEALTH-003", area="HEALTH", kind="positive", covers=["agent.GET./readyz"])
def test_readyz_on_empty_catalog(t1):
    assert t1.http("GET", "/readyz").status == 200


@case("SMK-HEALTH-004", area="HEALTH", kind="positive", covers=["agent.GET./version"])
def test_version_matches_daemon_build(t1, build):
    response = t1.http("GET", "/version")
    assert response.status == 200
    assert build["locksmithd"]["version"] in response.text
    assert build["locksmith"]["build"] == build["locksmithd"]["build"], "CLI and daemon are different builds"
