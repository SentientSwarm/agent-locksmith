"""Startup configuration validation (docs/user/architecture.md "Changing configuration").

Refusals run locksmithd in the foreground on a deliberately broken file in
t1's work directory; a config the daemon wrongly accepts shows as exit None
(still running at the timeout) and fails the case.
"""

import pytest

from fakes.dmn_support import mint_operator, run_once
from harness.target import free_port

case = pytest.mark.case
VALIDATION = "beh.config.validation"


def minimal(**extra) -> dict:
    return {"listen": {"host": "127.0.0.1", "port": free_port()}, **extra}


def refused(once, *needles: str) -> None:
    assert once.code == 1, f"expected exit 1, got {once.code}"
    for needle in needles:
        assert needle in once.output, f"error does not name {needle!r}"


def tool_with_patterns(patterns: list) -> dict:
    return {
        "name": "dmn-redact",
        "description": "d",
        "upstream": "http://127.0.0.1:9",
        "response": {"redaction_patterns": patterns},
    }


@case("SMK-DMN-001", area="DMN", kind="refusal", covers=[VALIDATION])
def test_unknown_top_level_field_refuses_start(t1):
    """architecture.md:170-171: startup validates the whole file (deny_unknown_fields) and refuses to start on any error."""
    refused(
        run_once(t1, "dmn-unknown-top", minimal(bogus_top_field=1)),
        "unknown field",
        "bogus_top_field",
    )


@case("SMK-DMN-002", area="DMN", kind="refusal", covers=[VALIDATION])
def test_unknown_nested_field_refuses_start(t1):
    """architecture.md:170-171: deny_unknown_fields applies to the whole file, nested blocks included."""
    cfg = minimal()
    cfg["listen"]["bogus_listen_field"] = True
    refused(
        run_once(t1, "dmn-unknown-nested", cfg), "unknown field", "bogus_listen_field"
    )


@case("SMK-DMN-003", area="DMN", kind="refusal", covers=[VALIDATION])
def test_wrong_type_refuses_start(t1):
    """architecture.md:170-171: any validation error refuses start; a string port is a type error."""
    cfg = minimal()
    cfg["listen"]["port"] = "not-a-port"
    refused(run_once(t1, "dmn-bad-type", cfg), "invalid type", "not-a-port")


@case("SMK-DMN-004", area="DMN", kind="refusal", covers=[VALIDATION])
def test_malformed_yaml_refuses_start(t1):
    """architecture.md:170-171: a file that does not parse refuses start."""
    once = run_once(t1, "dmn-bad-yaml", "listen: {host: 127.0.0.1\n  port: [\n")
    refused(once, "Failed to load config")


@case(
    "SMK-DMN-005",
    area="DMN",
    kind="refusal",
    covers=[VALIDATION, "beh.response-controls"],
)
def test_invalid_redaction_regex_refuses_start(t1):
    """m7-response-controls.md:14,170: a malformed redaction_patterns[].regex fails config load with `regex compile failed`."""
    cfg = minimal(tools=[tool_with_patterns([{"id": "broken", "regex": "(unclosed"}])])
    refused(run_once(t1, "dmn-bad-regex", cfg), "regex compile failed", "broken")


@case(
    "SMK-DMN-006",
    area="DMN",
    kind="refusal",
    covers=[VALIDATION, "beh.response-controls"],
)
def test_duplicate_redaction_id_refuses_start(t1):
    """m7-response-controls.md:15,171: two patterns sharing an id fail with `duplicate redaction_patterns id`."""
    pattern = {"id": "dup", "regex": "secret-[0-9]+"}
    cfg = minimal(tools=[tool_with_patterns([pattern, dict(pattern)])])
    refused(
        run_once(t1, "dmn-dup-regex-id", cfg), "duplicate redaction_patterns id", "dup"
    )


CONSENT = {
    "callback": {
        "address": "127.0.0.1:19444",
        "cert_path": "./callback.pem",
        "key_path": "./callback.key",
    },
    "profiles": [
        {
            "id": "twin",
            "kind": "controlled-linear-v1",
            "client_id": "fixture-client",
            "client_generation": 1,
            "issuer": "https://127.0.0.1:19443",
            "authorization_endpoint": "https://127.0.0.1:19443/authorize",
            "token_endpoint": "https://127.0.0.1:19443/token",
            "resource": "https://127.0.0.1:19443/mcp/readonly",
            "redirect_profile_id": "local",
            "redirect_uri": "https://127.0.0.1:19444/oauth/callback",
            "expected_workspace": "00000000-0000-0000-0000-000000000041",
            "expected_user": "00000000-0000-0000-0000-000000000042",
            "ca_path": "./provider-ca.pem",
        }
    ],
}


@case("SMK-DMN-007", area="DMN", kind="refusal", covers=[VALIDATION])
def test_consent_without_admin_substrate_refuses_start(t1):
    """oauth-consent.md:21-22: consent requires the admin substrate (the documented example block, no admin_socket)."""
    once = run_once(t1, "dmn-consent-no-admin", minimal(oauth_consent=CONSENT))
    refused(once, "oauth_consent requires admin substrate")


@case("SMK-DMN-008", area="DMN", kind="refusal", covers=[VALIDATION])
def test_duplicate_operator_public_id_refuses_start(t1):
    """oauth-consent.md:78-79: duplicate operator public IDs are rejected at startup."""
    text, _token = mint_operator(t1, "dmn-dup")
    body = text[text.index("operators:") :]
    entry = body.split("\n", 1)[1]
    ops = t1.write_file("dmn-dup-operators.yaml", body + entry)
    cfg = minimal(
        operator_credentials_path=str(ops),
        database={"path": str(t1.work / "dmn-dup.db")},
    )
    cfg["listen"]["admin_socket"] = {"path": str(t1.work / "dmn-dup.sock")}
    refused(run_once(t1, "dmn-dup-operator", cfg), "operator credentials")
    assert not (t1.work / "dmn-dup.sock").exists(), (
        "admin socket bound despite the refusal"
    )


@case("SMK-DMN-009", area="DMN", kind="positive", covers=[VALIDATION])
def test_env_var_expansion_in_config(target_factory):
    """config.example.yaml:82 and m5-sealed-secrets.md:35: `${VAR}` in the YAML expands from the daemon environment.

    The listen host is given only as `${QA_DMN_LISTEN_HOST}`; the daemon can bind only if it expanded.
    """
    t = target_factory(
        label="dmn-envexp",
        upstream=False,
        config={"listen": {"host": "${QA_DMN_LISTEN_HOST}"}},
        env={"QA_DMN_LISTEN_HOST": "127.0.0.1"},
    )
    assert t.http("GET", "/livez").status == 200


LEGACY = {
    "egress_proxy": "http://127.0.0.1:9",
    "telemetry": {"enabled": True},
    "tools": [
        {
            "name": "dmn-legacy",
            "description": "legacy M0 entry",
            "upstream": "http://127.0.0.1:9",
            "cloud": True,
            "timeout_seconds": 7,
        },
    ],
}


@pytest.fixture(scope="module")
def legacy(target_factory):
    return target_factory(label="dmn-legacy", upstream=False, config=LEGACY)


@case(
    "SMK-DMN-010", area="DMN", kind="positive", covers=[VALIDATION, "beh.seed.catalog"]
)
def test_deprecated_fields_are_translated(legacy):
    """m1-inference-hardening.md:128-137: legacy `cloud: true` -> egress proxied, `timeout_seconds: N` ->
    timeouts.request_seconds N with idle default 60, `telemetry` dropped; the deployment still works.
    architecture.md:187-189: legacy config.tools are migrated into registrations at startup."""
    got = legacy.cli("tool", "get", "dmn-legacy")
    assert got.code == 0, got.err
    assert got.json["egress"] == "proxied"
    assert got.json["timeouts"] == {"request_seconds": 7, "idle_seconds": 60}


@case("SMK-DMN-011", area="DMN", kind="corner", covers=[VALIDATION])
def test_deprecated_fields_warn_once_each(legacy):
    """m1-inference-hardening.md:105,132-135: each legacy field produces a one-shot WARN log naming it."""
    warns = [e for e in legacy.log_events() if e.get("level") == "WARN"]
    for field in ("tools[].cloud", "tools[].timeout_seconds", "telemetry"):
        named = [e for e in warns if e.get("fields", {}).get("field") == field]
        assert len(named) == 1, f"expected one WARN naming {field}, found {len(named)}"
