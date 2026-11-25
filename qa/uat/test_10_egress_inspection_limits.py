"""Journey 10: egress, inspection and rate limits (operator, agent).

Guide: docs/guide/10-egress-inspection-limits.md. The reference sidecar runs
verbatim; only LlamaFirewall is replaced, by a stub module in a throwaway venv
that scores one fixed phrase, so no model weights are needed.
"""

import json
import subprocess
import urllib.request
from pathlib import Path

import pytest

from harness.uat import daemon_ready, port_open

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"
PAGE = "10-egress-inspection-limits.md"
PORTS = ("LOCKSMITH_PORT", "REFERENCE_PORT")

# Stands in for LlamaFirewall: the reference sidecar's imports, with a score of
# 0.99 for text holding the journey's injection phrase and 0.01 otherwise.
STUB = '''"""Stub LlamaFirewall for the UAT: no model, one fixed phrase."""


class Role:
    USER, TOOL, ASSISTANT = "user", "tool", "assistant"


class ScannerType:
    PROMPT_GUARD, CODE_SHIELD = "prompt_guard", "code_shield"


class ScanDecision:
    ALLOW, BLOCK = "allow", "block"


class _Message:
    def __init__(self, content):
        self.content = content


class UserMessage(_Message):
    pass


class ToolMessage(_Message):
    pass


class AssistantMessage(_Message):
    pass


class _Result:
    def __init__(self, score):
        self.score = score
        self.decision = ScanDecision.BLOCK if score >= 0.5 else ScanDecision.ALLOW


class LlamaFirewall:
    def __init__(self, scanners):
        self.scanners = scanners

    def scan(self, message):
        hit = "ignore previous instructions" in message.content.lower()
        return _Result(0.99 if hit else 0.01)
'''


def case(n, kind="positive", covers=(), persona="OPR", codes=()):
    return pytest.mark.case(
        f"UAT-{persona}-EGRESS-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:10-egress-inspection-limits#{c}" for c in covers],
        codes=list(codes),
    )


def counts(j):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{j.var('REFERENCE_PORT')}/counts", timeout=5
    ) as r:
        return json.loads(r.read())


def stub_inspector_python(j):
    """A venv whose `llamafirewall` is the stub above, used as INSPECTOR_PYTHON."""
    venv = j.work / "inspector-venv"
    subprocess.run(
        ["python3", "-m", "venv", "--without-pip", str(venv)],
        check=True,
        timeout=60,
        env={"PATH": j.env["PATH"], "HOME": j.env["HOME"]},
    )
    python = venv / "bin" / "python"
    purelib = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    package = Path(purelib) / "llamafirewall"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(STUB)
    j.env["INSPECTOR_PYTHON"] = j.pins["INSPECTOR_PYTHON"] = str(python)
    j.substitute(
        "LlamaFirewall replaced by a stub module (in a throwaway venv) that flags "
        "one fixed phrase; the reference sidecar script itself runs unchanged"
    )


def inspector_up(j):
    return Path(j.var("LOCKSMITH_HOME"), "inspector.sock").is_socket()


@case(1, covers=["inspector", "config", "service", "start"])
def test_daemon_starts_with_external_egress_and_a_sidecar(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator")
    stub_inspector_python(journey)
    journey.start("inspector", ready=lambda: inspector_up(journey))
    journey.run("config")
    journey.start("service", ready=lambda: port_open(journey.var("REFERENCE_PORT")))
    journey.start("start", ready=lambda: daemon_ready(journey, "LOCKSMITH_PORT"))
    assert "synthetic-private-account" not in journey.log("start")


@case(2, covers=["register", "egress-policy"])
def test_proxied_routes_are_listed_for_the_network(journey):
    out = journey.run("register").out
    assert "search" in out and "accounts" in out
    policy = journey.run("egress-policy").json
    assert policy["mode"] == "external", policy
    text = json.dumps(policy)
    assert journey.var("REFERENCE_PORT") in text
    assert '"search"' in text and '"accounts"' in text


@case(3, covers=["flag"], persona="AGT")
def test_a_sidecar_hit_under_flag_is_forwarded(journey):
    before = counts(journey)
    out = journey.run("flag").out
    assert out.strip() == "X"
    assert counts(journey)["X"] == before["X"] + 1


@case(4, kind="refusal", covers=["block"], persona="AGT", codes=["inspection_blocked"])
def test_a_dlp_hit_under_block_is_refused_with_zero_dispatch(journey):
    before = counts(journey)
    out = journey.run("block").out
    assert "HTTP 403" in out
    assert '"code":"inspection_blocked"' in out.replace(" ", "")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert counts(journey)["received"] == before["received"]


@case(
    5,
    kind="refusal",
    covers=["sidecar-down"],
    persona="AGT",
    codes=["inspection_blocked"],
)
def test_a_request_fails_closed_without_its_sidecar(journey):
    journey.stop("inspector")
    before = counts(journey)
    out = journey.run("sidecar-down").out
    assert "HTTP 403" in out
    assert '"code":"inspection_blocked"' in out.replace(" ", "")
    assert counts(journey)["received"] == before["received"]
    journey.start("inspector", ready=lambda: inspector_up(journey), shot=False)


@case(6, kind="refusal", covers=["rate-limit"], persona="AGT", codes=["rate_limited"])
def test_the_third_call_in_a_minute_is_refused(journey):
    before = counts(journey)
    out = journey.run("rate-limit").out
    assert "call 1: HTTP 200" in out and "call 2: HTTP 200" in out
    assert "call 3: HTTP 429" in out
    assert "retry-after:" in out.lower()
    assert '"code":"rate_limited"' in out.replace(" ", "")
    assert counts(journey)["received"] == before["received"] + 2


@case(7, covers=["rate-limit-override"])
def test_an_agent_override_applies_at_once(journey):
    out = journey.run("rate-limit-override").out
    assert "accounts\troute default\t2" in out
    assert f"accounts\t{journey.var('BILLING_BOT_ID')}\t600" in out
    assert out.strip().splitlines()[-1] == "X"


@case(8, covers=["audit"], persona="AUD")
def test_audit_records_hits_by_rule_never_by_text(journey):
    out = journey.run("audit").out
    rows = [line.split("\t") for line in out.strip().splitlines()]
    events = {(r[0], r[1], r[2], r[4]) for r in rows}
    assert ("inspection_hit", "search", "allowed", "flag") in events, rows
    assert ("inspection_hit", "accounts", "denied", "block") in events, rows
    assert any(r[0] == "inspection_error" and r[1] == "search" for r in rows), rows
    assert any(r[0] == "rate_limited" and r[1] == "accounts" for r in rows), rows
    assert any("sidecar:promptguard/promptguard" in r[5] for r in rows), rows
    assert any("dlp/aws_access_key_id" in r[5] for r in rows), rows
    full = journey.sh("locksmith --format json audit query --event-class security").out
    assert "AKIAIOSFODNN7EXAMPLE" not in full
    assert "ignore previous instructions" not in full.lower()
