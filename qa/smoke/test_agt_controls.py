"""M7 response controls on config.tools entries (docs/v2/runbooks/m7-response-controls.md,
docs/user/agent-integration/wire-contract.md:192-235)."""

import hashlib

import pytest

from fakes.agt_support import audit, enrol
from fakes.agt_upstream import Reply, Upstream

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
RC = "beh.response-controls"
MARKER = '\n{"_locksmith":"response_size_exceeded"}\n'
CAP = 1000
SECRETS = ("qa-sk-abcdef123456", "qa-sk-zyxwvu987654")


@pytest.fixture(scope="module")
def rc(target_factory):
    up = Upstream()
    up.routes["/stream/big"] = Reply(
        content_type="text/event-stream", size=5000, chunks=5
    )
    up.routes["/stream/small"] = Reply(
        content_type="text/event-stream", size=500, chunks=2
    )
    up.routes["/buffer/big"] = Reply(size=5000)
    up.routes["/buffer/secret"] = Reply(
        body=f"id=1 key={SECRETS[0]} and {SECRETS[1]} end".encode()
    )
    up.routes["/ctype/html"] = Reply(
        content_type="text/html", body=b"<html>login</html>"
    )
    up.routes["/ctype/json"] = Reply(
        content_type="application/json; charset=utf-8", body=b'{"ok":true}'
    )

    def tool(name: str, path: str, response: dict) -> dict:
        return {
            "name": name,
            "description": f"qa {name}",
            "upstream": f"{up.url}/{path}",
            "egress": "direct",
            "response": response,
        }

    config = {
        "tools": [
            tool("agt-rc-stream", "stream", {"max_size_bytes": CAP}),
            tool(
                "agt-rc-buffer",
                "buffer",
                {
                    "max_size_bytes": CAP,
                    "redaction_patterns": [
                        {
                            "id": "qa_key",
                            "regex": "qa-sk-[a-z0-9]{12}",
                            "replacement": "[QA-REDACTED]",
                        }
                    ],
                },
            ),
            tool(
                "agt-rc-ctype",
                "ctype",
                {"content_type_allowlist": ["application/json"]},
            ),
        ]
    }
    t = target_factory(label="agt-controls", upstream=False, config=config)
    names = ["agt-rc-stream", "agt-rc-buffer", "agt-rc-ctype"]
    agent = enrol(t, "qa-agt-controls", names, {n: ["--no-auth"] for n in names})
    yield t, up, agent
    up.close()


@case("SMK-AGT-040", area="AGT", kind="positive", covers=[API, RC])
def test_streaming_over_cap_truncates_with_marker(rc):
    """m7-response-controls.md:70-74 — a stream over max_size_bytes is cut at the cap and the
    `\\n{"_locksmith":"response_size_exceeded"}\\n` marker appended; m7:116-118 audit
    response_size_exceeded records cap and observed bytes."""
    t, _up, agent = rc
    resp = t.http("GET", "/api/agt-rc-stream/big", token=agent["token"])
    assert resp.status == 200
    expected = Reply(size=5000).payload()[:CAP].decode()
    assert resp.text == expected + MARKER
    row = audit(t, "agt-rc-stream", "response_size_exceeded")[0]
    assert row["details"]["cap_bytes"] == CAP
    assert row["details"]["flow"] == "streaming"
    assert row["decision"] == "denied"


@case("SMK-AGT-041", area="AGT", kind="corner", covers=[API, RC])
def test_streaming_under_cap_passes_unchanged(rc):
    """m7-response-controls.md:74 — a stream under the cap passes through unchanged, no marker."""
    t, _, agent = rc
    resp = t.http("GET", "/api/agt-rc-stream/small", token=agent["token"])
    assert resp.status == 200
    assert resp.text == Reply(size=500).payload().decode()


@case(
    "SMK-AGT-042",
    area="AGT",
    kind="refusal",
    covers=[API, RC],
    codes=["response_size_exceeded"],
)
def test_buffered_over_cap_is_502(rc):
    """m7-response-controls.md:21 non-streaming over cap -> 502; wire-contract.md:235
    502 type upstream_error code response_size_exceeded; m7:118 audit row."""
    t, _, agent = rc
    resp = t.http("GET", "/api/agt-rc-buffer/big", token=agent["token"])
    assert resp.status == 502
    assert "0123456789abcdef" not in resp.text, "over-cap body leaked to the agent"
    rows = audit(t, "agt-rc-buffer", "response_size_exceeded")
    assert rows and rows[0]["details"]["cap_bytes"] == CAP
    assert resp.code == "response_size_exceeded"


@case("SMK-AGT-043", area="AGT", kind="positive", covers=[API, RC, "cli.audit.query"])
def test_redaction_replaces_matches_and_audits_hash_only(rc):
    """m7-response-controls.md:79-100 and :119 — matches are replaced; audit emits one
    response_redaction row per matching pattern with pattern_id, matches and match_hash
    (SHA-256 hex of the cleartext matches); cleartext is never recorded."""
    t, _, agent = rc
    resp = t.http("GET", "/api/agt-rc-buffer/secret", token=agent["token"])
    assert resp.status == 200
    assert resp.text == "id=1 key=[QA-REDACTED] and [QA-REDACTED] end"
    raw = t.cli("audit", "query", "--tool", "agt-rc-buffer", "--limit", "50")
    assert all(s not in raw.out for s in SECRETS), (
        "audit output carries redacted cleartext"
    )
    row = next(r for r in raw.json if r["event"] == "response_redaction")
    assert row["details"]["pattern_id"] == "qa_key"
    assert row["details"]["matches"] == 2
    assert (
        row["details"]["match_hash"]
        == hashlib.sha256("".join(SECRETS).encode()).hexdigest()
    )


@case(
    "SMK-AGT-044",
    area="AGT",
    kind="refusal",
    covers=[API, RC],
    codes=["response_content_type_disallowed"],
)
def test_disallowed_content_type_is_502(rc):
    """m7-response-controls.md:86-89 + wire-contract.md:234 — text/html against a JSON
    allowlist is 502 type upstream_error code response_content_type_disallowed; m7:117 audit."""
    t, _, agent = rc
    resp = t.http("GET", "/api/agt-rc-ctype/html", token=agent["token"])
    assert resp.status == 502
    assert "login" not in resp.text
    row = audit(t, "agt-rc-ctype", "response_content_type_disallowed")[0]
    assert row["details"]["observed_content_type"] == "text/html"
    assert resp.code == "response_content_type_disallowed"


@case("SMK-AGT-045", area="AGT", kind="corner", covers=[API, RC])
def test_allowlist_matches_with_charset_suffix(rc):
    """m7-response-controls.md:23 — `application/json; charset=utf-8` matches an
    `application/json` allowlist."""
    t, _, agent = rc
    resp = t.http("GET", "/api/agt-rc-ctype/json", token=agent["token"])
    assert resp.status == 200
    assert resp.json == {"ok": True}
