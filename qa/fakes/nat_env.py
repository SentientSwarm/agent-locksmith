"""Native MCP setup through the documented operator CLI only.

A native target trusts a per-run CA through `mcp.upstream_ca_bundle`
(docs/user/operator/native-tool-review.md:55-63) and talks to a FakeMcp
over verified TLS. Preparation follows native-tool-review.md and
native-tool-grants.md: show, observe, review, grants show, grants replace,
echoing exact returned preconditions.
"""

from __future__ import annotations

import http.client
import json
import socket

from .nat_mcp import FakeMcp
from .pki import CA

MCP_CONFIG = {"protocol_version": "2025-11-25", "allow_private_destination": True}


def native_target(target_factory, label: str, mcp: dict | None = None, **kwargs):
    """Start a daemon trusting a fresh CA, plus a FakeMcp signed by it."""
    ca = CA.create("qa-nat-ca")
    extra = kwargs.pop("config", None) or {}

    def overlay(work):
        bundle = work / "nat-upstream-ca.pem"
        bundle.write_bytes(ca.cert_pem())
        return {**extra, "mcp": {"upstream_ca_bundle": str(bundle), **(mcp or {})}}

    target = target_factory(config=overlay, label=label, upstream=False, **kwargs)
    return target, FakeMcp(ca, target.work)


def put_connection(
    target, url: str, name: str, *, compact: bool = False, config: dict | None = None
):
    body = dict(config or MCP_CONFIG)
    if compact:
        body["compact"] = True
    path = target.write_file(f"{name}-mcp.json", json.dumps(body))
    return target.cli(
        "tool",
        "put",
        name,
        "--upstream",
        url,
        "--auth",
        "none",
        "--egress",
        "direct",
        "--protocol",
        "mcp_streamable_http",
        "--mcp-config-file",
        str(path),
    )


def register(target, name: str, allow: str, *, select: bool = True) -> dict:
    reg = target.cli("agent", "register", "--name", name, "--allowlist", allow)
    assert reg.code == 0, reg.err
    agent = {"id": reg.json["public_id"], "token": reg.json["token"]}
    if select:
        sel = target.cli("agent", "set-credential", agent["id"], allow, "--no-auth")
        assert sel.code == 0, sel.err
    return agent


def write_json(target, name: str, value) -> str:
    return str(target.write_file(name, json.dumps(value)))


def observe(target, conn: str, agent_id: str):
    show = target.cli("tool", "mcp", "show", conn, "--agent", agent_id)
    assert show.code == 0, show.err
    current = show.json.get("observation")
    body = {
        "source": show.json["source"],
        "generation": current["generation"] if current else None,
    }
    return target.cli(
        "tool",
        "mcp",
        "observe",
        conn,
        "--agent",
        agent_id,
        "--file",
        write_json(target, "nat-observe.json", body),
    )


def review(
    target, conn: str, agent_id: str, observed: dict, name: str, effect: str = "read"
):
    entry = next(
        t
        for t in observed["observation"]["manifest"]["tools"]
        if t["tool"]["name"] == name
    )
    body = {
        "source": observed["source"],
        "generation": observed["observation"]["generation"],
        "name": name,
        "observed_digest": entry["observed_digest"],
        "effect": effect,
    }
    return target.cli(
        "tool",
        "mcp",
        "review",
        conn,
        "--agent",
        agent_id,
        "--file",
        write_json(target, "nat-review.json", body),
    )


def replace_grants(target, conn: str, agent_id: str, tools: list[dict]):
    state = target.cli("agent", "mcp-grants", "show", conn, "--agent", agent_id)
    assert state.code == 0, state.err
    body = {
        "source": state.json["source"],
        "generation": state.json["observation"]["generation"],
        "revision": state.json["grant_revision"],
        "tools": tools,
    }
    return target.cli(
        "agent",
        "mcp-grants",
        "replace",
        conn,
        "--agent",
        agent_id,
        "--file",
        write_json(target, "nat-grants.json", body),
    )


def prepare(
    target, conn: str, agent_id: str, names: tuple[str, ...] = ("read_record",)
) -> dict:
    """Observe, review and grant `names`; returns the replace response."""
    observed = observe(target, conn, agent_id)
    assert observed.code == 0, observed.err
    granted = []
    for name in names:
        reviewed = review(target, conn, agent_id, observed.json, name)
        assert reviewed.code == 0, reviewed.err
        granted.append(
            {"name": name, "contract_digest": reviewed.json["contract_digest"]}
        )
    result = replace_grants(target, conn, agent_id, granted)
    assert result.code == 0, result.err
    return result.json


class _Uds(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=30)
        self.uds = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.uds)


def admin_raw(
    target, method: str, path: str, body: dict, headers: dict
) -> tuple[int, dict | None]:
    """One admin UDS request with the operator bearer; recorded without it."""
    conn = _Uds(str(target.socket))
    try:
        payload = json.dumps(body).encode()
        conn.request(
            method,
            path,
            payload,
            {
                "Authorization": f"Bearer {target.op_token}",
                "Content-Type": "application/json",
                **headers,
            },
        )
        resp = conn.getresponse()
        text = resp.read().decode(errors="replace")
        status = resp.status
    finally:
        conn.close()
    target.bundle.transcript(
        target.current_case,
        "admin-uds",
        f"{method} {path} {sorted(headers)}\n{payload.decode()}\n--- {status}\n{text[:2000]}",
    )
    try:
        return status, json.loads(text)
    except ValueError:
        return status, None
