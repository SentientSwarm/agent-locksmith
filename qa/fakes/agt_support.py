"""Helpers shared by the AGT smoke modules: seed catalogs, synthetic OAuth
token responses, agent enrolment and audit lookups. Nothing here touches the
daemon's database; everything goes through the CLI."""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from urllib.parse import parse_qs

import yaml

from .agt_upstream import Reply, Upstream

# Synthetic credentials: harness redacts env values whose names contain TOKEN.
CRED = "agt-synthetic-bearer-credential-0001"
HDR_CRED = "agt-synthetic-header-credential-0002"
ACCOUNT_ID = "qa-chatgpt-account-0001"


def sealing_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def write_seed(work: Path, entries: list[dict]) -> Path:
    """Seed catalog in the work directory (LOCKSMITH_SEED_PATH points here)."""
    path = work / "agt-seed.yaml"
    path.write_text(yaml.safe_dump({"version": "9.9.9", "entries": entries}))
    return path


def codex_seed(up: Upstream) -> dict:
    """A seed `codex` entry shaped like seed/catalog.yaml, pointed at the fake."""
    return {
        "name": "codex",
        "kind": "model",
        "description": "qa codex (device-code OAuth)",
        "upstream": f"{up.url}/backend-api/codex",
        "auth": {
            "kind": "oauth_device_code",
            "client_id": "qa-codex-client",
            "scopes": ["openid", "offline_access"],
            "device_url": f"{up.url}/oauth/device/code",
            "token_url": f"{up.url}/oauth/token",
        },
        "egress": "direct",
        "metadata": {
            "modality": "text",
            "provider": "openai",
            "flow": "oauth_device_code",
        },
    }


def _b64u(doc: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(doc).encode()).rstrip(b"=").decode()


def access_jwt(account_id: str = ACCOUNT_ID, label: str = "default") -> str:
    """Unsigned JWT carrying the OpenAI auth namespace claim (oauth-flow.md G2)."""
    claims = {
        "https://api.openai.com/auth": {"chatgpt_account_id": account_id},
        "exp": int(time.time()) + 3600,
        "qa_label": label,
    }
    return f"{_b64u({'alg': 'none', 'typ': 'JWT'})}.{_b64u(claims)}.cWEtc2lnbmF0dXJlLW5vdC1jaGVja2Vk"


class TokenEndpoint:
    """Fake provider token endpoint keyed by the refresh token presented.

    `plans[refresh_token] = (access_token, next_refresh_token, expires_in)`;
    an unknown refresh token gets a 500 (provider failure)."""

    def __init__(self) -> None:
        self.plans: dict[str, tuple[str, str, int]] = {}
        self.calls: list[str] = []

    def __call__(self, _path: str, body: bytes) -> Reply:
        form = parse_qs(body.decode())
        presented = form.get("refresh_token", [""])[0]
        self.calls.append(presented)
        plan = self.plans.get(presented)
        if plan is None:
            return Reply(
                status=500,
                content_type="application/json",
                body=b'{"error":"server_error"}',
            )
        access, nxt, expires = plan
        doc = {
            "access_token": access,
            "refresh_token": nxt,
            "expires_in": expires,
            "token_type": "Bearer",
        }
        return Reply(content_type="application/json", body=json.dumps(doc).encode())


def enrol(target, name: str, allow: list[str], bindings: dict[str, list[str]]) -> dict:
    """Register an agent with a finite allowlist and explicit account bindings."""
    reg = target.cli(
        "agent", "register", "--name", name, "--allowlist", ",".join(allow)
    )
    assert reg.code == 0, reg.err
    pid = reg.json["public_id"]
    for registration, flags in bindings.items():
        bind = target.cli("agent", "set-credential", pid, registration, *flags)
        assert bind.code == 0, bind.err
    return {"id": pid, "token": reg.json["token"], "name": name}


def put_tool(target, name: str, upstream: str, auth: str = "none", *extra: str) -> None:
    put = target.cli(
        "tool", "put", name, "--upstream", upstream, "--auth", auth, *extra
    )
    assert put.code == 0, put.err


def audit(target, tool: str, event: str | None = None, limit: int = 50) -> list[dict]:
    """Audit rows for one tool, newest first (operator CLI, docs/user/cli-reference.md)."""
    result = target.cli("audit", "query", "--tool", tool, "--limit", str(limit))
    assert result.code == 0, result.err
    rows = result.json or []
    return [r for r in rows if event is None or r.get("event") == event]
