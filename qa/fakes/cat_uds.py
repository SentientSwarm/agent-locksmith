"""HTTP/1.1 over the admin Unix socket, for CAT smoke cases.

Some catalog routes have no CLI (operator stored-credential PUT/DELETE) and
some refusals are only reachable with a body the CLI never sends (malformed op
references, a missing If-Match). Cases reach them here. Every exchange is
recorded through the target's evidence bundle; request bodies are summarised
by key names only, never values, and the Authorization header is never
recorded.
"""

from __future__ import annotations

import http.client
import json
import socket
from dataclasses import dataclass
from typing import Any


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


@dataclass
class UdsResult:
    status: int
    text: str
    json: Any

    @property
    def code(self) -> str | None:
        """The error envelope's code, if any."""
        if isinstance(self.json, dict) and isinstance(self.json.get("error"), dict):
            return self.json["error"].get("code")
        return None


def uds(
    target,
    method: str,
    path: str,
    body: Any = None,
    *,
    token: str | None = None,
    headers: dict | None = None,
    content_type: str = "application/json",
    timeout: float = 30,
) -> UdsResult:
    """Send one admin request; `token=None` uses the target's operator token."""
    hdrs = dict(headers or {})
    hdrs["Authorization"] = f"Bearer {token if token is not None else target.op_token}"
    raw: bytes | None = None
    shown = ""
    if body is not None:
        raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", content_type)
        keys = sorted(body) if isinstance(body, dict) else ["<raw>"]
        shown = f" body-keys={keys}"
    conn = _UnixConnection(str(target.socket), timeout)
    try:
        conn.request(method, path, body=raw, headers=hdrs)
        resp = conn.getresponse()
        status, text = resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    auth = " (operator bearer)" if token is None else " (supplied bearer)"
    target.bundle.transcript(
        target.current_case,
        "uds",
        f"{method} {path}{auth}{shown}\n--- {status}\n{text[:4000]}",
    )
    return UdsResult(status, text, parsed)
