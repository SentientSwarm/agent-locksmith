"""Minimal HTTP/1.1 client over the admin Unix socket, for ADM smoke cases.

The CLI hides some admin routes (agent self-registration, deregistration,
operational logs, raw stored-value bodies). Cases reach them with this client
instead. Each exchange is recorded through the target's evidence bundle;
secret-named response fields are registered as canaries first and request
bodies are never recorded.
"""

from __future__ import annotations

import http.client
import json
import socket
from dataclasses import dataclass
from typing import Any

SECRET_KEYS = {
    "token",
    "secret",
    "wire_token",
    "value",
    "bootstrap_token",
    "current_secret",
}


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


def _harvest(canaries, value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in SECRET_KEYS and isinstance(item, str):
                canaries.add(item, f"uds-{key}")
            else:
                _harvest(canaries, item)
    elif isinstance(value, list):
        for item in value:
            _harvest(canaries, item)


def uds(
    target,
    method: str,
    path: str,
    token: str | None = None,
    body: dict | bytes | None = None,
    timeout: float = 30,
) -> UdsResult:
    """Send one request to the target's admin socket and record it."""
    headers = {"Host": "localhost"}
    data: bytes | None = None
    if isinstance(body, dict):
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    elif body is not None:
        data = body
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    conn = _UnixConnection(str(target.socket), timeout)
    try:
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        status, raw = resp.status, resp.read()
    finally:
        conn.close()
    text = raw.decode(errors="replace")
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    _harvest(target.canaries, parsed)
    auth = " (bearer)" if token is not None else ""
    sent = " <json body>" if data is not None else ""
    target.bundle.transcript(
        target.current_case,
        "uds",
        f"{method} {path}{auth}{sent}\n--- {status}\n{text[:4000]}",
    )
    return UdsResult(status, text, parsed)
