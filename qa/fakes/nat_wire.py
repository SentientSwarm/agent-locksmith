"""Raw MCP 2025-11-25 streamable-HTTP client for native MCP smoke cases.

http.client is used instead of urllib so a case can send duplicate headers,
omit Host, or stall a body. Every exchange is recorded in the target's
evidence bundle without the Authorization value.
"""

from __future__ import annotations

import http.client
import json
import socket
from dataclasses import dataclass
from typing import Any

PROTOCOL = "2025-11-25"
POST_HEADERS = [
    ("Content-Type", "application/json"),
    ("Accept", "application/json, text/event-stream"),
]
INIT = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": PROTOCOL,
        "capabilities": {},
        "clientInfo": {"name": "qa-nat", "version": "1"},
    },
}


@dataclass
class Reply:
    status: int
    headers: dict
    text: str
    json: Any

    @property
    def code(self) -> str | None:
        """HTTP-boundary refusal code (`error.code`)."""
        if isinstance(self.json, dict) and isinstance(self.json.get("error"), dict):
            code = self.json["error"].get("code")
            return code if isinstance(code, str) else None
        return None

    @property
    def rpc_code(self) -> str | None:
        """JSON-RPC refusal code (`error.data.code`)."""
        if isinstance(self.json, dict) and isinstance(self.json.get("error"), dict):
            data = self.json["error"].get("data")
            if isinstance(data, dict):
                return data.get("code")
        return None

    @property
    def session(self) -> str | None:
        return self.headers.get("mcp-session-id")


def _decode(content_type: str, text: str) -> Any:
    if content_type.startswith("text/event-stream"):
        found = None
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    value = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(value, dict) and ("result" in value or "error" in value):
                    found = value
        return found
    try:
        return json.loads(text)
    except ValueError:
        return None


def send(
    target,
    method: str,
    path: str,
    headers: list[tuple[str, str]] | None = None,
    body: bytes | dict | list | None = None,
    *,
    host: bool = True,
    timeout: float = 30,
    port: int | None = None,
) -> Reply:
    """One request; duplicate header names are sent as given."""
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    conn = http.client.HTTPConnection("127.0.0.1", port or target.port, timeout=timeout)
    try:
        conn.putrequest(method, path, skip_host=not host, skip_accept_encoding=True)
        for key, value in headers or []:
            conn.putheader(key, value)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        raw = resp.read()
        status = resp.status
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()
    text = raw.decode(errors="replace")
    reply = Reply(status, hdrs, text, _decode(hdrs.get("content-type", ""), text))
    shown = [
        f"{k}: {'<redacted>' if k.lower() == 'authorization' else v}"
        for k, v in headers or []
    ]
    sent = (body or b"")[:600].decode(errors="replace")
    target.bundle.transcript(
        target.current_case,
        "mcp",
        f"{method} {path}\n" + "\n".join(shown) + f"\n\n{sent}\n--- {status}\n"
        f"mcp-session-id: {'present' if reply.session else 'absent'}\n{text[:3000]}",
    )
    return reply


def auth(token: str) -> tuple[str, str]:
    return ("Authorization", f"Bearer {token}")


class Session:
    """A stateful native session for one agent on one path."""

    def __init__(self, target, token: str, path: str) -> None:
        self.target = target
        self.token = token
        self.path = path
        self.id: str | None = None
        self.next_id = 1

    def headers(self, extra: list[tuple[str, str]] | None = None) -> list:
        out = [auth(self.token), *POST_HEADERS]
        if self.id is not None:
            out += [("Mcp-Session-Id", self.id), ("MCP-Protocol-Version", PROTOCOL)]
        return out + (extra or [])

    def initialize(self) -> Reply:
        reply = send(self.target, "POST", self.path, self.headers(), INIT)
        self.id = reply.session
        return reply

    def post(self, message: dict, extra: list | None = None) -> Reply:
        return send(self.target, "POST", self.path, self.headers(extra), message)

    def notify(self, method: str, params: dict | None = None) -> Reply:
        message: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        return self.post(message)

    def call(self, method: str, params: dict | None = None, rid: Any = None) -> Reply:
        if rid is None:
            rid = self.next_id
            self.next_id += 1
        message: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            message["params"] = params
        return self.post(message)

    def open(self) -> Session:
        """initialize + notifications/initialized; asserts the documented replies."""
        init = self.initialize()
        assert init.status == 200, init.text
        assert self.id, "initialize returned no Mcp-Session-Id"
        done = self.notify("notifications/initialized")
        assert done.status == 202, done.text
        return self

    def delete(self) -> Reply:
        hdrs = [auth(self.token)]
        if self.id is not None:
            hdrs += [("Mcp-Session-Id", self.id), ("MCP-Protocol-Version", PROTOCOL)]
        return send(self.target, "DELETE", self.path, hdrs)


def stalled_post(target, path: str, token: str, declared: int = 64) -> socket.socket:
    """Send headers of a POST whose body never completes; caller closes the socket."""
    sock = socket.create_connection(("127.0.0.1", target.port), timeout=30)
    head = (
        f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{target.port}\r\n"
        f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
        "Accept: application/json, text/event-stream\r\n"
        f"Content-Length: {declared}\r\nConnection: close\r\n\r\n{{"
    )
    sock.sendall(head.encode())
    target.bundle.transcript(
        target.current_case,
        "mcp",
        f"POST {path} (stalled body, {declared} bytes declared)",
    )
    return sock


def read_reply(target, sock: socket.socket) -> Reply:
    """Read one HTTP/1.1 response from a raw socket (Connection: close)."""
    chunks = []
    while True:
        try:
            data = sock.recv(65536)
        except TimeoutError:
            break
        if not data:
            break
        chunks.append(data)
    raw = b"".join(chunks).decode(errors="replace")
    head, _, text = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
    hdrs = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        hdrs[key.strip().lower()] = value.strip()
    reply = Reply(status, hdrs, text, _decode(hdrs.get("content-type", ""), text))
    target.bundle.transcript(target.current_case, "mcp", f"--- {status}\n{text[:2000]}")
    return reply
