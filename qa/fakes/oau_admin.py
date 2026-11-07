"""Operator admin API over the daemon's Unix socket, for the OAU cases.

Some documented operator routes have no CLI form (registering an OAuth tool,
raw If-Match refusals), so cases call them as an operator client would. Each
exchange is recorded into the case transcript after canary redaction, like
``LocalTarget.http``.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
from urllib.parse import parse_qsl, urlsplit

from harness.target import CliResult, HttpResult, LocalTarget


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


def admin(
    target: LocalTarget,
    method: str,
    path: str,
    body: dict | bytes | None = None,
    headers: dict | None = None,
    token: str | None = None,
    timeout: float = 60,
) -> HttpResult:
    """Call an operator route (path under /admin/operator) as the target's operator."""
    send = {"Authorization": f"Bearer {token or target.op_token}", **(headers or {})}
    raw = body
    if isinstance(body, dict):
        raw = json.dumps(body).encode()
        send.setdefault("Content-Type", "application/json")
    conn = _UnixConnection(str(target.socket), timeout)
    try:
        conn.request(method, path, body=raw, headers=send)
        resp = conn.getresponse()
        status, hdrs, data = resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()
    text = data.decode(errors="replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    shown = {k: v for k, v in (headers or {}).items()}
    target.bundle.transcript(
        target.current_case,
        "admin",
        f"{method} {path} (operator bearer) headers={sorted(shown)}\n--- {status}\n{text[:4000]}",
    )
    return HttpResult(status, hdrs, text, parsed)


def cli_private(target: LocalTarget, *args: str, private: tuple[str, ...] = ("authorization_url",)) -> CliResult:
    """Run ``locksmith --format json <args>`` and register private fields before recording.

    ``oauth connect`` prints the authorization URL (which carries the private
    state) exactly once; ``LocalTarget.cli`` would record it before a case
    could register it as a canary. The URL and its query values are added
    to the canaries first, then the redacted transcript is written.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("LOCKSMITH_")}
    env["LOCKSMITH_OP_TOKEN"] = target.op_token or ""
    argv = [str(target.bins / "locksmith"), "--socket", str(target.socket), "--format", "json", *args]
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60, check=False)
    try:
        parsed = json.loads(proc.stdout)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        for field in private:
            value = parsed.get(field)
            if isinstance(value, str):
                target.canaries.add(value, f"oau-{field}")
                for name, item in parse_qsl(urlsplit(value).query):
                    if name in ("state", "code_challenge"):
                        target.canaries.add(item, f"oau-{field}-{name}")
    target.bundle.transcript(
        target.current_case,
        "cli",
        f"$ locksmith {' '.join(args)}\nexit {proc.returncode}\n--- stdout\n{proc.stdout}\n--- stderr\n{proc.stderr}",
    )
    return CliResult(proc.returncode, proc.stdout, proc.stderr, parsed)
