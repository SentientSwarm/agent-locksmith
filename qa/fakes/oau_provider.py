"""Local fake OAuth provider for the OAU smoke cases (127.0.0.1 only).

One threaded server plays every provider role the OAU cases need:

- ``POST /token``: refresh-token grant (legacy custody) and authorization-code
  grant with S256 verification (owner-bound consent), with configurable
  lifetime, rotation and failure modes.
- ``GET /authorize``: issues a one-time code and redirects to the
  ``redirect_uri`` with ``state`` and ``code`` (or ``error``), like a browser
  consent page that the operator approved (or denied).
- ``POST /api/accounts/deviceauth/usercode`` and ``.../token``: OpenAI's
  device-authorization dialect (the Codex CLI's), approving after a set
  number of polls; ``POST /oauth/token`` is the same token endpoint.
- ``GET /whoami``: ``workspace-user-v1`` identity for the current access token.
- ``POST /mcp`` / ``DELETE /mcp``: minimal MCP 2025-11-25 server for native calls.
- ``ANY /api/...``: plain HTTP resource that reports which access-token
  generation it received (never the token itself).

Every credential it issues is random per run and handed to ``on_secret`` so
the caller can register it as a redaction canary before anything is recorded.
Counters are plain integers; the fake never logs request contents.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
import threading
import time
from collections import Counter
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

WORKSPACE = "workspace-qa-oau"
USER = "user-qa-oau"
MCP_TOOLS = ("read_record", "inspect_catalog")
LEGACY_NAME = "provider"
DEVICE_NAME = "chatgpt"
DEVICE_CLIENT = "qa-device-client"


def legacy_registration(fake: FakeProvider) -> dict:
    """Operator PUT body for a legacy `oauth_pkce` tool backed by this fake."""
    origin = fake.origin
    return {
        "description": "QA legacy OAuth provider",
        "upstream": f"{origin}/api",
        "egress": "direct",
        "auth": {
            "kind": "oauth_pkce",
            "client_id": "qa-legacy-client",
            "redirect_uri": "http://127.0.0.1:9/callback",
            "scopes": ["read"],
            "auth_url": f"{origin}/authorize",
            "token_url": f"{origin}/token",
        },
    }


def device_registration(fake: FakeProvider) -> dict:
    """Operator PUT body for an `oauth_device_code` model in OpenAI's dialect."""
    origin = fake.origin
    return {
        "description": "QA ChatGPT-plan device login",
        "upstream": f"{origin}/api",
        "egress": "direct",
        "auth": {
            "kind": "oauth_device_code",
            "client_id": DEVICE_CLIENT,
            "scopes": ["openid", "offline_access"],
            "device_url": f"{origin}/api/accounts/deviceauth/usercode",
            "token_url": f"{origin}/oauth/token",
        },
    }


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


class FakeProvider:
    """Start with ``FakeProvider(on_secret=...).start()``; stop with ``stop()``."""

    def __init__(
        self,
        on_secret: Callable[[str, str], None],
        tls: tuple[Path, Path] | None = None,
    ) -> None:
        self.on_secret = on_secret
        self.tls = tls
        self.counts: Counter = Counter()
        self.lock = threading.Lock()
        # Behaviour knobs, changed by cases between steps.
        self.expires_in: int | None = 3600
        self.rotate_refresh = True
        self.refresh_fails = False
        self.deny_authorize = False
        self.wrong_identity = False
        self.scope = "catalog:inspect records:read"
        # Consent contract expectations (set by the case that configures them).
        self.client_id = ""
        self.client_secret: str | None = None
        self.resource = ""
        # Issued credentials: token -> generation.
        self.refresh_tokens: dict[str, int] = {}
        self.access_tokens: dict[str, int] = {}
        self.access_expiry: dict[str, float] = {}
        self.codes: dict[str, dict] = {}
        # Device authorization: id -> polls so far; approve on poll N.
        self.devices: dict[str, int] = {}
        self.device_approve_after = 2
        self.device_fails = False
        self.generation = 0
        self.server: ThreadingHTTPServer | None = None
        self.port = 0

    # -- lifecycle -------------------------------------------------------
    def start(self) -> FakeProvider:
        handler = type("Handler", (_Handler,), {"fake": self})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        if self.tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(self.tls[0]), str(self.tls[1]))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        self.server = server
        self.port = server.server_address[1]
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()
        return self

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()

    @property
    def origin(self) -> str:
        scheme = "https" if self.tls is not None else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    # -- credentials -----------------------------------------------------
    def _secret(self, label: str) -> str:
        value = f"qa-oau-{label}-{secrets.token_urlsafe(24)}"
        self.on_secret(value, f"oau-{label}")
        return value

    def mint_refresh_token(self) -> str:
        """A refresh token the operator obtained out of band (legacy handoff)."""
        token = self._secret("refresh")
        with self.lock:
            self.refresh_tokens[token] = self.generation
        return token

    def _issue_pair(self) -> dict:
        with self.lock:
            self.generation += 1
            generation = self.generation
        access = self._secret("access")
        refresh = self._secret("refresh")
        with self.lock:
            self.access_tokens[access] = generation
            if self.expires_in is not None:
                self.access_expiry[access] = time.time() + self.expires_in
            self.refresh_tokens[refresh] = generation
        body = {"access_token": access, "token_type": "Bearer"}
        if self.rotate_refresh:
            body["refresh_token"] = refresh
        if self.expires_in is not None:
            body["expires_in"] = self.expires_in
        return body

    def current_generation(self) -> int:
        with self.lock:
            return self.generation


class _Handler(BaseHTTPRequestHandler):
    fake: FakeProvider
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        pass

    def _reply(self, status: int, value=None, headers: dict | None = None) -> None:
        raw = b"" if value is None else json.dumps(value).encode()
        self.send_response(status)
        if value is not None:
            self.send_header("Content-Type", "application/json")
        for key, item in (headers or {}).items():
            self.send_header(key, item)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def _body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def _bearer_generation(self) -> int | None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        with self.fake.lock:
            token = auth[7:]
            if time.time() >= self.fake.access_expiry.get(token, float("inf")):
                self.fake.counts["expired-access-presented"] += 1
                return None
            return self.fake.access_tokens.get(token)

    def _count(self, key: str) -> None:
        with self.fake.lock:
            self.fake.counts[key] += 1

    # -- routes ----------------------------------------------------------
    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if url.path == "/authorize":
            return self._authorize(url.query)
        if url.path == "/whoami":
            return self._whoami()
        return self._resource()

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/token", "/oauth/token"):
            return self._token(self._body())
        if path == "/api/accounts/deviceauth/usercode":
            return self._device_code(self._body())
        if path == "/api/accounts/deviceauth/token":
            return self._device_poll(self._body())
        if path == "/mcp":
            return self._mcp(self._body())
        return self._resource()

    def do_DELETE(self) -> None:
        if urlsplit(self.path).path == "/mcp":
            self._count("mcp-delete")
            return self._reply(204)
        return self._resource()

    def _resource(self) -> None:
        self._count("resource")
        generation = self._bearer_generation()
        if generation is None:
            self._count("resource-unauthorized")
            return self._reply(401, {"error": "invalid_token"})
        return self._reply(200, {"generation": generation})

    def _authorize(self, query: str) -> None:
        fake = self.fake
        self._count("authorize")
        q = {k: v[0] for k, v in parse_qs(query).items()}
        valid = (
            q.get("response_type") == "code"
            and q.get("client_id") == fake.client_id
            and q.get("code_challenge_method") == "S256"
            and q.get("resource") == fake.resource
            and q.get("scope") == fake.scope
            and q.get("state")
            and q.get("code_challenge")
            and q.get("redirect_uri")
        )
        if not valid:
            self._count("authorize-invalid")
            return self._reply(400, {"error": "invalid_request"})
        if fake.deny_authorize:
            params = {"state": q["state"], "error": "access_denied"}
        else:
            code = fake._secret("code")
            with fake.lock:
                fake.codes[code] = q
            params = {"state": q["state"], "code": code}
        location = q["redirect_uri"] + "?" + urlencode(params)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _token(self, raw: bytes) -> None:
        self._count("token")
        form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
        grant = form.get("grant_type")
        if grant == "refresh_token":
            return self._refresh_grant(form)
        if grant == "authorization_code":
            return self._code_grant(form)
        return self._reply(400, {"error": "unsupported_grant_type"})

    def _refresh_grant(self, form: dict) -> None:
        fake = self.fake
        self._count("refresh")
        with fake.lock:
            known = form.get("refresh_token") in fake.refresh_tokens
        if fake.refresh_fails or not known:
            self._count("refresh-refused")
            return self._reply(400, {"error": "invalid_grant"})
        if fake.client_id and form.get("client_id") != fake.client_id:
            return self._reply(400, {"error": "invalid_client"})
        if (
            fake.client_secret is not None
            and form.get("client_secret") != fake.client_secret
        ):
            return self._reply(400, {"error": "invalid_client"})
        body = fake._issue_pair()
        if fake.resource:
            body["scope"] = fake.scope
        return self._reply(200, body)

    def _code_grant(self, form: dict) -> None:
        fake = self.fake
        self._count("code-exchange")
        with fake.lock:
            issued = fake.codes.pop(form.get("code", ""), None)
        if (
            issued is None
            or form.get("client_id") != fake.client_id
            or form.get("redirect_uri") != issued["redirect_uri"]
            or _s256(form.get("code_verifier", "")) != issued["code_challenge"]
            or (
                fake.client_secret is not None
                and form.get("client_secret") != fake.client_secret
            )
        ):
            self._count("code-refused")
            return self._reply(400, {"error": "invalid_grant"})
        body = fake._issue_pair()
        body["scope"] = fake.scope
        return self._reply(200, body)

    def _device_code(self, raw: bytes) -> None:
        fake = self.fake
        self._count("device-code")
        if json.loads(raw or b"{}").get("client_id") != DEVICE_CLIENT:
            return self._reply(400, {"error": "invalid_client"})
        device = fake._secret("device")
        with fake.lock:
            fake.devices[device] = 0
        user_code = f"QA{secrets.randbelow(10**6):06d}"
        body = {"device_auth_id": device, "user_code": user_code, "interval": "1"}
        return self._reply(200, body)

    def _device_poll(self, raw: bytes) -> None:
        fake = self.fake
        self._count("device-poll")
        device = json.loads(raw or b"{}").get("device_auth_id", "")
        with fake.lock:
            if device not in fake.devices:
                return self._reply(404, {"error": "unknown"})
            fake.devices[device] += 1
            polls = fake.devices[device]
        if fake.device_fails:
            return self._reply(400, {"error": "access_denied"})
        if polls < fake.device_approve_after:
            return self._reply(403, {"error": "authorization_pending"})
        verifier = fake._secret("verifier")
        code = fake._secret("code")
        with fake.lock:
            fake.devices.pop(device, None)
            fake.codes[code] = {
                "redirect_uri": f"{fake.origin}/deviceauth/callback",
                "code_challenge": _s256(verifier),
            }
        body = {
            "authorization_code": code,
            "code_challenge": _s256(verifier),
            "code_verifier": verifier,
        }
        return self._reply(200, body)

    def _whoami(self) -> None:
        self._count("identity")
        if self._bearer_generation() is None:
            return self._reply(401, {"error": "invalid_token"})
        user = "someone-else" if self.fake.wrong_identity else USER
        return self._reply(200, {"workspace_id": WORKSPACE, "user_id": user})

    def _mcp(self, raw: bytes) -> None:
        generation = self._bearer_generation()
        if generation is None:
            self._count("mcp-unauthorized")
            return self._reply(401, {"error": "invalid_token"})
        message = json.loads(raw)
        method = message.get("method")
        self._count(f"mcp-{method}")
        session = {"Mcp-Session-Id": "qa-oau-session"}
        if method == "notifications/initialized":
            return self._reply(202, headers=session)
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "qa-oau-fake", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": [_tool(name) for name in MCP_TOOLS]}
        elif method == "tools/call":
            self._count("mcp-tool-call")
            name = message.get("params", {}).get("name")
            text = json.dumps({"tool": name, "generation": generation})
            result = {"content": [{"type": "text", "text": text}]}
        else:
            return self._reply(400, {"error": "unsupported"})
        return self._reply(
            200, {"jsonrpc": "2.0", "id": message.get("id"), "result": result}, session
        )


def _tool(name: str) -> dict:
    return {
        "name": name,
        "description": "Invented read-only record lookup",
        "inputSchema": {
            "type": "object",
            "properties": {"record": {"type": "string", "const": "REC-1"}},
            "required": ["record"],
            "additionalProperties": False,
        },
    }
