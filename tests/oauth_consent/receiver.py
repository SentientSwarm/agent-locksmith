"""Controlled TLS twin; records arrival classes, never request/token values."""

import importlib.util
import json
import pathlib
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

root = pathlib.Path(sys.argv[1])
lock = threading.Lock()
refresh_number = 0
current_refresh = "fixture-refresh-0"
current_access = "fixture-access-204"
counts = {"token": 0, "workspace": 0, "user": 0, "other": 0, "delete": 0}


def record(kind):
    with lock:
        counts[kind] = counts.get(kind, 0) + 1
        temporary = root / "counts.new"
        temporary.write_text(json.dumps(counts))
        temporary.replace(root / "counts.json")


def wait(point):
    if (root / f"hold-{point}").exists():
        (root / f"entered-{point}").write_text("held")
        until = time.monotonic() + 12
        while not (root / f"release-{point}").exists():
            if time.monotonic() > until:
                return False
            time.sleep(0.01)
    return True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, value=None):
        raw = b"" if value is None else json.dumps(value).encode()
        # The client may already be gone (an embedding returned with this
        # request in flight). end_headers() writes too, so a closed peer can
        # fail there as well; the caller still records "response attempted".
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if self.path == "/mcp/readonly":
                self.send_header("Mcp-Session-Id", "fixture-session-204")
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_DELETE(self):
        record("delete")
        self.reply(500 if (root / "fail-delete").exists() else 405)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/token":
            return self._token(raw)
        if self.path != "/mcp/readonly":
            record("other")
            return self.reply(400)
        return self._mcp(raw)

    def _token(self, raw):
        record("token")
        form = parse_qs(raw.decode())
        assert form["client_id"] == ["fixture-client"]
        assert form["resource"] == [
            f"https://127.0.0.1:{self.server.server_port}/mcp/readonly"
        ]
        if form["grant_type"] == ["refresh_token"]:
            return self._refresh(form)
        return self._authorization_code(form)

    def _refresh(self, form):
        global refresh_number, current_refresh, current_access
        record("refresh")
        assert form["scope"] == ["read"]
        assert set(form) == {
            "grant_type",
            "refresh_token",
            "client_id",
            "resource",
            "scope",
        }
        with lock:
            valid = form["refresh_token"] == [current_refresh]
            if valid:
                refresh_number += 1
                current_refresh = f"fixture-refresh-{refresh_number}"
                current_access = f"fixture-access-{refresh_number}"
        if not valid or (root / "invalid-grant").exists():
            return self.reply(400, {"error": "invalid_grant"})
        record("consumed")
        record("issued")
        if not wait("refresh"):
            return self.reply(503)
        result = {
            "access_token": current_access,
            "refresh_token": current_refresh,
            "token_type": "Bearer",
        }
        if (root / "omit-refresh").exists():
            current_refresh = form["refresh_token"][0]
            del result["refresh_token"]
        if (root / "token-error-member").exists():
            result["error"] = "synthetic-refusal"
        if (root / "token-metadata").exists():
            result.update(json.loads((root / "token-metadata").read_text()))
        self.reply(200, result)
        (root / "finished-refresh").write_text("response attempted")

    def _authorization_code(self, form):
        assert form["grant_type"] == ["authorization_code"]
        assert len(form["code_verifier"][0]) == 43
        if not wait("token"):
            return self.reply(503)
        result = {"access_token": current_access, "token_type": "Bearer"}
        if (root / "refresh-enabled").exists():
            result.update(refresh_token=current_refresh, expires_in=3600, scope="read")
        self.reply(200, result)
        (root / "finished-token").write_text("response attempted")

    def _mcp(self, raw):
        assert self.headers.get("Authorization") == f"Bearer {current_access}"
        assert self.headers.get("Mcp-Protocol-Version") == "2025-11-25"
        message = json.loads(raw)
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "controlled", "version": "1"},
            }
        elif method == "notifications/initialized":
            return self.reply(202)
        elif method == "tools/list":
            result = self._tools_list()
        elif method == "tools/call":
            result = self._tools_call(message)
            if result is None:
                return
        else:
            record("other")
            return self.reply(400)
        self.reply(200, {"jsonrpc": "2.0", "id": message["id"], "result": result})

    def _tools_list(self):
        result = {
            "tools": [
                {
                    "name": "get_workspace",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "get_user",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                },
            ]
        }
        if (root / "schema-required-null").exists():
            result["tools"][0]["inputSchema"]["required"] = [None]
        for keyword in ("const", "enum"):
            if (root / f"schema-query-{keyword}").exists():
                result["tools"][1]["inputSchema"]["properties"]["query"][keyword] = (
                    "someone-else" if keyword == "const" else ["someone-else"]
                )
        if (root / "echo-old-refresh").exists():
            result["tools"][0]["description"] = "fixture-refresh-0"
        return result

    def _tools_call(self, message):
        """Return the call result, or None after replying with an error."""
        name = message["params"]["name"]
        if name not in ("get_workspace", "get_user"):
            record("other")
            self.reply(400)
            return None
        kind = "workspace" if name == "get_workspace" else "user"
        record(kind)
        if not wait(kind):
            self.reply(503)
            return None
        identity = (
            "00000000-0000-0000-0000-000000000041"
            if kind == "workspace"
            else "00000000-0000-0000-0000-000000000042"
        )
        if (root / "wrong-user").exists() and kind == "user":
            identity = "00000000-0000-0000-0000-000000000043"
        return {"content": [{"type": "text", "text": json.dumps({"id": identity})}]}


# Reuse the existing local receiver's no-reverse-DNS server plumbing.
spec = importlib.util.spec_from_file_location(
    "consent_receiver_base",
    pathlib.Path(__file__).parents[1] / "native_preparation" / "receiver.py",
)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
server = base.Server(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / "server.pem", root / "server.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
# Publish atomically: the test polls for this file and must never read it
# truncated-but-not-yet-written.
(root / "provider-port.new").write_text(json.dumps(server.server_port))
(root / "provider-port.new").replace(root / "provider-port.json")
server.serve_forever()
