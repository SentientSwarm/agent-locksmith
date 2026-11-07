"""Disposable streamable-HTTP MCP server over TLS for native MCP smoke cases.

Stdlib only. It answers initialize, notifications/initialized, tools/list and
tools/call for a fixed finite catalog, and counts every arrival so refusal
cases can prove zero dispatch. Its certificate is issued by a qa/fakes/pki.py
CA that the daemon trusts through `mcp.upstream_ca_bundle`.
"""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer

from .pki import CA

PROTOCOL = "2025-11-25"
READ_RECORD = {
    "name": "read_record",
    "description": "Read one record by key",
    "inputSchema": {
        "type": "object",
        "properties": {"key": {"type": "string"}},
        "required": ["key"],
        "additionalProperties": False,
    },
}
DELETE_RECORD = {
    "name": "delete_record",
    "description": "Delete one record by key",
    "inputSchema": {
        "type": "object",
        "properties": {"key": {"type": "string"}},
        "required": ["key"],
        "additionalProperties": False,
    },
}


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self) -> None:
        # No reverse DNS lookup for a loopback-only fixture.
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def handle_error(self, *_ignored) -> None:
        pass


class FakeMcp:
    """One TLS MCP endpoint at https://127.0.0.1:PORT/mcp."""

    def __init__(self, ca: CA, directory: Path) -> None:
        self.tools = [READ_RECORD, DELETE_RECORD]
        self.lock = threading.Lock()
        self.counts: dict[str, int] = {}
        self.calls: list[dict] = []
        leaf = ca.server(("127.0.0.1", "localhost"))
        cert = directory / "nat-upstream.pem"
        key = directory / "nat-upstream.key"
        cert.write_bytes(leaf.cert_pem())
        key.write_bytes(leaf.key_pem())
        key.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server = _Server(("127.0.0.1", 0), self._handler())
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}/mcp"
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def snapshot(self) -> dict:
        with self.lock:
            return {"counts": dict(self.counts), "calls": len(self.calls)}

    def record(self, key: str, call: dict | None = None) -> None:
        with self.lock:
            self.counts[key] = self.counts.get(key, 0) + 1
            if call is not None:
                self.calls.append(call)

    def result_for(self, message: dict, authorization: str) -> dict | None:
        method = message.get("method")
        if method == "initialize":
            return {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "qa-nat-fake", "version": "1"},
            }
        if method == "tools/list":
            return {"tools": [dict(t) for t in self.tools]}
        if method == "tools/call":
            params = message.get("params") or {}
            arguments = params.get("arguments") or {}
            self.record(
                "tools/call:" + str(params.get("name")),
                {
                    "name": params.get("name"),
                    "arguments": arguments,
                    "authorization": authorization,
                },
            )
            text = f"record {arguments.get('key', '')} via {params.get('name')}"
            return {"content": [{"type": "text", "text": text}], "isError": False}
        if method == "ping":
            return {}
        return None

    def _handler(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_ignored) -> None:
                pass

            def reply(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Mcp-Session-Id", "qa-nat-upstream-session")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def do_DELETE(self) -> None:
                fake.record("DELETE")
                self.reply(204, b"")

            def do_GET(self) -> None:
                fake.record("GET")
                self.reply(405, b"")

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                message = json.loads(self.rfile.read(length) or b"{}")
                method = message.get("method", "")
                if method != "tools/call":
                    fake.record(method)
                if method.startswith("notifications/"):
                    self.reply(202, b"")
                    return
                result = fake.result_for(message, self.headers.get("Authorization", ""))
                if result is None:
                    body = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {"code": -32601, "message": "unsupported"},
                    }
                else:
                    body = {"jsonrpc": "2.0", "id": message.get("id"), "result": result}
                self.reply(200, json.dumps(body).encode())

        return Handler
