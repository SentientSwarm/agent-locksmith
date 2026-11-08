#!/usr/bin/env python3
"""Disposable HTTPS MCP service with synthetic invoice records; stdlib only.

A stand-in for a customer MCP server, for trying Locksmith's native MCP path
(docs/guide/05-mcp-service.md). It serves streamable HTTP MCP at /mcp with two
tools, `read_record` (read) and `delete_record` (write), over a few fixed
invoices, and reports what it received at GET /counts. With --bearer-env it
requires `Authorization: Bearer <value of that env var>`. It binds loopback
only and never logs request contents.
"""

import argparse
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL = "2025-11-25"
RECORDS = {
    "INV-204": {
        "customer": "Northwind",
        "total": "1250.00",
        "currency": "USD",
        "status": "open",
    },
    "INV-205": {
        "customer": "Contoso",
        "total": "310.40",
        "currency": "EUR",
        "status": "paid",
    },
}
KEY_SCHEMA = {
    "type": "object",
    "properties": {
        "key": {"type": "string", "description": "Invoice number, e.g. INV-204"}
    },
    "required": ["key"],
    "additionalProperties": False,
}
TOOLS = [
    {
        "name": "read_record",
        "description": "Read one invoice by number",
        "inputSchema": KEY_SCHEMA,
    },
    {
        "name": "delete_record",
        "description": "Delete one invoice by number",
        "inputSchema": KEY_SCHEMA,
    },
]
COUNTS = {"received": 0, "tools/call": 0, "unauthorized": 0}
LOCK = threading.Lock()


def call_tool(name, arguments):
    key = str(arguments.get("key", ""))
    if name == "read_record" and key in RECORDS:
        return {
            "content": [
                {"type": "text", "text": json.dumps({"key": key, **RECORDS[key]})}
            ],
            "isError": False,
        }
    if name == "delete_record" and key in RECORDS:
        return {
            "content": [{"type": "text", "text": f"deleted {key}"}],
            "isError": False,
        }
    return {"content": [{"type": "text", "text": f"no invoice {key}"}], "isError": True}


def result_for(message):
    method = message.get("method")
    if method == "initialize":
        info = {"name": "records-service", "version": "1"}
        return {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": info,
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = message.get("params") or {}
        with LOCK:
            COUNTS["tools/call"] += 1
        return call_tool(params.get("name"), params.get("arguments") or {})
    if method == "ping":
        return {}
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    bearer = None

    def log_message(self, *_args):
        pass  # Never log credentials or request contents.

    def reply(self, status, body=b"", content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "records-service-session")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/counts":
            with LOCK:
                self.reply(200, json.dumps(COUNTS).encode())
            return
        self.reply(405)

    def do_DELETE(self):
        self.reply(204)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        with LOCK:
            COUNTS["received"] += 1
        if self.path != "/mcp":
            self.reply(404)
            return
        if (
            self.bearer is not None
            and self.headers.get("Authorization") != f"Bearer {self.bearer}"
        ):
            with LOCK:
                COUNTS["unauthorized"] += 1
            self.reply(401)
            return
        message = json.loads(raw or b"{}")
        if str(message.get("method", "")).startswith("notifications/"):
            self.reply(202)
            return
        result = result_for(message)
        body = {"jsonrpc": "2.0", "id": message.get("id")}
        body.update(
            {"result": result}
            if result is not None
            else {"error": {"code": -32601, "message": "unsupported"}}
        )
        self.reply(200, json.dumps(body).encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9400)
    parser.add_argument(
        "--cert", required=True, help="PEM server certificate for 127.0.0.1"
    )
    parser.add_argument("--key", required=True, help="PEM private key for --cert")
    parser.add_argument(
        "--bearer-env", help="require Authorization: Bearer <value of this env var>"
    )
    args = parser.parse_args()
    if args.bearer_env:
        Handler.bearer = os.environ[args.bearer_env]
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"https://127.0.0.1:{server.server_address[1]}/mcp", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
