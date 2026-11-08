"""Separate TLS receiver: exact merged arguments and committed admission witness."""

import http.server
import json
from pathlib import Path
import sqlite3
from socketserver import TCPServer
import ssl
import sys
import threading
import time

ROOT = Path(sys.argv[1])
LOCK = threading.Lock()


def read(name: str, default: object) -> object:
    path = ROOT / name
    return json.loads(path.read_text()) if path.exists() else default


def write(name: str, value: object) -> None:
    path = ROOT / name
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value))
    tmp.replace(path)


def hold(name: str) -> None:
    write(f"arrived-{name}.json", True)
    until = time.monotonic() + 20
    while not (ROOT / f"release-{name}.json").exists():
        if time.monotonic() >= until:
            return
        time.sleep(0.01)


class Server(http.server.ThreadingHTTPServer):
    def server_bind(self) -> None:
        # Match the existing local receiver: startup never needs reverse DNS.
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def reply(self, status: int, value: object) -> None:
        raw = json.dumps(value).encode() if value is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Mcp-Session-Id", "synthetic-session")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass

    def do_DELETE(self) -> None:
        behavior = read("behavior.json", {})
        if behavior.get("cleanup_hold"):
            hold(behavior["cleanup_hold"])
        self.reply(204, None)

    def do_POST(self) -> None:
        message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = message["method"]
        with LOCK:
            counts = read("counts.json", {})
            counts[method] = counts.get(method, 0) + 1
            write("counts.json", counts)
        if "id" not in message:
            self.reply(202, None)
            return
        result = self.result(method, message.get("params", {}))
        self.reply(200, {"jsonrpc": "2.0", "id": message["id"], "result": result})

    def result(self, method: str, params: dict) -> dict:
        behavior = read("behavior.json", {})
        if method == "initialize":
            if behavior.get("prepare_hold"):
                hold(behavior["prepare_hold"])
            return {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "context-fixture", "version": "1"},
            }
        if method == "tools/list":
            return read("manifest.json", {"tools": []})
        if method == "tools/call":
            return self.effect(params, behavior)
        return {}

    def effect(self, params: dict, behavior: dict) -> dict:
        account = {
            "": "None",
            "Bearer fixture-account-x": "X",
            "Bearer fixture-account-y": "Y",
        }.get(self.headers.get("Authorization", ""), "invalid")
        with LOCK, sqlite3.connect(ROOT / "state.db") as db:
            admission, reviewed, count = witness(db, params)
            effects = read("effects.json", [])
            effects.append(
                {
                    "account": account,
                    "committed": count,
                    "arguments": params["arguments"],
                    "admission": admission,
                    "reviewed_context": reviewed["context"],
                }
            )
            write("effects.json", effects)
            if behavior.get("outcome_fail"):
                db.execute(
                    "CREATE TRIGGER outcome_refuse BEFORE INSERT ON audit WHEN NEW.event='mcp_outcome' BEGIN SELECT RAISE(ABORT,'synthetic diagnostic failure'); END"
                )
        if behavior.get("call_hold"):
            hold(behavior["call_hold"])
        return {
            "content": [{"type": "text", "text": account}],
            "isError": behavior.get("tool_error", False),
        }


def witness(db: sqlite3.Connection, params: dict) -> tuple:
    rows = db.execute(
        "SELECT details FROM audit WHERE event='mcp_admitted' ORDER BY id"
    ).fetchall()
    admission = json.loads(rows[-1][0])
    assert admission["tool_name"] == params["name"]
    row = db.execute(
        "SELECT contract FROM native_reviews WHERE contract_digest=?",
        (admission["contract_digest"],),
    ).fetchone()
    reviewed = json.loads(row[0])
    assert all(params["arguments"].get(k) == v for k, v in reviewed["context"].items())
    return admission, reviewed, len(rows)


server = Server(("127.0.0.1", 0), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(ROOT / "server.pem", ROOT / "server.key")
server.socket = tls.wrap_socket(server.socket, server_side=True)
write("receiver-port.json", server.server_port)
server.serve_forever()
