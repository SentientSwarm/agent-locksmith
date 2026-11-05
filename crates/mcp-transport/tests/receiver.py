"""Disposable independent TLS receiver; synthetic identity only, no providers."""
import http.server
import json
import pathlib
import ssl
import socketserver
import sys
import threading
import time

COUNTS = {"requests": 0, "effects": 0, "denied": 0, "versioned": 0, "deleted": 0, "cancelled": 0, "initializations": 0, "gets": 0, "get_bodies": 0}
LOCK = threading.Lock()
ROOT = pathlib.Path(sys.argv[1])
GET_MODE = sys.argv[2] if len(sys.argv) > 2 else "405"


def count(key: str) -> None:
    with LOCK:
        COUNTS[key] += 1
        (ROOT / "counts.tmp").write_text(json.dumps(COUNTS))
        (ROOT / "counts.tmp").replace(ROOT / "counts.json")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def reply(self, status: int, body: bytes = b"", sse: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "synthetic-session")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def allowed(self) -> bool:
        count("requests")
        if self.headers.get("Authorization") != "Bearer synthetic-test-token":
            count("denied")
            self.reply(401)
            return False
        return True

    def do_GET(self) -> None:
        if not self.allowed():
            return
        count("gets")
        if GET_MODE in ("405", "startup") or COUNTS["gets"] > 5:
            self.reply(405)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()
        if GET_MODE == "deadline":
            time.sleep(10)
        count("get_bodies")
        body = b"retry: 0\n\n" if GET_MODE == "retry" else b":" + b"x" * 65536
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def do_DELETE(self) -> None:
        if self.allowed():
            count("deleted")
            self.reply(200)

    def do_POST(self) -> None:
        if not self.allowed():
            return
        length = int(self.headers.get("Content-Length", "0"))
        message = json.loads(self.rfile.read(length))
        method = message.get("method")
        if method != "initialize" and not self.valid_session():
            return
        if method == "notifications/cancelled":
            count("cancelled")
        if "id" not in message:
            self.reply(202)
            return
        result = dispatch(method, message.get("params", {}))
        response = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        body = json.dumps(response).encode()
        sse = message.get("params", {}).get("arguments", {}).get("mode") == "sse"
        if sse:
            body = b"data: " + body + b"\n\n"
        self.reply(200, body, sse)

    def valid_session(self) -> bool:
        if self.headers.get("Mcp-Session-Id") != "synthetic-session":
            self.reply(404)
            return False
        if self.headers.get("Mcp-Protocol-Version") != "2025-11-25":
            self.reply(400)
            return False
        count("versioned")
        return True


def dispatch(method: str, params: dict) -> dict:
    if method == "initialize":
        count("initializations")
        return {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                "serverInfo": {"name": "independent-receiver", "version": "1"}}
    if method == "tools/list":
        return {"tools": [{"name": "echo", "inputSchema": {"type": "object",
                "properties": {"mode": {"type": "string"}}}}]}
    if method == "tools/call":
        count("effects")
        mode = params.get("arguments", {}).get("mode")
        if mode == "slow":
            time.sleep(0.5)
        text = "x" * 65536 if mode == "large" else "receiver-ok"
        return {"content": [{"type": "text", "text": text}], "isError": mode == "error"}
    return {}


class LocalServer(http.server.ThreadingHTTPServer):
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


def main() -> None:
    server = LocalServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ROOT / "cert.pem", ROOT / "key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    if GET_MODE == "startup":
        (ROOT / "port").write_text("")
        time.sleep(0.03)
    (ROOT / "port.tmp").write_text(str(server.server_port))
    (ROOT / "port.tmp").replace(ROOT / "port")
    server.serve_forever()


if __name__ == "__main__":
    main()
