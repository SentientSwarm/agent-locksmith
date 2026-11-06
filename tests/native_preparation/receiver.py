"""Private TLS receiver for actual operator observation; never executes tools."""

import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time
from socketserver import TCPServer
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def write(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    os.replace(temporary, path)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self) -> None:
        # No reverse DNS in an isolated local fixture's startup.
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def handle_error(self, request: object, client_address: object) -> None:
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def reply(self, status: int, body: bytes, sse: bool = False) -> None:
        self.send_response(status)
        self.send_header(
            "Content-Type", "text/event-stream" if sse else "application/json"
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Mcp-Session-Id", "fixture-session")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_DELETE(self) -> None:
        self.reply(204, b"")

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        message = json.loads(body)
        method = message["method"]
        with lock:
            counts[method] = counts.get(method, 0) + 1
            write(directory / "counts.json", counts)
        if method == "notifications/initialized":
            self.reply(202, b"")
            return
        behavior = json.loads((directory / "behavior.json").read_text())
        if method == "tools/list" and behavior.get("hold"):
            hold(behavior["hold"])
        result = result_for(method)
        if result is None:
            self.reply(400, b"{}")
            return
        body = response(
            message, result, behavior, self.headers.get("Authorization", "")
        )
        self.reply(200, body, behavior.get("mode") == "sse")


def response(message: dict, result: dict, behavior: dict, authorization: str) -> bytes:
    mode = behavior.get("mode")
    value = {"jsonrpc": "2.0", "id": message["id"], "result": result}
    if message["method"] == "tools/list":
        change(result, mode, message["id"], authorization)
        if mode == "wrong-id":
            value["id"] = 999
    body = json.dumps(value).encode()
    if message["method"] == "tools/list" and mode == "duplicate":
        body = body.replace(b'"type": "string"', b'"type":"string","type":"integer"')
    if mode == "sse":
        body = b"data: " + body + b"\n\n"
    return body


def change(result: dict, mode: str, request_id: int, authorization: str) -> None:
    tool = result["tools"][0]
    if mode == "echo":
        tool["description"] = authorization.removeprefix("Bearer ")
    if mode == "metadata":
        tool["_meta"] = {"private": "synthetic-unprojected"}
    if mode == "schema":
        tool["inputSchema"]["$ref"] = "https://never-fetch.invalid/schema"
    if mode == "oversize":
        tool["description"] = "x" * 262144
    if mode == "too-many":
        result["tools"] = [dict(tool, name=f"name-{i}") for i in range(33)]
    if mode in ("pages", "duplicate-names", "cursor"):
        if mode == "pages":
            tool["name"] = f"page-{request_id}"
        result["nextCursor"] = "repeat" if mode == "cursor" else str(request_id)


def hold(name: str) -> None:
    write(directory / f"arrived-{name}.json", True)
    deadline = time.monotonic() + 20
    while not (directory / f"release-{name}.json").exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("fixture release deadline")
        time.sleep(0.01)


def result_for(method: str) -> dict | None:
    if method == "initialize":
        return {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "private-fixture", "version": "1"},
        }
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "read_record",
                    "description": "Read one record",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"key": {"type": "string"}},
                        "additionalProperties": False,
                    },
                }
            ]
        }
    return None


def main(path: Path) -> None:
    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(path / "server.pem", path / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    write(path / "behavior.json", {})
    write(path / "counts.json", {})
    write(path / "receiver-port.json", server.server_address[1])
    server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    lock = threading.Lock()
    counts: dict[str, int] = {}
    main(directory)
