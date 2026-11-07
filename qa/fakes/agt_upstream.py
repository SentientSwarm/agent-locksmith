"""Recording upstream and egress-proxy fakes for the AGT smoke area.

`Upstream` is an in-process HTTP(S) server on 127.0.0.1 that records every
request it receives (method, path with query, lower-cased headers, body) and
answers per path prefix with a configurable `Reply` (status, content type,
body or generated size, delay before headers, chunked streaming). Records
stay in memory and never reach evidence: they can hold the synthetic
credentials locksmith injects.

`EgressProxy` is a forward proxy for `egress: proxied`: absolute-form HTTP
requests are forwarded and recorded, CONNECT requests are tunnelled and
recorded by authority.
"""

from __future__ import annotations

import http.client
import json
import select
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


@dataclass
class Reply:
    status: int = 200
    content_type: str = "text/plain"
    body: bytes = b"ok"
    size: int | None = None  # generate this many bytes instead of `body`
    delay: float = 0.0  # seconds before the status line is sent
    chunks: int = 0  # >0: chunked transfer in this many pieces
    headers: dict = field(default_factory=dict)

    def payload(self) -> bytes:
        if self.size is None:
            return self.body
        return (b"0123456789abcdef" * (self.size // 16 + 1))[: self.size]


@dataclass
class Record:
    method: str
    path: str
    headers: dict  # lower-cased name -> list of values
    body: bytes

    def header(self, name: str) -> str | None:
        values = self.headers.get(name.lower())
        return values[0] if values else None

    def json(self):
        return json.loads(self.body)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, owner, ctx: ssl.SSLContext | None) -> None:
        self.owner = owner
        self.tls = ctx
        super().__init__(("127.0.0.1", 0), owner.handler)

    def finish_request(self, request, client_address) -> None:
        if self.tls is not None:
            try:
                request.settimeout(10)
                request = self.tls.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError):
                self.owner.tls_failures += 1
                return
        super().finish_request(request, client_address)


class _Base:
    handler: type

    def __init__(self, ctx: ssl.SSLContext | None = None) -> None:
        self.lock = threading.Lock()
        self.tls_failures = 0
        self.server = _Server(self, ctx)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def log_message(self, *_args) -> None:  # keep pytest output quiet
        pass

    def _handle(self) -> None:
        owner: Upstream = self.server.owner
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = _read_chunked(self.rfile)
        headers: dict = {}
        for name, value in self.headers.items():
            headers.setdefault(name.lower(), []).append(value)
        owner.record(Record(self.command, self.path, headers, body))
        reply = owner.reply_for(self.path, body)
        if reply.delay:
            time.sleep(reply.delay)
        payload = reply.payload()
        try:
            self.send_response(reply.status)
            self.send_header("Content-Type", reply.content_type)
            for name, value in reply.headers.items():
                self.send_header(name, value)
            if reply.chunks > 0:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                step = max(1, len(payload) // reply.chunks)
                for i in range(0, len(payload), step):
                    piece = payload[i : i + step]
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle


def _read_chunked(rfile) -> bytes:
    out = b""
    while True:
        size = int(rfile.readline().split(b";")[0].strip() or b"0", 16)
        if size == 0:
            rfile.readline()
            return out
        out += rfile.read(size)
        rfile.readline()


class Upstream(_Base):
    """Recording upstream. `routes` maps a path prefix to a `Reply` or a
    callable(path, body) -> Reply; the longest matching prefix wins."""

    handler = _UpstreamHandler

    def __init__(self, ctx: ssl.SSLContext | None = None) -> None:
        self.records: list[Record] = []
        self.routes: dict = {}
        super().__init__(ctx)

    @property
    def url(self) -> str:
        scheme = "https" if self.server.tls is not None else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def record(self, rec: Record) -> None:
        with self.lock:
            self.records.append(rec)

    def reply_for(self, path: str, body: bytes) -> Reply:
        match = ""
        for prefix in self.routes:
            if path.startswith(prefix) and len(prefix) > len(match):
                match = prefix
        route = self.routes.get(match, Reply())
        return route(path, body) if callable(route) else route

    def count(self, prefix: str = "") -> int:
        with self.lock:
            return sum(1 for r in self.records if r.path.startswith(prefix))

    def last(self, prefix: str = "") -> Record:
        with self.lock:
            hits = [r for r in self.records if r.path.startswith(prefix)]
        assert hits, f"upstream received nothing under {prefix!r}"
        return hits[-1]


def tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def log_message(self, *_args) -> None:
        pass

    def do_CONNECT(self) -> None:
        owner: EgressProxy = self.server.owner
        owner.record("CONNECT", self.path)
        host, _, port = self.path.rpartition(":")
        try:
            remote = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            self.send_error(502)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        self.close_connection = True
        _pipe(self.connection, remote)

    def _forward(self) -> None:
        owner: EgressProxy = self.server.owner
        owner.record(self.command, self.path)
        target = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in {"proxy-connection", "connection", "host"}
        }
        conn = http.client.HTTPConnection(
            target.hostname or "127.0.0.1", target.port or 80, timeout=10
        )
        path = target.path + (f"?{target.query}" if target.query else "")
        conn.request(self.command, path or "/", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        self.send_response(resp.status)
        for name, value in resp.getheaders():
            if name.lower() not in {
                "transfer-encoding",
                "content-length",
                "connection",
            }:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _forward


def _pipe(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            ready, _, _ = select.select([a, b], [], [], 15)
            if not ready:
                return
            for src in ready:
                data = src.recv(65536)
                if not data:
                    return
                (b if src is a else a).sendall(data)
    except OSError:
        return
    finally:
        b.close()


class EgressProxy(_Base):
    """Forward proxy recording (method, target) for every request it carries."""

    handler = _ProxyHandler

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []
        super().__init__(None)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def record(self, method: str, target: str) -> None:
        with self.lock:
            self.seen.append((method, target))

    def count(self) -> int:
        with self.lock:
            return len(self.seen)
