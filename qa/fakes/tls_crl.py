"""A tiny local CRL distribution point for the TLS smoke cases.

Serves whatever body the case sets (or an error status) on every GET, on
127.0.0.1 only, and counts fetches so a case can tell that the daemon
actually polled it.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CrlServer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._body: bytes = b""
        self._status = 503
        self._fetches = 0
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                status, body = server._take()
                self.send_response(status)
                self.send_header("Content-Type", "application/pkix-crl")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_: object) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/crl"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def _take(self) -> tuple[int, bytes]:
        with self._lock:
            self._fetches += 1
            return self._status, (self._body if self._status == 200 else b"unavailable")

    def serve(self, body: bytes) -> None:
        """Serve this CRL from now on."""
        with self._lock:
            self._body, self._status = body, 200

    def fail(self, status: int = 503) -> None:
        with self._lock:
            self._status = status

    @property
    def fetches(self) -> int:
        with self._lock:
            return self._fetches

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
