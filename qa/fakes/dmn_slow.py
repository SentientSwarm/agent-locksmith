"""A slow loopback upstream for drain tests.

`GET /delay/<seconds>` sleeps that long, then answers 200 `slow-done`.
Counters record requests received and responses completed, so a test can
send SIGTERM while a proxied request is provably in flight.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"slow-done"


class SlowUpstream:
    def __init__(self) -> None:
        self.received = 0
        self.completed = 0
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                with owner._lock:
                    owner.received += 1
                parts = self.path.strip("/").split("/")
                delay = (
                    float(parts[1]) if len(parts) == 2 and parts[0] == "delay" else 0.0
                )
                time.sleep(delay)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(BODY)))
                    self.end_headers()
                    self.wfile.write(BODY)
                except OSError:
                    return
                with owner._lock:
                    owner.completed += 1

            def log_message(self, *_args) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
