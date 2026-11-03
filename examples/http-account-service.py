#!/usr/bin/env python3
"""Disposable loopback reference API; synthetic accounts only, no dependencies."""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer

COUNTS = {"received": 0, "X": 0, "Y": 0, "NONE": 0}
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        with LOCK:
            if path == "/counts":
                body, status = json.dumps(COUNTS), 200
            else:
                COUNTS["received"] += 1
                auth = self.headers.get("Authorization")
                account = {
                    "Bearer synthetic-private-account-x": "X",
                    "Bearer synthetic-private-account-y": "Y",
                }.get(auth)
                if path == "/noauth" and auth is None:
                    account = "NONE"
                if path not in ("/check", "/noauth"):
                    body, status = "unknown route", 404
                elif account is None:
                    body, status = "account required", 401
                else:
                    COUNTS[account] += 1
                    body, status = account, 200
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass  # Do not log credentials or request contents.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9300)
    args = parser.parse_args()
    # TCPServer avoids HTTPServer's unnecessary reverse-DNS lookup at bind.
    server = ThreadingTCPServer(("127.0.0.1", args.port), Handler)
    print(f"http://127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
