"""Actual loopback HTTP exercises whole-operation bounds, not per-packet timeouts."""
import http.server
from pathlib import Path
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from native_validation.http import request


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            if self.server.mode == 'slow_header':
                for byte in b'HTTP/1.1 200 OK\r\n':
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(.015)
                return
            body = b'{"status":"live"}'
            self.send_response(200)
            if self.server.mode == 'large_header':
                self.send_header('X-Padding', 'a' * 40000)
            if self.server.mode == 'large_body':
                body = b' ' * 16384 + body
            self.send_header('Content-Length', str(len(body) + (7 if self.server.mode == 'truncated' else 0)))
            self.end_headers()
            self.close_connection = True
            for byte in body:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                if self.server.mode == 'slow_body':
                    time.sleep(.015)
        except (BrokenPipeError, ConnectionResetError):
            pass


class HttpContract(unittest.TestCase):
    def check(self, mode, timeout):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.mode = mode
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
        thread.start()
        try:
            return request(server.server_port, 'livez', time.monotonic() + timeout)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_prompt_response(self):
        self.assertEqual(self.check('prompt', 1), {'status': 'live'})

    def test_slow_header_and_body_have_absolute_deadline(self):
        for mode in ['slow_header', 'slow_body']:
            with self.subTest(mode=mode), self.assertRaises((OSError, ValueError)):
                self.check(mode, .05)

    def test_header_and_body_limits(self):
        for mode in ['large_header', 'large_body']:
            with self.subTest(mode=mode), self.assertRaises((OSError, ValueError)):
                self.check(mode, 1)

    def test_already_expired_deadline_opens_no_connection(self):
        with self.assertRaises(TimeoutError):
            request(1, 'livez', time.monotonic() - 1)

    def test_truncated_length_refuses_complete_json_prefix(self):
        with self.assertRaises((OSError, ValueError)):
            self.check('truncated', 1)
