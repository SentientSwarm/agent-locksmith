"""HTTP/1.1 over a Unix socket, shared by the admin-socket smoke clients."""

from __future__ import annotations

import http.client
import socket


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


def exchange(
    socket_path: str,
    method: str,
    path: str,
    body: bytes | None,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:
    """Send one request; return status, headers and body."""
    conn = UnixConnection(socket_path, timeout)
    try:
        try:
            conn.request(method, path, body=body, headers=headers)
        except (BrokenPipeError, ConnectionResetError):
            # The server may refuse on the headers alone (401) and close
            # before reading the body. Its response is already buffered,
            # so read it rather than fail the case (AGENT-292).
            pass
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()
