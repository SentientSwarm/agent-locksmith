"""AGENT-292: a refusal sent before the server reads the body is an answer."""

from __future__ import annotations

import os
import shutil
import socket
import tempfile
import threading

from fakes.uds_http import exchange

REFUSAL = (
    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
)


def _refuse_on_headers(server: socket.socket) -> None:
    conn, _ = server.accept()
    with conn:
        conn.settimeout(10)
        seen = b""
        while b"\r\n\r\n" not in seen:
            chunk = conn.recv(4096)
            if not chunk:
                return
            seen += chunk
        conn.sendall(REFUSAL)


def test_refusal_before_body_is_read_is_returned():
    root = tempfile.mkdtemp(prefix="uds-http-")
    path = os.path.join(root, "s")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
        server.listen(1)
        server.settimeout(10)
        worker = threading.Thread(target=_refuse_on_headers, args=(server,))
        worker.start()
        # Large enough that the body cannot fit in the socket buffer, so
        # the server's close always lands mid-body.
        body = b"x" * (8 * 1024 * 1024)
        status, _, data = exchange(path, "POST", "/x", body, {}, timeout=10)
        worker.join(10)
        assert not worker.is_alive(), "fake server did not finish"
        assert (status, data) == (401, b"{}")
    finally:
        server.close()
        shutil.rmtree(root, ignore_errors=True)
