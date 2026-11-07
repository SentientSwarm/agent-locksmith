"""Loopback HTTP smoke with absolute time and complete wire byte limits."""
import http.client
import socket
import time
from . import common as C


class BoundedSocket(socket.socket):
    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('smoke_http_deadline')
        self.settimeout(remaining)
        return remaining

    def recv_into(self, buffer, nbytes=0, flags=0):
        self.remaining()
        size = min(nbytes or len(buffer), 32769 - self.received)
        count = super().recv_into(buffer, size, flags)
        self.received += count
        self.remaining()
        if self.received > 32768:
            raise ValueError('smoke_http_wire_limit')
        return count

    def sendall(self, data, flags=0):
        self.remaining()
        super().sendall(data, flags)
        self.remaining()


def request(port, path, deadline=None):
    deadline = min(deadline or float('inf'), time.monotonic() + 1)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('smoke_http_deadline')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=remaining)
    try:
        connection.connect()
        raw = connection.sock
        connection.sock = BoundedSocket(raw.family, raw.type, raw.proto, fileno=raw.detach())
        connection.sock.deadline, connection.sock.received = deadline, 0
        connection.request('GET', '/' + path)
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError('smoke_http_refused')
            return decode(response, deadline)
    except http.client.HTTPException:
        raise ValueError('smoke_http_protocol') from None
    finally:
        connection.close()


def decode(response, deadline):
    data = response.read(16385)
    if len(data) > 16384 or response.read(1):
        raise ValueError('smoke_response_limit')
    if response.length not in (None, 0) or not response.isclosed():
        raise ValueError('smoke_response_truncated')
    if time.monotonic() >= deadline:
        raise TimeoutError('smoke_http_deadline')
    value = C.V.strict_json(data)
    if not isinstance(value, dict):
        raise ValueError('smoke_response_shape')
    return value
