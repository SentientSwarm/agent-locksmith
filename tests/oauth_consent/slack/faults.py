"""Bounded invented transport faults; no request values are recorded."""
import json
import socket
import time


def reply(handler, status, value, root):
    path = root / 'fault.json'
    if not path.exists():
        return False
    plan = json.loads(path.read_text())
    phase = getattr(handler, 'phase', '')
    if plan['phase'] != phase:
        return False
    (root / f'entered-{phase}').write_text('arrived')
    mode = plan['mode']
    if mode == 'abort':
        handler.connection.shutdown(socket.SHUT_RDWR)
        handler.connection.close()
        return True
    raw = json.dumps(value).encode()
    if mode == 'headers':
        time.sleep(plan['seconds'])
        return False
    if mode == 'hold':
        until = time.monotonic() + 35
        while not (root / f'release-{phase}').exists():
            assert time.monotonic() < until
            time.sleep(.01)
        return False
    return delayed_body(handler, raw, mode, plan['seconds'])


def delayed_body(handler, raw, mode, seconds):
    assert mode in ('body', 'sse')
    if mode == 'sse':
        raw = b'data: ' + raw + b'\n\n'
    handler.send_response(200)
    handler.send_header('Content-Type', 'text/event-stream' if mode == 'sse' else 'application/json')
    handler.send_header('Content-Length', str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw[:3])
    handler.wfile.flush()
    time.sleep(seconds)
    try:
        handler.wfile.write(raw[3:])
    except (BrokenPipeError, ConnectionResetError):
        pass
    return True
