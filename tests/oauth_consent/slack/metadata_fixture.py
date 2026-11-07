"""Invented diagnostic responses, used only by the local receiving fixture."""
import json


def reply(handler, status, value, root):
    path = root / 'metadata-case.json'
    if status != 200 or getattr(handler, 'phase', '') not in ('token', 'refresh') or not path.exists():
        return False
    plan = json.loads(path.read_text())
    raw = response(value, plan)
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)
    return True


def response(value, plan):
    if 'pad' in plan:
        raw = json.dumps(value).encode()
        assert len(raw) <= plan['pad'] <= 65536
        return raw + b' ' * (plan['pad'] - len(raw))
    if 'raw' in plan:
        return plan['raw'].encode()
    parent = value
    parts = plan['path'].split('/')
    for part in parts[:-1]:
        parent = parent[part]
    if plan['mode'] == 'missing':
        parent.pop(parts[-1], None)
    else:
        parent[parts[-1]] = plan['value']
    return json.dumps(value).encode()
