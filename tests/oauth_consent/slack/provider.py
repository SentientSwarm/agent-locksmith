"""Invented confidential Slack receiver; records only counts and compared facts."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import threading
import faults
import metadata_fixture
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlsplit

root = Path(sys.argv[1])
lock = threading.Lock()
counts, codes = {}, {}
access, refresh = 'invented-access-1', 'invented-refresh-1'

def record(kind):
    with lock:
        counts[kind] = counts.get(kind, 0) + 1
        temporary = root / 'counts.new'
        temporary.write_text(json.dumps(counts))
        temporary.replace(root / 'counts.json')

def resource(port):
    origin = f'https://127.0.0.1:{port}'
    return origin if (root / 'separate-resource').exists() else origin + '/mcp'

def token():
    value = dict(ok=True, access_token=access, refresh_token=refresh, expires_in=3600,
                token_type='user', authed_user=dict(id='UTEST001', scope='search:read.public,channels:history'), team=dict(id='TTEST001'))
    for field in ['refresh_token', 'expires_in']:
        if (root / ('omit-' + field)).exists():
            value.pop(field)
        if (root / ('null-' + field)).exists():
            value[field] = None
    if (root / 'separate-resource').exists():
        value['resource'] = resource(server.server_port)
        if (root / 'wrong-resource-echo').exists():
            value['resource'] += '/mcp'
    return value

def schema(name):
    return dict(name=name, description='Invented public channel read', inputSchema=dict(
        type='object', properties=dict(channel=dict(type='string', const='CPUBLIC1')),
        required=['channel'], additionalProperties=False))

def mcp(handler, value):
    method = value['method']
    handler.phase = 'native-' + method.split('/')[-1]
    record(handler.phase)
    if method == 'notifications/initialized':
        return handler.reply(202)
    if method == 'initialize':
        result = dict(protocolVersion='2025-11-25', capabilities=dict(tools={}), serverInfo=dict(name='invented-slack', version='1'))
    elif method == 'tools/list':
        record('list')
        result = dict(tools=[schema(n) for n in ['search_messages', 'read_thread', 'omitted_tool']])
    else:
        assert method == 'tools/call'
        params = value['params']
        assert params['name'] in ['search_messages', 'read_thread']
        assert params['arguments'] == dict(channel='CPUBLIC1')
        import sqlite3
        with sqlite3.connect(f'file:{root / "state.db"}?mode=ro', uri=True) as db:
            admitted = db.execute("SELECT count(*) FROM audit WHERE event='mcp_admitted'").fetchone()[0]
        assert admitted > counts.get('tool', 0)
        record('tool')
        record(params['name'])
        result = dict(content=[dict(type='text', text=json.dumps(dict(account='X', channel='CPUBLIC1', result='invented public thread')))])
    handler.reply(200, dict(jsonrpc='2.0', id=value['id'], result=result))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value=None):
        if metadata_fixture.reply(self, status, value, root):
            return
        if faults.reply(self, status, value, root):
            return
        raw = b'' if value is None else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        if (root / 'separate-resource').exists() and getattr(self, 'phase', '') == 'native-initialize':
            self.send_header('Mcp-Session-Id', 'invented-session')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlsplit(self.path)
        assert parsed.path == '/oauth/v2_user/authorize'
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        assert q['client_id'] == 'fixture-client' and q['code_challenge_method'] == 'S256'
        assert q['scope'] == 'search:read.public,channels:history'
        assert q['resource'] == resource(self.server.server_port)
        record('issued_code')
        code = f'invented-code-{counts["issued_code"]}'
        codes[code] = q
        self.send_response(302)
        self.send_header('Location', q['redirect_uri']+'?'+urlencode(dict(state=q['state'], code=code, iss=f'https://127.0.0.1:{self.server.server_port}')))
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path == '/api/oauth.v2.user.access':
            return exchange(self, parse_qs(raw.decode()))
        assert self.headers.get('Authorization') == 'Bearer '+access
        if self.path == '/api/auth.test':
            self.phase = 'identity'
            record('identity')
            return self.reply(200, dict(ok=True, team_id='TTEST001', user_id='UTEST001'))
        assert self.path == '/mcp' and self.headers.get('Mcp-Protocol-Version') == '2025-11-25'
        mcp(self, json.loads(raw))

    def do_DELETE(self):
        if (root / 'separate-resource').exists():
            assert self.path == '/mcp'
            assert self.headers.get('Authorization') == 'Bearer '+access
            record('transport-delete')
        self.reply(405)

def exchange(h, form):
    global access, refresh
    h.phase = 'token'
    record('token')
    assert form['client_id'] == ['fixture-client']
    if form.get('client_secret') != ['invented-client-secret']:
        record('bad_client')
        return h.reply(200, dict(ok=False, error='bad_client_secret'))
    assert form['resource'] == [resource(h.server.server_port)]
    if form['grant_type'] == ['refresh_token']:
        h.phase = 'refresh'
        assert form['refresh_token'] == [refresh]
        record('refresh')
        access = 'invented-access-rotated'
        if not (root / 'omit-refresh_token').exists():
            refresh = 'invented-refresh-rotated'
        return h.reply(200, token())
    assert form['grant_type'] == ['authorization_code']
    issued = codes.pop(form['code'][0])
    assert form['redirect_uri'] == [issued['redirect_uri']]
    verifier = form['code_verifier'][0]
    assert 43 <= len(verifier) <= 128
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    if challenge != issued['code_challenge']:
        record('bad_verifier')
        return h.reply(200, dict(ok=False, error='invalid_code'))
    record('matched_verifier')
    h.reply(200, token())

spec = importlib.util.spec_from_file_location('base', Path(__file__).parents[2] / 'native_preparation/receiver.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
server = base.Server(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / 'server.pem', root / 'server.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
ready = root / 'provider-port.new'
ready.write_text(json.dumps(server.server_port))
ready.replace(root / 'provider-port.json')
server.serve_forever(poll_interval=0.05)
