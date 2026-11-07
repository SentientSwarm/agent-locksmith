"""Actual TLS receiver for declared contracts and native calls; bounded counts only."""
import importlib.util
import json
from pathlib import Path
import ssl
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit
import wire

root = Path(sys.argv[1])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _record(self, key):
        counts = self.server.counts
        counts[key] = counts.get(key, 0) + 1
        tmp = root / 'counts.new'
        tmp.write_text(json.dumps(counts))
        tmp.replace(root / 'counts.json')

    def _reply(self, value=None):
        raw = b'' if value is None else json.dumps(value).encode()
        self.send_response(202 if value is None else 200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.server.profile = json.loads((root / 'config.yaml').read_text())['oauth_consent']['profiles'][0]
        url = urlsplit(self.path)
        if url.path == '/authorize/custom':
            return wire.authorize(self, url.query)
        assert url.path == '/identity/custom'
        assert self.headers.get('Authorization') == 'Bearer ' + self.server.access
        wire.identity(self)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path == '/token/custom':
            return wire.exchange(self, raw)
        assert self.headers.get('Authorization') == 'Bearer ' + self.server.access
        if self.path == '/identity/custom':
            return wire.identity(self)
        assert self.path == '/mcp/custom'
        mcp(self, json.loads(raw))

    def do_DELETE(self):
        assert self.path == '/mcp/custom'
        self._record('delete')
        self.send_response(204)
        self.send_header('Content-Length', '0')
        self.end_headers()


def schema(name):
    return dict(name=name, description='Invented contract read', inputSchema=dict(type='object',
                properties=dict(channel=dict(type='string', const='CPUBLIC1')), required=['channel'], additionalProperties=False))


def mcp(h, value):
    method = value['method']
    h._record('native-' + method)
    if method == 'notifications/initialized':
        return h._reply()
    if method == 'initialize':
        result = dict(protocolVersion='2025-11-25', capabilities=dict(tools={}), serverInfo=dict(name='unlisted-service', version='1'))
    elif method == 'tools/list':
        result = dict(tools=[schema(n) for n in ['search_messages', 'read_thread', 'omitted']])
    else:
        assert method == 'tools/call'
        assert value['params']['name'] in ['search_messages', 'read_thread']
        assert value['params']['arguments'] == dict(channel='CPUBLIC1')
        h._record('tool')
        result = dict(content=[dict(type='text', text=json.dumps(dict(account='X', channel='CPUBLIC1')))])
    h._reply(dict(jsonrpc='2.0', id=value['id'], result=result))


spec = importlib.util.spec_from_file_location('base', Path(__file__).parents[2] / 'native_preparation/receiver.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
server = base.Server(('127.0.0.1', 0), Handler)
server.root, server.codes, server.counts = root, {}, {}
server.access, server.refresh = 'contract-access-1', 'contract-refresh-1'
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / 'server.pem', root / 'server.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
(root / 'provider-port.json').write_text(json.dumps(server.server_port))
server.serve_forever(poll_interval=0.05)
