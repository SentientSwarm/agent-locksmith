"""Invented command/HTTP collaborator; not the product or native Rust binaries."""
import json
from pathlib import Path
from fixtures import IDENTITY

CODE = r'''
import json, os, signal, socket, sys
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROLE, IDENTITY, MODE = __VALUES__
with (Path(__file__).parent / 'children.jsonl').open('a') as log:
    log.write(str(os.getpid()) + '\n')
for name in ['OPENAI_API_KEY', 'HTTPS_PROXY', 'LOCKSMITH_ADMIN_URL']:
    assert name not in os.environ, 'inherited_environment'
if '--build-info' in sys.argv:
    print(json.dumps({'name': ROLE, 'version': IDENTITY['version'], 'build': {
        'revision': IDENTITY['revision'], 'source_state': 'clean'}}));sys.exit(0)
if '--version' in sys.argv:
    print(ROLE + ' ' + IDENTITY['version']);sys.exit(0)
if '--help' in sys.argv:
    print('invented role help');sys.exit(0)
if ROLE == 'locksmith':
    if 'bootstrap-operator' in sys.argv:
        print('operators: {}');print('lkop_invented_only',file=sys.stderr);sys.exit(0)
    assert sys.argv[1:] == ['--socket','admin.sock','--format','json','agent','list']
    assert os.environ['LOCKSMITH_OP_TOKEN'] == 'lkop_invented_only'
    assert Path('admin.sock').exists()
    print('[]');sys.exit(0)
if MODE == 'early':sys.exit(9)
if MODE == 'hang':
    import time
    time.sleep(20)
config=json.loads(Path('config.json').read_text())
admin=socket.socket(socket.AF_UNIX);admin.bind('admin.sock');admin.listen()
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        value={'status':'live' if self.path == '/livez' else 'ready'}
        if MODE == 'bad_status' and self.path == '/readyz':value={'status':'not_ready'}
        if self.path == '/version':value={'name':'agent-locksmith','version':IDENTITY['version'],
            'build':{'revision':IDENTITY['revision'],'source_state':'clean'}}
        if MODE == 'bad_version' and self.path == '/version':value['version']='9.0.0'
        body=json.dumps(value).encode();self.send_response(200);self.end_headers();self.wfile.write(body)
server=ThreadingHTTPServer(('127.0.0.1',config['listen']['port']),Handler)
def stop(*args):raise SystemExit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN if MODE == 'ignore_term' else stop)
try:server.serve_forever(poll_interval=.02)
finally:server.server_close();admin.close()
'''


def pair(root, mode='ok'):
    result = {}
    for role in ['locksmith', 'locksmithd']:
        path = root / role
        path.write_text('#!/usr/bin/env python3\n' + CODE.replace('__VALUES__', repr((role, IDENTITY, mode))))
        path.chmod(0o755)
        result[role] = path
    return result
