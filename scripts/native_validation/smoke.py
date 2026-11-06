"""Real supplied candidate smoke; no normal state, credentials or provider use."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from . import common as C
from .build import join
from .http import request

READY_TIMEOUT = 15


def configure(root, cli, env):
    result, private = C.V.execute(cli, ['bootstrap-operator', '--name', 'native-smoke'],
                                  cwd=root, env=env, capture_stderr=True)
    tokens = [line.strip() for line in private.decode().splitlines() if line.strip().startswith('lkop_')]
    if len(tokens) != 1:
        raise ValueError('operator_bootstrap_refused')
    env['LOCKSMITH_OP_TOKEN'] = tokens[0]
    (root / 'operators.yaml').write_bytes(result)
    (root / 'operators.yaml').chmod(0o600)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    config = {'listen': {'host': '127.0.0.1', 'port': port, 'auth_mode': 'bearer',
              'admin_socket': {'path': 'admin.sock'}}, 'database': {'path': 'state.db'},
              'operator_credentials_path': 'operators.yaml', 'tools': [], 'shutdown': {'drain_window_seconds': 1}}
    (root / 'config.json').write_text(json.dumps(config))
    return port


def wait_ready(child, root, port):
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise ValueError('daemon_early_exit')
        if (root / 'admin.sock').exists():
            try:
                if request(port, 'livez', deadline).get('status') == 'live' and time.monotonic() < deadline:
                    return
            except (OSError, ValueError):
                pass
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
    raise ValueError('daemon_readiness_timeout')


def check_status(child, root, port, files, identity, env):
    wait_ready(child, root, port)
    C.V.check_identity(request(port, 'version'), 'agent-locksmith', identity['version'], identity['revision'])
    if request(port, 'readyz').get('status') != 'ready':
        raise ValueError('smoke_status_refused')
    agents = C.V.strict_json(C.V.execute(files['locksmith'], ['--socket', 'admin.sock', '--format', 'json',
                                'agent', 'list'], cwd=root, env=env))
    if agents != []:
        raise ValueError('smoke_operator_status_refused')


def owned_smoke(files, identity, root, record):
    env = C.environment(root)
    record.update(stage='version_help', daemon_started=False, cleanup=None)
    for role, path in files.items():
        if C.V.execute(path, ['--version'], env=env).decode().strip() != role + ' ' + identity['version']:
            raise ValueError('smoke_version_mismatch')
        if not C.V.execute(path, ['--help'], env=env).strip():
            raise ValueError('smoke_help_empty')
    port = configure(root, files['locksmith'], env)
    child = subprocess.Popen([str(files['locksmithd']), '--config', 'config.json'], cwd=root, env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    record.update(stage='startup_status', daemon_started=True)
    try:
        check_status(child, root, port, files, identity, env)
    finally:
        record['cleanup'] = join(child)
    if record['cleanup'] != {'joined': True, 'exit': 0, 'forced': False}:
        raise ValueError('smoke_shutdown_incomplete')
    record['stage'] = 'complete'
    return {'startup': True, 'live_version': True, 'status': True, 'operator_status': True,
            'cleanup': record['cleanup']}


def smoke(root, output, target, expected):
    record = C.load(output / (target + '.build.json'))
    if record['source'] != C.source(root, expected) or record['flags'] != C.flags(target) \
            or record['host'] != C.host(target):
        raise ValueError('smoke_provenance_mismatch')
    files = C.pair(output, target)
    if {p.name: C.V.digest(p) for p in files.values()} != record['files']:
        raise ValueError('candidate_changed')
    sums = output / (target + '.sha256')
    sums.write_text(''.join(h + '  ' + n + '\n' for n, h in record['files'].items()))
    for path in files.values():
        C.binary_arch(path, target)
    C.V.verify(files['locksmith'], files['locksmithd'], sums,
               record['source']['version'], expected, env=C.environment(output))
    probe = {}
    try:
        with tempfile.TemporaryDirectory(prefix='native-smoke-') as private:
            result = owned_smoke(files, record['source'], Path(private), probe)
    finally:
        C.write(output / (target + '.smoke.json'), probe)
    if {p.name: C.V.digest(p) for p in files.values()} != record['files']:
        raise ValueError('candidate_changed')
    C.write(output / (target + '.json'), {**record, 'state': 'smoked_candidate', 'smoke': result})
    return {'state': 'smoked_candidate', 'target': target}
