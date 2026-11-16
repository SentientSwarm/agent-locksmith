#!/usr/bin/env python3
"""Root-only remote half of the teamclaude MOVE; invoked over SSH stdin.

Never reads Codex custody or changes Codex units. Serialize activation/revocation
even if the source SSH connection disappears. All diagnostics are secret-free.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import time

ROOT = Path('/srv/edge-state')
BASE = ROOT/'teamclaude'
HISTORY = ROOT/'teamclaude-history'
RECEIPT = ROOT/'custody/teamclaude.ready'
REVOKED = Path('/run/edge-teamclaude-move.revoked')
UNITS = ['edge-teamclaude-relay.socket', 'edge-teamclaude-relay.service', 'edge-teamclaude.service']


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, timeout=45, capture_output=True, **kwargs)


def property_of(unit, name):
    return run(['systemctl','show','--property='+name,'--value',unit],text=True).stdout.strip()


def prepare_config(config):
    if len(config.get('accounts', [])) != 3:
        raise RuntimeError('expected three existing accounts')
    proxy = config.get('proxy', {})
    if not isinstance(proxy.get('apiKey'),str) or not proxy['apiKey']:
        raise RuntimeError('existing shared proxy key required')
    if proxy.get('port',3456) != 3456 or proxy.get('host','127.0.0.1') not in ['127.0.0.1','localhost','::1']:
        raise RuntimeError('unexpected source listener')
    # Supported in 1.1.27. A TCP relay otherwise makes every caller localhost.
    proxy['trustLoopback'] = False
    proxy['host'] = '127.0.0.1'
    proxy['port'] = 3456
    return config


def destination(relative):
    part, separator, name = relative.partition('/')
    if not separator or part not in {'active','history'} or not name or Path(name).name != name:
        raise RuntimeError('invalid destination mapping')
    return (BASE if part == 'active' else HISTORY)/name


def check_certificates(p):
    run(['/usr/bin/node','--input-type=module','-','/opt/teamclaude',str(BASE/'teamclaude.json')],
        input=p['cert_source'].encode())


def precheck(p):
    if REVOKED.exists() or RECEIPT.exists():
        raise RuntimeError('previous attempt requires custody reconciliation')
    run(['systemctl','is-active','--quiet','edge-input.service'])
    if (ROOT/'.edge-state-id').read_text().strip() != 'edge-brokers':
        raise RuntimeError('wrong custody volume')
    if run(['findmnt','-n','-o','FSTYPE','--mountpoint',str(ROOT)],text=True).stdout.strip() != 'zfs':
        raise RuntimeError('custody volume is not ZFS')
    for path in [ROOT, ROOT/'custody', ROOT/'environment', BASE]:
        info=path.lstat()
        if path.is_symlink() or not path.is_dir() or (path != BASE and (info.st_uid != 0 or info.st_mode & 0o022)):
            raise RuntimeError('unsafe custody parent')
    for unit in UNITS:
        if property_of(unit,'ActiveState') != 'inactive' or property_of(unit,'UnitFileState') != 'masked':
            raise RuntimeError('teamclaude destination must be masked and inactive')
    if any(path.is_file() or path.is_symlink() for path in BASE.rglob('*')) or HISTORY.exists() or HISTORY.is_symlink():
        raise RuntimeError('teamclaude receiver already populated')
    environment=ROOT/'environment/teamclaude.env'
    if environment.is_symlink() or environment.stat().st_uid != 0 or environment.stat().st_mode & 0o077 or environment.read_bytes():
        raise RuntimeError('unsafe or populated environment file')
    package=Path('/opt/teamclaude')
    if json.loads((package/'package.json').read_text())['version'] != '1.1.27':
        raise RuntimeError('wrong installed package')
    for relative,digest in p['package'].items():
        if relative not in {'package.json'} and (not relative.startswith('src/') or '..' in Path(relative).parts):
            raise RuntimeError('unsafe package manifest')
        path=package/relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('package parity refused; reconcile source patches before drain')
    HISTORY.mkdir(mode=0o700)


def stop():
    # Revoke first, including before waiting for another activation's lock.
    REVOKED.touch(mode=0o600,exist_ok=True)
    RECEIPT.unlink(missing_ok=True)
    failed=False
    for argv in [
        ['systemctl','stop',UNITS[0]],
        ['systemctl','stop',*UNITS[1:]],
        ['systemctl','disable',UNITS[0],UNITS[2]],
        ['systemctl','mask',*UNITS],
    ]:
        try: run(argv)
        except (OSError,subprocess.SubprocessError): failed=True
    for unit in UNITS:
        try:
            if property_of(unit,'ActiveState') != 'inactive' or property_of(unit,'UnitFileState') != 'masked': failed=True
        except (OSError,subprocess.SubprocessError): failed=True
    if failed: raise RuntimeError('destination stop/mask unconfirmed; operator reconciliation required')


def activate(p):
    if REVOKED.exists() or time.time() > p['expires']:
        raise RuntimeError('activation expired or revoked')
    expected={destination(relative) for relative in p['custody']}
    actual={path for tree in [BASE,HISTORY] for path in tree.rglob('*') if not path.is_dir()}
    if actual != expected: raise RuntimeError('receiver differs from full custody inventory')
    for relative,digest in p['custody'].items():
        path=destination(relative)
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('moved custody checksum mismatch')
    config_path=BASE/'teamclaude.json'
    config=json.loads(config_path.read_text())
    prepare_config(config)
    ids=[account.get('id') for account in config['accounts']]
    if not all(isinstance(value,str) and value for value in ids) or len(set(ids)) != 3:
        raise RuntimeError('three stable account IDs required; no re-import')
    # Only the moved config is rewritten; never save a backup credential copy.
    with config_path.open('w') as output: json.dump(config,output)
    check_certificates(p)
    certs={name:hashlib.sha256((BASE/name).read_bytes()).hexdigest() for name in
           ['teamclaude-ca.pem','teamclaude-leaf.pem','teamclaude-leaf.key']}
    account=pwd.getpwnam('teamclaude')
    for tree,uid,gid in [(BASE,account.pw_uid,account.pw_gid),(HISTORY,0,0)]:
        for path in [tree,*tree.rglob('*')]:
            if path.is_symlink(): raise RuntimeError('unexpected custody symlink')
            os.chown(path,uid,gid)
            path.chmod(0o700 if path.is_dir() else 0o600)
    environment=ROOT/'environment/teamclaude.env'
    with environment.open('w') as output:
        for key,value in p['environment'].items(): output.write(key+'='+json.dumps(value)+'\n')
        output.write('TEAMROUTER_HOST=127.0.0.1\nTEAMROUTER_DISABLE_AUTOUPDATE=1\n')
    if REVOKED.exists() or time.time() > p['expires']:
        raise RuntimeError('activation expired or revoked')
    with RECEIPT.open('x') as output: output.write('edge-brokers:teamclaude\n')
    RECEIPT.chmod(0o600)
    run(['/usr/local/sbin/edge-state-check','edge-brokers','teamclaude'])
    run(['systemctl','is-active','--quiet','edge-input.service'])
    run(['systemctl','unmask',*UNITS])
    run(['systemctl','start','edge-teamclaude.service'])
    # Type=simple reports active before Node has bound its socket.
    import socket
    for attempt in range(40):
        try:
            with socket.create_connection(('127.0.0.1',3456),timeout=1): break
        except OSError:
            if attempt == 39: raise RuntimeError('teamclaude listener did not bind')
            time.sleep(0.25)
    run(['systemctl','start','edge-teamclaude-relay.socket'])
    probe={}
    exec(compile(p['probe_source'],'handoff_probe.py','exec'),probe)
    for host in ['127.0.0.1','10.250.4.12']:
        base='http://'+host+':3456'
        probe['reject_unauthenticated'](base,'teamclaude')
        probe['messages_probe'](base,config['proxy']['apiKey'],p['model'])
    time.sleep(5)
    for unit in [UNITS[0],UNITS[2],'edge-input.service']:
        run(['systemctl','is-active','--quiet',unit])
    if property_of(UNITS[2],'NRestarts') != '0': raise RuntimeError('teamclaude restarted')
    actual=json.loads(config_path.read_text())
    if [account.get('id') for account in actual['accounts']] != ids or actual['proxy']['trustLoopback'] is not False:
        raise RuntimeError('account identities or enforced authentication changed')
    if any(hashlib.sha256((BASE/name).read_bytes()).hexdigest() != digest for name,digest in certs.items()):
        raise RuntimeError('certificate identity changed during startup')


def dispatch(action,payload):
    if action == 'precheck': return precheck(payload)
    if action == 'stop': return stop()
    if action != 'activate': raise RuntimeError('unknown remote action')
    try: activate(payload)
    except BaseException:
        stop()
        raise


def interrupted(signum,frame):
    raise TimeoutError('remote action deadline or cancellation')


def main():
    if os.getuid() != 0: raise RuntimeError('root required')
    os.umask(0o077)
    payload=json.load(sys.stdin)
    action=payload.pop('action')
    if action == 'stop': REVOKED.touch(mode=0o600,exist_ok=True)
    signal.signal(signal.SIGALRM,interrupted)
    signal.signal(signal.SIGTERM,interrupted)
    signal.signal(signal.SIGHUP,interrupted)
    signal.alarm(300)
    with open('/run/edge-teamclaude-move.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        try: dispatch(action,payload)
        finally: signal.alarm(0)
    print('PASS teamclaude remote '+action)


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        print('REFUSED teamclaude remote: '+type(error).__name__+'; inspect privately',file=sys.stderr)
        sys.exit(1)
