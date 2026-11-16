#!/usr/bin/env python3
"""One-shot studio-1 Codex MOVE. Keeps source disabled; no automatic rollback.

Run prepare-edge.py on evo first. This process must use an independent model
control plane (teamclaude), never the Codex pool being stopped. Never use -x.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import socket
import stat
import subprocess
import sys

BASE = '/srv/edge-state/codex'
CODEX_HOME = BASE+'/home/.codex-terminal-pool'
PACKAGE = Path('/opt/homebrew/lib/node_modules/codex-multi-auth')
LABEL = 'com.jxstanford.agent-pools.codex'
COMPAT = 'com.sentientswarm.edge-compat.codex'


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(argv, **kwargs):
    return subprocess.run(argv,check=True,timeout=900,**kwargs)


def remote(code,payload=None):
    command=shlex.join(['sudo','incus','--project','edge','exec','edge-brokers','--','python3','-c',code])
    return run(['ssh','-o','BatchMode=yes','evo-x2-1',command],input=json.dumps(payload),text=True)


def files(root):
    if root.is_symlink(): raise RuntimeError('source symlink: resolve custody before moving')
    if not root.exists(): return []
    if root.is_file(): return [root]
    result=[]
    def failed(error): raise RuntimeError('source inventory unreadable') from error
    for parent,dirs,names in os.walk(root,followlinks=False,onerror=failed):
        for name in dirs+names:
            path=Path(parent)/name
            if path.is_symlink(): raise RuntimeError('source symlink: resolve custody before moving')
            mode=path.stat().st_mode
            if stat.S_ISREG(mode): result.append(path)
            elif not stat.S_ISDIR(mode): raise RuntimeError('nonregular source custody path')
    return result


PRECHECK = r'''
import hashlib,json,pathlib,subprocess,sys
p=json.load(sys.stdin)
root=pathlib.Path('/srv/edge-state')
for name in ['edge-codex.service','edge-codex-relay.service','edge-codex-relay.socket']:
    assert subprocess.check_output(['systemctl','show','--property=ActiveState','--value',name],text=True).strip()=='inactive'
    assert subprocess.check_output(['systemctl','show','--property=UnitFileState','--value',name],text=True).strip()=='masked'
assert not any((root/'custody').iterdir())
assert (root/'codex/home/.codex-terminal-pool').is_dir(), 'prepare CODEX_HOME parent first'
assert not any(path.is_file() or path.is_symlink() for path in (root/'codex').rglob('*')), 'destination codex tree already populated'
assert not (root/'codex/agent-pools').exists()
assert not (root/'codex/router.json').exists()
assert (root/'.edge-state-id').read_text().strip()=='edge-brokers'
assert (root/'environment/codex.env').read_bytes()==b''
assert json.loads(pathlib.Path('/opt/codex-multi-auth/package.json').read_text())['version']=='2.25.0'
for relative,digest in p['package'].items():
    path=pathlib.Path('/opt/codex-multi-auth')/relative
    assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==digest, 'source/destination package code differs; preserve patches before draining'
print('PASS destination precheck and installed source-code parity')
'''

ACTIVATE = r'''
import hashlib,json,os,pathlib,pwd,subprocess,sys,time,urllib.request,urllib.error
p=json.load(sys.stdin)
root=pathlib.Path('/srv/edge-state'); base=root/'codex'
for relative,digest in p['custody'].items():
    path=base/relative
    assert path.is_file() and not path.is_symlink()
    assert hashlib.sha256(path.read_bytes()).hexdigest()==digest, 'moved custody checksum mismatch'
source=base/'agent-pools/codex-router.json'; target=base/'router.json'
assert source.is_file() and not target.exists()
router=json.loads(source.read_text())
assert router.get('host') in ['127.0.0.1','localhost','::1'] and router.get('port')==43210
assert isinstance(router.get('clientApiKey'),str) and router['clientApiKey']
assert not router.get('upstreamBaseUrl'), 'chained upstream needs explicit owner mapping'
router['routerScriptPath']='/opt/codex-multi-auth/scripts/codex-app-router.js'
router['statusPath']=str(base/'status.json')
def rewrite(value):
    if isinstance(value,str) and value.startswith(p['home']+'/'):
        return str(base/'home')+value[len(p['home']):]
    if isinstance(value,list): return [rewrite(x) for x in value]
    if isinstance(value,dict): return {k:rewrite(v) for k,v in value.items()}
    return value
router=rewrite(router)
# Rename the moved file, then rewrite it in place; never a second pool copy.
source.rename(target)
with target.open('w') as output: json.dump(router,output)
target.chmod(0o600)
account=pwd.getpwnam('codex-pool')
for path in [base,*base.rglob('*')]:
    assert not path.is_symlink()
    os.chown(path,account.pw_uid,account.pw_gid)
    if path.is_file(): path.chmod(0o600)
    elif path.is_dir(): path.chmod(0o700)
environment=root/'environment/codex.env'
assert environment.stat().st_uid==0 and environment.stat().st_mode & 0o077==0
with environment.open('w') as output:
    for key,value in p['environment'].items():
        output.write(key+'='+json.dumps(value)+'\n')
receipt=root/'custody/codex.ready'
assert not receipt.exists()
fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as output: output.write('edge-brokers:codex\n')
subprocess.run(['/usr/local/sbin/edge-state-check','edge-brokers','codex'],check=True,timeout=10)
for argv in [
 ['systemctl','unmask','edge-input.service'],
 ['systemctl','start','edge-input.service'],
 ['systemctl','is-active','--quiet','edge-input.service'],
 ['systemctl','unmask','edge-codex.service','edge-codex-relay.socket','edge-codex-relay.service'],
 ['systemctl','start','edge-codex.service'],
 ['systemctl','is-active','--quiet','edge-codex.service'],
 ['systemctl','start','edge-codex-relay.socket'],
 ['systemctl','is-active','--quiet','edge-codex-relay.socket']]:
    subprocess.run(argv,check=True,timeout=30)
time.sleep(5)
for name in ['edge-input.service','edge-codex.service','edge-codex-relay.socket']:
    subprocess.run(['systemctl','is-active','--quiet',name],check=True,timeout=5)
assert subprocess.check_output(['systemctl','show','--property=NRestarts','--value','edge-codex.service'],text=True).strip()=='0'
probe={}
exec(compile(p['probe_source'],'handoff_probe.py','exec'),probe)
for host in ['127.0.0.1','10.250.4.12']:
    base='http://'+host+':43210'
    probe['reject_unauthenticated'](base,'codex')
    probe['responses_probe'](base,router['clientApiKey'],p['model'])
print('PASS local Codex completed Responses streams, original-key auth and missing/bad-auth rejection; no token output')
'''

STOP_DESTINATION = r'''
import pathlib,subprocess
for argv in [
 ['systemctl','stop','edge-codex-relay.socket'],
 ['systemctl','stop','edge-codex-relay.service','edge-codex.service']]:
 subprocess.run(argv,check=True,timeout=60)
pathlib.Path('/srv/edge-state/custody/codex.ready').unlink(missing_ok=True)
subprocess.run(['systemctl','disable','edge-codex-relay.socket','edge-codex.service'],check=True,timeout=10)
subprocess.run(['systemctl','mask','edge-codex-relay.socket','edge-codex-relay.service','edge-codex.service'],check=True,timeout=10)
for unit in ['edge-codex-relay.socket','edge-codex-relay.service','edge-codex.service']:
 assert subprocess.check_output(['systemctl','show','--property=ActiveState','--value',unit],text=True).strip()=='inactive'
print('Destination stopped, receipt revoked, units masked; reconcile current custody before any recovery')
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--canaries-approved',action='store_true',required=True)
    parser.add_argument('--model',required=True,help='known working model for the completed Responses canary')
    args=parser.parse_args()
    if sys.platform!='darwin' or socket.gethostname().split('.')[0]!='studio-1' or os.getuid()==0:
        raise SystemExit('Run as jxstanford on studio-1 from independent teamclaude control')
    home=Path.home(); codex=home/'.codex-terminal-pool'; pools=home/'.config/agent-pools'
    label=f'gui/{os.getuid()}/{LABEL}'
    assert json.loads((PACKAGE/'package.json').read_text())['version']=='2.25.0'
    package={str(path.relative_to(PACKAGE)):hashlib.sha256(path.read_bytes()).hexdigest()
             for directory in ['scripts','dist'] for path in (PACKAGE/directory).rglob('*')
             if path.is_file() and path.suffix in {'.js','.mjs','.json'}}
    assert package and 'scripts/codex-app-router.js' in package
    source_plist=home/'Library/LaunchAgents'/f'{LABEL}.plist'
    source_job=plistlib.loads(source_plist.read_bytes())
    environment={}
    for key,value in source_job.get('EnvironmentVariables',{}).items():
        if key in {'PATH','HOME','LANG','LC_ALL','TMPDIR'}: continue
        if not key.startswith('CODEX_'): raise RuntimeError('source tuning environment needs private owner mapping before drain')
        assert isinstance(value,str)
        if re.search('TOKEN|SECRET|PASSWORD|KEY',key) and not re.fullmatch(r'(?:[0-9]+|true|false|yes|no)',value,re.I):
            raise RuntimeError('source environment may contain credentials; explicit custody mapping required')
        if value.startswith(str(home)+'/'): value=BASE+'/home'+value[len(str(home)):]
        environment[key]=value
    compat_plist=home/'Library/LaunchAgents'/f'{COMPAT}.plist'
    assert not compat_plist.exists(), 'inspect existing compatibility job before an additional attempt'
    remote(PRECHECK,{'package':package})
    # Explicit one-shot latch: a failed/partial attempt must be reconciled,
    # never resumed by re-running rsync into a populated receiver.
    latch=Path(__file__).with_name('codex-move-attempted')
    with latch.open('x') as output: output.write('one-shot attempt; no automatic retries\n')
    run(['launchctl','disable',label])
    gate=load('drain_check')
    gate.stop_source_job('codex')
    if gate.check_source('codex',home): raise RuntimeError('source drain refused; source remains disabled, no transfer')
    if list((codex/'multi-auth/refresh-leases').glob('*.lock')):
        raise RuntimeError('refresh lease locks remain after drain; reconcile privately before MOVE')
    selected=[]
    for pattern in ['auth.json','accounts.json','auth.json.*','accounts.json.*']:
        selected.extend(codex.glob(pattern))
    selected=list(dict.fromkeys(selected))
    roots=[(codex/'multi-auth','home/.codex-terminal-pool/multi-auth'),(pools,'agent-pools')]
    manifest={}
    for root,prefix in roots:
        assert root.is_dir() and not root.is_symlink()
        for path in files(root): manifest[prefix+'/'+str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    for path in selected:
        for item in files(path): manifest['home/.codex-terminal-pool/'+item.name]=hashlib.sha256(item.read_bytes()).hexdigest()
    assert 'agent-pools/codex-router.json' in manifest
    assert 'home/.codex-terminal-pool/multi-auth/openai-codex-accounts.json' in manifest
    for root,prefix in roots:
        run(['rsync','-a','--no-links','--checksum','--remove-source-files','--ignore-existing','--no-owner','--no-group','--quiet',
             '--rsync-path=sudo incus --project edge exec edge-brokers -- rsync',str(root)+'/',f'evo-x2-1:{BASE}/{prefix}/'])
    for path in selected:
        run(['rsync','-a','--no-links','--checksum','--remove-source-files','--ignore-existing','--no-owner','--no-group','--quiet',
             '--rsync-path=sudo incus --project edge exec edge-brokers -- rsync',str(path),f'evo-x2-1:{CODEX_HOME}/'])
    assert all(not files(root) for root,_ in roots), 'source files remain: reconcile, do not activate'
    assert all(not path.exists() and not path.is_symlink() for path in selected), 'source top-level credentials remain'
    for pattern in ['auth.json','accounts.json','auth.json.*','accounts.json.*']:
        assert not list(codex.glob(pattern)), 'source top-level credentials appeared during move'
    if gate.check_source('codex',home): raise RuntimeError('post-MOVE drain refused; no destination activation')
    try:
        remote(ACTIVATE,{'custody':manifest,'environment':environment,'home':str(home),
                         'model':args.model,'probe_source':Path(__file__).with_name('handoff_probe.py').read_text()})
        definition=load('compat_launchd').definition('codex')
        with compat_plist.open('xb') as output: plistlib.dump(definition,output)
        compat_plist.chmod(0o600)
        compat_label=f'gui/{os.getuid()}/{COMPAT}'
        run(['launchctl','enable',compat_label])  # execution fix L4
        run(['launchctl','bootstrap',f'gui/{os.getuid()}',str(compat_plist)])
    except Exception:
        try:
            for action in ['disable','bootout']:
                try:
                    result=subprocess.run(['launchctl',action,f'gui/{os.getuid()}/{COMPAT}'],capture_output=True,timeout=10)
                    if result.returncode:
                        print('NOTICE: studio compatibility cleanup requires verification',file=sys.stderr)
                except subprocess.SubprocessError:
                    print('NOTICE: studio compatibility cleanup timed out; verify its listener privately',file=sys.stderr)
        finally:
            # Always attempt destination stop/revocation even if local cleanup fails.
            remote(STOP_DESTINATION)
        raise
    print('Codex custody MOVED; source disabled; edge local auth passed; studio transport relay loaded.')
    print('Coordinator must repoint both VM tunnels, prove streamed requests/serialized refresh and production Locksmith route, then enable persistence. Teamclaude remains on studio until that passes.')


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('REFUSED: '+type(error).__name__+'; no automatic source restart. Inspect privately and reconcile; never blindly rerun.',file=sys.stderr)
        sys.exit(1)
