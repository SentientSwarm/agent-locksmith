#!/usr/bin/env python3
"""Detached one-shot studio-1 -> edge-brokers teamclaude MOVE.

The operator drains new Claude launches before invoking --detach. The worker
drains existing HTTP requests, stops the source, moves custody, proves serving,
then loads the studio compatibility relay. It never restarts a source pool.
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
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request

LABEL='com.karpeleslab.teamclaude'
COMPAT='com.sentientswarm.edge-compat.teamclaude'
HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(argv,timeout=60,**kwargs):
    # Private capture, bounded subprocess group, no command/config diagnostics.
    with subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,start_new_session=True) as process:
        try:
            stdout,stderr=process.communicate(kwargs.get('input'),timeout=timeout)
            if process.returncode: raise RuntimeError('handoff command failed; inspect privately')
            return stdout
        except BaseException:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=10)
            raise


def remote(action,payload=None):
    code=(HERE/'teamclaude_destination.py').read_text()
    command=shlex.join(['sudo','-n','incus','--project','edge','exec','edge-brokers','--','python3','-c',code])
    return run(['ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=15',
                '-o','ServerAliveCountMax=2','evo-x2-1',command],timeout=600,
               input=json.dumps({**(payload or {}),'action':action}).encode())


def safe_file(path):
    if not path.is_absolute() or not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(path)):
        raise RuntimeError('custody path requires explicit safe mapping')
    if any(parent.is_symlink() for parent in [path,*path.parents]):
        raise RuntimeError('symlink in source custody path; reconcile before drain')
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('nonregular or hard-linked source custody; reconcile before drain')


def inventory(selected,extras,directories=()):
    if selected.suffix != '.json': raise RuntimeError('selected config must end in .json')
    stem=selected.with_suffix('')
    active={selected:'teamclaude.json',Path(str(stem)+'.state.json'):'teamclaude.state.json',
            Path(str(stem)+'.quota-series.json'):'teamclaude.quota-series.json',
            Path(str(stem)+'-crash.log'):'teamclaude-crash.log'}
    for name in ['teamclaude-ca.pem','teamclaude-leaf.pem','teamclaude-leaf.key','teamclaude-ca.key']:
        active[selected.parent/name]=name
    candidates=set(extras)|{path for path in active if path.exists() or path.is_symlink()}
    for directory in {selected.parent,*directories}:
        for pattern in ['teamclaude*','teamrouter*',selected.name+'*',stem.name+'.state*',stem.name+'.quota-series*']:
            candidates.update(directory.glob(pattern))
    result={}
    for path in sorted(candidates):
        safe_file(path)
        if path.name.endswith('.lock'):
            raise RuntimeError('config lock exists; reconcile privately before moving')
        name=active.get(path)
        result[path]='active/'+name if name else 'history/'+hashlib.sha256(str(path).encode()).hexdigest()[:16]+'-'+path.name
    if selected not in result: raise RuntimeError('selected config absent')
    if len(set(result.values())) != len(result): raise RuntimeError('ambiguous custody mapping')
    return result


def selected_config(job,home):
    environment=job.get('EnvironmentVariables',{})
    primary=environment.get('TEAMROUTER_CONFIG',environment.get('TEAMCLAUDE_CONFIG'))
    directory=Path(environment.get('XDG_CONFIG_HOME',str(home/'.config')))
    return Path(primary) if primary else directory/('teamrouter.json' if (directory/'teamrouter.json').exists() else 'teamclaude.json')


def package_from_job(job,explicit):
    candidates=[explicit] if explicit else []
    for arg in job.get('ProgramArguments',[]):
        if isinstance(arg,str) and arg.startswith('/'):
            candidates.extend(Path(arg).resolve().parents)
    candidates.extend([Path('/opt/homebrew/lib/node_modules/@karpeleslab/teamclaude'),
                       Path.home()/'.bun/install/global/node_modules/@karpeleslab/teamclaude'])
    for path in candidates:
        if not path or not (path/'package.json').is_file(): continue
        metadata=json.loads((path/'package.json').read_text())
        if metadata.get('name') == '@karpeleslab/teamclaude' and metadata.get('version') == '1.1.27': return path
    raise RuntimeError('cannot identify source teamclaude 1.1.27 package; provide --package')


def source_environment(job):
    result={}
    for key,value in job.get('EnvironmentVariables',{}).items():
        if key in {'PATH','HOME','LANG','LC_ALL','TMPDIR','XDG_CONFIG_HOME','TEAMROUTER_CONFIG','TEAMCLAUDE_CONFIG',
                   'TEAMROUTER_HOST','TEAMCLAUDE_HOST','TEAMROUTER_DISABLE_AUTOUPDATE','TEAMCLAUDE_DISABLE_AUTOUPDATE'}: continue
        if not re.fullmatch(r'TEAM(?:ROUTER|CLAUDE)_[A-Z0-9_]+',key) or not isinstance(value,str) or not re.fullmatch(r'[0-9]+|true|false',value,re.I):
            raise RuntimeError('source tuning needs explicit private mapping before drain')
        result[key]=value
    return result


def validate_private_config(config):
    load('teamclaude_destination').prepare_config(config)
    ids=[account.get('id') for account in config['accounts']]
    if not all(isinstance(value,str) and value for value in ids) or len(set(ids)) != 3:
        raise RuntimeError('three stable account IDs required before drain')
    def walk(value):
        if isinstance(value,str) and (value.startswith('/Users/') or value.startswith('~/')):
            raise RuntimeError('source config has a host-local path; explicit mapping required')
        if isinstance(value,list):
            for item in value: walk(item)
        if isinstance(value,dict):
            for item in value.values(): walk(item)
    walk(config)


def drain(key):
    deadline=time.monotonic()+120
    while time.monotonic() < deadline:
        request=urllib.request.Request('http://127.0.0.1:3456/teamclaude/drain',method='POST',
                    headers={'x-api-key':key,'Content-Type':'application/json'},data=b'{}')
        with urllib.request.urlopen(request,timeout=10) as response:
            status=json.loads(response.read(65537))
        if status.get('ok') is True and status.get('draining') is True and status.get('inFlight') == 0: return
        time.sleep(0.5)
    raise RuntimeError('teamclaude requests did not drain in 120 seconds')


def state(directory,message):
    # Only fixed phase names reach this file; never exception messages.
    (directory/'status').write_text(message+'\n')
    print(message,flush=True)


def worker(args,directory):
    with (directory/'worker-started').open('x') as latch:
        latch.write('one worker only; no retries\n')
    source_touched=False
    destination_prepared=False
    compat=Path.home()/'Library/LaunchAgents'/f'{COMPAT}.plist'
    try:
        signal.alarm(900)
        state(directory,'PREFLIGHT')
        home=Path.home()
        job=plistlib.loads((home/'Library/LaunchAgents'/f'{LABEL}.plist').read_bytes())
        selected=args.config
        if selected_config(job,home) != selected:
            raise RuntimeError('selected config differs from launchd selection')
        paths=inventory(selected,args.custody_path,[home/'.config'])
        config=json.loads(selected.read_text())
        validate_private_config(config)
        # Validate before outage; re-read after stop because the drain may refresh.
        package=package_from_job(job,args.package)
        node=args.node or Path(job['ProgramArguments'][0])
        if node.name not in {'node','nodejs'} or not node.is_file(): raise RuntimeError('provide source --node')
        cert_source=(HERE/'teamclaude_certcheck.mjs').read_text()
        run([str(node),'--input-type=module','-',str(package),str(selected)],input=cert_source.encode())
        codefiles=[package/'package.json',*(package/'src').rglob('*.js'),*(package/'src').rglob('*.json')]
        code={str(path.relative_to(package)):hashlib.sha256(path.read_bytes()).hexdigest() for path in codefiles}
        environment=source_environment(job)
        if compat.exists() or compat.is_symlink(): raise RuntimeError('compatibility job already exists')
        gate=load('drain_check')
        existing=gate.run_visible(['launchctl','print',f'gui/{os.getuid()}/{COMPAT}'])
        if existing.returncode == 0 or 'Could not find service' not in existing.stdout+existing.stderr:
            raise RuntimeError('compatibility registration not confirmed absent')
        if not gate.lsof_pids(['-a','-iTCP:3456','-sTCP:LISTEN']):
            raise RuntimeError('source listener absent before drain')
        load('handoff_probe').messages_probe('http://127.0.0.1:3456',config['proxy']['apiKey'],args.model)
        remote('precheck',{'package':code})
        destination_prepared=True
        state(directory,'DRAINING')
        source_touched=True
        drain(config['proxy']['apiKey'])
        run(['launchctl','disable',f'gui/{os.getuid()}/{LABEL}'])
        gate.stop_source_job('teamclaude')
        # Detect siblings/backups created by graceful shutdown; include them all.
        paths=inventory(selected,args.custody_path,[home/'.config'])
        if gate.check_source('teamclaude',home,paths): raise RuntimeError('source drain refused')
        config=json.loads(selected.read_text())
        validate_private_config(config)
        run([str(node),'--input-type=module','-',str(package),str(selected)],input=cert_source.encode())
        if any(hashlib.sha256((package/relative).read_bytes()).hexdigest() != digest for relative,digest in code.items()):
            raise RuntimeError('source package changed during drain')
        manifest={relative:hashlib.sha256(path.read_bytes()).hexdigest() for path,relative in paths.items()}
        # Persist only source path mappings and hashes, never credentials/content.
        (directory/'inventory.json').write_text(json.dumps({str(path):relative for path,relative in paths.items()},indent=2))
        (directory/'checksums.json').write_text(json.dumps(manifest,indent=2))
        state(directory,'MOVING')
        for path,relative in paths.items():
            part,_,name=relative.partition('/')
            target=('/srv/edge-state/teamclaude/' if part == 'active' else '/srv/edge-state/teamclaude-history/')+name
            run(['rsync','-a','--no-links','--checksum','--remove-source-files','--ignore-existing',
                 '--no-owner','--no-group','--quiet','-e','ssh -o BatchMode=yes -o ConnectTimeout=10',
                 '--rsync-path=sudo -n incus --project edge exec edge-brokers -- rsync',str(path),'evo-x2-1:'+target],timeout=120)
        if any(path.exists() or path.is_symlink() for path in paths): raise RuntimeError('source custody remains')
        # Re-scan supported locations; any newly appearing config/backup blocks start.
        if any(list(directory_path.glob(pattern)) for directory_path in {selected.parent,home/'.config'}
               for pattern in ['teamclaude*','teamrouter*',selected.name+'*',selected.stem+'.state*',selected.stem+'.quota-series*']):
            raise RuntimeError('source custody appeared during move')
        if gate.check_source('teamclaude',home,paths): raise RuntimeError('post-MOVE source drain refused')
        state(directory,'ACTIVATING')
        remote('activate',{'custody':manifest,'environment':environment,'model':args.model,'expires':time.time()+300,
                           'probe_source':(HERE/'handoff_probe.py').read_text(),'cert_source':cert_source})
        state(directory,'EDGE_LOCAL_SERVING')
        with compat.open('xb') as output: plistlib.dump(load('compat_launchd').definition('teamclaude'),output)
        compat.chmod(0o600)
        run(['launchctl','enable',f'gui/{os.getuid()}/{COMPAT}'])
        run(['launchctl','bootstrap',f'gui/{os.getuid()}',str(compat)])
        # Validate the actual temporary studio path with the original shared key.
        probe=load('handoff_probe')
        probe.reject_unauthenticated('http://127.0.0.1:3456','teamclaude')
        probe.messages_probe('http://127.0.0.1:3456',config['proxy']['apiKey'],args.model)
        state(directory,'LOCAL_SERVING_COMPAT_LOADED__AWAIT_COORDINATOR_ACCEPTANCE')
        return 0
    except BaseException:
        signal.alarm(0)
        # A second ordinary cancellation must not interrupt bounded cleanup.
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        state(directory,'FAILED__NO_SOURCE_RESTART__RECONCILE_CUSTODY')
        cleanup_ok=True
        if source_touched:
            try:
                run(['launchctl','disable',f'gui/{os.getuid()}/{LABEL}'],timeout=15)
                load('drain_check').stop_source_job('teamclaude')
            except BaseException: cleanup_ok=False
            for action in ['disable','bootout']:
                try: run(['launchctl',action,f'gui/{os.getuid()}/{COMPAT}'],timeout=15)
                except BaseException: pass
            # Confirm no compatibility listener or registration survives cleanup.
            try:
                gate=load('drain_check')
                if gate.lsof_pids(['-a','-iTCP:3456','-sTCP:LISTEN']): cleanup_ok=False
                registration=gate.run_visible(['launchctl','print',f'gui/{os.getuid()}/{COMPAT}'])
                if registration.returncode == 0 or 'Could not find service' not in registration.stdout+registration.stderr:
                    cleanup_ok=False
            except BaseException: cleanup_ok=False
        if destination_prepared:
            try: remote('stop')
            except BaseException: cleanup_ok=False
        if not cleanup_ok: state(directory,'FAILED__CLEANUP_UNCONFIRMED__OPERATOR_REQUIRED')
        return 1
    finally:
        signal.alarm(0)


def interrupted(signum,frame):
    raise TimeoutError('worker deadline or cancellation')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--detach',action='store_true')
    parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--canaries-approved',action='store_true',required=True)
    parser.add_argument('--inventory-complete',action='store_true',required=True,
                        help='operator attests no other teamclaude custody paths or launchers')
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--model',required=True,help='known working Claude Messages model')
    parser.add_argument('--package',type=Path)
    parser.add_argument('--node',type=Path)
    parser.add_argument('--custody-path',action='append',type=Path,default=[])
    args=parser.parse_args()
    if sys.platform != 'darwin' or socket.gethostname().split('.')[0] != 'studio-1' or os.getuid() == 0:
        parser.error('run as jxstanford on studio-1, with passwordless sudo lsof/remote Incus available')
    os.umask(0o077)
    directory=HERE/'teamclaude-move-attempt'
    if args.detach and not args.worker:
        directory.mkdir(mode=0o700,exist_ok=False)  # one-shot latch, never blindly retry
        with (directory/'worker.log').open('xb') as log:
            child=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),
                 *[value for value in sys.argv[1:] if value != '--detach'],'--worker'],
                 stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        (directory/'pid').write_text(str(child.pid)+'\n')
        print('Detached bounded worker started; secret-free status: '+str(directory/'status'))
        return 0
    if not args.worker or not directory.is_dir(): parser.error('use --detach; do not invoke the worker directly')
    signal.signal(signal.SIGALRM,interrupted)
    signal.signal(signal.SIGTERM,interrupted)
    signal.signal(signal.SIGINT,interrupted)
    return worker(args,directory)


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        print('REFUSED '+type(error).__name__+'; inspect privately; never blindly retry',file=sys.stderr)
        sys.exit(1)
