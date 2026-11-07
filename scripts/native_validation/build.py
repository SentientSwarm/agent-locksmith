"""Future native Cargo child with measured disk/growth/deadline and frozen capture."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
from . import common as C

GIB = 1024 ** 3
JOIN_TIMEOUT = 5
ENTRY, STOP, GROWTH, TIMEOUT = 8 * GIB, 2 * GIB, 6 * GIB, 1800


def allocated(root):
    total = 0
    for path in Path(root).rglob('*'):
        try:
            total += path.stat().st_blocks * 512
        except FileNotFoundError:
            continue
    return total


def signal_group(child, sig):
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        pass


def join(child):
    forced = False
    if child.poll() is None:
        signal_group(child, signal.SIGTERM)
        try:
            child.wait(timeout=JOIN_TIMEOUT)
        except subprocess.TimeoutExpired:
            forced = True
            signal_group(child, signal.SIGKILL)
    child.wait()
    signal_group(child, signal.SIGKILL)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return {'joined': True, 'exit': child.returncode, 'forced': forced}
        time.sleep(.01)
    return {'joined': False, 'exit': child.returncode, 'forced': forced}


def run_owned(command, root, target, record):
    initial, free = allocated(target), shutil.disk_usage(root).free
    record.update(entry_free=free, initial_target_bytes=initial, peak_target_growth=0, minimum_free=free)
    if free < ENTRY:
        raise ValueError('runner_disk_entry_refused')
    child = subprocess.Popen(command, cwd=root, env=C.environment(), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    started = time.monotonic()
    try:
        while True:
            free, growth = shutil.disk_usage(root).free, max(0, allocated(target) - initial)
            record.update(minimum_free=min(record['minimum_free'], free),
                          peak_target_growth=max(record['peak_target_growth'], growth))
            if free < STOP or growth > GROWTH:
                raise ValueError('runner_disk_stop_refused')
            if time.monotonic() - started >= TIMEOUT:
                raise ValueError('build_timeout')
            if child.poll() is not None:
                if child.returncode:
                    raise ValueError('cargo_failed')
                return
            time.sleep(.5)
    finally:
        record['process'] = join(child)


def build(root, output, target, expected):
    identity, machine = C.source(root, expected), C.host(target)
    resources = {'entry_floor': ENTRY, 'stop_floor': STOP, 'growth_limit': GROWTH, 'timeout_seconds': TIMEOUT}
    command = [shutil.which('cargo'), *C.flags(target)]
    if command[0] is None:
        raise ValueError('tool_missing')
    try:
        run_owned(command, root, root / 'target', resources)
    finally:
        C.write(output / (target + '.resources.json'), resources)
    if C.source(root, expected) != identity:
        raise ValueError('source_changed')
    files = C.pair(output, target)
    for role, destination in files.items():
        source = root / 'target' / target / 'release' / role
        C.binary_arch(source, target)
        with source.open('rb') as src, destination.open('xb') as dst:
            shutil.copyfileobj(src, dst)
        destination.chmod(0o755)
    hashes = {p.name: C.V.digest(p) for p in files.values()}
    C.write(output / (target + '.build.json'), {'state': 'built_not_smoked', 'source': identity,
            'host': machine, 'flags': C.flags(target), 'files': hashes, 'resources': resources})
    return {'state': 'built_not_smoked', 'target': target}
