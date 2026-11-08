"""Invented artifact metadata/headers only; never native-execution evidence."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from native_validation import common as C

IDENTITY = {'revision': 'a' * 40, 'tree': 'b' * 40, 'lock_sha256': 'c' * 64, 'version': '3.0.0'}
ROWS = [
    ('x86_64-unknown-linux-gnu', 'Linux', 'x86_64', 'ubuntu-24.04', 'linux-amd64'),
    ('aarch64-unknown-linux-gnu', 'Linux', 'aarch64', 'ubuntu-24.04-arm', 'linux-arm64'),
    ('x86_64-apple-darwin', 'Darwin', 'x86_64', 'macos-15-intel', 'darwin-amd64'),
    ('aarch64-apple-darwin', 'Darwin', 'arm64', 'macos-15', 'darwin-arm64'),
]


def dump(path, value):
    path.write_text(json.dumps(value))


def populate(root, identity=IDENTITY):
    cleanup = {'joined': True, 'exit': 0, 'forced': False}
    for target, system, machine, runner, suffix in ROWS:
        files = {}
        for role in ['locksmith', 'locksmithd']:
            header = bytearray(64)
            if system == 'Linux':
                header[:6] = b'\x7fELF\x02\x01'
                header[18:20] = struct.pack('<H', 62 if machine == 'x86_64' else 183)
            else:
                header[:4] = b'\xcf\xfa\xed\xfe'
                header[4:8] = struct.pack('<I', 0x1000007 if machine == 'x86_64' else 0x100000c)
            path = root / (role + '-' + suffix)
            path.write_bytes(header + role.encode())
            files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        resources = {'entry_floor': 8 * 1024**3, 'stop_floor': 2 * 1024**3, 'growth_limit': 6 * 1024**3,
                     'timeout_seconds': 1800, 'entry_free': 10 * 1024**3, 'initial_target_bytes': 0,
                     'peak_target_growth': 1024, 'minimum_free': 9 * 1024**3, 'process': copy.deepcopy(cleanup)}
        host = {'system': system, 'machine': machine, 'runner': runner, 'target': target,
                'translation': False, 'rust': {'binary': 'rustc', 'commit-hash': 'd' * 40,
                 'commit-date': '2026-03-01', 'release': '1.94.0', 'host': target, 'LLVM version': '21.1.8'},
                'image': {'ImageOS': 'invented', 'ImageVersion': '20261030.1'}}
        record = {'state': 'built_not_smoked', 'source': copy.deepcopy(identity), 'host': host,
                  'flags': ['+1.94.0', 'build', '--locked', '--release', '--bins', '--target', target],
                  'files': files, 'resources': resources}
        if system == 'Darwin':
            record['flags'] += ['--config', 'profile.release.build-override.strip="none"']
        finish(root, target, record, cleanup)


def finish(root, target, record, cleanup):
    dump(root / (target + '.build.json'), record)
    dump(root / (target + '.resources.json'), record['resources'])
    dump(root / (target + '.smoke.json'), {'stage': 'complete', 'daemon_started': True, 'cleanup': cleanup})
    dump(root / (target + '.json'), {**record, 'state': 'smoked_candidate', 'smoke': {
        'startup': True, 'live_version': True, 'status': True, 'operator_status': True, 'cleanup': cleanup}})
    (root / (target + '.sha256')).write_text(''.join(h + '  ' + n + '\n' for n, h in record['files'].items()))
