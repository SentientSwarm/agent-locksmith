"""Small shared native-candidate contract; no release or provider capability."""
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import tomllib

SPEC = importlib.util.spec_from_file_location('verify_build', Path(__file__).parents[1] / 'verify-build.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
TARGETS = {
    'x86_64-unknown-linux-gnu': ('Linux', 'x86_64', 'ubuntu-24.04', 'linux-amd64'),
    'aarch64-unknown-linux-gnu': ('Linux', 'aarch64', 'ubuntu-24.04-arm', 'linux-arm64'),
    'x86_64-apple-darwin': ('Darwin', 'x86_64', 'macos-15-intel', 'darwin-amd64'),
    'aarch64-apple-darwin': ('Darwin', 'arm64', 'macos-15', 'darwin-arm64'),
}


def command(name, args, **kwargs):
    path = shutil.which(name)
    if not path:
        raise ValueError('tool_missing')
    kwargs.setdefault('env', environment())
    return V.execute(Path(path), args, **kwargs).decode('utf-8')


def write(path, value):
    path = Path(path)
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, sort_keys=True)
        out.write('\n')


def load(path):
    return V.strict_json(V.bounded(Path(path), 65536))


def source(root, expected):
    revision = command('git', ['rev-parse', 'HEAD'], cwd=root).strip()
    if not re.fullmatch('[0-9a-f]{40}', expected) or revision != expected:
        raise ValueError('source_revision_mismatch')
    if command('git', ['status', '--porcelain', '--untracked-files=all'], cwd=root).strip():
        raise ValueError('source_dirty')
    if Path(command('git', ['rev-parse', '--show-toplevel'], cwd=root).strip()).resolve() != Path(root).resolve():
        raise ValueError('source_root_mismatch')
    return {'revision': revision, 'tree': command('git', ['rev-parse', 'HEAD^{tree}'], cwd=root).strip(),
            'lock_sha256': V.digest(Path(root) / 'Cargo.lock'),
            'version': tomllib.loads((Path(root) / 'Cargo.toml').read_text())['package']['version']}


def translated(system):
    if system != 'Darwin':
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    value, length = ctypes.c_int(), ctypes.c_size_t(ctypes.sizeof(ctypes.c_int))
    rc = libc.sysctlbyname(b'sysctl.proc_translated', ctypes.byref(value), ctypes.byref(length), None, 0)
    if rc == -1 and ctypes.get_errno() == errno.ENOENT:
        return False  # Apple's documented native result for an absent key.
    if rc == -1 or value.value not in (0, 1):
        raise ValueError('translation_unknown')
    return value.value == 1


def host(target):
    system, machine, runner, _ = TARGETS[target]
    if (platform.system(), platform.machine()) != (system, machine) or translated(system):
        raise ValueError('native_host_mismatch')
    rust = command('rustc', ['+1.94.0', '-vV'])
    fields = dict(line.split(': ', 1) for line in rust.splitlines() if ': ' in line)
    check_rust(fields, target)
    image = {k: os.environ.get(k, '') for k in ['ImageOS', 'ImageVersion']}
    if any(not re.fullmatch('[A-Za-z0-9._-]{1,128}', v) for v in image.values()):
        raise ValueError('runner_image_unknown')
    return {'system': system, 'machine': machine, 'runner': runner, 'rust': fields, 'image': image,
            'translation': False, 'target': target}


def binary_arch(path, target):
    with Path(path).open('rb') as stream:
        head = stream.read(64)
    system, machine, _, _ = TARGETS[target]
    if system == 'Linux':
        valid = len(head) >= 64 and head[:6] == b'\x7fELF\x02\x01'
        arch = struct.unpack('<H', head[18:20])[0] if valid else None
        valid = valid and arch == (62 if machine == 'x86_64' else 183)
    else:
        valid = len(head) >= 32 and head[:4] == b'\xcf\xfa\xed\xfe'
        arch = struct.unpack('<I', head[4:8])[0] if valid else None
        valid = valid and arch == (0x1000007 if machine == 'x86_64' else 0x100000c)
    if not valid:
        raise ValueError('binary_architecture_mismatch')


def flags(target):
    values = ['+1.94.0', 'build', '--locked', '--release', '--bins', '--target', target]
    if TARGETS[target][0] == 'Darwin':
        values += ['--config', 'profile.release.build-override.strip="none"']
    return values


def pair(root, target):
    suffix = TARGETS[target][3]
    return {role: Path(root) / (role + '-' + suffix) for role in ['locksmith', 'locksmithd']}


def environment(home=None):
    names = ['PATH', 'HOME', 'TMPDIR', 'CARGO_HOME', 'RUSTUP_HOME', 'SDKROOT', 'DEVELOPER_DIR']
    value = {k: os.environ[k] for k in names if k in os.environ}
    value.update(PYTHONDONTWRITEBYTECODE='1', LANG='C', RUST_LOG='error')
    if home is not None:
        value = {'PATH': value.get('PATH', '/usr/bin:/bin'), 'HOME': str(home), 'TMPDIR': str(home),
                 'PYTHONDONTWRITEBYTECODE': '1', 'LANG': 'C', 'RUST_LOG': 'error', 'LOCKSMITH_SEED_PATH': ''}
    return value


def exact(value, expected):
    """JSON structural equality that does not conflate booleans with integers."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(exact(value[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(exact(a, b) for a, b in zip(value, expected))
    return value == expected


def check_rust(fields, target):
    patterns = {'binary': 'rustc', 'commit-hash': '[0-9a-f]{40}', 'commit-date': r'\d{4}-\d{2}-\d{2}',
                'host': re.escape(target), 'release': r'1\.94\.0', 'LLVM version': r'\d+(?:\.\d+){1,3}'}
    if not isinstance(fields, dict) or fields.keys() != patterns.keys() or any(
            not isinstance(fields[k], str) or not re.fullmatch(pattern, fields[k]) for k, pattern in patterns.items()):
        raise ValueError('rust_host_mismatch')
