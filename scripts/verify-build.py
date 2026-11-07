#!/usr/bin/env python3
"""Verify captured files against checksums and an independently selected source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

LIMIT = 16 * 1024
TIMEOUT = 5.0


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def bounded(path, limit=LIMIT):
    with path.open('rb') as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError('input_too_large')
    return value


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate_json_member')
            value[key] = item
        return value

    def invalid(_):
        raise ValueError('invalid_json_constant')

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('invalid_json') from error


def collect(process, deadline, capture_stderr=False):
    output, errors, total = bytearray(), bytearray(), 0
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, True)
        selector.register(process.stderr, selectors.EVENT_READ, False)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('inspection_timeout')
            for key, _ in selector.select(remaining):
                data = os.read(key.fd, 4096)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                total += len(data)
                if total > LIMIT:
                    raise ValueError('inspection_too_large')
                if key.data:
                    output.extend(data)
                else:
                    errors.extend(data)
    if process.wait(timeout=max(.001, deadline - time.monotonic())) != 0:
        raise ValueError('inspection_failed')
    return (bytes(output), bytes(errors)) if capture_stderr else bytes(output)


def execute(path, arguments, *, env=None, cwd=None, capture_stderr=False, resolve=True):
    """Bounded owned command, shared by identity inspection and native smoke.

    Product binaries run from their resolved path. Toolchain proxies pass
    resolve=False: a rustup proxy may be a symlink to a multicall binary
    that dispatches on argv[0], so resolving it would run rustup itself.
    """
    program = path.resolve() if resolve else path.absolute()
    process = subprocess.Popen([str(program), *arguments], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True, env=env, cwd=cwd)
    try:
        return collect(process, time.monotonic() + TIMEOUT, capture_stderr)
    except subprocess.TimeoutExpired as error:
        raise ValueError('inspection_timeout') from error
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def inspect(path, *, env=None):
    return strict_json(execute(path, ['--build-info'], env=env))


def checksum_entries(path):
    entries = {}
    for line in bounded(path, 128 * 1024).decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/\\]+)', line)
        if match is None or match[2] in entries:
            raise ValueError('ambiguous_checksum_manifest')
        entries[match[2]] = match[1]
    return entries


def check_identity(value, name, version, revision):
    expected = {'name': name, 'version': version,
                'build': {'revision': revision, 'source_state': 'clean'}}
    if value != expected:
        raise ValueError('identity_mismatch')


def verify(cli, daemon, checksums, version, revision, response=None, *, env=None):
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or not version or len(version) > 128:
        raise ValueError('invalid_expected_identity')
    entries = checksum_entries(checksums)
    paths = {'locksmith': cli, 'locksmithd': daemon}
    if cli.resolve() == daemon.resolve() or cli.name == daemon.name:
        raise ValueError('distinct_files_required')
    # Check both files before executing either one.
    hashes = {role: digest(path) for role, path in paths.items()}
    for role, path in paths.items():
        if entries.get(path.name) != hashes[role]:
            raise ValueError('checksum_mismatch')
    for role, path in paths.items():
        check_identity(inspect(path, env=env), role, version, revision)
    for role, path in paths.items():
        if digest(path) != hashes[role]:
            raise ValueError('checksum_changed')
    result = {'verified': True, 'scope': 'files', 'version': version, 'revision': revision,
              'files': {role: {'file': path.name, 'sha256': hashes[role]} for role, path in paths.items()}}
    if response is not None:
        data = bounded(response)
        check_identity(strict_json(data), 'agent-locksmith', version, revision)
        result.update(scope='files_and_supplied_version_response', version_response_sha256=hashlib.sha256(data).hexdigest())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['cli', 'daemon', 'checksums']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-version', required=True)
    parser.add_argument('--expected-revision', required=True)
    parser.add_argument('--version-response', type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.cli, args.daemon, args.checksums, args.expected_version,
                        args.expected_revision, args.version_response)
    except (ValueError, OSError) as error:
        # Do not copy file paths, child output or OS exception details to receipts.
        code = str(error) if type(error) is ValueError else 'file_or_process_error'
        print(json.dumps({'verified': False, 'error': code}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
