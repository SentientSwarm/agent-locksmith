"""Fail-closed complete candidate consistency, not signatures or release publication."""
from pathlib import Path
import re
import shutil
from . import common as C
from .build import ENTRY, STOP, GROWTH

CLEANUP = {'joined': True, 'exit': 0, 'forced': False}
SMOKE = {'startup': True, 'live_version': True, 'status': True, 'operator_status': True, 'cleanup': CLEANUP}


def check_record(record, target, identity):
    if set(record) != {'state', 'source', 'host', 'flags', 'files', 'resources', 'smoke'}:
        raise ValueError('provenance_shape')
    if record['state'] != 'smoked_candidate' or record['source'] != identity or record['flags'] != C.flags(target):
        raise ValueError('provenance_mismatch')
    system, machine, runner, _ = C.TARGETS[target]
    host = record['host']
    if set(host) != {'system', 'machine', 'runner', 'rust', 'image', 'translation', 'target'}:
        raise ValueError('host_shape')
    if (host['system'], host['machine'], host['runner'], host['target']) != (system, machine, runner, target) \
            or host['translation'] is not False:
        raise ValueError('native_host_mismatch')
    C.check_rust(host['rust'], target)
    if not isinstance(host['image'], dict):
        raise ValueError('host_shape')
    if set(host['image']) != {'ImageOS', 'ImageVersion'} or any(
            not isinstance(v, str) or not re.fullmatch('[A-Za-z0-9._-]{1,128}', v) for v in host['image'].values()):
        raise ValueError('runner_image_unknown')
    if not C.exact(record['smoke'], SMOKE):
        raise ValueError('smoke_incomplete')
    check_resources(record['resources'])


def check_resources(resources):
    keys = {'entry_floor', 'stop_floor', 'growth_limit', 'timeout_seconds', 'entry_free',
            'initial_target_bytes', 'peak_target_growth', 'minimum_free', 'process'}
    if set(resources) != keys or not C.exact(resources['process'], CLEANUP):
        raise ValueError('build_resources_incomplete')
    if any(type(v) is not int or v < 0 for k, v in resources.items() if k != 'process'):
        raise ValueError('build_resources_shape')
    if (resources['entry_floor'], resources['stop_floor'], resources['growth_limit'], resources['timeout_seconds']) \
            != (ENTRY, STOP, GROWTH, 1800):
        raise ValueError('build_policy_mismatch')
    if resources['entry_free'] < ENTRY or resources['minimum_free'] < STOP or resources['peak_target_growth'] > GROWTH:
        raise ValueError('build_resource_refused')


def check_row(root, target, identity):
    record = C.load(root / (target + '.json'))
    check_record(record, target, identity)
    files = C.pair(root, target)
    hashes = {p.name: C.V.digest(p) for p in files.values()}
    if record['files'] != hashes:
        raise ValueError('candidate_changed')
    for path in files.values():
        C.binary_arch(path, target)
    check_receipts(root, target, record, hashes)
    return hashes


def check_receipts(root, target, record, hashes):
    built = {k: v for k, v in record.items() if k != 'smoke'}
    if not C.exact(C.load(root / (target + '.build.json')), {**built, 'state': 'built_not_smoked'}):
        raise ValueError('build_receipt_mismatch')
    if not C.exact(C.load(root / (target + '.resources.json')), record['resources']):
        raise ValueError('resource_receipt_mismatch')
    probe = C.load(root / (target + '.smoke.json'))
    if not C.exact(probe, {'stage': 'complete', 'daemon_started': True, 'cleanup': CLEANUP}):
        raise ValueError('smoke_receipt_mismatch')
    if C.V.checksum_entries(root / (target + '.sha256')) != hashes:
        raise ValueError('checksum_mismatch')


def aggregate(root, directory, output, expected, job_result):
    if job_result != 'success':
        raise ValueError('matrix_job_incomplete')
    identity = C.source(root, expected)
    expected_files = set()
    for target in C.TARGETS:
        expected_files.update(p.name for p in C.pair(directory, target).values())
        expected_files.update(target + suffix for suffix in ['.json', '.build.json', '.resources.json', '.smoke.json', '.sha256'])
    if {p.name for p in directory.iterdir()} != expected_files or any(p.is_symlink() or not p.is_file() for p in directory.iterdir()):
        raise ValueError('artifact_set_incomplete')
    hashes = {}
    for target in C.TARGETS:
        hashes.update(check_row(directory, target, identity))
    for name, digest in hashes.items():
        with (directory / name).open('rb') as src, (output / name).open('xb') as dst:
            shutil.copyfileobj(src, dst)
        if C.V.digest(output / name) != digest:
            raise ValueError('candidate_changed')
    (output / 'SHA256SUMS').write_text(''.join(h + '  ' + n + '\n' for n, h in sorted(hashes.items())))
    result = {'state': 'complete_native_candidate', 'source': identity, 'targets': list(C.TARGETS), 'files': hashes,
              'provenance': {t: C.load(directory / (t + '.json')) for t in C.TARGETS},
              'scope': 'Four native job smoke receipts and same downloaded bytes; not publication or packaged UAT'}
    C.write(output / 'validation.json', result)
    return result
