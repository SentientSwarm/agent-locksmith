"""Verifier controls use invented executables; real A/B evidence is separate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('verify_build', Path(__file__).parents[1] / 'scripts/verify-build.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
REV = 'a' * 40


class VerifyBuild(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cli = self.root / 'locksmith-darwin-arm64'
        self.daemon = self.root / 'locksmithd-darwin-arm64'
        self.sums = self.root / 'SHA256SUMS'
        self.write(self.cli, 'locksmith')
        self.write(self.daemon, 'locksmithd')
        self.checksums()

    def write(self, path, role, revision=REV, state='clean', raw=None):
        value = json.dumps({'name': role, 'version': '3.0.0', 'build': {'revision': revision, 'source_state': state}}) if raw is None else raw
        path.write_text('#!/usr/bin/env python3\nprint(' + repr(value) + ')\n')
        path.chmod(0o755)

    def checksums(self):
        self.sums.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in [self.cli, self.daemon]))

    def verify(self, **kwargs):
        return V.verify(self.cli, self.daemon, self.sums, kwargs.get('version', '3.0.0'), kwargs.get('revision', REV), kwargs.get('response'))

    def test_good_pair_and_supplied_response(self):
        self.assertTrue(self.verify()['verified'])
        response = self.root / 'version.json'
        response.write_text(json.dumps({'name': 'agent-locksmith', 'version': '3.0.0', 'build': {'revision': REV, 'source_state': 'clean'}}))
        self.assertEqual(self.verify(response=response)['scope'], 'files_and_supplied_version_response')

    def test_expected_version_and_revision_are_external(self):
        for args in [{'revision': 'b'*40}, {'version': '4.0.0'}, {'revision': 'short'}]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.verify(**args)

    def test_mixed_and_dirty_unknown(self):
        for revision, state in [('b'*40, 'clean'), (REV, 'dirty'), (None, 'unknown')]:
            self.write(self.daemon, 'locksmithd', revision, state)
            self.checksums()
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.verify()

    def test_roles_not_inferred_from_names(self):
        self.write(self.daemon, 'locksmith')
        self.checksums()
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_or_corrupt_before_execution(self):
        self.daemon.write_text('not executable bytes')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.verify()
        self.daemon.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.verify()

    def test_ambiguous_checksums(self):
        self.sums.write_text(self.sums.read_text() + self.sums.read_text().splitlines()[0] + '\n')
        with self.assertRaises(ValueError):
            self.verify()

    def test_strict_identity_json(self):
        for raw in ['{}', '{"name":"x","name":"y"}', 'NaN', '[]', '{', '{} {}']:
            self.write(self.daemon, 'locksmithd', raw=raw)
            self.checksums()
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.verify()

    def test_stale_response_refuses(self):
        response = self.root / 'version.json'
        response.write_text(json.dumps({'name': 'agent-locksmith', 'version': '3.0.0', 'build': {'revision': 'b'*40, 'source_state': 'clean'}}))
        with self.assertRaises(ValueError):
            self.verify(response=response)

    def test_bounded_output_and_timeout(self):
        for code in ["print('x'*20000)", 'import time; time.sleep(2)']:
            self.daemon.write_text('#!/usr/bin/env python3\n' + code + '\n')
            self.checksums()
            old = V.TIMEOUT
            V.TIMEOUT = .1
            try:
                with self.assertRaises(ValueError):
                    self.verify()
            finally:
                V.TIMEOUT = old

    def test_nonzero_does_not_copy_diagnostics(self):
        self.daemon.write_text('#!/usr/bin/env python3\nimport sys\nsys.stderr.write("SYNTHETIC_PRIVATE_CANARY")\nsys.exit(9)\n')
        self.checksums()
        with self.assertRaises(ValueError) as caught:
            self.verify()
        self.assertNotIn('SYNTHETIC_PRIVATE_CANARY', str(caught.exception))

    def test_identity_cannot_mutate_captured_bytes(self):
        self.daemon.write_text(self.daemon.read_text() + 'with open(__file__, "a") as f: f.write("# changed")\n')
        self.checksums()
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
