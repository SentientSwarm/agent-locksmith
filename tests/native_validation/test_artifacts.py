"""Independent malformed/tampered fixture outcomes through the real aggregator."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from fixtures import C, IDENTITY, ROWS, dump, populate
from native_validation import artifacts as A


class ArtifactContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'input'
        self.inputs.mkdir()
        populate(self.inputs)
        self.source = patch.object(C, 'source', return_value=copy.deepcopy(IDENTITY))
        self.source.start()
        self.addCleanup(self.source.stop)

    def aggregate(self, result='success'):
        output = self.root / ('output-' + str(len(list(self.root.iterdir()))))
        output.mkdir()
        return A.aggregate(self.root, self.inputs, output, IDENTITY['revision'], result), output

    def test_complete_same_eight_bytes(self):
        result, output = self.aggregate()
        self.assertEqual(result['state'], 'complete_native_candidate')
        self.assertEqual(len(result['files']), 8)
        self.assertEqual(len((output / 'SHA256SUMS').read_text().splitlines()), 8)
        for name, digest in result['files'].items():
            self.assertEqual(C.V.digest(output / name), digest)
            self.assertEqual((output / name).read_bytes(), (self.inputs / name).read_bytes())

    def test_missing_extra_symlink_and_unsuccessful_job(self):
        for result in ['failure', 'cancelled', 'skipped']:
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.aggregate(result)
        target = self.inputs / 'locksmithd-linux-arm64'
        data = target.read_bytes()
        target.unlink()
        with self.assertRaises(ValueError):
            self.aggregate()
        target.write_bytes(data)
        extra = self.inputs / 'extra'
        extra.symlink_to(target)
        with self.assertRaises(ValueError):
            self.aggregate()
        extra.unlink()
        target.unlink()
        target.symlink_to(self.inputs / 'locksmith-linux-arm64')
        with self.assertRaises(ValueError):
            self.aggregate()

    def test_wrong_identity_host_policy_smoke_and_resources(self):
        path = self.inputs / (ROWS[0][0] + '.json')
        original = json.loads(path.read_text())
        changes = [('source', 'revision', 'd' * 40), ('source', 'tree', 'e' * 40),
                   ('source', 'version', '9.0.0'), ('source', 'lock_sha256', 'f' * 64),
                   ('host', 'system', 'Darwin'), ('host', 'machine', 'aarch64'),
                   ('host', 'runner', 'paid-large'), ('host', 'translation', True),
                   ('host', 'rust', 'release: 1.95.0\nhost: wrong'),
                   ('smoke', 'status', False), ('smoke', 'operator_status', False), ('smoke', 'startup', 1),
                   ('resources', 'process', {'joined': 1, 'exit': 0, 'forced': False}),
                   ('resources', 'minimum_free', 0), ('resources', 'entry_free', True)]
        for section, key, value in changes:
            record = copy.deepcopy(original)
            record[section][key] = value
            dump(path, record)
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.aggregate()
        dump(path, original)
        record = copy.deepcopy(original)
        record['flags'].remove('--locked')
        dump(path, record)
        with self.assertRaises(ValueError):
            self.aggregate()

    def test_changed_bytes_architecture_checksums_and_duplicate_json(self):
        target = self.inputs / 'locksmith-linux-amd64'
        target.write_bytes(target.read_bytes() + b'changed after smoke')
        with self.assertRaises(ValueError):
            self.aggregate()
        populate(self.inputs)
        target.write_bytes(b'not a native file')
        with self.assertRaises(ValueError):
            C.binary_arch(target, ROWS[0][0])
        populate(self.inputs)
        sums = self.inputs / (ROWS[0][0] + '.sha256')
        sums.write_text(sums.read_text() * 2)
        with self.assertRaises(ValueError):
            self.aggregate()
        populate(self.inputs)
        record = self.inputs / (ROWS[0][0] + '.json')
        record.write_text('{"state":1,"state":2}')
        with self.assertRaises(ValueError):
            self.aggregate()

    def test_build_receipt_unjoined_and_copy_race_refuse(self):
        path = self.inputs / (ROWS[0][0] + '.build.json')
        record = json.loads(path.read_text())
        record['source']['revision'] = 'd' * 40
        dump(path, record)
        with self.assertRaises(ValueError):
            self.aggregate()
        populate(self.inputs)
        path = self.inputs / (ROWS[0][0] + '.smoke.json')
        record = json.loads(path.read_text())
        record['cleanup']['joined'] = False
        dump(path, record)
        with self.assertRaises(ValueError):
            self.aggregate()
        populate(self.inputs)
        with patch.object(A.shutil, 'copyfileobj', side_effect=lambda src, dst: dst.write(b'replaced')):
            with self.assertRaises(ValueError):
                self.aggregate()
