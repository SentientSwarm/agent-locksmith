"""Actual invented processes exercise the same smoke/build ownership boundaries."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from fixtures import C, IDENTITY
from fake_process import pair
from native_validation import build as B, smoke as S


class ProcessContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.addCleanup(self.assert_absent)

    def test_tool_proxy_symlink_keeps_its_invoked_name(self):
        # rustup proxies may be symlinks to one multicall binary that
        # dispatches on argv[0]; resolving the link would run rustup itself.
        tool = self.bin / 'multicall'
        tool.write_text('#!/bin/sh\necho "${0##*/}"\n')
        tool.chmod(0o755)
        (self.bin / 'rustc').symlink_to(tool)
        with patch.dict(os.environ, {'PATH': str(self.bin)}):
            self.assertEqual(C.command('rustc', []).strip(), 'rustc')

    def assert_absent(self):
        path = self.bin / 'children.jsonl'
        if path.exists():
            for pid in set(map(int, path.read_text().splitlines())):
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)

    def test_real_invented_smoke_and_environment_isolation(self):
        files = pair(self.bin)
        record = {}
        inherited = {'OPENAI_API_KEY': 'INVENTED_PRIVATE_CANARY', 'HTTPS_PROXY': 'http://invalid',
                     'LOCKSMITH_ADMIN_URL': 'http://invalid', 'LOCKSMITH_OP_TOKEN': 'wrong'}
        with patch.dict(os.environ, inherited):
            result = S.owned_smoke(files, IDENTITY, self.private, record)
        self.assertTrue(result['operator_status'])
        self.assertEqual(record['stage'], 'complete')
        self.assertEqual(result['cleanup'], {'joined': True, 'exit': 0, 'forced': False})
        self.assertNotIn('lkop_', json.dumps(result))
        self.assertNotIn('CANARY', json.dumps(result))

    def test_readiness_version_status_and_forced_shutdown_refuse(self):
        for mode in ['early', 'bad_version', 'bad_status', 'hang', 'ignore_term']:
            private = self.root / mode
            private.mkdir()
            record = {}
            with self.subTest(mode=mode), patch.object(S, 'READY_TIMEOUT', .3), patch.object(B, 'JOIN_TIMEOUT', .1):
                with self.assertRaises(ValueError):
                    S.owned_smoke(pair(self.bin, mode), IDENTITY, private, record)
                self.assertTrue(record['cleanup']['joined'])
                if mode == 'ignore_term':
                    self.assertTrue(record['cleanup']['forced'])
                    self.assertNotEqual(record['cleanup']['exit'], 0)

    def test_build_child_success_timeout_and_disk_refusal(self):
        target = self.root / 'target'
        target.mkdir()
        record = {}
        B.run_owned([sys.executable, '-B', '-c', 'pass'], self.root, target, record)
        self.assertEqual(record['process']['exit'], 0)
        self.assertTrue(record['process']['joined'])
        record = {}
        with patch.object(B, 'TIMEOUT', .01), self.assertRaisesRegex(ValueError, 'build_timeout'):
            B.run_owned([sys.executable, '-B', '-c', 'import time;time.sleep(10)'], self.root, target, record)
        self.assertTrue(record['process']['joined'])
        with patch.object(B.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(1, 1, 0)):
            with self.assertRaisesRegex(ValueError, 'runner_disk_entry_refused'):
                B.run_owned([sys.executable, '-B', '-c', 'pass'], self.root, target, {})

    def test_host_architecture_translation_and_unknown_toolchain_refuse(self):
        target = 'x86_64-unknown-linux-gnu'
        image = {'ImageOS': 'ubuntu24', 'ImageVersion': 'invented.1'}
        with patch.dict(os.environ, image), patch.object(C.platform, 'system', return_value='Linux'), \
             patch.object(C.platform, 'machine', return_value='x86_64'), patch.object(C, 'command', return_value='binary: rustc\ncommit-hash: ' + 'd' * 40 + '\ncommit-date: 2026-03-01\nLLVM version: 21.1.8\nrelease: 1.94.0\nhost: ' + target):
            self.assertEqual(C.host(target)['target'], target)
            with patch.object(C, 'translated', return_value=True), self.assertRaises(ValueError):
                C.host(target)
            with patch.object(C.platform, 'machine', return_value='aarch64'), self.assertRaises(ValueError):
                C.host(target)
            with patch.object(C, 'command', return_value='release: 1.95.0\nhost: ' + target), self.assertRaises(ValueError):
                C.host(target)
