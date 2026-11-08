"""Actual stdlib CLI, invented private inputs; never a retained URL."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from oauth_challenge_test import fixture
SCRIPT=Path.cwd()/'scripts/oauth-challenge.py'


def invoke(root, request, mode=0o600):
    source=root/'input.json';source.write_text(json.dumps(request));source.chmod(mode)
    return subprocess.run([sys.executable,'-B',str(SCRIPT),'--input',str(source),'--output',str(root/'output.json')],capture_output=True,text=True,timeout=3)


class PrivateCLI(unittest.TestCase):
    def test_success_private_and_exclusive(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);root.chmod(0o700);url,expected=fixture()
            result=invoke(root,dict(url=url,expected=expected))
            self.assertEqual(result.returncode,0)
            self.assertEqual(json.loads(result.stdout),dict(state='challenge_changed'))
            self.assertEqual((root/'output.json').stat().st_mode & 0o777,0o600)
            original=(root/'output.json').read_bytes()
            self.assertEqual(invoke(root,dict(url=url,expected=expected)).returncode,1)
            self.assertEqual((root/'output.json').read_bytes(),original)

    def test_wrong_permissions_refuse_without_values(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);root.chmod(0o700);url,expected=fixture()
            for mode in [0o644,0o400]:
                result=invoke(root,dict(url=url,expected=expected),mode)
                self.assertEqual(result.returncode,1)
                self.assertNotIn('invented',result.stdout+result.stderr)
                self.assertFalse((root/'output.json').exists())

    def test_parent_mode_and_symlink_refuse(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);root.chmod(0o755);url,expected=fixture()
            self.assertEqual(invoke(root,dict(url=url,expected=expected)).returncode,1)
            root.chmod(0o700)
            (root/'output.json').symlink_to(root/'input.json')
            self.assertEqual(invoke(root,dict(url=url,expected=expected)).returncode,1)

    def test_duplicate_json_refuses(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);root.chmod(0o700)
            source=root/'input.json';source.write_text('{"url":"private-canary","url":"private-canary"}');source.chmod(0o600)
            result=subprocess.run([sys.executable,'-B',str(SCRIPT),'--input',str(source),'--output',str(root/'output.json')],capture_output=True,text=True,timeout=3)
            self.assertEqual(result.returncode,1)
            self.assertNotIn('private-canary',result.stdout+result.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
