"""Storage/custody failures must prevent a broker from starting."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class StateCheckTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "state_check", Path(__file__).parents[1] / "state_check.py"
        )
        self.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guard)
        self.temp = tempfile.TemporaryDirectory(prefix="edge-state-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".edge-state-id").write_text("edge-brokers\n")
        (self.root / "custody").mkdir()
        (self.root / "custody/codex.ready").write_text("edge-brokers:codex\n")

    def check(self, *, mounted=True, fstype="zfs", component="codex"):
        with patch.object(self.guard.os, "getuid", return_value=0), patch.object(
            self.guard, "mount_type", return_value=fstype if mounted else None
        ), patch.object(self.guard, "TRUSTED_UID", self.root.stat().st_uid):
            self.guard.check(self.root, "edge-brokers", component)

    def test_verified_mount_and_custody(self):
        self.check()

    def test_directory_on_root_filesystem_is_refused(self):
        with self.assertRaises(self.guard.Refusal):
            self.check(mounted=False)

    def test_non_zfs_mount_is_refused(self):
        with self.assertRaises(self.guard.Refusal):
            self.check(fstype="ext4")

    def test_wrong_volume_is_refused(self):
        (self.root / ".edge-state-id").write_text("edge-locksmith\n")
        with self.assertRaises(self.guard.Refusal):
            self.check()

    def test_missing_custody_receipt_is_refused(self):
        (self.root / "custody/codex.ready").unlink()
        with self.assertRaises(self.guard.Refusal):
            self.check()

    def test_wrong_custody_receipt_is_refused(self):
        (self.root / "custody/codex.ready").write_text("edge-brokers:teamclaude\n")
        with self.assertRaises(self.guard.Refusal):
            self.check()

    def test_symlink_receipt_is_refused(self):
        receipt = self.root / "custody/codex.ready"
        receipt.unlink()
        receipt.symlink_to(self.root / ".edge-state-id")
        with self.assertRaises(self.guard.Refusal):
            self.check()

    def test_writable_receipt_is_refused(self):
        (self.root / "custody/codex.ready").chmod(0o666)
        with self.assertRaises(self.guard.Refusal):
            self.check()

    def test_path_traversal_component_is_refused(self):
        with self.assertRaises(self.guard.Refusal):
            self.check(component="../../outside")


if __name__ == "__main__":
    unittest.main()
