"""Storage, custody and component-list failures must prevent a service from starting."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

EDGE = Path(__file__).resolve().parent.parent


def load_guard():
    spec = importlib.util.spec_from_file_location(
        "state_check", EDGE / "state_check.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StateCheckTest(unittest.TestCase):
    def setUp(self):
        self.guard = load_guard()
        self.temp = tempfile.TemporaryDirectory(prefix="locksmith-edge-state-test-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "state"
        self.root.mkdir()
        (self.root / ".locksmith-edge-id").write_text("site-a\n")
        (self.root / "custody").mkdir()
        (self.root / "custody/app.ready").write_text("site-a:app\n")
        self.etc = base / "etc"
        self.etc.mkdir()
        self.config = self.etc / "components.json"
        # Execute-only, so the kernel makes the process non-dumpable at exec.
        self.binary = base / "app"
        self.binary.write_text("")
        self.binary.chmod(0o711)
        self.write_config()
        self.uid = self.root.stat().st_uid

    def write_config(self, **overrides):
        data = {
            "instance": "site-a",
            "state_root": str(self.root),
            "require_zfs": True,
            "components": {
                "app": {
                    "user": "app",
                    "executable": str(self.binary),
                    "environment_file": True,
                }
            },
        }
        data.update(overrides)
        self.config.write_text(json.dumps(data))

    def check(self, *, fstype="zfs", instance="site-a", component="app", uid=None):
        with (
            patch.object(self.guard.os, "getuid", return_value=0),
            patch.object(self.guard, "mount_type", return_value=fstype),
            patch.object(self.guard, "TRUSTED_UID", self.uid if uid is None else uid),
        ):
            self.guard.check(self.config, instance, component)

    def refused(self, fragment, **kwargs):
        with self.assertRaises(self.guard.Refusal) as ctx:
            self.check(**kwargs)
        self.assertIn(fragment, str(ctx.exception))

    def test_verified_mount_and_custody(self):
        self.check()

    def test_secret_holding_executable_must_be_execute_only(self):
        # A readable binary runs dumpable until it hardens itself, so a
        # same-uid process could read the environment file's secrets.
        for mode in (0o755, 0o751, 0o715, 0o731):
            self.binary.chmod(mode)
            self.refused("execute-only")

    def test_secret_holding_executable_must_be_root_owned(self):
        with patch.object(self.guard, "TRUSTED_UID", self.uid + 1):
            with self.assertRaises(self.guard.Refusal) as ctx:
                self.guard.execute_only(self.binary)
        self.assertIn("execute-only", str(ctx.exception))

    def test_secret_holding_executable_must_not_be_a_symlink(self):
        target = self.binary.with_name("real")
        self.binary.rename(target)
        self.binary.symlink_to(target)
        self.refused("execute-only")

    def test_readable_executable_allowed_without_an_environment_file(self):
        self.binary.chmod(0o755)
        self.write_config(
            components={
                "app": {
                    "user": "app",
                    "executable": str(self.binary),
                    "environment_file": False,
                }
            }
        )
        self.check()

    def test_components_file_without_executable_is_refused(self):
        self.write_config(components={"app": {"user": "app"}})
        self.refused("components file")

    def test_not_root_is_refused(self):
        with (
            patch.object(self.guard.os, "getuid", return_value=1000),
            self.assertRaises(self.guard.Refusal),
        ):
            self.guard.check(self.config, "site-a", "app")

    def test_directory_on_root_filesystem_is_refused(self):
        self.refused("mounted", fstype=None)

    def test_non_zfs_mount_is_refused(self):
        self.refused("ZFS", fstype="ext4")

    def test_non_zfs_mount_allowed_when_not_required(self):
        self.write_config(require_zfs=False)
        self.check(fstype="ext4")

    def test_unmounted_refused_even_when_zfs_not_required(self):
        self.write_config(require_zfs=False)
        self.refused("mounted", fstype=None)

    def test_wrong_volume_is_refused(self):
        (self.root / ".locksmith-edge-id").write_text("site-b\n")
        self.refused("identity")

    def test_missing_custody_receipt_is_refused(self):
        (self.root / "custody/app.ready").unlink()
        self.refused("unavailable")

    def test_wrong_custody_receipt_is_refused(self):
        (self.root / "custody/app.ready").write_text("site-a:other\n")
        self.refused("custody")

    def test_symlink_receipt_is_refused(self):
        receipt = self.root / "custody/app.ready"
        receipt.unlink()
        receipt.symlink_to(self.root / ".locksmith-edge-id")
        self.refused("unsafe")

    def test_writable_receipt_is_refused(self):
        (self.root / "custody/app.ready").chmod(0o666)
        self.refused("unsafe")

    def test_unlisted_component_is_refused(self):
        self.refused("component", component="other")

    def test_path_traversal_component_is_refused(self):
        self.refused("component", component="../../outside")

    def test_wrong_instance_is_refused(self):
        self.refused("instance", instance="site-b")

    def test_writable_components_file_is_refused(self):
        self.config.chmod(0o666)
        self.refused("components file")

    def test_writable_components_dir_is_refused(self):
        self.etc.chmod(0o777)
        self.refused("components file")

    def test_non_root_owned_components_file_is_refused(self):
        self.refused("components file", uid=self.uid + 1)

    def test_symlink_components_file_is_refused(self):
        real = self.etc / "real.json"
        self.config.rename(real)
        self.config.symlink_to(real)
        self.refused("components file")

    def test_malformed_components_file_is_refused(self):
        self.config.write_text("{not json")
        self.refused("components file")

    def test_relative_state_root_is_refused(self):
        self.write_config(state_root="state")
        self.refused("components file")

    def test_findmnt_runs_by_absolute_path_with_a_clean_environment(self):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs.get("env")))
            return subprocess.CompletedProcess(argv, 1, "", "")

        with patch.object(self.guard.subprocess, "run", side_effect=fake_run):
            self.assertIsNone(self.guard.mount_type(self.root))
        argv, env = calls[0]
        self.assertEqual(argv[0], "/usr/bin/findmnt")
        self.assertEqual(env, {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})

    def test_shebang_is_isolated(self):
        first = (EDGE / "state_check.py").read_text().splitlines()[0]
        self.assertEqual(first, "#!/usr/bin/python3 -I")


if __name__ == "__main__":
    unittest.main()
