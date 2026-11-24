"""scripts/release-gate.py manifest and identity checks (no QA run)."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_gate", ROOT / "scripts/release-gate.py")
assert SPEC is not None and SPEC.loader is not None
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)

REV = "a" * 40
VERSION = "3.0.0"


def info(name, revision=REV, state="clean", version=VERSION):
    return {"name": name, "version": version,
            "build": {"revision": revision, "source_state": state}}


def manifest(**overrides):
    value = {
        "mode": "release",
        "release_ready": True,
        "commit": REV,
        "tree_dirty": False,
        "binaries": {name: info(name) for name in G.BINARIES},
    }
    value.update(overrides)
    return value


class ReleaseGateTest(unittest.TestCase):
    def test_a_release_ready_manifest_at_the_revision_passes(self):
        self.assertEqual(G.check_manifest(manifest(), VERSION, REV), [])

    def test_a_manifest_that_is_not_release_ready_fails(self):
        self.assertIn("manifest: release_ready is not true",
                      G.check_manifest(manifest(release_ready=False), VERSION, REV))

    def test_a_pr_mode_run_fails(self):
        self.assertTrue(G.check_manifest(manifest(mode="pr"), VERSION, REV))

    def test_another_commit_or_a_dirty_tree_fails(self):
        self.assertTrue(G.check_manifest(manifest(commit="b" * 40), VERSION, REV))
        self.assertTrue(G.check_manifest(manifest(tree_dirty=True), VERSION, REV))

    def test_binaries_must_report_the_version_revision_and_a_clean_state(self):
        for bad in (info("locksmithd", revision="b" * 40),
                    info("locksmithd", state="dirty"),
                    info("locksmithd", version="2.8.0")):
            binaries = {"locksmith": info("locksmith"), "locksmithd": bad}
            self.assertTrue(G.check_manifest(manifest(binaries=binaries), VERSION, REV))
        self.assertTrue(G.check_manifest(manifest(binaries={"locksmith": info("locksmith")}),
                                         VERSION, REV))

    def test_the_version_comes_from_cargo_toml(self):
        self.assertRegex(G.cargo_version(), r"^\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
