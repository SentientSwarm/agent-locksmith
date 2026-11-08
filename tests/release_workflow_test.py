"""Release workflow contract and scripts/release-notes.py checks (no hosted execution)."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts/release-notes.py")
assert SPEC is not None and SPEC.loader is not None
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


def assets(root: Path, version: str = "3.0.0") -> Path:
    for name in R.BINARIES:
        (root / name).write_bytes(name.encode())
    (root / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}\n" for n in R.BINARIES)
    )
    (root / "validation.json").write_text(json.dumps({"source": {"version": version}}))
    return root


class ReleaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.value = yaml.load(
            (ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader
        )

    def test_publishes_validated_bytes_only_from_a_tag_push(self):
        jobs = self.value["jobs"]
        self.assertEqual(
            jobs["validate"]["uses"], "./.github/workflows/native-validation.yml"
        )
        self.assertEqual(jobs["release"]["needs"], "validate")
        self.assertEqual(self.value["permissions"], {"contents": "read"})
        self.assertEqual(jobs["release"]["permissions"], {"contents": "write"})
        steps = jobs["release"]["steps"]
        publish = [s for s in steps if "gh release create" in s.get("run", "")]
        self.assertEqual(len(publish), 1)
        self.assertIn("github.event_name == 'push'", publish[0]["if"])
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", publish[0]["if"])
        for name in ("locksmith-*", "locksmithd-*", "SHA256SUMS", "validation.json"):
            self.assertIn(name, publish[0]["run"])
        check = next(
            i for i, s in enumerate(steps) if "release-notes.py" in s.get("run", "")
        )
        self.assertLess(check, steps.index(publish[0]))
        self.assertFalse(any("cargo " in s.get("run", "") for s in steps))

    def test_checkout_does_not_persist_credentials(self):
        checkout = next(
            s
            for s in self.value["jobs"]["release"]["steps"]
            if s.get("uses") == "actions/checkout@v4"
        )
        self.assertEqual(checkout["with"]["persist-credentials"], "false")


class ReleaseNotes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_complete_asset_set_passes(self):
        R.check_assets(assets(self.dir), "3.0.0")

    def test_missing_daemon_or_extra_file_refuses(self):
        assets(self.dir)
        (self.dir / "locksmithd-linux-amd64").unlink()
        with self.assertRaisesRegex(ValueError, "locksmithd-linux-amd64"):
            R.check_assets(self.dir, "3.0.0")

    def test_changed_bytes_refuse(self):
        assets(self.dir)
        (self.dir / "locksmith-darwin-arm64").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "does not match SHA256SUMS"):
            R.check_assets(self.dir, "3.0.0")

    def test_validated_version_must_match_cargo(self):
        with self.assertRaisesRegex(ValueError, "validated version"):
            R.check_assets(assets(self.dir, "2.9.0"), "3.0.0")

    def test_tag_must_name_cargo_version(self):
        R.check_ref("refs/tags/v3.0.0", "3.0.0")
        R.check_ref("refs/heads/main", "3.0.0")
        R.check_ref("refs/pull/1/merge", "3.0.0")
        with self.assertRaisesRegex(ValueError, "v3.0.1"):
            R.check_ref("refs/tags/v3.0.1", "3.0.0")

    def test_changelog_section_keeps_subsections_and_stops_at_next_release(self):
        text = "# Changelog\n\n## 3.0.0\n\n- one\n\n### Changed\n\n- two\n\n## 2.8.0\n\n- old\n"
        self.assertEqual(
            R.changelog_section(text, "3.0.0"), "- one\n\n### Changed\n\n- two"
        )
        with self.assertRaisesRegex(ValueError, "no section"):
            R.changelog_section(text, "3.1.0")

    def test_repository_changelog_has_this_version(self):
        self.assertTrue(
            R.changelog_section((ROOT / "CHANGELOG.md").read_text(), R.version(ROOT))
        )


if __name__ == "__main__":
    unittest.main()
