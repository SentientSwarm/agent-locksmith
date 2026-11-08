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


REV = "a" * 40


def assets(root: Path, version: str = "3.0.0", revision: str = REV) -> Path:
    for name in R.BINARIES:
        (root / name).write_bytes(name.encode())
    (root / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}\n" for n in R.BINARIES)
    )
    (root / "validation.json").write_text(
        json.dumps({"source": {"version": version, "revision": revision}})
    )
    return root


class ReleaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.value = yaml.load(
            (ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader
        )

    def test_publishes_validated_bytes_only_from_a_tag_push(self):
        jobs = self.value["jobs"]
        self.assertEqual(jobs["validate"]["uses"], "./.github/workflows/native-validation.yml")
        self.assertEqual(self.value["permissions"], {"contents": "read"})
        self.assertNotIn("permissions", jobs["check"])  # read-only on every event
        publish = jobs["publish"]
        self.assertEqual(publish["permissions"], {"contents": "write", "actions": "read"})
        self.assertIn("github.event_name == 'push'", publish["if"])
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", publish["if"])
        self.assertEqual(set(publish["needs"]), {"validate", "check"})
        runs = [s.get("run", "") for s in publish["steps"]]
        create = next(i for i, r in enumerate(runs) if "gh release create" in r)
        check = next(i for i, r in enumerate(runs) if "release-notes.py" in r)
        gate = next(i for i, r in enumerate(runs) if "actions/workflows/ci.yml/runs" in r)
        self.assertLess(check, create)
        self.assertLess(gate, create)
        self.assertIn("event=push&status=success", runs[gate])
        for name in ("locksmith-*", "locksmithd-*", "SHA256SUMS", "validation.json"):
            self.assertIn(name, runs[create])
        self.assertFalse(any("cargo " in r for r in runs))

    def test_downloads_the_artifact_validation_produced(self):
        jobs = self.value["jobs"]
        for job in ("check", "publish"):
            download = next(
                s for s in jobs[job]["steps"] if s.get("uses") == "actions/download-artifact@v4"
            )
            self.assertEqual(download["with"]["name"], "${{ needs.validate.outputs.artifact }}")
        native = yaml.load(
            (ROOT / ".github/workflows/native-validation.yml").read_text(), Loader=yaml.BaseLoader
        )
        self.assertEqual(
            native["on"]["workflow_call"]["outputs"]["artifact"]["value"],
            "${{ jobs.aggregate.outputs.artifact }}",
        )
        self.assertEqual(
            native["jobs"]["aggregate"]["outputs"]["artifact"], "native-complete-${{ github.run_attempt }}"
        )

    def test_checkout_does_not_persist_credentials(self):
        checkout = next(
            s
            for s in self.value["jobs"]["publish"]["steps"]
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
        R.check_assets(assets(self.dir), "3.0.0", REV)

    def test_missing_daemon_or_extra_file_refuses(self):
        assets(self.dir)
        (self.dir / "locksmithd-linux-amd64").unlink()
        with self.assertRaisesRegex(ValueError, "locksmithd-linux-amd64"):
            R.check_assets(self.dir, "3.0.0", REV)

    def test_changed_bytes_refuse(self):
        assets(self.dir)
        (self.dir / "locksmith-darwin-arm64").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "does not match SHA256SUMS"):
            R.check_assets(self.dir, "3.0.0", REV)

    def test_validated_revision_must_match_this_run(self):
        with self.assertRaisesRegex(ValueError, "validated revision"):
            R.check_assets(assets(self.dir, revision="b" * 40), "3.0.0", REV)

    def test_validated_version_must_match_cargo(self):
        with self.assertRaisesRegex(ValueError, "validated version"):
            R.check_assets(assets(self.dir, "2.9.0"), "3.0.0", REV)

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
