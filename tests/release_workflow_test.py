"""Release workflow contract and scripts/release-notes.py checks (no hosted execution)."""

import hashlib
import importlib.util
import json
import re
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

    def test_six_binaries_for_the_three_shipped_platforms(self):
        self.assertEqual(R.SUFFIXES, ["linux-amd64", "linux-arm64", "darwin-arm64"])
        self.assertEqual(len(R.BINARIES), 6)

    def test_an_intel_mac_pair_is_refused(self):
        assets(self.dir)
        (self.dir / "locksmith-darwin-amd64").write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "extra .*locksmith-darwin-amd64"):
            R.check_assets(self.dir, "3.0.0", REV)

    def test_notes_list_only_the_shipped_platforms(self):
        text = R.notes("- body")
        for suffix in R.SUFFIXES:
            self.assertIn(f"`{suffix}`", text)
        self.assertNotIn("darwin-amd64", text)
        self.assertIn("Intel Mac, build from source", text)
        self.assertIn("All six", text)

    def test_release_notes_fit_in_a_github_release_body(self):
        # GitHub refuses a release body over 125,000 characters.
        body = R.changelog_section((ROOT / "CHANGELOG.md").read_text(), R.version(ROOT))
        self.assertLess(len(R.notes(body)), 125_000)


class ThreeZeroZeroChangelogTest(unittest.TestCase):
    """The 3.0.0 section is the whole release and reads as shipped (AGENT-214)."""

    def setUp(self):
        self.text = (ROOT / "CHANGELOG.md").read_text()
        self.section = R.changelog_section(self.text, "3.0.0")

    def test_breaking_legacy_mode_removal_leads(self):
        first = re.search(r"^### (.+)\n\n- (.+)", self.section, re.MULTILINE)
        self.assertEqual(first.group(1), "Removed")
        self.assertIn("**Breaking:** legacy mode", first.group(2))

    def test_no_unreleased_section_sits_above_3_0_0_before_the_tag(self):
        if R.version(ROOT) == "3.0.0":
            self.assertNotIn("## Unreleased", self.text)

    def test_nothing_says_3_0_0_cannot_open_its_own_databases(self):
        for path in [ROOT / "CHANGELOG.md", *sorted((ROOT / "docs").rglob("*.md"))]:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertNotRegex(path.read_text(), r"3\.0\.0 binary|3\.0\.0 cannot")

    def test_docs_name_the_three_shipped_platforms_and_no_intel_mac_download(self):
        install = (ROOT / "docs/guide/01-install.md").read_text()
        self.assertIn("platform=linux-amd64   # or linux-arm64, darwin-arm64\n", install)
        self.assertIn("no Intel Mac\n(darwin-amd64) downloads", install)
        upgrading = re.search(r"^### Upgrading\n(.*?)(?=^### |\Z)", self.section,
                              re.MULTILINE | re.DOTALL).group(1)
        self.assertIn("Linux amd64, Linux arm64 and macOS arm64", upgrading)
        self.assertIn("build from source", upgrading)
        for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("[!a]*/**/*.md"))]:
            if path.is_file():
                with self.subTest(path=path.relative_to(ROOT)):
                    text = path.read_text()
                    self.assertNotRegex(text, r"(locksmithd?|\$platform|download)[^\n]*darwin-amd64"
                                              r"|or linux-arm64, darwin-amd64")

    def test_upgrading_names_the_migrations_from_each_prior_build(self):
        upgrading = re.search(r"^### Upgrading\n(.*?)(?=^### |\Z)", self.section,
                              re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(upgrading)
        note = upgrading.group(1)
        self.assertIn("From v2.8.0 it\n  applies migrations 0009 to", note)
        self.assertIn("b0cf08c", note)
        self.assertIn("restoring the backup", note)
        if R.version(ROOT) == "3.0.0":
            newest = max(p.name[:4] for p in (ROOT / "migrations").glob("[0-9]*.sql"))
            self.assertIn(f"0009 to {newest}", note)
            self.assertIn(f"0023 to {newest}", note)


if __name__ == "__main__":
    unittest.main()
