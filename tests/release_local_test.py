"""scripts/release-local.py asset-naming, checksum and rerun contract (offline, no builds)."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


L = module("release_local", "scripts/release-local.py")
R = module("release_notes", "scripts/release-notes.py")
REV = "c" * 40
SOURCE = {"version": "3.0.0", "revision": REV, "tree": "d" * 40, "lock_sha256": "e" * 64}


class FakeProducer:
    """Writes stand-in binaries the way a real build captures them."""

    def __init__(self, out, fail=(), refuse=()):
        self.out, self.fail, self.refuse = Path(out), set(fail), set(refuse)
        self.built, self.verified = [], []

    def build_and_smoke(self, target):
        self.built.append(target.suffix)
        if target.suffix in self.fail:
            raise L.Failed(f"{target.suffix} build exited 101")
        local = self.out / "targets" / target.suffix
        local.mkdir(parents=True, exist_ok=True)
        for name in target.names():
            (local / name).write_bytes(f"{name} {REV}".encode())
        return {"state": "smoked", "target": target.triple, "suffix": target.suffix, "revision": REV,
                "version": "3.0.0", "files": {n: L.sha256(local / n) for n in target.names()},
                "build": {"host": "h", "rustc": "rustc 1.94.0", "builder": "cargo build", "command": "c",
                          "seconds": 1},
                "smoke": {"method": target.smoke, "host": "h", "wrapper": None, "result": {"checks": {}}}}

    def verify(self, target, sums):
        self.verified.append(target.suffix)
        entries = dict(reversed(line.split("  ")) for line in Path(sums).read_text().splitlines())
        ok = all(entries[n] == L.sha256(self.out / "targets" / target.suffix / n) for n in target.names())
        return {"accepted": ok, "wrong_revision_refused": target.suffix not in self.refuse}


class ReleaseLocal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.logs = []

    def tearDown(self):
        self.tmp.cleanup()

    def run_release(self, producer):
        return L.release(self.out, REV, SOURCE, producer, log=self.logs.append)

    def test_asset_names_are_release_yml_names(self):
        self.assertEqual(L.BINARIES, R.BINARIES)
        self.assertEqual({t.triple for t in L.TARGETS}, set(L.C.TARGETS))
        workflow = yaml.load((ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader)
        create = next(s["run"] for s in workflow["jobs"]["publish"]["steps"] if "gh release create" in s.get("run", ""))
        for pattern in ("locksmith-*", "locksmithd-*", "SHA256SUMS", "validation.json"):
            self.assertIn(pattern, create)

    def test_builds_with_the_tested_recipe(self):
        for target in L.TARGETS:
            args = L.cargo_args(target)
            self.assertEqual(args[:2], ["+1.94.0", target.builder])
            self.assertIn("--locked", args)
            self.assertIn("--release", args)
            self.assertEqual(args[args.index("--target") + 1], target.triple)
        smoke = {t.suffix: t.smoke for t in L.TARGETS}
        self.assertEqual(smoke, {"linux-amd64": "native", "linux-arm64": "qemu-user",
                                 "darwin-arm64": "native", "darwin-amd64": "rosetta"})

    def test_complete_run_writes_assets_release_notes_accepts(self):
        self.assertEqual(self.run_release(FakeProducer(self.out)), {})
        assets = self.out / "assets"
        self.assertEqual({p.name for p in assets.iterdir()}, R.EXPECTED)
        lines = (assets / "SHA256SUMS").read_text().splitlines()
        self.assertEqual([line.split("  ")[1] for line in lines], L.BINARIES)  # sorted, exactly eight
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((assets / name).read_bytes()).hexdigest(), digest)
        R.check_assets(assets, "3.0.0", REV)  # what the publish step checks
        validation = json.loads((assets / "validation.json").read_text())
        self.assertEqual(validation["source"], SOURCE)
        self.assertEqual(set(validation["assets"]), set(L.BINARIES))
        for name, entry in validation["assets"].items():
            self.assertEqual(entry["revision"], REV)
            self.assertTrue({"target", "sha256", "build_host", "rustc", "smoke", "verify"} <= set(entry), name)
        self.assertEqual(validation["assets"]["locksmith-linux-arm64"]["smoke"]["method"], "qemu-user")

    def test_a_failed_target_is_named_and_leaves_no_checksums(self):
        (self.out / "assets").mkdir()
        (self.out / "assets" / "SHA256SUMS").write_text("stale\n")  # from an earlier run
        failures = self.run_release(FakeProducer(self.out, fail={"darwin-amd64"}))
        self.assertEqual(list(failures), ["darwin-amd64"])
        self.assertFalse((self.out / "assets").exists())
        self.assertFalse(list(self.out.rglob("SHA256SUMS")))

    def test_a_pair_that_does_not_refuse_a_wrong_revision_fails(self):
        failures = self.run_release(FakeProducer(self.out, refuse={"linux-arm64"}))
        self.assertEqual(list(failures), ["linux-arm64"])
        self.assertFalse((self.out / "assets").exists())

    def test_rerun_reuses_verified_targets_and_rebuilds_only_the_failed_one(self):
        first = FakeProducer(self.out, fail={"darwin-amd64"})
        self.run_release(first)
        self.assertEqual(len(first.built), 4)
        second = FakeProducer(self.out)
        self.assertEqual(self.run_release(second), {})
        self.assertEqual(second.built, ["darwin-amd64"])
        third = FakeProducer(self.out)
        self.assertEqual(self.run_release(third), {})
        self.assertEqual((third.built, third.verified), ([], []))  # all verified: nothing redone

    def test_a_changed_binary_or_another_commit_is_rebuilt(self):
        self.run_release(FakeProducer(self.out))
        (self.out / "targets" / "linux-amd64" / "locksmith-linux-amd64").write_bytes(b"tampered")
        again = FakeProducer(self.out)
        self.assertEqual(self.run_release(again), {})
        self.assertEqual(again.built, ["linux-amd64"])
        other = FakeProducer(self.out)
        self.assertEqual(L.release(self.out, "f" * 40, SOURCE, other, log=self.logs.append), {})
        self.assertEqual(len(other.built), 4)


if __name__ == "__main__":
    unittest.main()
