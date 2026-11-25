"""scripts/release-local.py asset-naming, checksum and rerun contract (offline, no builds)."""

import hashlib
import importlib.util
import json
import platform
import socket
import subprocess
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
        self.assertEqual(L.BINARIES, sorted(f"{role}-{s}" for role in ("locksmith", "locksmithd")
                                            for s in ("linux-amd64", "linux-arm64", "darwin-arm64")))
        self.assertLessEqual({t.triple for t in L.TARGETS}, set(L.C.TARGETS))
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
                                 "darwin-arm64": "native"})

    def test_darwin_amd64_is_not_built(self):
        # 3.0.0 ships no Intel Mac programs: nothing can smoke-test them.
        self.assertNotIn("x86_64-apple-darwin", {t.triple for t in L.TARGETS})
        self.assertFalse([n for n in L.BINARIES if "darwin-amd64" in n])

    def test_complete_run_writes_assets_release_notes_accepts(self):
        self.assertEqual(self.run_release(FakeProducer(self.out)), {})
        assets = self.out / "assets"
        self.assertEqual({p.name for p in assets.iterdir()}, R.EXPECTED)
        lines = (assets / "SHA256SUMS").read_text().splitlines()
        self.assertEqual([line.split("  ")[1] for line in lines], L.BINARIES)  # sorted, exactly six
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
        failures = self.run_release(FakeProducer(self.out, fail={"darwin-arm64"}))
        self.assertEqual(list(failures), ["darwin-arm64"])
        self.assertFalse((self.out / "assets").exists())
        self.assertFalse(list(self.out.rglob("SHA256SUMS")))

    def test_a_pair_that_does_not_refuse_a_wrong_revision_fails(self):
        failures = self.run_release(FakeProducer(self.out, refuse={"linux-arm64"}))
        self.assertEqual(list(failures), ["linux-arm64"])
        self.assertFalse((self.out / "assets").exists())

    def test_rerun_reuses_verified_targets_and_rebuilds_only_the_failed_one(self):
        first = FakeProducer(self.out, fail={"darwin-arm64"})
        self.run_release(first)
        self.assertEqual(len(first.built), 3)
        second = FakeProducer(self.out)
        self.assertEqual(self.run_release(second), {})
        self.assertEqual(second.built, ["darwin-arm64"])
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
        self.assertEqual(len(other.built), 3)


    def test_capture_script_quotes_every_path(self):
        # Output-derived paths reach a shell; a space or $ in them must not split or expand.
        work = self.out / "odd dir $HOME;x"
        target = next(t for t in L.TARGETS if t.suffix == "linux-amd64")
        built = work / "t" / target.triple / "release"
        built.mkdir(parents=True)
        for role in L.ROLES:
            (built / role).write_text(role)
        pair = f"{work}/pair-{target.suffix}"
        subprocess.run(["bash", "-c", L.capture_script(f"{work}/t", target, pair)], check=True)
        self.assertEqual(sorted(p.name for p in Path(pair).iterdir()), sorted(target.names()))
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["odd dir $HOME;x"])

    def test_host_labels_name_the_platform_not_the_host(self):
        # validation.json is a published asset: no host names in it.
        local = L.Local(self.out / "local")
        self.assertEqual(local.label(), f"{platform.system()} {platform.machine()}")
        self.assertNotIn(socket.gethostname().split(".")[0], local.label())
        remote = L.Remote("builder@private-mac.internal", [])
        remote.sh = lambda command, **kw: "Darwin arm64\n" if command == "uname -sm" else ""
        self.assertEqual(remote.label(), "Darwin arm64")

    def test_remote_rejects_a_destination_ssh_would_read_as_an_option(self):
        for dest in ("-oProxyCommand=touch pwned", "host", "user@-oX", "user@host cmd"):
            with self.assertRaises(ValueError, msg=dest):
                L.Remote(dest, [])
        with self.assertRaises(SystemExit):
            L.driver_main(["--commit", "HEAD", "--out", str(self.out), "--mac", "-oProxyCommand=touch pwned"])

    def test_remote_work_dir_comes_from_mktemp(self):
        remote, sent = L.Remote("builder@mac", []), []

        def sh(command, **kw):
            sent.append(command)
            return "/tmp/release-local.Ab12Cd34\n"
        remote.sh = sh
        self.assertEqual(remote.make_work(), "/tmp/release-local.Ab12Cd34")
        self.assertEqual(len(sent), 1)
        self.assertIn("mktemp -d", sent[0])
        remote.cleanup()
        self.assertEqual(sent[-1], "rm -rf /tmp/release-local.Ab12Cd34")

    def test_a_notes_failure_leaves_nothing_publishable(self):
        def notes():
            (self.out / "notes.md").write_text("partial")
            raise L.Failed("release notes exited 1")
        failures = L.produce(self.out, REV, SOURCE, FakeProducer(self.out), notes, log=self.logs.append)
        self.assertEqual(list(failures), ["release notes"])
        self.assertFalse((self.out / "assets").exists())
        self.assertFalse((self.out / "notes.md").exists())
        self.assertFalse(list(self.out.rglob("SHA256SUMS")))
        self.assertEqual(L.produce(self.out, REV, SOURCE, FakeProducer(self.out), lambda: None,
                                   log=self.logs.append), {})
        self.assertTrue((self.out / "assets" / "SHA256SUMS").exists())

    @unittest.skipUnless((platform.system(), platform.machine()) == ("Linux", "x86_64"), "driver runs on x86_64 Linux")
    def test_a_failed_setup_removes_an_earlier_runs_assets(self):
        (self.out / "assets").mkdir()
        (self.out / "assets" / "SHA256SUMS").write_text("from an earlier commit\n")
        (self.out / "notes.md").write_text("earlier notes")
        code = L.driver_main(["--commit", "no-such-revision", "--out", str(self.out), "--mac", "builder@mac"])
        self.assertEqual(code, 1)
        self.assertFalse((self.out / "assets").exists())
        self.assertFalse((self.out / "notes.md").exists())


if __name__ == "__main__":
    unittest.main()
