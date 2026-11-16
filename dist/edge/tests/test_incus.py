"""Tests for dist/edge/incus.py (reviewable Incus preparation commands)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

EDGE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EDGE))

import incus
import sitefile

EXAMPLE = sitefile.load(EDGE / "site.example.toml")
IMAGE = "images:ubuntu/24.04/amd64"


def script(**kwargs):
    args = {"project": "edge", "image": IMAGE, "pool": "tank"} | kwargs
    return incus.commands(EXAMPLE, **args)


class IncusTest(unittest.TestCase):
    def test_never_starts_anything(self):
        text = script()
        for line in text.splitlines():
            words = line.split()
            self.assertNotIn("start", words, line)
            self.assertNotIn("launch", words, line)
            self.assertNotIn("exec", words, line)

    def test_stopped_hardened_instances(self):
        text = script()
        inits = [l for l in text.splitlines() if " init " in l]
        self.assertEqual(len(inits), 3)
        for line in inits:
            self.assertIn("boot.autostart=false", line)
            self.assertIn("security.nesting=false", line)
            self.assertIn("security.privileged=false", line)
            self.assertNotIn("security.nesting=true", line)

    def test_per_instance_limits(self):
        text = script()
        locksmith = next(
            l for l in text.splitlines() if " init " in l and "edge-locksmith" in l
        )
        self.assertIn("limits.cpu=2", locksmith)
        self.assertIn("limits.memory=2GiB", locksmith)
        pipelock = next(
            l for l in text.splitlines() if " init " in l and "edge-pipelock" in l
        )
        self.assertIn("limits.cpu=1", pipelock)
        self.assertIn("limits.memory=1GiB", pipelock)

    def test_dedicated_state_volume_per_instance(self):
        text = script()
        for name in ("edge-locksmith", "edge-pipelock", "edge-inspector"):
            self.assertIn(
                f"incus storage volume create tank {name}-state --project edge", text
            )
            self.assertIn(
                f"incus --project edge config device add {name} state disk pool=tank "
                f"source={name}-state path=/srv/locksmith-edge",
                text,
            )

    def test_volume_size_optional(self):
        self.assertIn(
            "edge-locksmith-state --project edge size=64GiB",
            script(volume_size="64GiB"),
        )
        with self.assertRaises(incus.IncusError):
            script(volume_size="64 GiB; rm")

    def test_fixed_address(self):
        self.assertIn(
            "incus --project edge config device override edge-locksmith eth0 ipv4.address=10.0.4.10",
            script(),
        )

    def test_guards_refuse_existing(self):
        text = script()
        self.assertIn("incus --project edge info edge-locksmith >/dev/null 2>&1", text)
        self.assertIn(
            "incus storage volume show tank edge-locksmith-state --project edge", text
        )
        self.assertIn("Type: container", text)
        # Every guard runs before the first change.
        first_init = text.index(" init ")
        self.assertLess(text.rindex("already exists"), first_init)

    def test_inventory_conflict_refused(self):
        with self.assertRaises(incus.IncusError):
            script(existing={"instances": ["edge-pipelock"], "volumes": []})
        with self.assertRaises(incus.IncusError):
            script(existing={"instances": [], "volumes": ["edge-inspector-state"]})
        script(existing={"instances": ["other"], "volumes": ["other-state"]})

    def test_bad_project_or_pool_refused(self):
        with self.assertRaises(incus.IncusError):
            script(project="edge; rm -rf /")
        with self.assertRaises(incus.IncusError):
            script(pool="$(id)")
        with self.assertRaises(incus.IncusError):
            script(image="images:x y")

    def test_script_parses(self):
        with tempfile.TemporaryDirectory(prefix="incus-test-") as tmp:
            path = Path(tmp) / "prepare.sh"
            path.write_text(script())
            result = subprocess.run(
                ["bash", "-n", str(path)], check=False, capture_output=True, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_reads_inventory(self):
        with tempfile.TemporaryDirectory(prefix="incus-test-") as tmp:
            inv = Path(tmp) / "inv.json"
            inv.write_text(json.dumps({"instances": ["edge-locksmith"], "volumes": []}))
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(EDGE / "incus.py"),
                    str(EDGE / "site.example.toml"),
                    "--project",
                    "edge",
                    "--image",
                    IMAGE,
                    "--pool",
                    "tank",
                    "--existing",
                    str(inv),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("edge-locksmith", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_module_cannot_execute_commands(self):
        source = (EDGE / "incus.py").read_text()
        for word in ("subprocess", "os.system", "popen", "execv"):
            self.assertNotIn(word, source)


if __name__ == "__main__":
    unittest.main()
