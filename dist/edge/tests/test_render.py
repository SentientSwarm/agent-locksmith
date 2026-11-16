"""Tests for dist/edge/render.py (inactive unit, firewall and sysusers render)."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

EDGE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EDGE))

import render
import sitefile

EXAMPLE = sitefile.load(EDGE / "site.example.toml")
UNITS = "usr/local/lib/systemd/system"
SANDBOX = [
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "RestrictSUIDSGID=yes",
    "RestrictRealtime=yes",
    "RestrictNamespaces=yes",
    "LockPersonality=yes",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "SystemCallArchitectures=native",
    "UMask=0077",
]

ESCAPES = """
[site]
state_root = "/srv/edge"

[[instance]]
name = "site-a"

[[instance.component]]
name = "app"
user = "app"
command = "/usr/bin/app --home %h --price $5"
env = { NOTE = 'say "hi" \\ bye', SPACE = "a b" }
ingress = [{ port = 8080, from = ["10.0.0.0/24", "2001:db8::/32"] }]

[[instance.component]]
name = "quiet"
user = "quiet"
command = "/usr/bin/quiet"
"""


class RenderTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="render-test-")
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def out(self, instance, site=EXAMPLE):
        path = self.root / instance
        render.render(site, instance, path)
        return path

    def unit(self, out, component):
        return (out / UNITS / f"locksmith-edge-{component}.service").read_text()

    def test_sandbox_lines_present(self):
        text = self.unit(self.out("lab-locksmith"), "locksmith")
        lines = text.splitlines()
        for line in SANDBOX:
            self.assertIn(line, lines)
        self.assertIn("MemoryDenyWriteExecute=yes", lines)
        self.assertIn("User=locksmith", lines)
        self.assertIn(
            "ConditionPathExists=/srv/locksmith-edge/custody/locksmith.ready", lines
        )
        self.assertIn(
            "ReadWritePaths=/srv/locksmith-edge/locksmith /run/locksmith-edge/locksmith", lines
        )

    def test_jit_relaxes_only_memory_deny(self):
        lines = self.unit(self.out("lab-locksmith"), "inspector").splitlines()
        self.assertIn("MemoryDenyWriteExecute=no", lines)
        self.assertIn("NoNewPrivileges=yes", lines)

    def test_guard_runs_in_its_own_unit_without_the_environment_file(self):
        out = self.out("lab-locksmith")
        guard = (
            (out / UNITS / "locksmith-edge-locksmith-guard.service")
            .read_text()
            .splitlines()
        )
        self.assertIn("Type=oneshot", guard)
        self.assertIn(
            "ExecStart=/usr/bin/python3 -I /usr/local/sbin/locksmith-edge-state-check "
            "lab-locksmith locksmith",
            guard,
        )
        for line in guard:
            self.assertFalse(
                line.startswith(("Environment", "User=", "ExecStartPre")), line
            )
        self.assertNotIn("[Install]", guard)

    def test_component_requires_and_follows_its_guard(self):
        lines = self.unit(self.out("lab-locksmith"), "locksmith").splitlines()
        self.assertIn(
            "Requires=locksmith-edge-input.service locksmith-edge-locksmith-guard.service",
            lines,
        )
        self.assertIn(
            "After=network-online.target locksmith-edge-input.service "
            "locksmith-edge-locksmith-guard.service",
            lines,
        )
        self.assertFalse([l for l in lines if l.startswith("ExecStartPre")])

    def test_no_unit_wide_environment(self):
        for instance in ("lab-locksmith", "lab-pipelock"):
            out = self.out(instance)
            for unit in (out / UNITS).glob("*.service"):
                for line in unit.read_text().splitlines():
                    self.assertFalse(
                        line.startswith("Environment="), f"{unit.name}: {line}"
                    )

    def test_home_and_env_only_on_execstart(self):
        text = self.unit(self.out("lab-locksmith"), "inspector")
        exec_line = next(l for l in text.splitlines() if l.startswith("ExecStart="))
        self.assertIn('"HOME=/srv/locksmith-edge/inspector/home"', exec_line)
        self.assertIn('"HF_HUB_OFFLINE=1"', exec_line)
        self.assertTrue(exec_line.startswith("ExecStart=/usr/bin/env "))

    def test_environment_file_only_when_declared(self):
        locksmith = self.unit(self.out("lab-locksmith"), "locksmith")
        self.assertIn(
            "EnvironmentFile=/srv/locksmith-edge/environment/locksmith.env",
            locksmith.splitlines(),
        )
        pipelock = self.unit(self.out("lab-pipelock"), "pipelock")
        self.assertNotIn("EnvironmentFile=", pipelock)

    def test_specifiers_and_dollars_escaped(self):
        site = sitefile.parse(ESCAPES)
        text = self.unit(self.out("site-a", site), "app")
        exec_line = next(l for l in text.splitlines() if l.startswith("ExecStart="))
        self.assertIn("--home %%h --price $$5", exec_line)
        self.assertIn(r'"NOTE=say \"hi\" \\ bye"', exec_line)
        self.assertIn('"SPACE=a b"', exec_line)

    def test_refuses_existing_output(self):
        existing = self.root / "live"
        existing.mkdir()
        with self.assertRaises(FileExistsError):
            render.render(EXAMPLE, "lab-locksmith", existing)
        self.assertEqual(list(existing.iterdir()), [])

    def test_unit_name_collision_refused_even_if_validation_is_bypassed(self):
        comp = sitefile.Component(name="input", user="app", command="/bin/true")
        site = sitefile.Site(
            state_root="/srv/edge",
            instances=[sitefile.Instance(name="site-a", components=[comp])],
        )
        with self.assertRaises(ValueError):
            render.render(site, "site-a", self.root / "collide")

    def test_runtime_directory_is_namespaced(self):
        lines = self.unit(self.out("lab-locksmith"), "locksmith").splitlines()
        self.assertIn("RuntimeDirectory=locksmith-edge/locksmith", lines)
        self.assertIn(
            "ReadWritePaths=/srv/locksmith-edge/locksmith /run/locksmith-edge/locksmith",
            lines,
        )
        comp = sitefile.Component(name="systemd", user="app", command="/bin/true")
        site = sitefile.Site(
            state_root="/srv/edge",
            instances=[sitefile.Instance(name="site-a", components=[comp])],
        )
        text = self.unit(self.out("site-a", site), "systemd")
        self.assertNotIn("RuntimeDirectory=systemd\n", text)
        self.assertNotIn(" /run/systemd", text)

    def test_unknown_instance(self):
        with self.assertRaises(KeyError):
            render.render(EXAMPLE, "nope", self.root / "nope")
        self.assertFalse((self.root / "nope").exists())

    def test_no_activation_artifacts(self):
        out = self.out("lab-locksmith")
        names = [p.name for p in out.rglob("*")]
        self.assertFalse([n for n in names if n.endswith(".wants")])
        self.assertFalse([n for n in names if n.endswith(".ready")])
        self.assertFalse((out / "srv").exists())

    def test_guard_copied_executable(self):
        guard = self.out("lab-locksmith") / "usr/local/sbin/locksmith-edge-state-check"
        self.assertEqual(guard.read_bytes(), (EDGE / "state_check.py").read_bytes())
        self.assertEqual(guard.stat().st_mode & 0o777, 0o755)

    def test_modes_ignore_operator_umask(self):
        old = os.umask(0o002)
        try:
            out = self.out("lab-locksmith")
        finally:
            os.umask(old)
        for path in [out, *out.rglob("*")]:
            mode = path.stat().st_mode & 0o777
            expected = (
                0o755
                if path.is_dir() or path.name == "locksmith-edge-state-check"
                else 0o644
            )
            self.assertEqual(mode, expected, path)

    def test_nft_accepts_only_declared_sources(self):
        nft = (self.out("lab-locksmith") / "etc/locksmith-edge/input.nft").read_text()
        accepts = [l.strip() for l in nft.splitlines() if "saddr" in l]
        self.assertEqual(
            accepts, ["ip saddr { 198.51.100.0/24 } tcp dport 9200 accept;"]
        )
        self.assertIn("tcp dport { 9200 } reject;", nft)
        self.assertIn("table inet locksmith_edge_input {", nft)
        self.assertIn("delete table inet locksmith_edge_input", nft)

    def test_nft_splits_ipv4_and_ipv6(self):
        site = sitefile.parse(ESCAPES)
        nft = (self.out("site-a", site) / "etc/locksmith-edge/input.nft").read_text()
        self.assertIn("ip saddr { 10.0.0.0/24 } tcp dport 8080 accept;", nft)
        self.assertIn("ip6 saddr { 2001:db8::/32 } tcp dport 8080 accept;", nft)

    def test_nft_without_ingress_rejects_nothing(self):
        site = sitefile.parse(
            ESCAPES.replace(
                'ingress = [{ port = 8080, from = ["10.0.0.0/24", "2001:db8::/32"] }]\n',
                "",
            )
        )
        nft = (self.out("site-a", site) / "etc/locksmith-edge/input.nft").read_text()
        self.assertNotIn("reject", nft)
        self.assertNotIn("saddr", nft)

    def test_input_service_loads_table(self):
        out = self.out("lab-locksmith")
        text = (out / UNITS / "locksmith-edge-input.service").read_text()
        self.assertIn("ExecStart=/usr/sbin/nft -f /etc/locksmith-edge/input.nft", text)
        unit = self.unit(out, "locksmith")
        self.assertIn("Requires=locksmith-edge-input.service", unit)

    def test_sysusers_and_components(self):
        site = sitefile.parse(ESCAPES)
        out = self.out("site-a", site)
        users = (out / "etc/sysusers.d/locksmith-edge.conf").read_text().splitlines()
        self.assertEqual(
            users,
            [
                'u app - "Locksmith edge app" /srv/edge/app/home /usr/sbin/nologin',
                'u quiet - "Locksmith edge quiet" /srv/edge/quiet/home /usr/sbin/nologin',
            ],
        )
        data = json.loads((out / "etc/locksmith-edge/components.json").read_text())
        self.assertEqual(
            data,
            {
                "instance": "site-a",
                "state_root": "/srv/edge",
                "require_zfs": True,
                "components": {"app": {"user": "app"}, "quiet": {"user": "quiet"}},
            },
        )
        self.assertEqual((out / "etc/locksmith-edge/instance").read_text(), "site-a\n")


if __name__ == "__main__":
    unittest.main()
