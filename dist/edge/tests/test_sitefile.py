"""Tests for dist/edge/sitefile.py (site schema and validation)."""

import sys
import unittest
from pathlib import Path

EDGE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EDGE))

import sitefile

EXAMPLE = EDGE / "site.example.toml"

MINIMAL = """
[site]
state_root = "/srv/edge"

[[instance]]
name = "site-a"

[[instance.component]]
name = "locksmith"
user = "locksmith"
command = "/usr/local/bin/locksmithd --config /srv/edge/locksmith/config.yaml"
"""


def with_component_line(line: str) -> str:
    return MINIMAL + line + "\n"


class ExampleTest(unittest.TestCase):
    def test_example_validates(self):
        site = sitefile.load(EXAMPLE)
        self.assertEqual(site.state_root, "/srv/locksmith-edge")
        self.assertTrue(site.require_zfs)
        names = [i.name for i in site.instances]
        self.assertEqual(names, ["edge-locksmith", "edge-pipelock", "edge-inspector"])
        inspector = site.instances[2].components[0]
        self.assertTrue(inspector.jit)
        self.assertEqual(inspector.env["HF_HUB_OFFLINE"], "1")
        locksmith = site.instances[0].components[0]
        self.assertTrue(locksmith.environment_file)
        self.assertEqual(locksmith.ingress[0].port, 9200)
        self.assertEqual(locksmith.ingress[0].sources, ["10.0.1.0/24"])

    def test_minimal_defaults(self):
        site = sitefile.parse(MINIMAL)
        comp = site.instances[0].components[0]
        self.assertTrue(site.require_zfs)
        self.assertFalse(comp.environment_file)
        self.assertFalse(comp.jit)
        self.assertEqual(comp.env, {})
        self.assertEqual(comp.ingress, [])
        self.assertIsNone(site.instances[0].address)


class RefusalTest(unittest.TestCase):
    def assertRefused(self, text: str, fragment: str):
        with self.assertRaises(sitefile.SiteError) as ctx:
            sitefile.parse(text)
        self.assertIn(fragment, str(ctx.exception))

    def test_unknown_top_level_key(self):
        self.assertRefused(MINIMAL + "\n[extra]\nx = 1\n", "unknown key")

    def test_unknown_site_key(self):
        text = MINIMAL.replace(
            'state_root = "/srv/edge"', 'state_root = "/srv/edge"\nroot = "/x"'
        )
        self.assertRefused(text, "unknown key")

    def test_unknown_component_key(self):
        self.assertRefused(with_component_line("restart = 'always'"), "unknown key")

    def test_duplicate_component_name(self):
        dup = (
            MINIMAL
            + """
[[instance]]
name = "site-b"

[[instance.component]]
name = "locksmith"
user = "locksmith"
command = "/usr/local/bin/locksmithd"
"""
        )
        self.assertRefused(dup, "duplicate component")

    def test_duplicate_instance_name(self):
        dup = (
            MINIMAL
            + """
[[instance]]
name = "site-a"

[[instance.component]]
name = "other"
user = "other"
command = "/usr/bin/true"
"""
        )
        self.assertRefused(dup, "duplicate instance")

    def test_relative_state_root(self):
        self.assertRefused(MINIMAL.replace('"/srv/edge"', '"srv/edge"'), "state_root")

    def test_dotdot_state_root(self):
        self.assertRefused(
            MINIMAL.replace('"/srv/edge"', '"/srv/../etc"'), "state_root"
        )

    def test_state_root_shell_characters(self):
        for bad in ("/srv/edge state", "/srv/$(id)", "/srv/edge;x"):
            self.assertRefused(MINIMAL.replace('"/srv/edge"', f'"{bad}"'), "state_root")

    def test_bad_cidr(self):
        self.assertRefused(
            with_component_line('ingress = [{ port = 9200, from = ["10.0.0.0/33"] }]'),
            "CIDR",
        )

    def test_host_bits_cidr(self):
        self.assertRefused(
            with_component_line('ingress = [{ port = 9200, from = ["10.0.0.1/24"] }]'),
            "CIDR",
        )

    def test_empty_sources(self):
        self.assertRefused(
            with_component_line("ingress = [{ port = 9200, from = [] }]"), "from"
        )

    def test_bad_port(self):
        self.assertRefused(
            with_component_line('ingress = [{ port = 70000, from = ["10.0.0.0/24"] }]'),
            "port",
        )

    def test_bool_port(self):
        self.assertRefused(
            with_component_line('ingress = [{ port = true, from = ["10.0.0.0/24"] }]'),
            "port",
        )

    def test_name_with_slash(self):
        self.assertRefused(
            MINIMAL.replace('name = "locksmith"', 'name = "lock/smith"'), "name"
        )

    def test_instance_name_with_slash(self):
        self.assertRefused(
            MINIMAL.replace('name = "site-a"', 'name = "../site-a"'), "name"
        )

    def test_newline_in_command(self):
        text = MINIMAL.replace(
            'command = "/usr/local/bin/locksmithd --config /srv/edge/locksmith/config.yaml"',
            'command = "/usr/bin/true\\nExecStartPost=/bin/sh"',
        )
        self.assertRefused(text, "control character")

    def test_newline_in_env_value(self):
        self.assertRefused(
            with_component_line('env = { A = "x\\nUser=root" }'), "control character"
        )

    def test_bad_env_name(self):
        self.assertRefused(with_component_line('env = { "a b" = "x" }'), "env")

    def test_relative_command(self):
        text = MINIMAL.replace("/usr/local/bin/locksmithd", "locksmithd")
        self.assertRefused(text, "command")

    def test_bad_user(self):
        self.assertRefused(
            MINIMAL.replace('user = "locksmith"', 'user = "root"'), "user"
        )

    def test_bad_address(self):
        text = MINIMAL.replace(
            'name = "site-a"', 'name = "site-a"\naddress = "10.0.0.300"'
        )
        self.assertRefused(text, "address")

    def test_non_bool_jit(self):
        self.assertRefused(with_component_line('jit = "yes"'), "jit")

    def test_no_components(self):
        text = '[site]\nstate_root = "/srv/edge"\n\n[[instance]]\nname = "site-a"\n'
        self.assertRefused(text, "component")

    def test_invalid_toml(self):
        self.assertRefused("[site\n", "TOML")


if __name__ == "__main__":
    unittest.main()
