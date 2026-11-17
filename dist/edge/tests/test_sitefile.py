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
        self.assertEqual(names, ["lab-locksmith", "lab-broker"])
        inspector = site.instances[0].components[1]
        self.assertTrue(inspector.jit)
        # The example broker runs Node, which needs JIT memory to start.
        broker = site.instances[1].components[0]
        self.assertTrue(broker.jit)
        self.assertEqual(inspector.env["HF_HUB_OFFLINE"], "1")
        locksmith = site.instances[0].components[0]
        self.assertTrue(locksmith.environment_file)
        self.assertEqual(locksmith.ingress[0].port, 9200)
        self.assertEqual(locksmith.ingress[0].sources, ["198.51.100.0/24"])

    def test_example_inspector_shares_locksmiths_container_and_user(self):
        site = sitefile.load(EXAMPLE)
        locksmith, inspector = site.instances[0].components
        self.assertEqual(inspector.name, "inspector")
        self.assertEqual(inspector.user, locksmith.user)
        # The reference sidecar requires --socket; it must be under the
        # inspector's own runtime directory, the only writable /run path.
        reference = (EDGE.parent / "inspector/locksmith_inspector.py").read_text()
        self.assertIn('"--socket", required=True', reference)
        self.assertIn("--socket /run/locksmith-edge/inspector/", inspector.command)

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

    def test_closed_ports(self):
        comp = sitefile.parse(with_component_line("closed = [9201, 9300]")).instances[0].components[0]
        self.assertEqual(comp.closed, [9201, 9300])

    def test_closed_defaults_empty(self):
        self.assertEqual(sitefile.parse(MINIMAL).instances[0].components[0].closed, [])

    def test_closed_bad_port(self):
        for bad in ("[0]", "[70000]", "[true]", '["9201"]', "9201"):
            self.assertRefused(with_component_line(f"closed = {bad}"), "closed")

    def test_closed_duplicate(self):
        self.assertRefused(with_component_line("closed = [9201, 9201]"), "closed")

    def test_closed_port_also_ingress(self):
        self.assertRefused(
            with_component_line(
                'ingress = [{ port = 9201, from = ["10.0.0.0/24"] }]\nclosed = [9201]'
            ),
            "both",
        )

    def test_closed_port_ingress_in_sibling_component(self):
        self.assertRefused(
            with_component_line("closed = [9201]")
            + """
[[instance.component]]
name = "staging"
user = "staging"
command = "/usr/local/bin/locksmithd --config /srv/edge/staging/config.yaml"
ingress = [{ port = 9201, from = ["10.0.0.0/24"] }]
""",
            "both",
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

    def test_address_scope_id_refused(self):
        for bad in ("fe80::1%a;id;#", "fe80::1%$(id)", "fe80::1%eth0"):
            text = MINIMAL.replace(
                'name = "site-a"', f'name = "site-a"\naddress = "{bad}"'
            )
            self.assertRefused(text, "address")

    def test_cidr_scope_id_refused(self):
        for bad in (
            "fe80::%x/64",
            "fe80::%x } tcp dport 22 accept ; ip6 saddr { ::/64",
        ):
            self.assertRefused(
                with_component_line(f'ingress = [{{ port = 9200, from = ["{bad}"] }}]'),
                "CIDR",
            )

    def test_reserved_component_names_refused(self):
        for bad in ("input", "app-guard"):
            self.assertRefused(
                MINIMAL.replace('name = "locksmith"', f'name = "{bad}"'), "reserved"
            )

    def test_trailing_backslash_in_command_refused(self):
        text = MINIMAL.replace('config.yaml"', 'config.yaml \\\\"')
        self.assertIn('\\\\"', text)
        self.assertRefused(text, "command")

    def test_existing_system_users_refused(self):
        for bad in (
            "daemon",
            "bin",
            "www-data",
            "messagebus",
            "systemd-network",
            "sshd",
        ):
            self.assertRefused(
                MINIMAL.replace('user = "locksmith"', f'user = "{bad}"'), "user"
            )

    def test_trailing_newline_does_not_pass_a_pattern(self):
        cases = [
            ('user = "locksmith"', 'user = "root\\n"', "user"),
            ('name = "locksmith"', 'name = "lock\\n"', "name"),
            ('name = "site-a"', 'name = "site-a\\n"', "name"),
        ]
        for old, new, fragment in cases:
            self.assertRefused(MINIMAL.replace(old, new), fragment)
        self.assertRefused(with_component_line('env = { "A\\n" = "x" }'), "env")
        text = MINIMAL.replace('name = "site-a"', 'name = "site-a"\nmemory = "2GiB\\n"')
        self.assertRefused(text, "memory")

    def test_state_subdirectory_names_reserved(self):
        for bad in ("custody", "environment", "models"):
            self.assertRefused(
                MINIMAL.replace('name = "locksmith"', f'name = "{bad}"'), "reserved"
            )

    def test_state_root_hidden_by_the_sandbox_refused(self):
        for bad in (
            "/home/edge",
            "/root/edge",
            "/tmp/edge",
            "/var/tmp/edge",
            "/run/edge",
            "/proc/x",
            "//srv/edge",
        ):
            self.assertRefused(MINIMAL.replace('"/srv/edge"', f'"{bad}"'), "state_root")

    def test_lone_semicolon_in_command_refused(self):
        text = MINIMAL.replace('config.yaml"', 'config.yaml ; /bin/sh"')
        self.assertRefused(text, "command")

    def test_invalid_toml(self):
        self.assertRefused("[site\n", "TOML")


if __name__ == "__main__":
    unittest.main()
