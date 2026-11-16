import importlib.util
from pathlib import Path
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"{name}.py")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class BundleTest(unittest.TestCase):
    def test_inactive_render_has_no_custody_or_enabled_units(self):
        render = module("render")
        with tempfile.TemporaryDirectory(prefix="edge-render-test-") as root:
            for instance in render.IP:
                output = Path(root) / instance
                render.render(output, instance)
                self.assertFalse((output / "srv").exists())
                self.assertEqual([], list(output.rglob("*.wants")))
                self.assertEqual([], list(output.rglob("*.ready")))
                for component in render.SERVICES[instance]:
                    unit = (output / f"usr/local/lib/systemd/system/edge-{component}.service").read_text()
                    self.assertIn(f"ConditionPathExists=/srv/edge-state/custody/{component}.ready", unit)
                    self.assertIn(f"edge-state-check {instance} {component}", unit)
                    self.assertIn("NoNewPrivileges=yes", unit)
                    self.assertIn("ProtectSystem=strict", unit)
                    if render.SERVICES[instance][component][2]:
                        self.assertIn(f"EnvironmentFile=/srv/edge-state/environment/{component}.env", unit)
                        self.assertNotIn(f"EnvironmentFile=/srv/edge-state/{component}/", unit)

    def test_relays_support_early_boot_and_firewall_is_not_after_basic(self):
        with tempfile.TemporaryDirectory(prefix="edge-render-test-") as root:
            output = Path(root) / "broker"
            module("render").render(output, "edge-brokers")
            units = output / "usr/local/lib/systemd/system"
            firewall = (units / "edge-input.service").read_text()
            self.assertIn("DefaultDependencies=no", firewall)
            self.assertIn("After=local-fs.target", firewall)
            for name in ["codex", "teamclaude"]:
                self.assertIn("FreeBind=yes", (units / f"edge-{name}-relay.socket").read_text())
            self.assertFalse((output / "etc/systemd/system").exists())

    def test_destination_paths_override_service_environment_files(self):
        import os
        import shlex
        import subprocess
        import json
        render = module("render")
        for component, variable, expected in [
            ("codex", "CODEX_HOME", "/srv/edge-state/codex/home/.codex-terminal-pool"),
            ("teamclaude", "TEAMROUTER_CONFIG", "/srv/edge-state/teamclaude/teamclaude.json"),
        ]:
            user, command, has_env = render.SERVICES["edge-brokers"][component]
            text = render.service("edge-brokers", component, user, command, has_env)
            start = next(line.removeprefix("ExecStart=") for line in text.splitlines() if line.startswith("ExecStart="))
            argv = shlex.split(start)
            # Run only env's final assignments, with a harmless Python getter
            # in place of the real broker. No production process is started.
            assignments = []
            for arg in argv[1:]:
                if "=" not in arg:
                    break
                assignments.append(arg)
            result = subprocess.check_output(
                [argv[0], *assignments, __import__('sys').executable, "-c",
                 f"import os,json; print(json.dumps(os.environ[{variable!r}]))"],
                env={**os.environ, variable: "/old/studio/path"}, text=True,
                timeout=5,
            )
            self.assertEqual(expected, json.loads(result))

    def test_render_refuses_existing_tree(self):
        with tempfile.TemporaryDirectory(prefix="edge-render-test-") as root:
            with self.assertRaises(FileExistsError):
                module("render").render(Path(root), "edge-brokers")

    def test_broker_firewall_excludes_herd_from_scanner(self):
        text = module("render").firewall("edge-brokers")
        allow_herd = next(line for line in text.splitlines() if "10.250.1.0/24" in line)
        self.assertNotIn("9100", allow_herd)
        self.assertIn("10.250.4.10 tcp dport { 43210, 3456, 9100 } accept", text)
        self.assertIn("tcp dport { 43210, 3456, 17321, 9100 } reject", text)

    def test_5a_host_compatibility_ingress_is_broker_only(self):
        text = module("render").firewall("edge-brokers", studio_compat=True)
        rule = next(line for line in text.splitlines() if "10.250.4.1 " in line)
        self.assertIn("tcp dport { 43210, 3456 } accept", rule)
        self.assertNotIn("17321", rule)
        self.assertNotIn("9100", rule)
        self.assertNotIn("10.250.4.1 ", module("render").firewall("edge-brokers"))

    def test_compatibility_job_is_transport_only_and_loopback_bound(self):
        compat = module("compat_launchd")
        for name, port in [("codex", 43210), ("teamclaude", 3456)]:
            job = compat.definition(name)
            args = job["ProgramArguments"]
            self.assertEqual("/usr/bin/ssh", args[0])
            self.assertIn(f"127.0.0.1:{port}:10.250.4.12:{port}", args)
            self.assertIn("ExitOnForwardFailure=yes", args)
            self.assertIn("BatchMode=yes", args)
            self.assertNotIn("EnvironmentVariables", job)
            self.assertNotIn("CODEX_HOME", str(job))


class ProcessGateTest(unittest.TestCase):
    def test_native_agent_counts_as_refresher(self):
        self.assertIsNotNone(module("drain_check").classify("/opt/homebrew/bin/codex resume abc", "codex"))

    def test_live_multi_auth_helper_counts_as_refresher(self):
        self.assertIsNotNone(module("drain_check").classify(
            "/opt/homebrew/opt/node@24/bin/node /opt/homebrew/lib/node_modules/codex-multi-auth/scripts/codex.js", "codex"))

    def test_claude_node_entry_counts_as_client(self):
        self.assertIsNotNone(module("drain_check").classify(
            "/usr/bin/node /opt/node_modules/@anthropic-ai/claude-code/cli.js", "teamclaude"))

    def test_gate_does_not_match_quoted_shell_or_its_own_script(self):
        gate = module("drain_check")
        self.assertIsNone(gate.classify("/bin/zsh -c 'pgrep codex'", "codex"))
        self.assertIsNone(gate.classify("python3 /repo/dist/evo-edge/drain_check.py codex", "codex"))

    def test_teamclaude_broker_is_detected(self):
        self.assertIsNotNone(module("drain_check").classify(
            "/usr/bin/node /Users/jxstanford/.bun/bin/teamclaude server --headless", "teamclaude"))


if __name__ == "__main__":
    unittest.main()
