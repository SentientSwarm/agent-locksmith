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
        self.assertNotIn("10.250.4.10 tcp dport", text)
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

    def test_relay_activation_graph_cannot_start_pool(self):
        with tempfile.TemporaryDirectory(prefix="edge-render-test-") as root:
            output = Path(root) / "broker"
            module("render").render(output, "edge-brokers")
            units = output / "usr/local/lib/systemd/system"
            for component in ["codex", "teamclaude"]:
                for suffix in ["relay.service", "relay.socket"]:
                    text = (units / f"edge-{component}-{suffix}").read_text()
                    dependencies = []
                    for line in text.splitlines():
                        key, _, value = line.partition("=")
                        if key in {"Requires", "Wants", "BindsTo", "Upholds"}:
                            dependencies.extend(value.split())
                    self.assertNotIn(f"edge-{component}.service", dependencies)

    def test_cpu_limit_does_not_depend_on_mutable_profile(self):
        text = (Path(__file__).parents[1] / "prepare.sh").read_text()
        self.assertIn("limits.cpu=2", text)


class ProcessGateTest(unittest.TestCase):
    def test_extensionless_node_shim_is_refresher(self):
        self.assertIsNotNone(module("drain_check").classify(
            "node /opt/homebrew/bin/codex-multi-auth auth status", "codex"))

    def test_relative_import_and_script_forms_are_refresher(self):
        for command in ["node scripts/codex.js", "node --import=./runtime-rotation/helper.mjs app.js",
                        "node --import=./codex-multi-auth/dist/boot.js app.js"]:
            self.assertIsNotNone(module("drain_check").classify(command, "codex"))

    def test_component_and_compiler_paths_are_not_omp(self):
        self.assertIsNone(module("drain_check").classify(
            "node /repo/component/compiler.js", "codex"))

    def test_plain_claude_is_client_not_a_pool_refresher(self):
        self.assertEqual("claude-client", module("drain_check").classify(
            "/Users/jxstanford/.local/bin/claude --resume session", "teamclaude"))

    def test_listener_is_a_hard_gate_even_without_known_process_name(self):
        from unittest.mock import patch
        import subprocess
        gate = module("drain_check")
        with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "123\n", "")):
            self.assertEqual({123}, gate.lsof_pids(["-iTCP:43210", "-sTCP:LISTEN"]))

    def test_unavailable_file_holder_visibility_refuses(self):
        from unittest.mock import patch
        import subprocess
        gate = module("drain_check")
        with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "sudo: denied")):
            with self.assertRaises(gate.GateError):
                gate.lsof_pids(["+D", "/source-pool"])

    def test_resource_checks_are_component_specific_and_include_open_files(self):
        from unittest.mock import patch
        gate = module("drain_check")
        with tempfile.TemporaryDirectory(prefix="edge-drain-test-") as root:
            home = Path(root)
            (home / ".codex-terminal-pool").mkdir()
            (home / ".config/agent-pools").mkdir(parents=True)
            config = home / "teamclaude.json"
            config.touch()
            for component, paths, expected_port, excluded_port in [
                ("codex", [], "-iTCP:43210", "-iTCP:3456"),
                ("teamclaude", [config], "-iTCP:3456", "-iTCP:43210"),
            ]:
                with patch.object(gate, "lsof_pids", return_value={12}) as lsof:
                    holders = gate.resource_holders(component, home, paths)
                    self.assertEqual({12}, holders["listener"])
                    self.assertEqual({12}, holders["custody-open"])
                    options = [a for call in lsof.call_args_list for a in call.args[0]]
                    self.assertIn(expected_port, options)
                    self.assertNotIn(excluded_port, options)
                    self.assertIn("+D" if component == "codex" else "--", options)
            with self.assertRaises(gate.GateError):
                gate.resource_holders("teamclaude", home)

    def test_listener_or_file_holder_blocks_otherwise_drained_source(self):
        import contextlib
        import io
        import os
        import subprocess
        from unittest.mock import patch
        gate = module("drain_check")
        replies = [
            subprocess.CompletedProcess([], 1, "", "Could not find service"),
            subprocess.CompletedProcess([], 0, '"com.jxstanford.agent-pools.codex" => true', ""),
            subprocess.CompletedProcess([], 0, f"501 {os.getpid()} python drain_check.py codex\n501 123 /usr/bin/sleep 1\n", ""),
        ]
        for kind in ["listener", "custody-open"]:
            with patch.object(gate, "run_visible", side_effect=replies), patch.object(
                    gate, "resource_holders", return_value={kind: {987}}), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertTrue(gate.check_source("codex", Path("/source")))
                self.assertIn(f"pid=987 kind={kind}", output.getvalue())
                self.assertNotIn("/usr/bin/sleep", output.getvalue())

    def test_plain_claude_client_does_not_block_drained_broker(self):
        import contextlib
        import io
        import subprocess
        from unittest.mock import patch
        gate = module("drain_check")
        replies = [
            subprocess.CompletedProcess([], 1, "", "Could not find service"),
            subprocess.CompletedProcess([], 0, '"com.karpeleslab.teamclaude" => true', ""),
            subprocess.CompletedProcess([], 0, "501 123 /usr/local/bin/claude --resume abc\n", ""),
        ]
        with patch.object(gate, "run_visible", side_effect=replies), patch.object(
                gate, "resource_holders", return_value={"listener": set(), "custody-open": set()}), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertFalse(gate.check_source("teamclaude", Path("/source"), [Path("/source/teamclaude.json")]))
            self.assertIn("INFO: pid=123 kind=claude-client", output.getvalue())

    def test_lsof_timeout_and_unrecognized_output_fail_closed(self):
        import subprocess
        from unittest.mock import patch
        gate = module("drain_check")
        with patch.object(gate.subprocess, "run", side_effect=subprocess.TimeoutExpired("lsof", 60)):
            with self.assertRaises(gate.GateError):
                gate.lsof_pids(["+D", "/source"])
        with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "private-file-name\n", "")):
            with self.assertRaises(gate.GateError):
                gate.lsof_pids(["+D", "/source"])

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
        self.assertIsNone(gate.classify("/bin/zsh -c 'python3 /repo/drain_check.py teamclaude'", "teamclaude"))
        self.assertIsNone(gate.classify("python3 /repo/drain_check.py teamclaude", "teamclaude"))

    def test_teamclaude_broker_is_detected(self):
        self.assertIsNotNone(module("drain_check").classify(
            "/usr/bin/node /Users/jxstanford/.bun/bin/teamclaude server --headless", "teamclaude"))


if __name__ == "__main__":
    unittest.main()
