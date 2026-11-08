"""Workflow contract only; parsing/fixtures do not establish hosted execution."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    'x86_64-unknown-linux-gnu': 'ubuntu-24.04',
    'aarch64-unknown-linux-gnu': 'ubuntu-24.04-arm',
    'x86_64-apple-darwin': 'macos-15-intel',
    'aarch64-apple-darwin': 'macos-15',
}


def workflow():
    path = ROOT / '.github/workflows/native-validation.yml'
    if not path.exists():
        path = ROOT / '.github/workflows/release.yml'  # Before control: publication is not validation.
    return yaml.load(path.read_text(), Loader=yaml.BaseLoader)


class WorkflowContract(unittest.TestCase):
    def test_read_only_events_and_no_publication(self):
        value = workflow()
        # workflow_call lets the release workflow reuse these exact bytes; this
        # workflow itself still has read-only permissions and never publishes.
        self.assertEqual(set(value['on']), {'pull_request', 'workflow_dispatch', 'workflow_call'})
        self.assertEqual(value['permissions'], {'contents': 'read'})
        self.assertNotIn('pull_request_target', value['on'])
        self.assertIn('concurrency', value)
        # A caller (Release) must not share and cancel this workflow's own PR group.
        self.assertIn('${{ github.workflow }}', value['concurrency']['group'])
        text = str(value)
        for forbidden in ['action-gh-release', 'contents: write', 'secrets.', 'environment', 'git push']:
            self.assertNotIn(forbidden, text)

    def test_exact_native_target_runner_matrix(self):
        job = workflow()['jobs'].get('native', {})
        rows = job.get('strategy', {}).get('matrix', {}).get('include', [])
        self.assertEqual({r['target']: r['os'] for r in rows}, EXPECTED)
        self.assertEqual(len(rows), 4)
        self.assertEqual(job.get('runs-on'), '${{ matrix.os }}')
        self.assertLessEqual(int(job.get('timeout-minutes', 1000)), 45)
        self.assertEqual(job.get('strategy', {}).get('fail-fast'), 'false')

    def test_locked_build_then_smoke_then_upload_same_directory(self):
        steps = workflow()['jobs'].get('native', {}).get('steps', [])
        commands = [s.get('run', '') for s in steps]
        build = next((i for i, s in enumerate(commands) if 'native-validate.py build' in s), -1)
        smoke = next((i for i, s in enumerate(commands) if 'native-validate.py smoke' in s), -1)
        upload = next((i for i, s in enumerate(steps) if s.get('uses') == 'actions/upload-artifact@v4'), -1)
        self.assertGreaterEqual(build, 0)
        self.assertGreater(smoke, build)
        self.assertGreater(upload, smoke)
        self.assertFalse(any('cargo ' in c for c in commands[smoke + 1:]))
        self.assertTrue(any(s.get('uses') == 'dtolnay/rust-toolchain@1.94.0' for s in steps))
        self.assertIn('--expected-revision "$GITHUB_SHA"', commands[build])

    def test_aggregate_requires_all_matrix_jobs_and_preserves_failure(self):
        value = workflow()
        aggregate = value['jobs'].get('aggregate', {})
        self.assertEqual(aggregate.get('needs'), 'native')
        self.assertEqual(aggregate.get('if'), '${{ always() }}')
        text = str(aggregate)
        self.assertIn('native-validate.py aggregate', text)
        self.assertIn('${{ needs.native.result }}', text)
        self.assertIn('actions/download-artifact@v4', text)
        self.assertIn('actions/upload-artifact@v4', text)
        self.assertIn('always()', text)

    def test_checkout_does_not_persist_credentials(self):
        value = workflow()
        for job in value['jobs'].values():
            checkouts = [s for s in job['steps'] if s.get('uses') == 'actions/checkout@v4']
            self.assertEqual(len(checkouts), 1)
            self.assertEqual(checkouts[0].get('with', {}).get('persist-credentials'), 'false')
