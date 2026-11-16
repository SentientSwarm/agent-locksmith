import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock
from types import SimpleNamespace


def module(name):
    path=Path(__file__).parents[1]/(name+'.py')
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class DrainRegressionTest(unittest.TestCase):
    def test_signed_nobody_uid_does_not_refuse_unrelated_process(self):
        import contextlib,io
        gate=module('drain_check')
        replies=[subprocess.CompletedProcess([],1,'','Could not find service'),
                 subprocess.CompletedProcess([],0,'"com.jxstanford.agent-pools.codex" => disabled',''),
                 subprocess.CompletedProcess([],0,'-2 123 /usr/sbin/dhcp6d\n','')]
        with patch.object(gate,'run_visible',side_effect=replies), patch.object(
            gate,'process_executables',return_value={123:'/usr/sbin/dhcp6d'}), patch.object(
            gate,'resource_holders',return_value={'listener':set(),'custody-open':set()}), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(gate.check_source('codex',Path('/source')))

    def test_bootout_waits_until_job_disappears(self):
        gate=module('drain_check')
        present=subprocess.CompletedProcess([],0,'','')
        absent=subprocess.CompletedProcess([],113,'','Could not find service')
        with patch.object(gate,'run_visible',side_effect=[present,present,present,absent]), patch.object(
                gate.time,'sleep'):
            gate.stop_source_job('codex',wait_seconds=30)

    def test_already_unloaded_job_is_not_booted_out_again(self):
        gate=module('drain_check')
        absent=subprocess.CompletedProcess([],113,'','Could not find service')
        with patch.object(gate,'run_visible',return_value=absent) as run:
            gate.stop_source_job('codex')
            self.assertFalse(any('bootout' in call.args[0] for call in run.call_args_list))

    def test_bootout_timeout_refuses_and_visibility_failure_is_not_absence(self):
        gate=module('drain_check')
        with patch.object(gate,'run_visible',return_value=subprocess.CompletedProcess([],0,'','')), patch.object(
                gate.time,'monotonic',side_effect=[0,0,0,31]), patch.object(gate.time,'sleep'):
            with self.assertRaises(gate.GateError): gate.stop_source_job('codex',wait_seconds=30)
        with patch.object(gate,'run_visible',return_value=subprocess.CompletedProcess([],1,'','permission denied')):
            with self.assertRaises(gate.GateError): gate.stop_source_job('codex')


class ResponsesRegressionTest(unittest.TestCase):
    def test_cdn_challenge_is_not_an_authentication_canary(self):
        probe=module('handoff_probe')
        import urllib.error
        with patch.object(probe.urllib.request,'urlopen',side_effect=urllib.error.HTTPError(
                'http://test/v1/responses',403,'challenge',{},None)):
            with self.assertRaises(probe.ProbeError):
                probe.reject_unauthenticated('http://test','codex')

    def test_error_incomplete_and_oversized_streams_refuse(self):
        probe=module('handoff_probe')
        import io
        for data in [b'data: {"type":"error"}\n',b'data: {"type":"response.incomplete"}\n',b'x'*65537]:
            with self.assertRaises(probe.ProbeError):
                probe.completed_stream(io.BytesIO(data),'response.completed')

    def test_probe_requires_completed_responses_stream_not_models_catalog(self):
        probe=module('handoff_probe')
        class Response:
            status=200
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def __init__(self): self.lines=iter([b'data: {"type":"response.created"}\n',b'data: {"type":"response.completed"}\n'])
            def readline(self,limit): return next(self.lines,b'')
        with patch.object(probe.urllib.request,'urlopen',return_value=Response()) as opened:
            probe.responses_probe('http://127.0.0.1:43210','private-test-client-key','working-model')
            request=opened.call_args.args[0]
            self.assertTrue(request.full_url.endswith('/v1/responses'))
            self.assertNotIn('models',request.full_url)
        class Incomplete(Response):
            def __init__(self): self.lines=iter([b'data: {"type":"response.created"}\n'])
        with patch.object(probe.urllib.request,'urlopen',return_value=Incomplete()):
            with self.assertRaises(probe.ProbeError):
                probe.responses_probe('http://127.0.0.1:43210','private-test-client-key','working-model')


class TeamHandoffTest(unittest.TestCase):
    def test_transfer_must_finish_before_activation_and_activation_failure_stops_destination(self):
        import json,plistlib
        mover=module('move-teamclaude')
        for fail_activation in [False,True]:
            with self.subTest(fail_activation=fail_activation), tempfile.TemporaryDirectory(prefix='edge-worker-test-') as root:
                home=Path(root); (home/'.config').mkdir(); (home/'Library/LaunchAgents').mkdir(parents=True)
                selected=home/'.config/teamclaude.json'
                selected.write_text(json.dumps({'proxy':{'apiKey':'private-test-key'},'accounts':[{'id':str(i)} for i in range(3)]}))
                package=home/'package'; (package/'src').mkdir(parents=True)
                (package/'package.json').write_text(json.dumps({'name':'@karpeleslab/teamclaude','version':'1.1.27'}))
                (package/'src/index.js').write_text('// public code')
                node=home/'node'; node.touch()
                job={'ProgramArguments':[str(node)],'EnvironmentVariables':{}}
                (home/'Library/LaunchAgents'/f'{mover.LABEL}.plist').write_bytes(plistlib.dumps(job))
                attempt=home/'attempt'; attempt.mkdir()
                gate=SimpleNamespace(run_visible=Mock(return_value=subprocess.CompletedProcess([],113,'','Could not find service')),
                    lsof_pids=Mock(side_effect=[{123},set()]),stop_source_job=Mock(),check_source=Mock(return_value=False))
                probe=SimpleNamespace(messages_probe=Mock(),reject_unauthenticated=Mock())
                real_load=mover.load
                def load(name): return gate if name=='drain_check' else probe if name=='handoff_probe' else real_load(name)
                events=[]
                def run(argv,**kwargs):
                    if argv[0]=='rsync':
                        events.append('transfer'); Path(argv[-2]).unlink()
                    return b''
                def remote(action,payload=None):
                    events.append(action)
                    if action=='activate':
                        self.assertFalse(selected.exists())
                        if fail_activation: raise RuntimeError('simulated activation failure')
                args=SimpleNamespace(config=selected,custody_path=[],package=package,node=node,model='working-model')
                with patch.object(mover.Path,'home',return_value=home), patch.object(mover,'load',side_effect=load), patch.object(
                        mover,'run',side_effect=run), patch.object(mover,'remote',side_effect=remote), patch.object(
                        mover,'drain'), patch.object(mover.signal,'alarm'), patch.object(mover.signal,'signal'):
                    result=mover.worker(args,attempt)
                self.assertEqual(int(fail_activation),result)
                self.assertLess(events.index('transfer'),events.index('activate'))
                self.assertFalse(selected.exists())  # no automatic source restore
                if fail_activation:
                    self.assertEqual('stop',events[-1])
                else:
                    self.assertIn('LOCAL_SERVING_COMPAT_LOADED', (attempt/'status').read_text())

    def test_inventory_moves_selected_siblings_and_archives_other_configs_and_backups(self):
        mover=module('move-teamclaude')
        with tempfile.TemporaryDirectory(prefix='edge-team-test-') as root:
            directory=Path(root)
            for name in ['teamclaude.json','teamclaude.state.json','teamclaude.quota-series.json',
                         'teamclaude-leaf.key','teamclaude-ca.pem','teamclaude-leaf.pem',
                         'teamrouter.json','teamclaude.json.bak','unrelated.json']:
                (directory/name).write_text('{}')
            inventory=mover.inventory(directory/'teamclaude.json',[])
            self.assertEqual('active/teamclaude.json',inventory[directory/'teamclaude.json'])
            self.assertEqual('active/teamclaude.state.json',inventory[directory/'teamclaude.state.json'])
            self.assertTrue(inventory[directory/'teamrouter.json'].startswith('history/'))
            self.assertTrue(inventory[directory/'teamclaude.json.bak'].startswith('history/'))
            self.assertNotIn(directory/'unrelated.json',inventory)

    def test_inventory_refuses_links_and_existing_config_lock(self):
        mover=module('move-teamclaude')
        with tempfile.TemporaryDirectory(prefix='edge-team-test-') as root:
            directory=Path(root); selected=directory/'teamclaude.json'
            selected.write_text('{}')
            backup=directory/'teamclaude.json.bak'; backup.symlink_to(selected)
            with self.assertRaises(RuntimeError): mover.inventory(selected,[])
            backup.unlink(); (directory/'teamclaude.json.lock').write_text('{}')
            with self.assertRaises(RuntimeError): mover.inventory(selected,[])

    def test_only_transport_and_loopback_auth_settings_change(self):
        destination=module('teamclaude_destination')
        config={'proxy':{'apiKey':'private-test-key','clientKeys':[{'key':'client-test-key'}]},
                'accounts':[{'id':str(i),'refreshToken':'private-test-token'} for i in range(3)],
                'routes':{'example':'original'}}
        import copy
        old=copy.deepcopy(config)
        destination.prepare_config(config)
        self.assertIs(config['proxy']['trustLoopback'],False)
        self.assertEqual(config['accounts'],old['accounts'])
        self.assertEqual(config['routes'],old['routes'])
        self.assertEqual(config['proxy']['apiKey'],old['proxy']['apiKey'])
        self.assertEqual(config['proxy']['clientKeys'],old['proxy']['clientKeys'])

    def test_destination_activation_failure_always_stops_and_revokes(self):
        destination=module('teamclaude_destination')
        with patch.object(destination,'activate',side_effect=RuntimeError('private-detail')), patch.object(
                destination,'stop') as stop:
            with self.assertRaises(RuntimeError): destination.dispatch('activate',{})
            stop.assert_called_once()


if __name__=='__main__': unittest.main()
