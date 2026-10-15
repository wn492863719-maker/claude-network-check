import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import environment as server


def state(timezone='Asia/Shanghai', locale='zh_CN', enabled=True):
    return {'platform': 'Darwin', 'timezone': timezone, 'locale': locale,
            'languages': ['zh-Hans', 'en-NZ'],
            'proxy_states': {'Wi-Fi': {k: enabled for k in server.PROXY_TYPES}}}


class PlansTest(unittest.TestCase):
    def setUp(self):
        server.PLANS.clear()
        server.EXIT_TARGETS = [{'country':'NZ','timezone':'Pacific/Auckland','locale':'en_NZ','detected_at':server.time.monotonic()}]

    def test_timezone_already_correct_does_not_write(self):
        with patch('environment.snapshot', return_value=state('Pacific/Auckland')):
            plan = server.make_plan({'fields': ['timezone'], 'target_index': 0})
        self.assertEqual(plan['actions'], [])
        with patch('environment.execute_actions') as execute:
            self.assertIsNone(server.apply_plan(plan['plan_id'])['restore_id'])
            execute.assert_not_called()

    def test_invalid_timezone_and_services_are_rejected(self):
        with self.assertRaises(ValueError):
            server.make_plan({'fields': ['timezone'], 'target_index': 99})
        with patch('environment.snapshot', return_value=state()):
            with self.assertRaises(ValueError):
                server.make_plan({'proxy': {'service': 'unknown-service', 'kind': 'http'}})

    def test_locale_does_not_change_languages(self):
        with patch('environment.snapshot', return_value=state()):
            plan = server.make_plan({'fields': ['locale'], 'target_index': 0})
        self.assertEqual([a['kind'] for a in plan['actions']], ['locale'])
        self.assertEqual(plan['actions'][0]['after'], 'en_NZ')

    def test_unknown_proxy_state_blocks_mutation(self):
        original = state()
        original['proxy_states']['Wi-Fi']['socks'] = None
        with patch('environment.snapshot', return_value=original):
            with self.assertRaises(ValueError):
                server.make_plan({'proxy': {'service': 'Wi-Fi', 'kind': 'socks'}})

    def test_stale_preview_blocks_mutation(self):
        with patch('environment.snapshot', return_value=state()):
            plan = server.make_plan({'fields': ['timezone'], 'target_index': 0})
        with patch('environment.snapshot', return_value=state('Pacific/Chatham')):
            with patch('environment.execute_actions') as execute:
                with self.assertRaises(ValueError):
                    server.apply_plan(plan['plan_id'])
                execute.assert_not_called()

    def test_preview_only_consumed_once_and_snapshot_saved_first(self):
        network = {'observations': [{'geo': {'sources': [
            {'ok': True, 'country_code': 'NZ', 'timezone': 'Pacific/Auckland'}]}}]}
        with tempfile.TemporaryDirectory() as temp, patch('environment.STORE', Path(temp) / 'points'), patch('environment.snapshot', return_value=state()), patch('environment.network_scan', return_value=network):
            plan = server.make_plan({'fields': ['timezone'], 'target_index': 0})
            def execute(actions):
                files = list(server.STORE.glob('*.json'))
                self.assertEqual(len(files), 1)
                self.assertEqual(json.loads(files[0].read_text())['actions'][0]['before'], 'Asia/Shanghai')
                self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
                return [{'action': actions[0], 'ok': True, 'message': 'mock'}]
            with patch('environment.execute_actions', side_effect=execute):
                result = server.apply_plan(plan['plan_id'])
            self.assertTrue(result['restore_id'])
            self.assertEqual(server.STORE.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(ValueError):
                server.apply_plan(plan['plan_id'])

    def test_cancelled_admin_does_not_write_locale(self):
        actions = [{'kind': 'timezone', 'before': 'Asia/Shanghai', 'after': 'Pacific/Auckland'},
                   {'kind': 'locale', 'before': 'zh_CN', 'after': 'en_NZ'}]
        with patch('environment.run', return_value={'ok': False, 'text': '', 'code': 1}) as run:
            results = server.execute_actions(actions)
        self.assertEqual(run.call_count, 1)
        self.assertFalse(any(r['ok'] for r in results))

    def test_command_success_without_changed_setting_is_failure(self):
        action = {'kind': 'timezone', 'before': 'Asia/Shanghai', 'after': 'Pacific/Auckland'}
        with patch('environment.run', return_value={'ok': True, 'text': 'NZ_OK:0'}), patch('environment.system_timezone', return_value='Asia/Shanghai'):
            self.assertFalse(server.execute_actions([action])[0]['ok'])

    def test_command_argument_is_not_interpreted_as_shell_code(self):
        malicious = 'Wi-Fi; touch /tmp/should-not-exist $(whoami)'
        action = {'kind': 'proxy', 'service': malicious, 'proxy_kind': 'http', 'before': True, 'after': False}
        command = server.protected_command(action)
        self.assertEqual(command[2], malicious)
        self.assertEqual(command[3], 'off')
        import shlex
        self.assertEqual(shlex.split(shlex.join(command)), command)

    def test_restore_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            server.restore_record('../../arbitrary')

    def test_restore_does_not_override_a_later_setting(self):
        with tempfile.TemporaryDirectory() as temp, patch('environment.STORE', Path(temp) / 'points'):
            record = {'id': '20261004T000000Z-aabbccdd', 'actions': [
                {'kind': 'locale', 'before': 'zh_CN', 'after': 'en_NZ', 'label': 'locale'}]}
            server.save_record(record)
            with patch('environment.preference', return_value='en_AU'), patch('environment.execute_actions') as execute:
                with self.assertRaises(ValueError):
                    server.restore_record(record['id'])
                execute.assert_not_called()

    def test_geo_rejects_private_or_malformed_ip(self):
        with patch('environment.request_json') as request:
            for ip in ('127.0.0.1', '192.168.1.1', 'http://localhost/', '::1'):
                with self.assertRaises(ValueError):
                    server.geo_lookup(ip)
            request.assert_not_called()

    def test_geo_preserves_source_disagreement_and_outage(self):
        responses = [({'country': 'New Zealand', 'country_code': 'NZ', 'connection': {}, 'timezone': {}}, None),
                     ({'country_name': 'Australia', 'country_code': 'AU'}, None)]
        with patch('environment.request_json', side_effect=responses):
            result = server.geo_lookup('8.8.8.8')
        self.assertEqual([g['country_code'] for g in result['sources']], ['NZ', 'AU'])
        with patch('environment.request_json', side_effect=OSError('offline')):
            result = server.geo_lookup('8.8.8.8')
        self.assertFalse(any(g['ok'] for g in result['sources']))


class ExitTargetTest(unittest.TestCase):
    def test_us_target_uses_observed_timezone_and_locale(self):
        server.EXIT_TARGETS = [{'country':'US','timezone':'America/Los_Angeles',
                                'locale':'en_US','detected_at':server.time.monotonic()}]
        with patch('environment.snapshot', return_value=state('Pacific/Auckland','en_NZ')):
            plan = server.make_plan({'fields':['timezone','locale'],'target_index':0})
        self.assertEqual([a['after'] for a in plan['actions']], ['America/Los_Angeles','en_US'])
        self.assertNotIn('languages',[a['kind'] for a in plan['actions']])

    def test_single_proxy_does_not_touch_other_types(self):
        with patch('environment.snapshot', return_value=state()):
            plan = server.make_plan({'proxy':{'service':'Wi-Fi','kind':'http'}})
        self.assertEqual(len(plan['actions']),1)
        self.assertEqual(plan['actions'][0]['proxy_kind'],'http')

    def test_expired_exit_target_cannot_be_applied(self):
        server.EXIT_TARGETS = [{'country':'NZ','timezone':'Pacific/Auckland',
                                'locale':'en_NZ','detected_at':server.time.monotonic()-301}]
        with patch('environment.snapshot', return_value=state()):
            with self.assertRaises(ValueError):
                server.make_plan({'fields':['timezone'],'target_index':0})

    def test_unavailable_country_timezone_is_not_guessed(self):
        source = {'ok':True,'country_code':'US','country':'United States',
                  'timezone':None,'source':'fixture'}
        with patch('environment.local_scan',return_value={}), patch('environment.network_scan',return_value={
            'observations':[{'ok':True,'ip':'8.8.8.8','geo':{'sources':[source]}}]}):
            result=server.detect()
        self.assertEqual(result['targets'],[])

    def test_disagreeing_sources_are_kept_as_separate_targets(self):
        sources = [{'ok':True,'country_code':code,'country':code,'timezone':zone,'source':name}
                   for code,zone,name in [('NZ','Pacific/Auckland','one'),('US','America/New_York','two')]]
        with patch('environment.local_scan',return_value={}), patch('environment.network_scan',return_value={
            'observations':[{'ok':True,'ip':'8.8.8.8','geo':{'sources':sources}}]}):
            result=server.detect()
        self.assertEqual(len(result['targets']),2)

    def test_bridge_rejects_arbitrary_commands(self):
        with self.assertRaises(ValueError):
            server.dispatch('shell',{'command':'any'})

    def test_changed_network_prevents_alignment(self):
        server.EXIT_TARGETS = [{'country':'US','timezone':'America/Los_Angeles',
                                'locale':'en_US','detected_at':server.time.monotonic()}]
        with patch('environment.snapshot', return_value=state()):
            plan = server.make_plan({'fields':['timezone'],'target_index':0})
            with patch('environment.network_scan', return_value={'observations':[]}), patch('environment.execute_actions') as execute:
                with self.assertRaises(ValueError):
                    server.apply_plan(plan['plan_id'])
                execute.assert_not_called()

    def test_proxy_operation_cannot_include_alignment(self):
        with self.assertRaises(ValueError):
            server.make_plan({'fields':['timezone'],'target_index':0,
                              'proxy':{'service':'Wi-Fi','kind':'http'}})


if __name__ == '__main__':
    unittest.main()
