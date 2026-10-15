import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import egress
import environment


def sample(ip='8.8.8.8', ok=True, source='Cloudflare', country='US', seconds=0.4):
    return {'ok': ok, 'ip': ip if ok else None, 'source': source, 'country': country,
            'round': 1, 'seconds': seconds, 'error': None if ok else 'TLS 连接失败'}


class EgressTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / 'private/egress-history.json'
        self.patch = patch('egress.STATE_FILE', self.file)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        runtime = patch('egress.runtime_state', return_value={'proxy': {}, 'route_id': 'fixed', 'clients': []})
        runtime.start()
        self.addCleanup(runtime.stop)
        self.routes = [dict(id='primary', label='系统代理', family=4, primary=True, proxy=None),
                       dict(id='os-ipv6', label='IPv6', family=6, primary=False, proxy=None)]

    def report(self, ips=None, contexts=None, failures=False):
        calls = {'primary': 0}
        def probe(route, source, round_number):
            if route['family'] == 6:
                return sample('2606:4700:4700::1111', source=source)
            n = calls['primary']
            calls['primary'] += 1
            return sample((ips or ['8.8.8.8'])[n % len(ips or ['8.8.8.8'])],
                          ok=not (failures and n == 1), source=source)
        context = contexts or [{'id': 'network-a', 'note': ''}] * 4
        with patch('egress.network_context', side_effect=context), patch('egress.discover_routes', return_value=self.routes), patch('egress.probe', side_effect=probe), patch('egress.time.sleep'):
            return egress.check({})

    def test_ipv4_ipv6_do_not_create_false_multiple_exit(self):
        r = self.report()
        self.assertEqual(r['kind'], 'good')
        self.assertFalse(r['paths'][0]['multi_exit'])
        self.assertFalse(r['paths'][1]['multi_exit'])

    def test_different_countries_same_ip_are_not_multiple_exit(self):
        p = egress.summarize(self.routes[0], [sample(country='US'), sample(country='NZ')])
        self.assertFalse(p['multi_exit'])
        self.assertEqual(p['countries'], ['NZ', 'US'])

    def test_same_path_rotating_ip_is_independent_of_connection_failure(self):
        r = self.report(['8.8.8.8', '1.1.1.1'])
        self.assertTrue(r['paths'][0]['multi_exit'])
        self.assertEqual(r['paths'][0]['failures'], 0)
        self.assertIn('多个 IPv4', r['headline'])

    def test_connection_failure_does_not_imply_ip_rotation(self):
        r = self.report(failures=True)
        self.assertFalse(r['paths'][0]['multi_exit'])
        self.assertIn('部分检测请求失败', r['headline'])

    def test_network_switch_between_checks_not_marked_same_network_change(self):
        self.report()
        r = self.report(['1.1.1.1'], [{'id': 'network-b', 'note': ''}] * 4)
        self.assertTrue(r['network_changed'])
        self.assertFalse(r['changed_since_previous'])
        self.assertEqual(r['kind'], 'good')

    def test_same_network_changed_ip_is_detected_without_claiming_failure(self):
        self.report()
        r = self.report(['1.1.1.1'])
        self.assertTrue(r['changed_since_previous'])
        self.assertFalse(r['network_changed'])
        self.assertEqual(r['kind'], 'good')

    def test_switch_and_return_during_check_requires_retry(self):
        contexts = [{'id': value, 'note': ''} for value in ['a', 'b', 'a', 'a']]
        r = self.report(contexts=contexts)
        self.assertTrue(r['changed_during'])
        self.assertIn('重新检查', r['headline'])

    def test_missing_network_identity_skips_historical_comparison(self):
        self.report()
        r = self.report(['1.1.1.1'], [{'id': None, 'note': ''}] * 4)
        self.assertFalse(r['network_changed'])
        self.assertFalse(r['changed_since_previous'])

    def test_fixed_ip_matches_exact_address_not_country(self):
        egress.set_reference('8.8.8.8')
        self.assertEqual(self.report(['1.1.1.1'])['reference_status'], 'mismatch')
        self.assertEqual(self.report(['8.8.8.8', '1.1.1.1'])['reference_status'], 'partial')
        self.assertEqual(self.report()['reference_status'], 'match')
        mismatch = self.report(['1.1.1.1'])
        self.assertEqual(mismatch['kind'], 'warn')
        self.assertIn('不匹配', mismatch['headline'])

    def test_proxy_change_with_same_network_invalidates_sample(self):
        states = [{'proxy': {'HTTPSEnable': value}, 'route_id': 'fixed'} for value in ['1', '1', '0', '0']]
        with patch('egress.runtime_state', side_effect=states):
            result = self.report()
        self.assertTrue(result['changed_during'])
        self.assertTrue(result['proxy_changed_during'])

    def test_country_disagreement_does_not_report_good(self):
        p = egress.summarize(self.routes[0], [sample(country='US'), sample(country='NZ')])
        self.assertEqual(egress.verdict(p)[1], 'warn')
        p['countries'] = []
        self.assertEqual(egress.verdict(p, expected_country='US')[1], 'warn')

    def test_reference_is_validated_private_and_clearable(self):
        for value in ['127.0.0.1', '192.168.1.2', 'https://example.com', '2606:4700:4700::1111', 123]:
            with self.assertRaises(ValueError):
                egress.set_reference(value)
        self.assertFalse(self.file.exists())
        egress.set_reference('8.8.8.8')
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.file.parent.stat().st_mode & 0o777, 0o700)
        self.assertIsNone(egress.set_reference('')['reference_ip'])

    def test_history_retention_is_bounded(self):
        for _ in range(15):
            self.report()
        state = egress.load_state()
        self.assertEqual(len(state['history']), 12)
        self.assertNotIn('samples', state['history'][0]['paths'][0])

    def test_corrupt_history_is_preserved(self):
        self.file.parent.mkdir()
        self.file.write_text('broken-json')
        r = self.report()
        self.assertTrue(r['history_error'])
        self.assertEqual(self.file.read_text(), 'broken-json')

    def test_detect_physical_route_without_storing_ssid_or_subnet(self):
        values = ['default 192.168.1.1 UGScg en0 \n1 192.168.255.10 UGSc utun4\n',
                  'inet 192.168.1.22 netmask 0xffffff00', 'Current Wi-Fi Network: Private WiFi']
        with patch('egress.command', side_effect=values):
            context = egress.network_context()
        self.assertTrue(context['id'])
        self.assertNotIn('Private WiFi', json.dumps(context))
        self.assertNotIn('192.168.1', json.dumps(context))

    def test_structurally_invalid_history_does_not_block_diagnostics(self):
        self.file.parent.mkdir()
        raw = json.dumps({'reference_ip': None, 'history': [123]})
        self.file.write_text(raw)
        r = self.report()
        self.assertTrue(r['history_error'])
        self.assertEqual(self.file.read_text(), raw)

    def test_current_mixed_proxy_is_not_tested_twice_as_http_and_socks(self):
        proxy = {'HTTPSEnable': '1', 'HTTPSProxy': '127.0.0.1', 'HTTPSPort': '7892',
                 'SOCKSEnable': '1', 'SOCKSProxy': '127.0.0.1', 'SOCKSPort': '7892'}
        with patch('egress.socket.create_connection', side_effect=OSError):
            routes = egress.discover_routes(proxy)
        self.assertEqual(len(routes), 3)
        self.assertTrue(routes[0]['primary'])
        self.assertFalse(routes[1]['primary'])

    def test_curl_does_not_inherit_proxy_credentials(self):
        response = subprocess.CompletedProcess([], 0, 'ip=8.8.8.8\nloc=US\n\nMETRICS:200,0.45', '')
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://user:password@host'}), patch('egress.subprocess.run', return_value=response) as run:
            r = egress.probe(self.routes[0], 'Cloudflare', 1)
        self.assertTrue(r['ok'])
        self.assertNotIn('HTTPS_PROXY', run.call_args.kwargs['env'])
        self.assertIn('--noproxy', run.call_args.args[0])

    def test_failed_and_invalid_responses_not_public_exits(self):
        for code, body in [(0, '127.0.0.1\nMETRICS:200,0.5'),
                           (0, '2606:4700:4700::1111\nMETRICS:200,0.5'),
                           (0, '8.8.8.8\nMETRICS:429,0.5'), (35, '\nMETRICS:000,0.5')]:
            response = subprocess.CompletedProcess([], code, body, 'secret-token')
            with patch('egress.subprocess.run', return_value=response):
                r = egress.probe(self.routes[0], 'ipify', 1)
            self.assertFalse(r['ok'])
            self.assertIsNone(r['ip'])
            self.assertNotIn('secret-token', json.dumps(r))

    def test_bridge_allows_only_fixed_probe_targets(self):
        with patch('egress.check') as check:
            with self.assertRaises(ValueError):
                environment.dispatch('egress', {'url': 'http://localhost/'})
            check.assert_not_called()
        with self.assertRaises(ValueError):
            environment.dispatch('egress_reference', {'ip': '8.8.8.8', 'command': 'shell'})

    def test_runtime_route_fingerprint_ignores_arp_expiry(self):
        def snapshot(expiry):
            replies=['HTTPSEnable : 1',
                     'default 192.168.1.1 UGScg en0\n1 192.168.255.10 UGSc utun4\n192.168.1.1 aa:bb UHLWI en0 '+str(expiry),
                     'default fe80::1 UGcg en0\n', 'nameserver[0] : 192.168.1.1', 'SmartVPN']
            with patch('egress.command',side_effect=replies):
                return self._real_runtime()
        a,b=snapshot(100),snapshot(99)
        self.assertEqual(a['route_id'],b['route_id'])
        self.assertTrue(a['dns_id'])

    _real_runtime = staticmethod(egress.runtime_state)


if __name__ == '__main__':
    unittest.main()
