import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import environment
import egress
import privacy_audit as audit


def browser(token, ip='8.8.8.8', rtc='1.1.1.1'):
    return {'version': 1, 'session': token, 'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'origin_kind': 'local-file', 'secure_context': True, 'timezone': 'America/Los_Angeles',
            'languages': ['en-US'], 'geolocation_permission': 'denied',
            'webrtc': {'status': 'complete', 'candidates': [{'scope': 'public', 'type': 'srflx', 'protocol': 'udp', 'ip': rtc}]},
            'exits': [{'source': source, 'round': n, 'ok': True, 'ip': ip, 'country': 'US' if source == 'Cloudflare' else None,
                       'seconds': 0.2, 'error': None} for n in (1, 2, 3) for source in ('Cloudflare', 'ipify IPv4', 'ipify 双栈')]}


def native(ip='8.8.8.8'):
    return {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'headline': '本次出口一致',
            'context': {'id': 'network'}, 'runtime': {'proxy': {}, 'route_id': 'route', 'clients': [], 'corporate_dns_hint': True},
            'changed_during': False, 'paths': [{'id': 'os-ipv4', 'primary': True, 'family': 4, 'ips': [ip],
                                            'success': 6, 'attempts': 6, 'countries': ['US']}]}


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        audit.SESSIONS.clear()
        for name, value in [('privacy_audit.STORE', Path(self.temp.name)/'private/state.json'),
                            ('privacy_audit.EXPORT', Path(self.temp.name)/'export/report.md'),
                            ('egress.network_context', {'id': 'network'}),
                            ('egress.runtime_state', {'proxy': {}, 'route_id': 'route', 'clients': []})]:
            p = patch(name, value) if isinstance(value, Path) else patch(name, return_value=value)
            p.start(); self.addCleanup(p.stop)

    def start(self, label='company', ip='8.8.8.8', note='same US node / global'):
        with patch('egress.check', return_value=native(ip)):
            return audit.start(label, {}, note)

    def test_valid_import_is_single_use_and_has_no_precision_location(self):
        result = self.start();token = result['session']
        imported = audit.import_browser(json.dumps(browser(token)))
        self.assertTrue(imported['record']['browser'])
        findings = imported['record']['findings']
        self.assertTrue(any('额外暴露' in item for item in findings['site_visible']))
        self.assertTrue(any('精确位置' in item for item in findings['unverified']))
        with self.assertRaises(ValueError):audit.import_browser(json.dumps(browser(token)))
        self.assertEqual(audit.STORE.stat().st_mode & 0o777, 0o600)

    def test_expired_foreign_and_overwritten_sessions_rejected(self):
        result = self.start();token = result['session']
        with self.assertRaises(ValueError):audit.import_browser(json.dumps(browser('0'*32)))
        audit.SESSIONS[token]['created'] = time.monotonic()-601
        with self.assertRaises(ValueError):audit.import_browser(json.dumps(browser(token)))
        old = self.start()['session'];self.start()
        with self.assertRaises(ValueError):audit.import_browser(json.dumps(browser(old)))

    def test_network_and_proxy_changes_reject_import(self):
        token = self.start()['session']
        with patch('egress.network_context', return_value={'id':'other'}):
            with self.assertRaises(ValueError):audit.import_browser(json.dumps(browser(token)))
        with patch('egress.runtime_state', return_value={'proxy': {'HTTPSEnable':'1'}, 'route_id':'route'}):
            with self.assertRaises(ValueError):audit.import_browser(json.dumps(browser(token)))

    def test_invalid_shapes_and_injected_fields_rejected(self):
        token=self.start()['session']
        modifications=[lambda d:d.update(command='shell'), lambda d:d.update(version=True),
                       lambda d:d.update(languages=['<script>']), lambda d:d['exits'].append(d['exits'][0]),
                       lambda d:d['exits'][0].update(ip='127.0.0.1'),
                       lambda d:d['webrtc']['candidates'][0].update(scope='private'),
                       lambda d:d['exits'][0].update(seconds=float('nan'))]
        for modify in modifications:
            d=browser(token);modify(d)
            with self.assertRaises((ValueError,TypeError)):audit.validate_browser(json.dumps(d))
        with self.assertRaises(ValueError):audit.validate_browser('x'*12001)

    def test_unavailable_browser_is_not_treated_as_safe(self):
        token=self.start()['session'];d=browser(token)
        d['webrtc']={'status':'unsupported','candidates':[]}
        for s in d['exits']:s.update(ok=False,ip=None,country=None,error='查询超时')
        r=audit.import_browser(json.dumps(d))
        self.assertTrue(any('未验证' in item for item in r['record']['findings']['unverified']))

    def test_bracketed_webrtc_ipv6_normalized_and_private_rejected(self):
        token = self.start()['session']
        d = browser(token, rtc='[2606:4700:4700::1111]')
        result = audit.import_browser(json.dumps(d))
        self.assertEqual(result['record']['browser']['webrtc']['candidates'][0]['ip'], '2606:4700:4700::1111')
        for value in ('[::1]', '[fe80::1]', '[8.8.8.8]', '[2606:4700::1111]:80'):
            with self.assertRaises(ValueError):audit.public_ip(value)

    def test_same_and_different_network_exits_and_confounding(self):
        self.start('company');self.start('hotspot')
        self.assertFalse(audit.compare()['comparable'])
        state=audit.load();state['networks']['hotspot']['native']['context']['id']='hotspot-network';audit.save(state)
        c=audit.compare();self.assertTrue(c['same_exit']);self.assertTrue(c['comparable'])
        state['networks']['hotspot']['native']['runtime']['clients']=['Eternal']
        self.assertFalse(audit.compare(state)['comparable'])
        self.start('hotspot','1.1.1.1');self.assertFalse(audit.compare()['same_exit'])
        self.start('hotspot',note='different node');self.assertFalse(audit.compare()['comparable'])
        s=audit.load();s['networks']['hotspot']['native']['runtime']['proxy']={'HTTPSEnable':'1'}
        self.assertFalse(audit.compare(s)['comparable'])

    def test_export_redacts_ips_company_details_and_node_notes(self):
        token=self.start(note='private company node')['session']
        audit.import_browser(json.dumps(browser(token)))
        out=audit.export();text=Path(out['path']).read_text()
        for secret in ['8.8.8.8','1.1.1.1','private company node','tencent.com','route']:
            self.assertNotIn(secret,text)
        self.assertIn('手机热点',text);self.assertIn('未验证',text)
        self.assertIn('公网地址-1',text)

    def test_preview_enable_preserves_single_type_and_endpoint(self):
        state={'platform':'Darwin','proxy_states':{'Wi-Fi':{'http':False}}}
        with patch('environment.snapshot',return_value=state),patch('environment.proxy_enable_guard'),patch('environment.configured_local_proxy',return_value={'host':'127.0.0.1','port':7892}):
            p=environment.make_plan({'proxy':{'service':'Wi-Fi','kind':'http','enabled':True}})
        a=p['actions'][0]
        self.assertEqual(a['before'],False);self.assertEqual(a['after'],True)
        self.assertEqual(environment.protected_command(a)[-1],'on')
        self.assertEqual(environment.protected_command(a,True)[-1],'off')

    def test_company_management_unknown_or_ioa_blocks_enable(self):
        no={'ok':True,'text':'Enrolled via DEP: No\nMDM enrollment: No'}
        for values in [[{'ok':False,'text':''},{'ok':True,'text':''}],
                       [no,{'ok':True,'text':'/Applications/iOA/iOA.app/Contents/SmartVPN/SmartVPN'}]]:
            with patch('environment.run',side_effect=values):
                with self.assertRaises(ValueError):environment.proxy_enable_guard()

    def test_private_browser_page_embeds_nonce_without_url_fragment(self):
        r=self.start();page=Path(r['browser_url'].replace('file://',''))
        from urllib.parse import unquote
        page=Path(unquote(str(page)))
        self.assertIn('const session="'+r['session']+'";',page.read_text())
        self.assertNotIn('#session=',r['browser_url'])
        self.assertEqual(page.stat().st_mode&0o777,0o600)

    def test_geo_source_disagreement_is_visible(self):
        geo={'sources':[{'ok':True,'country_code':'NZ','source':'fixture'}]}
        with patch('egress.check',return_value=native()):
            result=audit.start('company',{},lookup=lambda ip:geo)
        self.assertEqual(result['record']['native']['kind'],'warn')
        self.assertIn('分歧',result['record']['native']['headline'])

    def test_overlapping_samples_do_not_prove_different_proxy_routes(self):
        record={'native':native(),'browser':browser('a'*32)}
        record['native']['paths'][0]['ips']=['8.8.8.8','1.1.1.1']
        facts=audit.findings(record)['site_visible']
        self.assertTrue(any('部分重合' in fact for fact in facts))
        self.assertFalse(any('未出现在本机' in fact for fact in facts))

    def test_changed_endpoint_before_apply_blocks_without_execution(self):
        state={'platform':'Darwin','proxy_states':{'Wi-Fi':{'http':False}}}
        with patch('environment.snapshot',return_value=state),patch('environment.proxy_enable_guard'),patch('environment.configured_local_proxy',return_value={'host':'127.0.0.1','port':7892}):
            p=environment.make_plan({'proxy':{'service':'Wi-Fi','kind':'http','enabled':True}})
            with patch('environment.configured_local_proxy',return_value={'host':'127.0.0.1','port':7897}),patch('environment.execute_actions') as execute:
                with self.assertRaises(ValueError):environment.apply_plan(p['plan_id'])
                execute.assert_not_called()


if __name__ == '__main__':unittest.main()
