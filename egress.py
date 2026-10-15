"""Bounded, read-only egress probes and private local comparison history."""
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import statistics
import subprocess
import time

STATE_FILE = Path.home() / 'Library/Application Support/Network Environment Check/egress-history.json'
LAST_REPORT = None
PROXY_ENV = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
             'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
ENDPOINTS = {'Cloudflare': 'https://www.cloudflare.com/cdn-cgi/trace',
             'ipify': 'https://api.ipify.org',
             'ipify IPv6': 'https://api64.ipify.org'}


def command(args, timeout=4):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def network_context():
    # Default en* route identifies the physical path even with more-specific TUN routes.
    routes = command(['/usr/sbin/netstat', '-rn', '-f', 'inet'])
    match = re.search(r'^default\s+(\S+)\s+\S+\s+(en\d+)\s', routes, re.M)
    if not match:
        return {'id': None, 'note': '未取得物理网络特征，跳过换网比较'}
    gateway, interface = match.groups()
    config = command(['/sbin/ifconfig', interface])
    address = re.search(r'\binet\s+(\S+)\s+netmask\s+(\S+)', config)
    if not address:
        return {'id': None, 'note': '未取得物理网络特征，跳过换网比较'}
    try:
        mask = address[2]
        if mask.startswith('0x'):
            mask = str(ipaddress.IPv4Address(int(mask, 16)))
        subnet = str(ipaddress.IPv4Network(address[1] + '/' + mask, strict=False))
        ipaddress.IPv4Address(gateway)
    except ValueError:
        return {'id': None, 'note': '未取得物理网络特征，跳过换网比较'}
    wifi = command(['/usr/sbin/networksetup', '-getairportnetwork', interface])
    ssid = wifi.split(': ', 1)[1].strip() if wifi.startswith('Current Wi-Fi Network: ') else ''
    digest = hashlib.sha256('|'.join((interface, gateway, subnet, ssid)).encode()).hexdigest()
    return {'id': digest, 'note': '网络特征仅保存摘要；可用时包含 Wi-Fi 名称'}


def proxy_route(kind, host, port, label, primary=False):
    try:
        port = int(port)
        if not 1 <= port <= 65535 or not isinstance(host, str):
            return None
        if not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', host):
            return None
        scheme = 'socks5h' if kind == 'socks' else 'http'
        authority = '[' + host + ']' if ':' in host else host
        url = f'{scheme}://{authority}:{port}'
        return {'id': hashlib.sha256(url.encode()).hexdigest()[:16], 'label': label,
                'family': 4, 'proxy': url, 'primary': primary}
    except (TypeError, ValueError):
        return None


def discover_routes(proxy):
    routes, addresses = [], set()
    for prefix, kind in [('HTTPS', 'http'), ('HTTP', 'http'), ('SOCKS', 'socks')]:
        if str(proxy.get(prefix + 'Enable')) != '1':
            continue
        host, port = proxy.get(prefix + 'Proxy'), proxy.get(prefix + 'Port')
        if (host, str(port)) in addresses:
            continue
        route = proxy_route(kind, host, port, '系统 ' + prefix + ' 代理', not routes)
        if route:
            routes.append(route)
            addresses.add((host, str(port)))
    for port in (7892, 7897):
        if ('127.0.0.1', str(port)) in addresses or len(routes) >= 3:
            continue
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.25):
                pass
        except OSError:
            continue
        routes.append(proxy_route('http', '127.0.0.1', port, f'其他本地代理 · {port}'))
    routes.append({'id': 'os-ipv4', 'label': '不显式使用代理 · IPv4',
                   'family': 4, 'proxy': None, 'primary': not any(r['primary'] for r in routes)})
    routes.append({'id': 'os-ipv6', 'label': '不显式使用代理 · IPv6',
                   'family': 6, 'proxy': None, 'primary': False})
    return routes


def probe(route, source, round_number):
    url = ENDPOINTS[source]
    args = ['/usr/bin/curl', '-q', '-sS', '-' + str(route['family']),
            '--connect-timeout', '5', '--max-time', '8', '--max-filesize', '65536']
    args += ['--proxy', route['proxy'], '--noproxy', ''] if route['proxy'] else ['--noproxy', '*']
    args += [url, '-w', '\nMETRICS:%{http_code},%{time_total}']
    env = {k: v for k, v in os.environ.items() if k not in PROXY_ENV}
    result = {'source': source, 'round': round_number, 'ok': False, 'ip': None,
              'country': None, 'seconds': None, 'error': None, 'code': None}
    try:
        r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=9)
        body, _, metrics = r.stdout.rpartition('\nMETRICS:')
        status, _, seconds = metrics.partition(',')
        result.update(code=r.returncode, http_status=status or None)
        try:
            result['seconds'] = round(float(seconds), 3)
        except ValueError:
            pass
        if r.returncode or status != '200':
            result['error'] = ({5: '代理解析失败', 6: '域名解析失败', 7: '连接失败',
                                28: '连接或响应超时', 35: 'TLS 连接失败', 60: '证书验证失败'}
                               .get(r.returncode, 'HTTP ' + status if status else '请求未完成'))
            return result
        fields = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
        address = ipaddress.ip_address(fields.get('ip', '') if source == 'Cloudflare' else body.strip())
        if not address.is_global:
            raise ValueError('invalid public address')
        result['actual_family'] = address.version
        if address.version != route['family']:
            result['observed_ip'] = str(address)
            result['error'] = '查询返回 IPv' + str(address.version) + '，未验证请求的地址族'
            return result
        country = fields.get('loc', '')
        result.update(ok=True, ip=str(address),
                      country=country if re.fullmatch('[A-Z]{2}', country) else None)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        result['error'] = '响应无效或请求超时'
    return result


def summarize(route, samples):
    successes = [s for s in samples if s['ok']]
    ips = sorted({s['ip'] for s in successes})
    failures = [s for s in samples if not s['ok']]
    counts = {}
    for s in samples:
        count = counts.setdefault(s['source'], {'success': 0, 'failed': 0})
        count['success' if s['ok'] else 'failed'] += 1
    errors = sorted({s['error'] for s in failures if s['error']})
    durations = [s['seconds'] for s in successes if s['seconds'] is not None]
    return {'id': route['id'], 'label': route['label'], 'family': route['family'],
            'primary': route['primary'], 'ips': ips, 'multi_exit': len(ips) > 1,
            'success': len(successes), 'attempts': len(samples), 'failures': len(failures),
            'median_seconds': round(statistics.median(durations), 3) if durations else None,
            'sources': counts, 'errors': errors,
            'countries': sorted({s['country'] for s in successes if s.get('country')}),
            'samples': samples}


def load_state():
    if not STATE_FILE.exists():
        return {'reference_ip': None, 'history': []}
    if STATE_FILE.stat().st_size > 1048576:
        raise ValueError('出口历史文件过大，请检查本地记录')
    state = json.loads(STATE_FILE.read_text())
    if not isinstance(state, dict) or not isinstance(state.get('history'), list):
        raise ValueError('出口历史不可读取；未覆盖原文件')
    for record in state['history']:
        if not isinstance(record, dict) or not isinstance(record.get('paths'), list):
            raise ValueError('出口历史不可读取；未覆盖原文件')
        for path in record['paths']:
            if not isinstance(path, dict) or not isinstance(path.get('id'), str) or not isinstance(path.get('ips'), list):
                raise ValueError('出口历史不可读取；未覆盖原文件')
            for address in path['ips']:
                if not isinstance(address, str) or not ipaddress.ip_address(address).is_global:
                    raise ValueError('出口历史不可读取；未覆盖原文件')
    if state.get('reference_ip'):
        address = ipaddress.ip_address(state['reference_ip'])
        if address.version != 4 or not address.is_global:
            raise ValueError('固定 IP 参考不可读取；未覆盖原文件')
    return state


def save_state(state):
    STATE_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE_FILE.parent, 0o700)
    temp = STATE_FILE.with_suffix('.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(temp, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(state, out, ensure_ascii=False, indent=2)
    temp.replace(STATE_FILE)


def reference_status(ips, expected):
    if not expected:
        return 'unset'
    if not ips:
        return 'unknown'
    if ips == [expected]:
        return 'match'
    return 'partial' if expected in ips else 'mismatch'


def set_reference(value):
    if not isinstance(value, str):
        raise ValueError('请输入固定 IPv4 地址')
    value = value.strip()
    if value:
        try:
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_global:
                raise ValueError()
        except ValueError:
            raise ValueError('参考必须是有效公网 IPv4 地址') from None
        value = str(address)
    state = load_state()
    state['reference_ip'] = value or None
    save_state(state)
    return {'reference_ip': state['reference_ip']}


def runtime_state():
    text = command(['/usr/sbin/scutil', '--proxy'])
    keys = ('HTTPEnable', 'HTTPProxy', 'HTTPPort', 'HTTPSEnable', 'HTTPSProxy',
            'HTTPSPort', 'SOCKSEnable', 'SOCKSProxy', 'SOCKSPort', 'ProxyAutoConfigEnable')
    proxy = {key: m[1].strip() for key in keys
             if (m := re.search(r'^\s*' + key + r'\s*:\s*(.*?)$', text, re.M))}
    routes = command(['/usr/sbin/netstat', '-rn', '-f', 'inet'])
    routes6 = command(['/usr/sbin/netstat', '-rn', '-f', 'inet6'])
    stable_routes = [' '.join(line.split()[:4]) for line in routes.splitlines()
                     if line.startswith('default') or ('utun' in line and 'UHL' not in line)]
    stable_routes += ['v6 ' + ' '.join(line.split()[:4]) for line in routes6.splitlines()
                      if line.startswith('default')]
    route_id = hashlib.sha256('\n'.join(sorted(stable_routes)).encode()).hexdigest() if routes else None
    dns = command(['/usr/sbin/scutil', '--dns'])
    servers = set(re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', dns))
    processes = command(['/bin/ps', '-axo', 'comm'])
    return {'proxy': proxy, 'route_id': route_id,
            'dns_id': hashlib.sha256('|'.join(sorted(servers)).encode()).hexdigest() if dns else None,
            'dns_server_count': len(servers), 'corporate_dns_hint': 'tencent.com' in dns,
            'tunnel_route_present': 'utun' in routes,
            'clients': [label for token, label in [('SmartVPN', 'iOA SmartVPN'),
                        ('EternalCore', 'Eternal'), ('verge-mihomo', 'Clash')]
                        if token in processes]}


def verdict(primary, expected=None, changed=False, expected_country=None):
    reference = reference_status(primary['ips'], expected)
    countries = primary.get('countries', [])
    if changed:
        return '检测期间网络或代理路径变化，请重新检查', 'warn'
    if reference in ('mismatch', 'partial'):
        return '固定 IP 参考不匹配' if reference == 'mismatch' else '仅部分请求匹配固定 IP', 'warn'
    if len(countries) > 1:
        return '出口国家来源有分歧', 'warn'
    if expected_country and countries and countries != [expected_country]:
        return '观测国家与预期出口不同', 'warn'
    if primary['multi_exit']:
        return '同一路径观测到多个 IPv4 出口', 'warn'
    if not primary['success']:
        return '当前路径的检测请求未完成', 'warn'
    if primary['failures']:
        return '本次出口一致，部分检测请求失败', 'warn'
    if expected_country and not countries:
        return '本次地址一致，出口国家尚未验证', 'warn'
    return '本次多轮检查出口一致', 'good'


def check(proxy, expected_country=None):
    global LAST_REPORT
    started, context = time.monotonic(), network_context()
    context_ids = [context['id']]
    runtime_snapshots = [runtime_state()]
    routes = discover_routes(proxy)
    samples = {r['id']: [] for r in routes}
    def timed_probe(route, source, round_number):
        result = probe(route, source, round_number)
        result['completed_after_seconds'] = round(time.monotonic() - started, 3)
        return result
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for round_number in range(1, 4):
            if round_number > 1:
                context_ids.append(network_context()['id'])
                runtime_snapshots.append(runtime_state())
            jobs = [(r, source, pool.submit(timed_probe, r, source, round_number))
                    for r in routes for source in ('Cloudflare', 'ipify' if r['family'] == 4 else 'ipify IPv6')]
            for route, _, task in jobs:
                samples[route['id']].append(task.result())
            if round_number < 3:
                time.sleep(2)
    after = network_context()
    context_ids.append(after['id'])
    runtime_snapshots.append(runtime_state())
    signatures = [json.dumps({'proxy': s['proxy'], 'route': s['route_id'], 'dns': s.get('dns_id')}, sort_keys=True)
                  for s in runtime_snapshots]
    proxy_changed = len(set(signatures)) > 1
    changed_during = len(set(context_ids)) > 1 or proxy_changed
    paths = [summarize(r, samples[r['id']]) for r in routes]
    primary = next(p for p in paths if p['primary'])
    state_error = None
    try:
        state = load_state()
    except (OSError, ValueError, TypeError, KeyError):
        state = {'reference_ip': None, 'history': []}
        state_error = '本地出口历史不可读取，本次结果未保存'
    previous = next((r for r in reversed(state['history']) if not r.get('changed_during')), None)
    comparable = bool(previous and context['id'] and previous.get('network_id'))
    network_changed = comparable and previous['network_id'] != context['id']
    prior_path = next((p for p in previous.get('paths', []) if p['id'] == primary['id']), None) if previous else None
    changed_since = bool(comparable and not network_changed and prior_path
                         and prior_path.get('ips') and primary['ips'] and prior_path['ips'] != primary['ips'])
    expected = state.get('reference_ip')
    headline, kind = verdict(primary, expected, changed_during, expected_country)
    notes = ['不同 IPv4 / IPv6 地址、不同代理路径不合并为同一路径多出口。',
             'IPv6 查询失败不代表 IPv4 掉线；查询站点失败不直接代表目标应用故障。',
             'IP 改变本身不证明掉线；短测通过不证明长期稳定。']
    if network_changed:
        notes.insert(0, '网络特征与上次不同，换网前后的 IP 变化不自动判为故障。')
    elif changed_since:
        notes.insert(0, '相同网络特征与请求路径下，出口与上次观测不同。')
    ipv4_paths = [p for p in paths if p['family'] == 4 and p['ips']]
    if any(set(p['ips']) != set(primary['ips']) for p in ipv4_paths) and primary['ips']:
        notes.append('不同请求路径的 IPv4 出口不同；目标应用需核实其实际代理路径。')
    if str(proxy.get('ProxyAutoConfigEnable')) == '1':
        notes.append('PAC 已开启，检测不执行 PAC；实际应用路径可能不同。')
    report = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'duration_seconds': round(time.monotonic() - started, 1), 'rounds': 3,
              'context': context, 'changed_during': changed_during,
              'proxy_changed_during': proxy_changed, 'runtime': runtime_snapshots[0],
              'expected_country': expected_country,
              'first_success_seconds': min((s['completed_after_seconds'] for s in primary['samples'] if s['ok']), default=None),
              'network_changed': bool(network_changed), 'changed_since_previous': changed_since,
              'headline': headline, 'kind': kind, 'paths': paths, 'notes': notes,
              'reference_ip': expected, 'reference_status': reference_status(primary['ips'], expected),
              'history_error': state_error}
    if not state_error:
        stored = {'checked_at': report['checked_at'], 'network_id': context['id'],
                  'changed_during': changed_during,
                  'paths': [{k: p[k] for k in ('id', 'family', 'primary', 'ips')} for p in paths]}
        state['history'] = (state['history'] + [stored])[-12:]
        try:
            save_state(state)
        except OSError:
            report['history_error'] = '本地出口历史未保存，本次检测结果仍可查看'
    LAST_REPORT = report
    return report
