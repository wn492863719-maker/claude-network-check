#!/usr/bin/env python3
"""Desktop diagnostics worker. JSON over stdio; no listening socket."""
import concurrent.futures
import datetime as dt
import email.utils
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import subprocess
import threading
import time
import urllib.request
from zoneinfo import ZoneInfo
import egress
import privacy_audit

ROOT = Path(__file__).resolve().parent
STORE = Path.home() / 'Library/Application Support/Network Environment Check/restore-points'
EXIT_TARGETS = []
PROXY_TYPES = {
    'http': ('-getwebproxy', '-setwebproxystate'),
    'https': ('-getsecurewebproxy', '-setsecurewebproxystate'),
    'socks': ('-getsocksfirewallproxy', '-setsocksfirewallproxystate'),
    'pac': ('-getautoproxyurl', '-setautoproxystate'),
    'discovery': ('-getproxyautodiscovery', '-setproxyautodiscoverystate'),
}
PLANS = {}
LOCK = threading.Lock()


def run(args, timeout=12):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {'ok': r.returncode == 0, 'code': r.returncode,
                'text': r.stdout.strip(), 'error': r.stderr.strip()[:300]}
    except (OSError, subprocess.TimeoutExpired):
        return {'ok': False, 'code': -1, 'text': '', 'error': '命令不可用或执行超时'}


def preference(key):
    r = run(['/usr/bin/defaults', 'read', '-g', key])
    if not r['ok']:
        return None
    if key == 'AppleLanguages':
        # defaults renders arrays using old-style plist syntax.
        return re.findall(r'"([A-Za-z0-9_-]+)"', r['text']) or re.findall(
            r'^\s*([A-Za-z][A-Za-z0-9_-]*)\s*,?\s*$', r['text'], re.M)
    return r['text']


def system_timezone():
    try:
        return str(Path('/etc/localtime').resolve()).split('/zoneinfo/', 1)[1]
    except (OSError, IndexError):
        return None


def proxy_state(service, kind):
    r = run(['/usr/sbin/networksetup', PROXY_TYPES[kind][0], service])
    m = re.search(r'(?:Enabled|Auto Proxy Discovery):\s*(Yes|No|On|Off)', r['text'], re.I)
    return (m.group(1).lower() in ('yes', 'on')) if r['ok'] and m else None


def snapshot():
    if platform.system() != 'Darwin':
        return {'platform': platform.system(), 'timezone': None, 'locale': None,
                'languages': None, 'services': {}, 'proxy_states': {}}
    r = run(['/usr/sbin/networksetup', '-listallnetworkservices'])
    names = [n.strip() for n in r['text'].splitlines()[1:]
             if n.strip() and not n.startswith('*')] if r['ok'] else []
    names = names[:30]
    states = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {(name, kind): pool.submit(proxy_state, name, kind)
                   for name in names for kind in PROXY_TYPES}
        for (name, kind), task in futures.items():
            states.setdefault(name, {})[kind] = task.result()
    return {'platform': platform.system(), 'timezone': system_timezone(),
            'locale': preference('AppleLocale'), 'languages': preference('AppleLanguages'),
            'proxy_states': states}


def safe_proxy_summary():
    r = run(['/usr/sbin/scutil', '--proxy'])
    # Report only state, host and port; PAC URL and bypass lists are omitted.
    keys = ('HTTPEnable', 'HTTPProxy', 'HTTPPort', 'HTTPSEnable', 'HTTPSProxy',
            'HTTPSPort', 'SOCKSEnable', 'SOCKSProxy', 'SOCKSPort',
            'ProxyAutoConfigEnable', 'ProxyAutoDiscoveryEnable')
    return {k: m.group(1).strip() for k in keys
            if (m := re.search(r'^\s*' + k + r'\s*:\s*(.*?)$', r['text'], re.M))}


def local_scan():
    state = snapshot()
    dns = run(['/usr/sbin/scutil', '--dns']) if state['platform'] == 'Darwin' else {'text': ''}
    servers = sorted(set(re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', dns['text'])))
    route = run(['/sbin/route', '-n', 'get', 'default']) if state['platform'] == 'Darwin' else {'text': ''}
    interface = re.search(r'interface:\s*(\S+)', route['text'])
    interfaces = run(['/sbin/ifconfig', '-l']) if state['platform'] == 'Darwin' else {'text': ''}
    tunnels = [v for v in interfaces['text'].split() if v.startswith(('utun', 'tun', 'tap'))]
    # Environment values can contain passwords. Only expose presence.
    env_names = [k for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                            'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy') if os.environ.get(k)]
    return {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'system': state,
            'effective_proxy': safe_proxy_summary() if state['platform'] == 'Darwin' else {},
            'dns_servers': servers, 'default_interface': interface.group(1) if interface else None,
            'tunnel_interfaces': tunnels, 'proxy_environment_names': env_names,
            'timezone_environment': os.environ.get('TZ'),
            'network_note': 'utun 也可能由 Apple 服务创建；不能据此断定 VPN 正在使用。DNS 地址不是出口位置。'}


def request_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Claude-Network-Check/2.2.1',
                                              'Accept': 'application/json'})
    start = time.time()
    with urllib.request.urlopen(req, timeout=10) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('响应过大')
        date = response.headers.get('Date')
        clock = None
        if date:
            remote = email.utils.parsedate_to_datetime(date).timestamp()
            clock = round(remote - ((start + time.time()) / 2), 1)
        return json.loads(raw), clock


def geo_lookup(address):
    ip = ipaddress.ip_address(address)
    if not ip.is_global:
        raise ValueError('不是公网 IP')
    sources = []
    for label, url in [('ipwho.is', 'https://ipwho.is/' + str(ip)),
                       ('ipapi.co', 'https://ipapi.co/' + str(ip) + '/json/')]:
        try:
            data, _ = request_json(url)
            if data.get('success') is False or data.get('error'):
                raise ValueError('查询被限流或拒绝')
            if label == 'ipwho.is':
                connection = data.get('connection') or {}
                result = {'country': data.get('country'), 'country_code': data.get('country_code'),
                          'region': data.get('region'), 'city': data.get('city'),
                          'isp': connection.get('isp'), 'asn': connection.get('asn'),
                          'timezone': (data.get('timezone') or {}).get('id')}
            else:
                result = {'country': data.get('country_name'), 'country_code': data.get('country_code'),
                          'region': data.get('region'), 'city': data.get('city'),
                          'isp': data.get('org'), 'asn': data.get('asn'), 'timezone': data.get('timezone')}
            if not result['country_code']:
                raise ValueError('缺少地区数据')
            sources.append({'source': label, 'ok': True, **result})
        except (OSError, ValueError, TypeError, KeyError):
            sources.append({'source': label, 'ok': False, 'error': '查询失败、超时或限流'})
    return {'ip': str(ip), 'sources': sources}


def network_scan():
    def probe(label, url):
        try:
            data, clock = request_json(url)
            address = str(ipaddress.ip_address(data['ip']))
            return {'source': label, 'ok': True, 'ip': address,
                    'clock_delta_seconds': clock, 'geo': geo_lookup(address)}
        except (OSError, ValueError, TypeError, KeyError):
            return {'source': label, 'ok': False, 'error': '连接失败、超时或响应不可用'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        tasks = [pool.submit(probe, '本地程序 IPv4', 'https://api.ipify.org?format=json'),
                 pool.submit(probe, '本地程序双栈', 'https://api64.ipify.org?format=json')]
        return {'observations': [t.result() for t in tasks],
                'note': '这是 Python 本地服务对检测站点的出口；PAC、浏览器扩展及分流可能使 Claude 使用不同出口。'}


def configured_local_proxy(service, kind, check_connection=True):
    if kind not in ('http', 'https', 'socks'):
        raise ValueError('启用仅支持已配置的本地 HTTP、HTTPS 或 SOCKS 代理')
    response = run(['/usr/sbin/networksetup', PROXY_TYPES[kind][0], service])
    server = re.search(r'^Server:\s*(\S+)', response['text'], re.M)
    port = re.search(r'^Port:\s*(\d+)', response['text'], re.M)
    if not response['ok'] or not server or not port or server[1] not in ('127.0.0.1', '::1', 'localhost'):
        raise ValueError('当前类型没有已配置的本地代理；请在系统设置中配置')
    endpoint = (server[1], int(port[1]))
    if not 1 <= endpoint[1] <= 65535:
        raise ValueError('本地代理端口不合法')
    try:
        import socket
        if check_connection:
            with socket.create_connection(endpoint, timeout=1):
                pass
    except OSError:
        raise ValueError('已配置的本地代理端口不可连接，未启用') from None
    return {'host': endpoint[0], 'port': endpoint[1]}


def proxy_enable_guard():
    enrollment = run(['/usr/bin/profiles', 'status', '-type', 'enrollment'])
    processes = run(['/bin/ps', '-axo', 'comm'])
    text = enrollment['text']
    if not enrollment['ok'] or not processes['ok'] or 'MDM enrollment: No' not in text or 'Enrolled via DEP: No' not in text:
        raise ValueError('未确认设备为非受管理环境；只提供系统设置入口')
    if 'SmartVPN' in processes['text'] or '/Applications/iOA/' in processes['text']:
        raise ValueError('iOA 正在运行，自动启用代理可能改变公司网络路径；请使用系统设置')


def make_plan(options):
    if not isinstance(options, dict) or set(options) - {'fields', 'target_index', 'proxy'}:
        raise ValueError('修复选项不合法')
    fields = options.get('fields', [])
    proxy = options.get('proxy')
    if not isinstance(fields, list) or any(f not in ('timezone', 'locale') for f in fields):
        raise ValueError('只能对齐时区与地区格式')
    fields = list(dict.fromkeys(fields))
    if proxy is not None and (fields or not isinstance(proxy, dict) or set(proxy) not in ({'service', 'kind'}, {'service', 'kind', 'enabled'})
                             or not isinstance(proxy.get('service'), str) or proxy.get('kind') not in PROXY_TYPES
                             or ('enabled' in proxy and not isinstance(proxy['enabled'], bool))):
        raise ValueError('代理必须按服务与类型单独处理')
    state = snapshot()
    if state['platform'] != 'Darwin':
        raise ValueError('自动修复仅支持 macOS')
    actions = []
    if fields:
        index = options.get('target_index')
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(EXIT_TARGETS):
            raise ValueError('请先检测出口并选择有效参考值')
        target = EXIT_TARGETS[index]
        if time.monotonic() - target['detected_at'] > 300:
            raise ValueError('出口检测已超过五分钟，请重新检查后再对齐')
        if 'timezone' in fields and state['timezone'] != target['timezone']:
            if not state['timezone']:
                raise ValueError('无法保存原时区，请使用系统设置')
            ZoneInfo(state['timezone'])
            actions.append({'kind': 'timezone', 'before': state['timezone'], 'after': target['timezone'],
                            'label': '时区：' + state['timezone'] + ' → ' + target['timezone']})
        if 'locale' in fields and state['locale'] != target['locale']:
            actions.append({'kind': 'locale', 'before': state['locale'], 'after': target['locale'],
                            'label': '地区格式：' + (state['locale'] or '默认') + ' → ' + target['locale']})
    if proxy:
        service, kind = proxy['service'], proxy['kind']
        if service not in state['proxy_states']:
            raise ValueError('网络服务不存在，请重新检查')
        enabled = state['proxy_states'][service][kind]
        if enabled is None:
            raise ValueError('无法读取此项代理状态，请使用系统设置')
        desired = proxy.get('enabled', False)
        endpoint = None
        network_id = None
        if desired:
            proxy_enable_guard()
            endpoint = configured_local_proxy(service, kind)
            network_id = egress.network_context().get('id')
            if not network_id:
                raise ValueError('未取得当前网络特征，不能安全预览启用')
        if enabled != desired:
            actions.append({'kind': 'proxy', 'service': service, 'proxy_kind': kind,
                            'before': enabled, 'after': desired,
                            **({'endpoint': endpoint} if endpoint else {}),
                            **({'network_context_id': network_id} if desired else {}),
                            'label': ('仅启用 ' if desired else '仅关闭 ') + service + ' 的 ' + kind.upper() + ' 代理'})
    plan_id = secrets.token_urlsafe(24)
    PLANS[plan_id] = {'created': time.monotonic(), 'actions': actions, 'state': state,
                      'reference': target.copy() if fields else None}
    for old_id in list(PLANS):
        if time.monotonic() - PLANS[old_id]['created'] > 300:
            PLANS.pop(old_id, None)
    return {'plan_id': plan_id, 'actions': actions,
            'admin_required': any(a['kind'] != 'locale' for a in actions)}


def protected_command(action, restore=False):
    value = action['before'] if restore else action['after']
    if action['kind'] == 'timezone':
        ZoneInfo(value)
        return ['/usr/sbin/systemsetup', '-settimezone', value]
    if action['kind'] == 'proxy':
        if not isinstance(value, bool):
            raise ValueError('代理恢复值不合法')
        return ['/usr/sbin/networksetup', PROXY_TYPES[action['proxy_kind']][1],
                action['service'], 'on' if value else 'off']
    raise ValueError('命令类型不合法')


def execute_actions(actions, restore=False):
    results = []
    root_actions = [(i, a) for i, a in enumerate(actions) if a['kind'] != 'locale']
    root_status = {}
    if root_actions:
        # A single native administrator prompt. Only fixed commands, individually quoted args.
        script_parts = []
        for i, action in root_actions:
            cmd = shlex.join(protected_command(action, restore))
            script_parts.append(f"if {cmd} >/dev/null 2>&1; then printf 'NZ_OK:{i}\\n'; else printf 'NZ_FAIL:{i}\\n'; fi")
        shell_script = '\n'.join(script_parts)
        literal = '"' + shell_script.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
        r = run(['/usr/bin/osascript', '-e', 'do shell script ' + literal + ' with administrator privileges'], timeout=180)
        for i, _ in root_actions:
            root_status[i] = r['ok'] and ('NZ_OK:' + str(i)) in r['text'].splitlines()
        authorization_completed = r['ok']
    else:
        authorization_completed = True
    for i, action in enumerate(actions):
        if action['kind'] == 'locale':
            value = action['before'] if restore else action['after']
            cmd = ['/usr/bin/defaults', 'delete', '-g', 'AppleLocale'] if value is None else [
                '/usr/bin/defaults', 'write', '-g', 'AppleLocale', '-string', value]
            # If the user cancels the administrator prompt, do not write optional preferences.
            ok = run(cmd)['ok'] if authorization_completed else False
        else:
            ok = root_status[i]
        # Command success is not enough; re-read the setting.
        expected = action['before'] if restore else action['after']
        if ok:
            actual = system_timezone() if action['kind'] == 'timezone' else (
                preference('AppleLocale') if action['kind'] == 'locale' else
                proxy_state(action['service'], action['proxy_kind']))
            ok = actual == expected
        results.append({'action': action, 'ok': ok,
                        'message': '已回读确认' if ok else '未确认成功；可能取消了授权、权限不足或设置未生效'})
    return results


def save_record(record):
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STORE, 0o700)
    file = STORE / (record['id'] + '.json')
    # Private files; no tokens, chat contents or proxy credentials.
    temp = file.with_suffix('.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(record, out, ensure_ascii=False, indent=2)
    temp.replace(file)


def apply_plan(plan_id):
    with LOCK:
        plan = PLANS.pop(plan_id, None)
        if not plan or time.monotonic() - plan['created'] > 300:
            raise ValueError('预览已过期或已执行，请重新预览')
        if not plan['actions']:
            return {'results': [], 'restore_id': None}
        if snapshot() != plan['state']:
            raise ValueError('系统设置已变化，请重新检测并预览')
        for action in plan['actions']:
            if action['kind'] == 'proxy' and action['after']:
                proxy_enable_guard()
                if egress.network_context().get('id') != action['network_context_id']:
                    raise ValueError('网络已变化，未修改代理设置')
                if configured_local_proxy(action['service'], action['proxy_kind']) != action['endpoint']:
                    raise ValueError('代理端点已变化，未修改设置')
        reference = plan.get('reference')
        if reference:
            current = network_scan()
            matching = [g for observation in current['observations']
                        for g in observation.get('geo', {}).get('sources', [])
                        if g.get('ok') and g.get('country_code') == reference['country']
                        and g.get('timezone') == reference['timezone']]
            if not matching:
                raise ValueError('出口参考已变化或无法复核，请重新检查；没有修改设置')
        record = {'id': dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(4),
                  'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'actions': plan['actions'], 'results': None}
        save_record(record)
        record['results'] = execute_actions(plan['actions'])
        save_record(record)
        return {'results': record['results'], 'restore_id': record['id']}


def restore_record(record_id):
    if not isinstance(record_id, str) or not re.fullmatch(r'\d{8}T\d{6}Z-[a-f0-9]{8}', record_id):
        raise ValueError('恢复记录不合法')
    with LOCK:
        record = json.loads((STORE / (record_id + '.json')).read_text())
        actions = record['actions']
        # Apply only settings that still match the tool's recorded value.
        for a in actions:
            if a.get('endpoint') and configured_local_proxy(a['service'], a['proxy_kind'], False) != a['endpoint']:
                raise ValueError('代理端点已被其他程序修改，停止恢复')
            actual = system_timezone() if a['kind'] == 'timezone' else (
                preference('AppleLocale') if a['kind'] == 'locale' else
                proxy_state(a['service'], a['proxy_kind']))
            if actual not in (a['before'], a['after']):
                raise ValueError('设置已被其他程序修改，停止恢复以免覆盖；请在系统设置中调整')
        results = execute_actions(actions, restore=True)
        record['restored_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
        record['restore_results'] = results
        save_record(record)
        return {'results': results}


def restore_list():
    items = []
    if STORE.exists():
        for p in sorted(STORE.glob('*.json'), reverse=True)[:30]:
            try:
                data = json.loads(p.read_text())
                items.append({'id': data['id'], 'created_at': data['created_at'],
                              'labels': [a['label'] for a in data['actions']]})
            except (OSError, ValueError, KeyError):
                continue
    return items


def detect(include_network=True):
    global EXIT_TARGETS
    EXIT_TARGETS = []
    local = local_scan()
    network = network_scan() if include_network else {'observations': []}
    targets = []
    seen = set()
    for observation in network['observations']:
        for source in observation.get('geo', {}).get('sources', []):
            country, timezone = source.get('country_code'), source.get('timezone')
            if not source.get('ok') or not re.fullmatch(r'[A-Z]{2}', country or '') or not timezone:
                continue
            try:
                ZoneInfo(timezone)
            except (ValueError, KeyError):
                continue
            key = (country, timezone)
            if key not in seen:
                seen.add(key)
                targets.append({'country': country, 'country_name': source.get('country') or country,
                                'timezone': timezone, 'locale': 'en_' + country,
                                'ip': observation['ip'], 'sources': [source['source']],
                                'detected_at': time.monotonic()})
            else:
                item = next(t for t in targets if (t['country'], t['timezone']) == key)
                if source['source'] not in item['sources']:
                    item['sources'].append(source['source'])
    EXIT_TARGETS = targets
    # Native worker consults current system proxy settings instead of inherited CLI overrides.
    return {'local': local, 'network': network, 'targets': targets,
            'checked_at': dt.datetime.now(dt.timezone.utc).isoformat()}


def dispatch(method, payload):
    if not isinstance(payload, dict):
        raise ValueError('请求格式不合法')
    if method == 'scan':
        include = payload.get('network', True)
        if not isinstance(include, bool):
            raise ValueError('查询选项不合法')
        return detect(include)
    if method == 'preview':
        return make_plan(payload.get('options', {}))
    if method == 'egress':
        if payload:
            raise ValueError('出口检查不接受自定义目标或命令')
        return egress.check(safe_proxy_summary(), expected_country='US')
    if method == 'egress_reference':
        if set(payload) != {'ip'}:
            raise ValueError('固定 IP 参考格式不合法')
        return egress.set_reference(payload['ip'])
    if method == 'privacy_start':
        if set(payload) - {'label', 'node_note', 'retest'}:
            raise ValueError('会话参数不合法')
        return privacy_audit.start(payload.get('label'), safe_proxy_summary(),
                                   payload.get('node_note', ''), payload.get('retest', False), geo_lookup)
    if method == 'privacy_import':
        if set(payload) != {'text'}:
            raise ValueError('导入参数不合法')
        return privacy_audit.import_browser(payload['text'])
    if method == 'privacy_summary':
        if payload:
            raise ValueError('查询参数不合法')
        return privacy_audit.summary()
    if method == 'privacy_export':
        if payload:
            raise ValueError('导出参数不合法')
        return privacy_audit.export()
    if method == 'privacy_browser':
        if set(payload) != {'session'} or payload['session'] not in privacy_audit.SESSIONS:
            raise ValueError('请先开始有效测试会话')
        token = payload['session']
        if time.monotonic() - privacy_audit.SESSIONS[token]['created'] > 600:
            raise ValueError('测试会话已过期')
        url = privacy_audit.browser_page(token).as_uri()
        if not run(['/usr/bin/open', '-a', 'Google Chrome', url])['ok']:
            raise ValueError('无法打开 Chrome；请确认浏览器已安装')
        return {'ok': True}
    if method == 'apply':
        return apply_plan(payload.get('plan_id', ''))
    if method == 'restore':
        return restore_record(payload.get('id'))
    if method == 'records':
        return {'items': restore_list()}
    if method == 'settings':
        urls = {'time': 'x-apple.systempreferences:com.apple.Date-Time-Settings.extension',
                'network': 'x-apple.systempreferences:com.apple.Network-Settings.extension',
                'browser_location': 'chrome://settings/content/location',
                'browser_policy': 'chrome://policy',
                'language': 'x-apple.systempreferences:com.apple.Localization-Settings.extension'}
        pane = payload.get('pane')
        if pane not in urls:
            raise ValueError('设置入口不合法')
        cmd = ['/usr/bin/open', '-a', 'Google Chrome', urls[pane]] if pane.startswith('browser_') else ['/usr/bin/open', urls[pane]]
        return {'ok': run(cmd)['ok']}
    raise ValueError('操作不受支持')


def bridge_main():
    import sys
    for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
        os.environ.pop(name, None)
    for line in sys.stdin:
        request = {}
        try:
            if len(line.encode('utf-8')) > 32768:
                raise ValueError('请求过大')
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError('请求格式不合法')
            result = dispatch(request.get('method'), request.get('payload', {}))
            response = {'id': request.get('id'), 'ok': True, 'result': result}
        except Exception as error:
            message = str(error)[:250] if isinstance(error, (ValueError, TypeError, KeyError, FileNotFoundError)) else '操作未完成，请重新检查'
            response = {'id': request.get('id') if isinstance(request, dict) else None,
                        'ok': False, 'error': message}
        print(json.dumps(response, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    bridge_main()
