"""Local two-network audit, bounded browser import and redacted Markdown export."""
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import time
from zoneinfo import ZoneInfo
import egress

ROOT = Path(__file__).resolve().parent
STORE = egress.STATE_FILE.parent / 'privacy-audit.json'
EXPORT = Path.home() / 'Documents/网络环境检查报告/地区暴露对照报告.md'
LABELS = {'hotspot': '手机热点', 'company': '公司网络'}
SESSIONS = {}


def load():
    if not STORE.exists():
        return {'version': 1, 'networks': {}}
    if STORE.stat().st_size > 1048576:
        raise ValueError('对照历史过大，未覆盖原文件')
    value = json.loads(STORE.read_text())
    if not isinstance(value, dict) or value.get('version') != 1 or not isinstance(value.get('networks'), dict):
        raise ValueError('对照历史不可读取，未覆盖原文件')
    if set(value['networks']) - set(LABELS) or any(not isinstance(x, dict) for x in value['networks'].values()):
        raise ValueError('对照历史不可读取，未覆盖原文件')
    return value


def save(value):
    STORE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STORE.parent, 0o700)
    temp = STORE.with_name(STORE.name + '.' + secrets.token_hex(4) + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
    temp.replace(STORE)


def signature(context, runtime):
    return hashlib.sha256(json.dumps({'network': context.get('id'),
            'proxy': runtime.get('proxy'), 'route': runtime.get('route_id'), 'dns': runtime.get('dns_id')}, sort_keys=True).encode()).hexdigest()


def primary(record):
    return next((p for p in record.get('native', {}).get('paths', []) if p.get('primary')), {})


def findings(record):
    browser = record.get('browser')
    native = record.get('native', {})
    p = primary(record)
    site, local, unknown, repairs = [], [], [], []
    local.append('本机检测：' + native.get('headline', '未验证'))
    runtime = native.get('runtime', {})
    if runtime.get('corporate_dns_hint'):
        local.append('本机 DNS 配置包含公司网络线索；不能据此断言网站可读取该配置。')
    if runtime.get('tunnel_route_present'):
        local.append('存在 TUN 路由；不显式使用代理的请求仍可能经过该路由。')
    geo = record.get('geo')
    if geo:
        for source in geo.get('sources', []):
            if source.get('ok'):
                local.append('出口地址数据库 ' + source.get('source', '') + '：' +
                             ' / '.join(str(source.get(k) or '未提供') for k in ('country_code', 'region', 'city')) +
                             '。这是出口归属参考，不是物理位置证明。')
    unknown.append('真实所在地、精确位置、目标应用的登录与持续会话状态未验证。')
    unknown.append('DNS 检查仅涵盖本机配置；远端递归解析路径未验证。')
    if not browser:
        unknown.append('Chrome 出口、WebRTC、浏览器时区和定位权限尚未导入。')
    else:
        http_ips = sorted({e['ip'] for e in browser['exits'] if e['ok']})
        v4 = [ip for ip in http_ips if ipaddress.ip_address(ip).version == 4]
        site.append('浏览器 HTTP：观测 ' + str(len(http_ips)) + ' 个公网地址，IPv4 与 IPv6 分别比较。')
        countries = sorted({e['country'] for e in browser['exits'] if e['ok'] and e.get('country')})
        if countries:
            site.append('浏览器检测站点国家参考：' + ' / '.join(countries) + ('；与美国预期不同或来源不一致。' if countries != ['US'] else '。'))
        else:
            unknown.append('浏览器出口国家未取得，不能只凭地址一致认定美国出口已验证。')
        if len(v4) > 1:
            site.append('浏览器同一轮测试出现多个 IPv4；目标分流或上游多出口需要进一步核实。')
        if p.get('ips') and v4 and set(p['ips']) != set(v4):
            if set(p['ips']).isdisjoint(v4):
                site.append('浏览器 IPv4 未出现在本机当前路径观测中；采样时点或请求路径差异均需核实。')
            else:
                site.append('浏览器与本机 IPv4 观测部分重合，不能只凭集合差异认定代理路径不同。')
        rtc_ips = sorted({c['ip'] for c in browser['webrtc']['candidates'] if c.get('ip')})
        extra = set(rtc_ips) - set(http_ips)
        if extra:
            site.append('WebRTC 自测返回 HTTP 查询未出现的公网地址；属于额外暴露线索，尚未证明真实所在地。')
            unproxied = next((path for path in native.get('paths', []) if path.get('id') == 'os-ipv4'), {})
            if extra.intersection(unproxied.get('ips', [])):
                site.append('额外 WebRTC 候选与本机不显式使用代理的 IPv4 观测相同；该路径仍可能经过 TUN 或公司网关。')
            repairs.append('打开 Chrome 策略检查，核实 WebRtcIPHandling 是否受管理；企业策略交由管理员处理。')
            repairs.append('在个人代理客户端核实 UDP 接管范围；系统 HTTP 代理不证明 WebRTC UDP 已由同一出口接管。公司 iOA 与 DNS 保持原配置。')
            repairs.append('若需限制非代理 UDP，应通过 Chrome 支持的隐私策略配置；本工具不直接写入策略或安装扩展。调整后复测网页出口与 WebRTC 候选。')
        elif rtc_ips:
            site.append('WebRTC 本轮公网地址均包含在 HTTP 观测中。')
        else:
            unknown.append('本轮未观测到 WebRTC 公网候选；不能据此保证不存在泄漏。')
        site.append('浏览器可见时区：' + str(browser['timezone'] or '未提供') + '；语言：' +
                    ' / '.join(browser['languages']) + '。这些设置不证明物理位置。')
        site.append('本地自测页定位权限：' + browser['geolocation_permission'] + '；未调用精确定位。')
        repairs.append('打开 Chrome 定位权限设置，核对具体网站授权；本地文件权限不能代表这些网站。')
        unknown.append('本地文件自测不能覆盖所有 HTTPS 网站、扩展、PAC 或浏览器配置。')
        if any(not e['ok'] for e in browser['exits']):
            unknown.append('部分浏览器查询失败或受跨域限制，相应路径未验证。')
    if p.get('multi_exit'):
        repairs.append('向服务商确认所选美国节点是否提供同一固定落地 IP；设置节点名称或保存参考不能固定上游分配。')
    return {'site_visible': site, 'native_only': local, 'unverified': unknown, 'repair_steps': repairs}


def start(label, proxy, node_note='', retest=False, lookup=None):
    if label not in LABELS or not isinstance(node_note, str) or len(node_note) > 100:
        raise ValueError('请选择手机热点或公司网络；节点备注最长 100 字')
    if '://' in node_note or '@' in node_note:
        raise ValueError('节点备注只填写名称与模式，不填账号或订阅地址')
    if not isinstance(retest, bool):
        raise ValueError('复测选项不合法')
    report = egress.check(proxy, expected_country='US')
    token = secrets.token_hex(16)
    record = {'session': token, 'label': label, 'node_note': node_note.strip(),
              'checked_at': report['checked_at'], 'native': report, 'browser': None,
              'retest': retest, 'geo': None}
    addresses = primary(record).get('ips', [])
    if lookup and len(addresses) == 1:
        record['geo'] = lookup(addresses[0])
        countries = {s.get('country_code') for s in record['geo'].get('sources', []) if s.get('ok') and s.get('country_code')}
        countries.update(primary(record).get('countries', []))
        if len(countries) > 1:
            report['geo_country_disagreement'] = True
            if report.get('reference_status') not in ('mismatch', 'partial') and not report['changed_during']:
                report['headline'], report['kind'] = '出口国家来源有分歧', 'warn'
    record['findings'] = findings(record)
    state = load()
    state['networks'][label] = record
    save(state)
    now = time.monotonic()
    for key in list(SESSIONS):
        if now - SESSIONS[key]['created'] > 600 or SESSIONS[key]['label'] == label:
            SESSIONS.pop(key)
    SESSIONS[token] = {'created': now, 'label': label,
                       'signature': signature(report['context'], report['runtime'])}
    return {'record': record, 'session': token,
            'browser_url': browser_page(token).as_uri(),
            'comparison': compare(state)}


def browser_page(token):
    if token not in SESSIONS or not re.fullmatch('[a-f0-9]{32}', token):
        raise ValueError('浏览器测试会话不合法')
    template = (ROOT / 'browser_probe.html').read_text()
    marker = "const session=new URLSearchParams(location.hash.slice(1)).get('session')||'';"
    if template.count(marker) != 1:
        raise ValueError('浏览器自测模板不可用')
    page = template.replace(marker, 'const session=' + json.dumps(token) + ';')
    folder = STORE.parent / 'browser-sessions'
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    file = folder / (token + '.html')
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(page)
    os.chmod(file, 0o600)
    return file


def public_ip(value):
    if not isinstance(value, str) or len(value) > 47:
        raise ValueError('浏览器地址格式不合法')
    if value.startswith('[') and value.endswith(']') and ':' in value:
        value = value[1:-1]
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError('导入只接受公网地址，不接受私网地址或本地文件路径')
    return str(address)


def validate_browser(raw):
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > 12000:
        raise ValueError('浏览器结果过大或格式不合法')
    try:
        d = json.loads(raw)
    except ValueError:
        raise ValueError('请粘贴自测页复制的完整 JSON 结果') from None
    keys = {'version', 'session', 'checked_at', 'origin_kind', 'secure_context', 'timezone',
            'languages', 'geolocation_permission', 'webrtc', 'exits'}
    if not isinstance(d, dict) or set(d) != keys or type(d['version']) is not int or d['version'] != 1:
        raise ValueError('浏览器结果字段不合法')
    if not isinstance(d['session'], str) or not re.fullmatch('[a-f0-9]{32}', d['session']):
        raise ValueError('测试会话不合法')
    if d['origin_kind'] != 'local-file' or not isinstance(d['secure_context'], bool):
        raise ValueError('浏览器来源不合法')
    if not isinstance(d['checked_at'], str) or len(d['checked_at']) > 40:
        raise ValueError('检测时间不合法')
    stamp = dt.datetime.fromisoformat(d['checked_at'].replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('检测时间必须包含时区')
    if d['timezone'] is not None:
        if not isinstance(d['timezone'], str) or len(d['timezone']) > 80:
            raise ValueError('浏览器时区不合法')
        try:
            ZoneInfo(d['timezone'])
        except (ValueError, KeyError):
            raise ValueError('浏览器时区不可识别') from None
    if not isinstance(d['languages'], list) or len(d['languages']) > 16 or any(
            not isinstance(v, str) or not re.fullmatch('[A-Za-z0-9-]{2,40}', v) for v in d['languages']):
        raise ValueError('浏览器语言列表不合法')
    if d['geolocation_permission'] not in ('granted', 'denied', 'prompt', 'unsupported'):
        raise ValueError('定位权限状态不合法')
    rtc = d['webrtc']
    if not isinstance(rtc, dict) or set(rtc) != {'status', 'candidates'} or rtc['status'] not in ('complete', 'timeout', 'error', 'unsupported'):
        raise ValueError('WebRTC 状态不合法')
    if not isinstance(rtc['candidates'], list) or len(rtc['candidates']) > 24:
        raise ValueError('WebRTC 结果过大')
    for candidate in rtc['candidates']:
        if not isinstance(candidate, dict) or set(candidate) != {'scope', 'type', 'protocol', 'ip'}:
            raise ValueError('WebRTC 候选字段不合法')
        if candidate['scope'] not in ('public', 'private', 'mdns', 'unknown') or candidate['type'] not in ('host', 'srflx', 'relay', 'prflx', 'unknown') or candidate['protocol'] not in ('udp', 'tcp', ''):
            raise ValueError('WebRTC 候选类型不合法')
        if candidate['scope'] == 'public':
            candidate['ip'] = public_ip(candidate['ip'])
        elif candidate['ip'] is not None:
            raise ValueError('私网和 mDNS 候选不得包含地址原文')
    if not isinstance(d['exits'], list) or len(d['exits']) != 9:
        raise ValueError('浏览器检测需包含三轮、三个来源')
    seen = set()
    for sample in d['exits']:
        if not isinstance(sample, dict) or set(sample) != {'source', 'round', 'ok', 'ip', 'country', 'seconds', 'error'}:
            raise ValueError('出口结果字段不合法')
        key = (sample['source'], sample['round'])
        if sample['source'] not in ('ipify IPv4', 'ipify 双栈', 'Cloudflare') or type(sample['round']) is not int or sample['round'] not in (1, 2, 3) or key in seen:
            raise ValueError('出口来源或轮次不合法')
        seen.add(key)
        if not isinstance(sample['ok'], bool) or type(sample['seconds']) not in (int, float) or not 0 <= sample['seconds'] <= 60:
            raise ValueError('出口状态或耗时不合法')
        if sample['country'] is not None and (not isinstance(sample['country'], str) or not re.fullmatch('[A-Z]{2}', sample['country'])):
            raise ValueError('国家参考不合法')
        if sample['ok']:
            sample['ip'] = public_ip(sample['ip'])
            if sample['error'] is not None:
                raise ValueError('成功记录不应包含错误')
        elif sample['ip'] is not None or sample['error'] not in ('查询超时', '查询失败或跨域受限'):
            raise ValueError('失败记录不合法')
    return d


def import_browser(raw):
    d = validate_browser(raw)
    session = SESSIONS.get(d['session'])
    if not session or time.monotonic() - session['created'] > 600:
        raise ValueError('会话失效或已导入，请重新开始本轮检测')
    context, runtime = egress.network_context(), egress.runtime_state()
    if not context.get('id') or signature(context, runtime) != session['signature']:
        raise ValueError('网络或代理路径已变化，请在当前网络重新检测')
    state = load()
    record = state['networks'].get(session['label'])
    if not record or record.get('session') != d['session'] or record['native'].get('changed_during'):
        raise ValueError('结果不属于当前轮次或本轮网络不稳定，请重测')
    record['browser'] = d
    record['findings'] = findings(record)
    save(state)
    SESSIONS.pop(d['session'])
    return {'record': record, 'comparison': compare(state)}


def compare(state=None):
    state = state if state is not None else load()
    networks = state['networks']
    a, b = networks.get('hotspot'), networks.get('company')
    statuses = {key: ('未验证' if key not in networks else
                     '采样路径变化，需重测' if networks[key].get('native', {}).get('changed_during') else
                     '本机完成，浏览器未验证' if not networks[key].get('browser') else '本机与浏览器已采集') for key in LABELS}
    notes = []
    if not a or not b:
        return {'statuses': statuses, 'headline': '等待两种网络的实测', 'comparable': False, 'notes': notes}
    pa, pb = primary(a), primary(b)
    same_proxy = a['native'].get('runtime', {}).get('proxy') == b['native'].get('runtime', {}).get('proxy')
    same_node = bool(a.get('node_note')) and a['node_note'] == b.get('node_note')
    valid = not a['native'].get('changed_during') and not b['native'].get('changed_during') and bool(pa.get('success') and pb.get('success'))
    if not same_proxy:
        notes.append('两轮系统代理设置不同，出口差异不能只归因于热点或公司网络。')
    same_clients = a['native'].get('runtime', {}).get('clients') == b['native'].get('runtime', {}).get('clients')
    if not same_clients:
        notes.append('两轮网络客户端运行状态不同，需核实接管方式。')
    if not same_node:
        notes.append('未获得两轮相同的节点与模式备注，节点条件尚未核实。')
    else:
        notes.append('节点与模式一致依据用户备注；软件未读取代理账号或订阅。')
    ca, cb = a['native'].get('context', {}).get('id'), b['native'].get('context', {}).get('id')
    if not ca or not cb or ca == cb:
        notes.append('物理网络特征未明确区分两种网络，网络身份仍依赖用户标记。')
    distinct_networks = bool(ca and cb and ca != cb)
    try:
        interval = abs((dt.datetime.fromisoformat(a['checked_at']) - dt.datetime.fromisoformat(b['checked_at'])).total_seconds())
        recent_pair = interval <= 1800
    except (ValueError, TypeError, KeyError):
        recent_pair = False
    if not recent_pair:
        notes.append('两轮采样时间相隔超过三十分钟或时间不可核实，建议相邻复测。')
    if not valid:
        notes.append('有检测未完成或采样期间路径变化，无法建立稳定出口对照。')
    ips_equal = bool(pa.get('ips') and pb.get('ips') and set(pa['ips']) == set(pb['ips']))
    headline = ('两轮出口集合相同，但未证明固定出口' if len(pa.get('ips', [])) > 1 else '两种网络本轮出口一致') if ips_equal and valid else '两种网络出口不同或证据未齐'
    return {'statuses': statuses, 'headline': headline, 'comparable': bool(valid and same_proxy and same_clients and same_node and distinct_networks and recent_pair),
            'same_exit': ips_equal, 'notes': notes}


def summary():
    state = load()
    for record in state['networks'].values():
        record['findings'] = findings(record)
    return {'comparison': compare(state), 'records': list(state['networks'].values())}


def export():
    state = load()
    comparison = compare(state)
    lines = ['# 热点与公司网络地区暴露对照报告', '',
             '生成时间：' + dt.datetime.now(dt.timezone.utc).isoformat(), '',
             '预期出口：美国。IP、网络名称、节点备注及公司网络细节已隐藏。', '',
             '## 对照结论', '', comparison['headline'], '',
             '因果比较条件：' + ('本轮代理设置与节点备注一致' if comparison['comparable'] else '条件或证据未齐，不能只归因于网络'), '']
    lines += ['- ' + note for note in comparison['notes']]
    aliases = {}
    def alias(address):
        if address not in aliases:
            aliases[address] = '公网地址-' + str(len(aliases) + 1)
        return aliases[address]
    for label, name in LABELS.items():
        lines += ['', '## ' + name, '', '状态：' + comparison['statuses'][label], '']
        record = state['networks'].get(label)
        if not record:
            continue
        native = record['native']
        lines += ['采样时间：' + record['checked_at'], '', '本机结果：' + native['headline'], '',
                  '从点击检测到首次成功请求：' + str(native.get('first_success_seconds', '未验证')) + ' 秒。此值不是实际换网总耗时。', '']
        for index, path in enumerate(native['paths'], 1):
            lines.append('- 请求路径 ' + str(index) + '（IPv' + str(path['family']) + '）：' +
                         str(path['success']) + '/' + str(path['attempts']) + ' 成功；' +
                         (' / '.join(alias(ip) for ip in path['ips']) or '未取得有效地址／未验证') + '；国家参考 ' +
                         (' / '.join(path.get('countries', [])) or '未验证') +
                         ('；失败项：' + ' / '.join(path['errors']) if path.get('errors') else ''))
        browser = record.get('browser')
        if browser:
            ips = sorted({sample['ip'] for sample in browser['exits'] if sample['ok']})
            rtc = sorted({candidate['ip'] for candidate in browser['webrtc']['candidates'] if candidate.get('ip')})
            lines += ['', '浏览器 HTTP：' + ' / '.join(alias(ip) for ip in ips),
                      'WebRTC：' + (' / '.join(alias(ip) for ip in rtc) or '未观测到公网候选')]
        for key, title in [('site_visible', '网站可见'), ('native_only', '本机应用可读'), ('unverified', '尚未验证'), ('repair_steps', '处理建议')]:
            lines += ['', '### ' + title, '']
            # Corporate and city database details stay in the private local UI, not exported.
            items = findings(record).get(key, [])
            if key == 'native_only':
                items = ['本机路由、DNS 与出口归属参考已检查，具体细节仅保留在本机。']
            lines += ['- ' + item for item in items]
    lines += ['', '浏览器记录为用户导入的自测结果；会话校验防止混轮，不能提供不可伪造的真实性证明。',
              '本地文件的权限与 WebRTC 行为不能覆盖所有网站；IP 数据库不证明真实物理位置。', '']
    text = '\n'.join(lines)
    EXPORT.parent.mkdir(parents=True, exist_ok=True)
    if EXPORT.exists() and not EXPORT.read_text().startswith('# 热点与公司网络地区暴露对照报告'):
        raise ValueError('报告路径存在其他文件，未覆盖')
    EXPORT.write_text(text)
    os.chmod(EXPORT, 0o600)
    return {'path': str(EXPORT), 'comparison': comparison}
