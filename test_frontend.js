// Offline native bridge tests. No real browser, network or system mutations.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/index.html', 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];

class Element {
  constructor() { this.listeners = {}; this.style = {}; this.dataset = {}; this.textContent = '';
    this.disabled = false; this.value = '0'; this.classList = {add() {}, remove() {}}; }
  addEventListener(event, callback) { this.listeners[event] = callback; }
  showModal() { this.open = true; }
  close() { this.open = false; }
  insertAdjacentHTML() { this.value = '-1'; }
}

function setup({native = true, targets = 1, offline = false, egressError = false} = {}) {
  let context;
  const elements = new Map(), requests = [];
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const entries = Array.from({length: targets}, (_, i) => ({country: i ? 'NZ' : 'US',
    country_name: i ? 'New Zealand' : 'United States',
    timezone: i ? 'Pacific/Auckland' : 'America/New_York', locale: i ? 'en_NZ' : 'en_US', sources: ['fixture']}));
  const state = {timezone: 'Pacific/Auckland', locale: 'en_NZ', proxy_states: {
    'Wi-Fi': {http: true, https: true, socks: true, pac: false, discovery: false}}};
  const report = {local: {system: state, dns_servers: [], tunnel_interfaces: [], default_interface: 'en0'},
    targets: entries, network: {observations: []}};
  const postMessage = request => {
    requests.push(request);
    queueMicrotask(() => {
      let result = {};
      if (offline && request.method === 'scan')
        return context.window.nativeResult({id: request.id, ok: false, error: 'offline'});
      if (request.method === 'scan') result = report;
      else if (request.method === 'records') result = {items: []};
      else if (request.method === 'egress') {
        if(egressError)return context.window.nativeResult({id:request.id,ok:false,error:'出口检查失败'});
        result={headline:'本次多轮检查出口一致',checked_at:new Date().toISOString(),rounds:3,duration_seconds:15,
          reference_ip:null,reference_status:'unset',notes:['IPv4 / IPv6 分开比较'],paths:[
            {id:'fixture',label:'系统 HTTPS 代理',family:4,primary:true,ips:['8.8.8.8'],multi_exit:false,
             success:6,attempts:6,failures:0,median_seconds:0.5,errors:[],countries:['US'],samples:[
               {round:1,source:'<unsafe>',ok:false,error:'<error>',seconds:0.2}]}]};
      }
      else if (request.method === 'egress_reference') result={reference_ip:request.payload.ip||null};
      else if (request.method === 'privacy_summary') result={records:[],comparison:{headline:'等待两种网络的实测',statuses:{company:'未验证',hotspot:'未验证'},notes:[]}};
      else if (request.method === 'privacy_start') result={session:'a'.repeat(32),record:{native:{headline:'本次多轮检查出口一致',checked_at:new Date().toISOString(),rounds:3,duration_seconds:2,paths:[],notes:[],reference_status:'unset'},findings:{site_visible:['<unsafe>'],native_only:[],unverified:['未验证']}},comparison:{headline:'等待两种网络的实测',statuses:{company:'本机完成，浏览器未验证',hotspot:'未验证'},notes:[]}};
      else if (request.method === 'privacy_import') return context.window.nativeResult({id:request.id,ok:false,error:'会话失效'});
      else if (request.method === 'preview') result = {plan_id: 'test', admin_required: true,
        actions: [{label: JSON.stringify(request.payload.options)}]};
      context.window.nativeResult({id: request.id, ok: true, result});
    });
  };
  context = vm.createContext({console, Date, String, Object, Number, Set, Map, Promise, Array,
    setTimeout() { return 1; }, clearTimeout() {}, setInterval() { return 1; }, clearInterval() {}, Math,
    document: {getElementById: get, querySelectorAll() { return []; }},
    window: native ? {webkit: {messageHandlers: {environment: {postMessage}}}} : {}});
  vm.runInContext(source + '\nthis.hooks={scan,preview,handle:()=>data};', context);
  return {get, requests, hooks: context.hooks};
}

(async () => {
  let app = setup();
  await app.hooks.scan();
  assert.equal(app.get('align').disabled, false);
  assert.equal(app.get('fixTimezone').disabled, false);
  assert(app.get('proxies').innerHTML.includes('data-proxy="http"'));
  await app.get('fixTimezone').listeners.click();
  let request = app.requests.find(r => r.method === 'preview');
  assert.equal(JSON.stringify(request.payload.options.fields), '["timezone"]');
  assert.equal(app.get('dialog').open, true);
  await app.get('cancel').listeners.click();
  assert(!app.requests.some(r => r.method === 'apply'));
  await app.get('align').listeners.click();
  request = app.requests.filter(r => r.method === 'preview').at(-1);
  assert.equal(JSON.stringify(request.payload.options.fields), '["timezone","locale"]');

  app = setup({targets: 2});
  await app.hooks.scan();
  assert.equal(app.get('align').disabled, true);
  app.get('target').value = '0';
  app.get('target').listeners.change();
  assert.equal(app.get('align').disabled, false);

  app = setup({targets: 0});
  await app.hooks.scan();
  assert.equal(app.get('align').disabled, true);

  app = setup({offline: true});
  await app.hooks.scan();
  assert.equal(app.get('scan').disabled, false);
  assert.equal(app.get('status').textContent, 'offline');

  app = setup({native: false});
  assert.equal(app.get('scan').disabled, true);
  assert.equal(app.get('stability').disabled, true);
  assert.equal(app.requests.length, 0);
  app=setup();
  await app.get('stability').listeners.click();
  assert.equal(app.get('stability').disabled,false);
  assert.equal(app.get('stabilityHeadline').textContent,'本次多轮检查出口一致');
  assert(app.get('stabilityPaths').innerHTML.includes('&lt;unsafe&gt;'));
  assert(!app.get('stabilityPaths').innerHTML.includes('<unsafe>'));
  app.get('referenceIP').value='1.1.1.1';
  await app.get('saveReference').listeners.click();
  assert(app.get('referenceState').textContent.includes('不同'));
  app.get('referenceIP').value='8.8.8.8';
  await app.get('saveReference').listeners.click();
  assert(app.get('referenceState').textContent.includes('一致'));
  assert(!app.requests.some(r=>['apply','restore'].includes(r.method)));
  app=setup({egressError:true});
  await app.get('stability').listeners.click();
  assert.equal(app.get('stability').disabled,false);
  assert.equal(app.get('status').textContent,'出口检查失败');
  app=setup();app.get('auditNetwork').value='company';app.get('nodeNote').value='US node / global';
  assert.equal(app.get('auditBrowser').disabled,true);
  await app.get('auditStart').listeners.click();
  assert.equal(app.get('auditBrowser').disabled,false);
  assert(app.get('auditFindings').innerHTML.includes('&lt;unsafe&gt;'));
  app.get('browserResult').value='{}';await app.get('auditImport').listeners.click();
  assert.equal(app.get('status').textContent,'会话失效');
  assert.equal(app.get('auditStart').disabled,false);
  app.get('auditNetwork').listeners.change();
  assert.equal(app.get('auditBrowser').disabled,true);
  console.log('PASS: native bridge, item-specific preview, cancel, exit alignment, disagreement, unavailable exit, retry, HTML preview');
})().catch(error => { console.error(error); process.exitCode = 1; });
