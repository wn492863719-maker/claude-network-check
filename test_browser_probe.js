const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const script=fs.readFileSync(__dirname+'/browser_probe.html','utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
function setup({session='a'.repeat(32),offline=false,rtc=true}={}){
 const elements=new Map();let requested=0,precise=0,media=0;
 const get=id=>{if(!elements.has(id))elements.set(id,{value:'',textContent:'',disabled:false,listeners:{},addEventListener(n,f){this.listeners[n]=f},focus(){},select(){}});return elements.get(id)};
 class Peer{
  createDataChannel(){} close(){} createOffer(){return Promise.resolve({type:'offer'})}
  async setLocalDescription(){queueMicrotask(()=>{
   for(const [address,type] of [['198.18.0.1','host'],['1.1.1.1','srflx'],['[2606:4700:4700::1111]','srflx'],['[fe80::1]','host']])this.onicecandidate({candidate:{candidate:`candidate:0 1 udp 1 ${address} 9000 typ ${type}`,address,type,protocol:'udp'}});
   this.onicecandidate({candidate:null});
  })}
 }
 const context=vm.createContext({console,Date,JSON,URLSearchParams,Intl,Array,Object,Number,String,Promise,AbortController,
   globalThis:{isSecureContext:true},performance:{now:()=>10},location:{hash:'#session='+session},
   document:{getElementById:get},setTimeout,clearTimeout,
   navigator:{languages:['en-US'],permissions:{query:async()=>({state:'denied'})},
     geolocation:{getCurrentPosition(){precise++;throw new Error('forbidden')}},
     mediaDevices:{getUserMedia(){media++;throw new Error('forbidden')}},clipboard:{writeText:async()=>{}}},
   fetch:async url=>{requested++;if(offline)throw new Error('offline');return {ok:true,text:async()=>url.includes('cloudflare')?'ip=8.8.8.8\nloc=US':JSON.stringify({ip:'8.8.8.8'})}},
   ...(rtc?{RTCPeerConnection:Peer}:{})});
 vm.runInContext(script+'\nthis.test={run,addressScope,normalizeAddress};',context);
 return {get,run:context.test.run,scope:context.test.addressScope,normalize:context.test.normalizeAddress,counts:()=>({requested,precise,media})};
}
(async()=>{
 let app=setup();await app.run();let report=JSON.parse(app.get('output').value);
 assert.equal(report.exits.length,9);assert.equal(report.geolocation_permission,'denied');
 assert.equal(report.webrtc.candidates[0].scope,'private');assert.equal(report.webrtc.candidates[0].ip,null);
 assert.equal(report.webrtc.candidates[1].ip,'1.1.1.1');assert.deepEqual(app.counts(),{requested:9,precise:0,media:0});
 assert.equal(report.webrtc.candidates[2].ip,'2606:4700:4700::1111');assert.equal(report.webrtc.candidates.length,3);
 assert.equal(app.scope(app.normalize('[fe80::1]')),'private');
 assert.equal(app.scope('phone.local'),'mdns');assert.equal(app.scope('192.168.1.2'),'private');
 app=setup({offline:true,rtc:false});await app.run();report=JSON.parse(app.get('output').value);
 assert(report.exits.every(x=>!x.ok));assert.equal(report.webrtc.status,'unsupported');assert.equal(app.get('copy').disabled,false);
 app=setup({session:'invalid'});await app.run();assert.equal(app.counts().requested,0);
 console.log('PASS: browser probe, three rounds, denied permissions, no precise location/media, private candidate redaction, failure preservation');
})().catch(e=>{console.error(e);process.exitCode=1});
