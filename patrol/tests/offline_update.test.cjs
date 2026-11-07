const test = require('node:test');
const assert = require('node:assert/strict');
const createUpdater = require('../static/offline-update.js');
function fixture() {
  const calls = [];
  const registration = { scope: 'https://patrol.test/', active: { scriptURL: 'https://patrol.test/offline-sw.js' },
    installing: null, waiting: null, async update() { calls.push('update'); } };
  const env = { isSecureContext: true, location: { origin: 'https://patrol.test' }, navigator: { onLine: true,
    serviceWorker: { async getRegistration(scope) { calls.push(['get',scope]); return registration; },
      register() { throw Error('Must not create a worker for an unprepared browser'); } } } };
  for (const key of ['indexedDB','localStorage','sessionStorage','fetch']) Object.defineProperty(env,key,{get(){throw Error('Private/network capability must not be read: '+key);}});
  return { env, registration, calls, update:createUpdater(env) };
}
test('public updater refreshes an existing exact worker without identity or private capabilities', async()=>{
  const f=fixture();assert.equal(await f.update(),true);
  assert.deepEqual(f.calls,[['get','https://patrol.test/'],'update']);
});
test('fresh or unrelated registrations are never created, adopted or updated',async()=>{
  for(const variant of ['none','nested','other','foreign','query','mixed']){
    const f=fixture();
    if(variant==='none')f.env.navigator.serviceWorker.getRegistration=async()=>undefined;
    if(variant==='nested')f.registration.scope='https://patrol.test/another/';
    if(variant==='other')f.registration.active.scriptURL='https://patrol.test/other-sw.js';
    if(variant==='foreign')f.registration.active.scriptURL='https://external.test/offline-sw.js';
    if(variant==='query')f.registration.active.scriptURL+='?unexpected=1';
    if(variant==='mixed')f.registration.waiting={scriptURL:'https://patrol.test/other-sw.js'};
    assert.equal(await f.update(),false,variant);assert(!f.calls.includes('update'),variant);
  }
});
test('offline, insecure and unsupported contexts do not contact registration',async()=>{
  for(const variant of ['offline','insecure','unsupported']){
    const f=fixture();if(variant==='offline')f.env.navigator.onLine=false;
    if(variant==='insecure')f.env.isSecureContext=false;
    if(variant==='unsupported')delete f.env.navigator.serviceWorker;
    assert.equal(await f.update(),false);assert.deepEqual(f.calls,[]);
  }
});
test('installation already in progress is not restarted',async()=>{
  for(const key of ['installing','waiting']){
    const f=fixture();f.registration[key]={scriptURL:'https://patrol.test/offline-sw.js'};
    assert.equal(await f.update(),false);assert(!f.calls.includes('update'));
  }
});
test('concurrent page lifecycle callbacks share one update and retry after failure',async()=>{
  const f=fixture();let reject;
  f.registration.update=()=>{f.calls.push('update');return new Promise((_,fail)=>{reject=fail;});};
  const first=f.update(),second=f.update();assert.equal(first,second);
  await Promise.resolve();reject(Error('offline'));assert.equal(await first,false);
  f.registration.update=async()=>{f.calls.push('update');};assert.equal(await f.update(),true);
  assert.equal(f.calls.filter(x=>x==='update').length,2);
});
test('going offline while registration resolves suppresses update and later recovery is possible',async()=>{
  const f=fixture();let release;
  f.env.navigator.serviceWorker.getRegistration=()=>new Promise(resolve=>{release=resolve;});
  const pending=f.update();f.env.navigator.onLine=false;release(f.registration);
  assert.equal(await pending,false);assert(!f.calls.includes('update'));
  f.env.navigator.onLine=true;f.env.navigator.serviceWorker.getRegistration=async()=>f.registration;
  assert.equal(await f.update(),true);
});
test('synchronous registration denial cannot poison future retries',async()=>{
  const f=fixture();f.env.navigator.serviceWorker.getRegistration=()=>{throw Error('storage denied');};
  assert.equal(await f.update(),false);
  f.env.navigator.serviceWorker.getRegistration=async()=>f.registration;
  assert.equal(await f.update(),true);assert.equal(f.calls.filter(x=>x==='update').length,1);
});
