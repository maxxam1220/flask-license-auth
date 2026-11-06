'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const code = fs.readFileSync(require('node:path').join(__dirname, '../static/i18n.js'), 'utf8');
function setup(locale) {
  const messages = {'同步': {id:'Sinkron',vi:'Đồng bộ'},'已確認 {count} 筆':{id:'Diterima {count}',vi:'Đã nhận {count}'}};
  let events = [];
  const label = {textContent:'同步', hasAttribute: k=>k==='data-i18n', getAttribute:()=> '同步'};
  const doc = {readyState:'complete',documentElement:{lang:''},getElementById:()=>({textContent:JSON.stringify({locale,messages})}), querySelectorAll:()=>[label],dispatchEvent:e=>events.push(e)};
  const window = {};
  vm.runInNewContext(code, {window,document:doc,CustomEvent: function(type,opts){this.type=type;this.detail=opts.detail;}});
  return {api:window.PatrolI18n,doc,label,events};
}
test('data catalog translates state and interpolation without evaluating markup',()=>{
  const {api,label,doc}=setup('vi');
  assert.equal(label.textContent,'Đồng bộ');
  assert.equal(doc.documentElement.lang,'vi');
  assert.equal(api.t('已確認 {count} 筆',{count:4}),'Đã nhận 4');
  assert.equal(api.t('已確認 5 筆'),'Đã nhận 5');
  assert.equal(api.t('<script>bad</script>'),'<script>bad</script>');
});
test('language switch updates leaves and emits only on actual changes',()=>{
  const {api,label,events}=setup('vi');
  api.setLocale('vi'); assert.equal(events.length,0);
  api.setLocale('id'); assert.equal(label.textContent,'Sinkron'); assert.equal(events.length,1);
  api.setLocale('zh-Hant'); assert.equal(label.textContent,'同步'); assert.equal(events.length,2);
  api.setLocale('invalid'); assert.equal(events.length,2);
});
test('point names require authenticated metadata and never translate arbitrary notes',()=>{
  const {api}=setup('id');
  assert.equal(api.pointName('原始點名',{id:'Titik A',vi:'Điểm A'}),'Titik A');
  assert.equal(api.pointName('unknown name'),'unknown name');
});
