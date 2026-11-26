"use strict";
const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict");
const bootstrap=fs.readFileSync(path.join(__dirname,"frontend_corrections_mock.cjs"),"utf8").split("let checks=0;")[0];
const {t,context,vm}=new Function("require","__dirname",bootstrap+"\nreturn {t,context,vm};")(require,__dirname);
const $=selector=>context.document.querySelector(selector),prefixes=["","reference-","crop-"];
let count=0;function check(name,fn){fn();count++;console.log(`PASS ${name}`);}
function fresh(){for(const prefix of prefixes){const input=$("#"+prefix+"recognition-engine");input.dataset.recognitionInitialized="";input.value="local";$("#"+prefix+"label-scope").value="sticker";}t.state.crop=null;}
const unlimited={cloud_available:true,cloud_unlimited:true,cloud_limit:null,cloud_remaining:null,default_engine:"cloud"};
fresh();t.configureRecognition(unlimited);
check("open unlimited cloud defaults all fresh recognition controls to cloud",()=>{for(const prefix of prefixes){assert.equal($("#"+prefix+"recognition-engine").value,"cloud");assert.equal(t.recognitionSettings(prefix).recognition_engine,"cloud");}});
check("unlimited cloud names API billing and never displays a trial allowance",()=>{for(const prefix of prefixes){const note=$("#"+prefix+"recognition-choice-note").textContent;assert.match(note,/雲端辨識已開放，依 API 帳戶可用額度計費/);assert.doesNotMatch(note,/試用|20|ChatGPT|null|無限免費/);}});
$("#recognition-engine").value="local";t.recognitionChoiceNote();t.configureRecognition(unlimited);
check("refreshing unlimited availability preserves an explicit local selection and a short local-only note",()=>{assert.equal($("#recognition-engine").value,"local");assert.equal($("#recognition-choice-note").textContent,"使用一般辨識。");});
fresh();t.configureRecognition({cloud_available:true,cloud_unlimited:false,cloud_limit:20,cloud_remaining:7,default_engine:"cloud"});
check("finite counters remain internal and the paid date reread is disclosed",()=>{assert.equal(t.state.recognition.cloud_remaining,7);assert.equal(t.state.recognition.cloud_limit,20);assert.match($("#recognition-choice-note").textContent,/依 API 帳戶可用額度計費。日期看不清時，最多另送一次局部重讀/);assert.doesNotMatch($("#recognition-choice-note").textContent,/7|20|試用/);});
t.configureRecognition({...unlimited,cloud_limit:20,cloud_remaining:7});
check("the explicit unlimited flag takes precedence over stale finite counters",()=>{assert.doesNotMatch($("#recognition-choice-note").textContent,/7|20|試用/);assert.match($("#recognition-choice-note").textContent,/API 帳戶/);});
fresh();t.configureRecognition({...unlimited,cloud_available:false});
check("unlimited configuration without an available provider does not advertise open cloud",()=>{for(const prefix of prefixes){assert.equal($("#"+prefix+"recognition-engine").value,"local");assert.equal($("#"+prefix+"recognition-choice-note").textContent,"使用一般辨識。");}});
fresh();t.configureRecognition(unlimited);t.configureRecognition({...unlimited,cloud_available:false});
check("provider unavailability retains cloud selection with a concise unavailable note",()=>{assert.equal($("#recognition-engine").value,"cloud");assert.equal($("#recognition-choice-note").textContent,"雲端辨識暫時無法使用。");assert.throws(()=>t.recognitionSettings(),/無法使用雲端/);});
fresh();t.configureRecognition({cloud_available:false,cloud_unlimited:false,cloud_limit:0,cloud_remaining:0,default_engine:"local"});
check("explicit disabled mode cannot be presented as unlimited or available",()=>{assert.equal($("#recognition-engine").value,"local");assert.doesNotMatch($("#recognition-choice-note").textContent,/已開放/);$("#recognition-engine").value="cloud";assert.throws(()=>t.recognitionSettings(),/無法使用雲端/);});
fresh();t.configureRecognition({cloud_available:false,cloud_unlimited:false,cloud_limit:20,cloud_remaining:0,default_engine:"local"});$("#recognition-engine").value="cloud";t.recognitionChoiceNote();
check("exhausted finite mode hides counters without disabling the submission guard",()=>{assert.equal($("#recognition-choice-note").textContent,"雲端辨識暫時無法使用。");assert.doesNotMatch($("#recognition-choice-note").textContent,/0|20|試用|保留/);assert.throws(()=>t.recognitionSettings(),/無法使用雲端/);});
fresh();t.configureRecognition({cloud_available:false,cloud_unlimited:"true",cloud_limit:null,cloud_remaining:null,default_engine:"cloud"});
check("malformed unlimited values cannot bypass the availability gate",()=>{assert.equal(t.state.recognition.cloud_unlimited,false);assert.equal($("#recognition-engine").value,"local");assert.doesNotMatch($("#recognition-choice-note").textContent,/已開放/);});
console.log(`${count} cloud-access frontend checks passed`);
