"use strict";
// Independent offline result-section contracts. Anonymous inputs only; no API,
// production database, live model, or changes to original photo/OCR evidence.
const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict");
// Reuse just the DOM/VM bootstrap, not the original suite's test execution.
const bootstrap=fs.readFileSync(path.join(__dirname,"frontend_corrections_mock.cjs"),"utf8").split("let checks=0;")[0];
const {t,context,vm,Node}=new Function("require","__dirname",bootstrap+"\nreturn {t,context,vm,Node};")(require,__dirname);
const pick=name=>vm.runInContext(name,context),sections=pick("buildResultSections"),coverage=pick("resultCoverage"),rowStatus=pick("resultRowStatus"),bounds=pick("resultPhotoBounds");
const plain=value=>JSON.parse(JSON.stringify(value));
const line=(id,text,box)=>({id,text,score:.99,box:box || [[10,id*30+10],[300,id*30+10],[300,id*30+30],[10,id*30+30]]});
const sourceCheck=(id,text,status="pass")=>({key:`source_line_${id}`,source:"database",label:"標籤文字",status,expected:text,actual:text,line_ids:[id]});
function sample(lines,checks=[],extra={}){const result={status:"review",fields:{},checks,notes:[],...extra},inspection={id:"anonymous",image:{url:"/photo/anonymous",width:1000,height:800},template_snapshot:{},ocr:{lines},result};return {inspection,result,ocr:inspection.ocr};}
const build=s=>sections(s.inspection,s.result,s.ocr);
let count=0;function check(name,run){run();count++;console.log(`PASS ${name}`);}

check("scattered label with one heat value has no nutrition table",()=>{
  const lines=[line(0,"測試蘋果單顆裝"),line(1,"55"),line(2,"價格元"),line(3,"熱量 106.2 大卡/份"),line(4,"保存收件:7℃以下冷藏"),line(5,"某某農產股份有限公司")];
  const s=sample(lines,[sourceCheck(0,lines[0].text),{...sourceCheck(4,lines[4].text,"fail"),expected:"保存條件:7℃以下冷藏"}]);
  const before=JSON.stringify(s),model=build(s);
  assert.equal(model.hasTable,false);assert.equal(model.nutrition.length,0);assert.equal(model.content.length,6);
  assert.equal(model.content.find(row=>row.line_ids.includes(4)).status,"fail");assert.equal(JSON.stringify(s),before);
});
check("date pass cannot verify unrelated words on the same original line",()=>{
  const text="內容物:糖 製造日期:2026.11.17",s=sample([line(0,text)],[{key:"manufacture",source:"date",status:"pass",actual:"2026.11.17",line_ids:[0]},{key:"text_line_0",source:"ocr",status:"read",actual:text,line_ids:[0]}],{fields:{manufacture:{value:"2026.11.17",line_ids:[0]}}});
  const model=build(s);assert.equal(model.dateChecks.length,1);assert.equal(model.content.length,1);assert.equal(model.content[0].status,"read");assert.equal(model.content[0].text,text);
});
check("whole date evidence moves to date card without polluting content",()=>{
  const s=sample([line(0,"製造日期:2026.11.17")],[{key:"manufacture",source:"date",status:"pass",actual:"2026.11.17",line_ids:[0]}],{fields:{manufacture:{value:"2026.11.17",line_ids:[0]}}});
  const model=build(s);assert.equal(model.dateChecks.length,1);assert.equal(model.content.length,0);
});
check("date evidence spans retain any remaining non-date ink",()=>{
  const text="到店日2026.11.18 糖",s=sample([line(0,text)],[{key:"arrival",source:"date",status:"pass",actual:"2026.11.18",line_ids:[0]}],{fields:{arrival:{value:"2026.11.18",line_ids:[0],evidence_spans:[{line_id:0,start:0,end:13}]}}});
  const model=build(s);assert.equal(model.content.length,1);assert.equal(model.content[0].status,"read");
});
check("no standard never yields a green overall verdict",()=>{
  const s=sample([],[],{status:"pass",source_match:{status:"unmatched"}});assert.equal(coverage(s.inspection,s.result,[]).status,"review");assert.match(coverage(s.inspection,s.result,[]).title,/尚無比對標準/);
});
check("uncovered OCR overrides a stale pass summary",()=>{
  const s=sample([line(0,"尚未建立依據的文字")],[],{status:"pass",counts:{pass:1,read:0},source_match:{status:"matched"}}),model=build(s);
  assert.equal(model.rows[0].status,"read");assert.equal(coverage(s.inspection,s.result,model.rows).status,"review");
});
check("multiple sticker metadata cannot retain a historical green verdict",()=>{
  const s=sample([line(0,"商品")],[sourceCheck(0,"商品")],{status:"pass",source_match:{status:"matched"}});s.ocr.label_scope={status:"multiple"};
  assert.equal(coverage(s.inspection,s.result,build(s).rows).status,"review");
});
check("scope blocked metadata is conservative even with all passing rows",()=>{
  const s=sample([line(0,"商品")],[sourceCheck(0,"商品")],{status:"pass",source_match:{status:"matched"},label_scope:{blocked:true,reason:"範圍不明"}});
  assert.equal(coverage(s.inspection,s.result,build(s).rows).status,"review");
});
check("real differences remain red even when the label scope is blocked",()=>{
  const s=sample([line(0,"商品")],[sourceCheck(0,"商品","fail")],{status:"fail",source_match:{status:"matched"},label_scope:{blocked:true}});
  assert.equal(coverage(s.inspection,s.result,build(s).rows).status,"fail");
});
check("ordinary users see why multiple stickers require a crop",()=>{
  const s=sample([line(0,"尚未核對文字")],[{key:"photo_scope",status:"review",reason:"多張標籤",line_ids:[]}]);s.ocr.label_scope={status:"multiple"};
  const role=t.state.role,permissions=t.state.permissions;t.state.role="operator";t.state.permissions={};
  const area=new Node();pick("renderResultHero")(s.inspection,s.result,area);
  const warning=area.querySelector(".result-scope-warning");assert.ok(warning);assert.match(warning.textContent,/框選一張/);assert.equal(warning.attrs.role,"status");
  t.state.role=role;t.state.permissions=permissions;
});
function nutritionSample(){
  const lines=[line(0,"營養標示"),line(1,"脂肪"),line(2,"0.1公克"),line(3,"0.1公克"),line(4,"糖"),line(5,"1.4毫克"),line(6,"1.2毫克")];
  const display_rows=[{text:"營養標示",source_line_ids:[0],row_type:"text"},{text:"脂肪 0.1公克 0.1公克",source_line_ids:[1,2,3],row_type:"nutrition"},{text:"糖",source_line_ids:[4],row_type:"text"},{text:"1.4毫克 1.2毫克",source_line_ids:[5,6],row_type:"nutrition_values"}];
  return sample(lines,[{key:"source_nutrition_fat",source:"database",status:"pass",expected:"脂肪 0.1公克 0.1公克",actual:"脂肪 0.1公克 0.1公克",line_ids:[1,2,3]}],{display_rows});
}
check("whole nutrition rows preserve both equal cells and all source IDs",()=>{
  const model=build(nutritionSample()),fat=model.nutrition.find(row=>row.text.startsWith("脂肪"));assert.equal(fat.text,"脂肪 0.1公克 0.1公克");assert.deepEqual(plain(fat.line_ids),[1,2,3]);assert.equal(fat.status,"pass");
});
check("standalone ingredient sugar remains content even beside a nutrition table",()=>{
  const model=build(nutritionSample());assert.equal(model.content.find(row=>row.text==="糖").status,"read");assert.equal(model.nutrition.some(row=>row.text==="糖"),false);
});
check("missing nutrient name remains unknown values and is never invented",()=>{
  const model=build(nutritionSample()),unknown=model.nutrition.find(row=>row.row_type==="nutrition_values");assert.equal(unknown.text,"1.4毫克 1.2毫克");assert.equal(unknown.status,"read");assert.equal(model.rows.some(row=>row.text.includes("鈉")),false);
});
check("math fail is separate from matching printed nutrition text",()=>{
  const s=nutritionSample();s.result.checks.push({key:"nutrition_relation",source:"logic",status:"fail",label:"數值關係",line_ids:[1,2,3]});const model=build(s);
  assert.equal(model.nutrition.find(row=>row.text.startsWith("脂肪")).status,"pass");assert.equal(model.nutritionChecks.length,1);assert.equal(rowStatus([...model.nutrition,...model.nutritionChecks]),"fail");assert.equal(model.content.some(row=>row.status==="fail"),false);
});
check("math pass without text reference cannot make nutrition text green",()=>{
  const s=nutritionSample();s.result.checks=[{key:"nutrition_relation",source:"logic",status:"pass",line_ids:[1,2,3]}];const model=build(s);
  assert.equal(model.nutrition.find(row=>row.text.startsWith("脂肪")).status,"read");assert.equal(rowStatus([...model.nutrition,...model.nutritionChecks]),"read");
});
check("an approved manual source without extra metadata prioritizes correction instead of standard changes",()=>{
  for(const source of [{code:"manual:anonymous",name:"測試品名"},{code:"manual:anonymous",name:"測試品名",source_kind:"manual"}]){
    const s=sample([line(0,"讀錯品名")],[sourceCheck(0,"讀錯品名","fail")],{status:"fail",source_match:{status:"matched",code:source.code}});s.inspection.template_snapshot={source};
    const choice=pick("resultStandardAction")(s.inspection,s.result);assert.equal(choice?.action,"correct");assert.doesNotMatch(choice.label,/更新|改標準/);
    s.result.checks[0].status="pass";s.result.status="pass";assert.equal(pick("resultStandardAction")(s.inspection,s.result),null);
  }
});
check("nutrition header explicitly reports math failures even when every text row matches",()=>{
  const s=nutritionSample(),model=build(s),fat=model.nutrition.find(row=>row.text.startsWith("脂肪"));
  for(const status of ["fail","review"]){
    const area=new Node(),logic=[{key:"nutrition_relation",source:"logic",status,label:"營養數值關係",reason:"請確認數值關係",line_ids:[1,2,3]}];
    pick("renderResultZone")("nutrition",[fat],logic,s.inspection,false,area);
    const section=area.querySelector(".result-zone-nutrition"),heading=section.querySelector(".section-status-summary");
    assert.ok(section.className.split(" ").includes(status));assert.match(heading.textContent,/✓/);assert.match(heading.textContent,status==="fail" ? /✕.*邏輯.*異常/ : /\?.*邏輯.*確認/);assert.equal(fat.status,"pass");
  }
});
check("full Code128 payload belongs only in the barcode section",()=>{
  const s=sample([line(0,"AB:12-Z")],[{key:"source_line_0",label:"條碼",source:"database",status:"pass",expected:"AB:12-Z",actual:"AB:12-Z",line_ids:[0]}]);const model=build(s);assert.equal(model.barcodeChecks.length,1);assert.equal(model.content.length,0);
});
check("mixed text alongside barcode data remains unverified content",()=>{
  const s=sample([line(0,"品名:蘋果 AB:12-Z")],[{key:"source_line_0",label:"條碼",source:"database",status:"pass",expected:"AB:12-Z",actual:"AB:12-Z",line_ids:[0]}]);const model=build(s);assert.equal(model.content.length,1);assert.equal(model.content[0].status,"read");
});
check("photo crop unions original row boxes and leaves raw evidence unchanged",()=>{
  const s=sample([line(0,"脂肪",[[10,20],[70,20],[70,40],[10,40]]),line(1,"0.1公克",[[100,20],[190,20],[190,40],[100,40]]),line(2,"0.1公克",[[250,20],[340,20],[340,40],[250,40]])]);const before=JSON.stringify(s),b=bounds(s.inspection,{line_ids:[0,1,2]});assert.ok(b.x<=10 && b.x+b.width>=340);assert.ok(b.y<=20 && b.y+b.height>=40);assert.equal(JSON.stringify(s),before);
});
check("missing or invalid positions cannot pretend to be a located line",()=>{
  const s=sample([{id:0,text:"沒有位置",box:[]},{id:1,text:"壞位置",box:[[NaN,1],[-1,3],[5000,2]]}]);assert.equal(bounds(s.inspection,{line_ids:[0]}),null);assert.equal(bounds(s.inspection,{line_ids:[1]}),null);
});
check("late original image load cannot repaint the next inspection",()=>{
  const images=[];context.Image=class{constructor(){this.naturalWidth=1000;this.naturalHeight=800;images.push(this);}};
  vm.runInContext("api=()=>{throw new Error('photo viewing must not call an API')}",context);
  const draw=pick("drawResultPhoto"),painted=[],canvas=()=>({getContext:()=>({drawImage:(...args)=>painted.push(args)})});
  t.state.resultRenderEpoch=1;t.state.resultPhotoCache=null;draw(canvas(),{image:{url:"/old",width:1000,height:800},ocr:{lines:[]}});
  t.state.resultRenderEpoch=2;draw(canvas(),{image:{url:"/new",width:1000,height:800},ocr:{lines:[]}});images[0].onload();assert.equal(painted.length,0);images[1].onload();assert.equal(painted.length,1);assert.equal(painted[0][0].src,"/new");
});
console.log(`PASS ${count} independent result section checks`);
