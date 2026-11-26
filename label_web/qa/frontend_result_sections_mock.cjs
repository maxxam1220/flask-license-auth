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

check("standalone heat without a reference stays in nutrition and other label fields keep their findings",()=>{
  const lines=[line(0,"測試蘋果單顆裝"),line(1,"55"),line(2,"價格元"),line(3,"熱量 106.2 大卡/份"),line(4,"保存收件:7℃以下冷藏"),line(5,"某某農產股份有限公司")];
  const s=sample(lines,[sourceCheck(0,lines[0].text),{...sourceCheck(4,lines[4].text,"fail"),expected:"保存條件:7℃以下冷藏"}]);
  const before=JSON.stringify(s),model=build(s);
  assert.equal(model.nutrition[0].text,"熱量 106.2 大卡/份");assert.equal(model.nutrition[0].status,"read");assert.equal(model.content.length,5);
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
check("packaging date is shown with its year check in the date card",()=>{
  const date = {key:"date_line_0_0", label:"包裝日期格式", actual:"2026/11/18",
    source:"date", status:"pass", whole_date_label:"包裝日期", line_ids:[0]};
  const year = {key:"date_year_0_0", label:"日期年份", actual:"2026", source:"date", status:"fail", line_ids:[0]};
  const s = sample([line(0,"包裝日期: 2026/11/18")], [date, year]);
  const area = new Node("div");
  pick("renderUnmatchedDates")(s.inspection, s.result, area, true);
  assert.match(area.textContent, /包裝日期.*2026\/11\/18.*有異常/);
  assert.equal(build(s).content.length, 0);
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
check("legacy nutrition failures do not change the grade of other checks",()=>{
  const s=nutritionSample();s.result.checks.push({key:"nutrition_relation",source:"logic",status:"fail",label:"數值關係",line_ids:[1,2,3]},
    {key:"barcode_hri",status:"review",actual:"12345678",line_ids:[]});
  const model=build(s);
  assert.equal(model.nutrition.find(row=>row.text.startsWith("脂肪")).status,"pass");
  assert.deepEqual(plain(model.assessed.counts),{fail:0,review:1,read:0,pass:1});
  assert.deepEqual(plain(model.assessed.checks.map(check=>check.key)),["source_nutrition_fat","barcode_hri"]);
});
check("nutrition without an actual standard never has a positive assessment",()=>{
  for(const checks of [[],[{key:"nutrition_energy",source:"logic",status:"pass",line_ids:[0]}]]){
    const s=sample([line(0,"熱量 111.1 大卡/份")],checks,{status:"pass",source_match:{status:"matched"}});
    const model=build(s);
    assert.equal(model.assessed.status,"review");assert.equal(model.content.length,0);assert.equal(model.nutrition[0].status,"read");
  }
});
check("projected row flags preserve ingredient text and separate nutrition from ordinary label fields",()=>{
  const s=sample([line(0,"糖"),line(1,"0.1公克")],[sourceCheck(0,"糖","fail")],
    {nutrition_policy:"literal-text-v2",status:"fail",display_rows:[
      {text:"糖",row_type:"nutrition",source_line_ids:[0],nutrition_text:false},
      {text:"0.1公克",row_type:"text",source_line_ids:[1],nutrition_text:true}]});
  const model=build(s);assert.equal(model.content[0].text,"糖");assert.equal(model.content[0].status,"fail");
  assert.equal(model.nutrition[0].text,"0.1公克");assert.equal(model.assessed.status,"fail");
});
check("an approved manual source without extra metadata prioritizes correction instead of standard changes",()=>{
  for(const source of [{code:"manual:anonymous",name:"測試品名"},{code:"manual:anonymous",name:"測試品名",source_kind:"manual"}]){
    const s=sample([line(0,"讀錯品名")],[sourceCheck(0,"讀錯品名","fail")],{status:"fail",source_match:{status:"matched",code:source.code}});s.inspection.template_snapshot={source};
    const choice=pick("resultStandardAction")(s.inspection,s.result);assert.equal(choice?.action,"correct");assert.doesNotMatch(choice.label,/更新|改標準/);
    s.result.checks[0].status="pass";s.result.status="pass";assert.equal(pick("resultStandardAction")(s.inspection,s.result),null);
  }
});
check("nutrition section shows visible checkmarks for literal matches, without calculation warnings",()=>{
  const s=nutritionSample(),model=build(s),area=new Node();
  pick("renderResultZone")("nutrition",model.nutrition,s.inspection,false,area);
  const section=area.querySelector(".result-zone-nutrition");
  assert.match(section.textContent,/✓ 1 行相符/);assert.match(section.textContent,/脂肪 0.1公克 0.1公克/);
  assert.equal(section.querySelector(".section-normal-text").open,true);assert.ok(section.querySelectorAll(".line-mark").some(mark=>mark.textContent==="✓"));
  assert.doesNotMatch(section.textContent,/僅供閱讀|邏輯異常|熱量換算/);
  assert.equal(section.querySelectorAll(".section-issue").length,0);
});
check("one mismatched printed nutrient shows its original and standard exactly once and counts in the verdict",()=>{
  for(const status of ["fail","review"]){
    const rows=[line(0,"熱量 58大卡 42大卡")],printed={key:"nutrition_7",source:"database",label:"熱量",status,expected:"熱量 59大卡 43大卡",actual:rows[0].text,line_ids:[0]};
    const s=sample(rows,[printed,{key:"nutrition_energy",source:"logic",status:"fail",label:"熱量換算",line_ids:[0]}],{status:"fail"});
    const model=build(s),area=new Node();pick("renderResultZone")("nutrition",model.nutrition,s.inspection,false,area);
    const block=area.querySelector(".section-issue");
    assert.equal(model.rows.length,1);assert.equal(model.nutrition[0].status,status);assert.equal(model.assessed.status,status);
    assert.equal(model.assessed.counts[status],1);assert.match(block.querySelector(".issue-observed").textContent,/熱量 58大卡 42大卡/);
    assert.match(block.querySelector(".issue-expected").textContent,/熱量 59大卡 43大卡/);assert.doesNotMatch(area.textContent,/熱量換算/);
    assert.ok(block.querySelector(".row-correct-primary"));
  }
});
check("missing approved nutrient appears once in nutrition with its expected original text",()=>{
  const s=sample([],[{key:"source_nutrition_fat",source:"database",status:"review",label:"脂肪",actual:"",expected:"脂肪 0.1公克 0.1公克",line_ids:[]}]);
  const model=build(s),area=new Node();pick("renderResultZone")("nutrition",model.nutrition,s.inspection,false,area);
  assert.equal(model.content.length,0);assert.equal(model.nutrition.length,1);assert.equal(model.rows[0].status,"review");assert.match(area.textContent,/脂肪 0.1公克 0.1公克/);
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
check("an old unread-bars warning cannot add a review to a correct print or hide an unrelated error",()=>{
  const unread={key:"barcode_unread",label:"條碼圖形",status:"review",actual:"2834 6654 32931"};
  const rule={key:"web_barcode_rule",source:"database",status:"pass",expected:"2834665432931",actual:"2834665432931"};
  const date={key:"date_order",source:"date",status:"fail",label:"日期先後",reason:"有效日早於製造日。"};
  const s=sample([], [unread,rule,date],{status:"fail",source_match:{status:"matched"}});
  Object.assign(s.inspection,{reviews:[],created_at:"2026-11-25T01:00:00Z"});
  t.renderInspection(s.inspection);
  const header=context.document.querySelector("#result-area").querySelector(".scan-result-header");
  assert.equal(header.querySelector(".count-review"),null);
  assert.match(header.querySelector(".count-fail").textContent,/日期先後.*有效日早於製造日/);
  assert.doesNotMatch(context.document.querySelector("#result-area").textContent,/條碼圖形未讀到|實際掃碼|條紋已解碼/);
  const only=sample([],[unread,rule],{status:"review",source_match:{status:"matched"}}),model=build(only);
  assert.deepEqual(plain(model.assessed.counts),{pass:1,read:0,fail:0,review:0});assert.equal(model.assessed.status,"pass");
  const unsupported=sample([],[unread],{status:"review",source_match:{status:"unmatched"}});
  assert.equal(build(unsupported).assessed.status,"review");assert.equal(build(unsupported).assessed.counts.pass,0);
});
check("history uses the reasons from the same revision as the counts",()=>{
  const original={counts:{fail:0,review:0},issue_reasons:[]};
  assert.equal(t.historyProblemSummary(original),"已核對項目無差異");
  const uncertain={counts:{fail:0,review:1},issue_reasons:[{status:"review",key:"barcode_hri",label:"條碼與印字",reason:"數字不完整。"}]};
  assert.match(t.historyProblemSummary(uncertain),/待確認 1 個檢查點\n條碼與印字：數字不完整/);
  const revised={...original,manual_revision:1,manual_counts:{fail:1,review:0},manual_issue_reasons:[{status:"fail",key:"date_order",label:"日期先後",reason:"日期顛倒。"}]};
  assert.match(t.historyProblemSummary(revised),/差異 1 項.*\n日期先後：日期顛倒/);
  assert.doesNotMatch(t.historyProblemSummary({...revised,manual_issue_reasons:undefined}),/條碼|日期顛倒/);
  assert.doesNotMatch(t.historyProblemSummary({...revised,manual_counts:{fail:0,review:0}}),/日期顛倒|條碼/);
});
check("uncertain date rows open their own original with evidence, while dependent checks remain counted",()=>{
  const manufacture={...line(11,"製造日期: 2026.11.26"),ambiguous:true,score:0,alternatives:[{text:"製造日期: 2026.11.20"}]};
  const expiry={...line(13,"有效日期: 2026.11.29 03時"),ambiguous:true,score:0};
  const reasons=["製造日期讀到「2026.11.26」，另一候選為「2026.11.20」。","雲端將有效日期「2026.11.29 03時」標為不確定。"];
  const checks=[{key:"manufacture",source:"date",status:"review",label:"製造日期",actual:"2026.11.26",reason:reasons[0],line_ids:[11]},
    {key:"expiry",source:"date",status:"review",label:"有效日期",actual:"2026.11.29 03時",reason:reasons[1],line_ids:[13]},
    {key:"date_order",source:"date",status:"review",label:"日期先後",reason:"等待兩日確認",line_ids:[11,13]},
    {key:"expiry_year",source:"date",status:"review",label:"有效日年份",reason:"等待有效日期確認",line_ids:[13]},
    {key:"barcode_multiple",source:"barcode",status:"fail",label:"商品碼",reason:"另外讀到不同商品碼"}];
  const {inspection}=sample([manufacture,expiry],checks,{status:"fail",source_match:{status:"matched"}});
  Object.assign(inspection,{reviews:[],created_at:"2026-11-26T01:38:00Z"});
  t.state.inspection=inspection;t.renderInspection(inspection);
  const $=selector=>context.document.querySelector(selector),area=$("#result-area");
  const header=area.querySelector(".scan-result-header"),other=header.querySelector(".rule-date-details");
  assert.match(header.querySelector(".count-review").textContent,/4 個檢查點/);
  assert.match(header.textContent,/另外讀到不同商品碼/);assert.match(other.querySelector("summary").textContent,/2 項/);
  assert.match(other.textContent,/等待兩日確認/);assert.ok(!other.open);
  const rows=area.querySelector("#result-date-card").querySelectorAll(".date-first-row");
  assert.equal(rows.length,2);
  for(const [index,original] of [manufacture,expiry].entries()){
    const row=rows[index],button=row.querySelector("button");
    assert.equal(row.querySelector(".date-first-reason").textContent,reasons[index]);
    assert.equal(button.dataset.correctLine,String(original.id));button.onclick();
    assert.equal($("#correction-kind").value,"confirmed_text");
    assert.equal($("#correction-original").value,original.text);assert.equal($("#correction-text").value,original.text);
    assert.equal($("#correction-text").readOnly,true);assert.equal($("#correction-date-note").textContent,reasons[index]);
    assert.equal(t.state.correction.lineId,original.id);assert.equal($("#correction-full-photo").href,inspection.image.url);
    $("#correction-dialog").close();
  }
  t.state.inspection={...inspection,id:"another"};
  rows[0].querySelector("button").onclick();assert.ok(!$("#correction-dialog").open);
});
check("history nutrition starts fully collapsed with its mixed verdict visible and opens all rows in one step",()=>{
  const print=[line(0,"熱量 51大卡"),line(1,"脂肪 0.1公克"),line(2,"蛋白質 0.2公克")];
  const s=sample(print,print.map((row,index)=>({...sourceCheck(row.id,row.text,["pass","fail","review"][index]),key:`source_nutrition_${index}`})));
  t.state.historyNutrition={inspectionId:s.inspection.id,open:false};
  try{
    const area=new Node();pick("renderResultZone")("nutrition",build(s).nutrition,s.inspection,false,area);
    const section=area.querySelector(".result-zone-nutrition"),summary=section.children[0];
    assert.equal(section.tagName,"DETAILS");assert.equal(section.open,false);assert.equal(summary.tagName,"SUMMARY");
    assert.match(summary.textContent,/營養標示.*1 處差異.*1 處需確認.*1 行相符/);
    assert.equal(summary.querySelector(".issue-observed"),null);assert.equal(section.querySelector(".section-normal-text"),null);
    assert.equal(section.querySelectorAll(".section-issue").length,2);assert.ok(section.querySelector(".line-mark"));
  }finally{t.state.historyNutrition=null;}
});
console.log(`PASS ${count} independent result section checks`);
