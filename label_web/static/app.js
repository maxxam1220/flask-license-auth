"use strict";
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = {csrf: "", templates: [], referenceJob: null, source: null, inspectSource: null, inspectSearchRequest: 0, supersedes: null, busy: false, page: 1, inspection: null, resultDirty: false, retryJobs: {}, failedJobs: [], failedJobsRequest: 0, manualView: true, correction: null, correctionImageRequest: 0, standardEdit: null};
const statusLabels = {pass: "已核對項目相符", fail: "發現差異", review: "需要人工複核", read: "僅辨識"};
const reviewLabels = {confirmed_good: "人工確認正確", confirmed_bad: "人工確認異常", retake: "需要重拍"};
const textFields = ["product", "spec", "storage", "origin", "company", "address", "phone"];
const fieldLabels = {product: "品名", spec: "規格", storage: "保存條件", origin: "產地", company: "公司名稱", address: "地址", phone: "電話"};
const maxPhotoBytes = 15 * 1024 * 1024;
let toastTimer;
Object.assign(state, {role:"anonymous", authenticated:false, permissions:{}, adminConfigured:false, authEpoch:0, historySelection:new Map(), standardSaved:false});
let cleanupContext = null;

function allowed(permission = "manage_standards") { return state.role === "admin" && state.permissions[permission] === true; }
function requireAdmin(permission = "manage_standards") {
  if (allowed(permission)) return true;
  toast("此功能需管理員解鎖；掃描與本筆訂正仍可使用。", true); return false;
}
function isAdminPath(path) {
  return /^\/api\/(?:templates(?:[/?]|$)|manual-standards(?:[/?]|$)|admin\/history(?:[/?]|$)|source-labels\/)/.test(path)
    || /^\/api\/inspections\/[^/]+\/(?:standard|manual-standard)(?:[/?]|$)/.test(path);
}
function purgeAdminData() {
  state.standardEdit = null; manualStandard = null; cleanupContext = null;
  state.referenceJob = null; state.source = null; state.supersedes = null; state.historySelection.clear();
  manualLibraryRequest++; manualLibraryTotal = 0;
  $$(".history-select").forEach(node=>node.remove());
  state.templates = state.templates.map(({id,name,version}) => ({id,name,version}));
  for (const id of ["standard-edit-dialog","manual-standard-dialog","history-cleanup-dialog"]) { const node=$("#"+id); if(node.open)node.close(); }
  for (const id of ["standard-form","standard-edit-form","manual-standard-form","cleanup-filter-form","cleanup-confirm-form"]) $("#"+id).reset();
  $$("#standard-edit-dialog input, #standard-edit-dialog textarea, #manual-standard-dialog input, #manual-standard-dialog textarea, #history-cleanup-dialog input, #history-cleanup-dialog textarea").forEach(node=>{node.value="";node.checked=false;});
  for(const id of ["library-list","manual-library-list","source-results","reference-lines","standard-edit-line-fields","standard-edit-date-fields","standard-edit-history-list","standard-edit-preview","manual-standard-preview","cleanup-items","cleanup-batches"]) $("#"+id).replaceChildren();
  for(const id of ["standard-edit-source","standard-edit-notice","standard-edit-error","manual-standard-notice","manual-standard-error","source-note","manual-library-status","cleanup-error","cleanup-notice","cleanup-summary","cleanup-selection-note"]) $("#"+id).textContent="";
  $("#reference-preview").removeAttribute("src"); $("#reference-preview").hidden=true; $("#reference-ocr").hidden=true; $("#standard-fields").disabled=true;
  $("#manual-library-query").value=""; $("#source-query").value=""; $("#nav-count").textContent="0";
  delete state.retryJobs.reference; $("#reference-retry").hidden=true; setUploadError("reference");
  sessionStorage.setItem("labelcheck-failed-jobs",JSON.stringify(state.retryJobs));
  state.failedJobs=state.failedJobs.filter(item=>item.kind!=="reference"); renderFailedJobs();
  selectedStandard(); updateCleanupSelection();
}
function applySession(session) {
  const role=session.authenticated ? session.role || "operator" : "anonymous";
  const changed=state.role!==role || state.authenticated!==!!session.authenticated;
  if(changed)state.authEpoch++;
  state.role=role; state.authenticated=!!session.authenticated; state.permissions=session.permissions || {};
  state.adminConfigured=!!session.admin_configured; if(session.csrf)state.csrf=session.csrf;
  if(!allowed())purgeAdminData();
  $$("[data-permission]").forEach(node=>{node.hidden=!allowed(node.dataset.permission);});
  $$("[data-action='new-standard']").forEach(node=>{node.hidden=!allowed();});
  $("#admin-access").textContent=allowed() ? "管理員" : "管理功能";
  $("#logout").hidden=!session.requires_login; $("#admin-logout").hidden=!session.requires_login;
  $("#login").hidden=state.authenticated; $("#app-shell").hidden=!state.authenticated;
  if(!state.authenticated){
    state.inspection=null;state.correction=null;state.inspectSource=null;state.templates=[];state.failedJobs=[];state.inspectSearchRequest++;state.failedJobsRequest++;
    for(const id of ["result-area","history-list","inspect-source-results","inspect-source-selected","selected-standard","failed-jobs-list"])$("#"+id).replaceChildren();
    $("#template-select").replaceChildren(new Option("自動對應系統標籤與清單",""));
    $("#correction-form").reset();$("#correction-original").value="";$("#correction-text").value="";$("#correction-standard").textContent="";$("#correction-full-photo").removeAttribute("href");
    const canvas=$("#correction-photo");canvas.width=canvas.width;
    for(const id of ["admin-dialog","correction-dialog","camera-dialog"])if($("#"+id).open)$("#"+id).close();
    $("#admin-password").value="";return;
  }
  if(!allowed() && ["library","standard"].includes(location.hash.slice(1)))showView("inspect");
  if(changed && state.inspection)renderInspection(state.inspection);
  if(changed && location.hash==="#history")loadHistory().catch(error=>toast(error.message,true));
}
function openAdminDialog() {
  if(state.busy)return toast("請等待目前工作完成，再切換管理權限。");
  $("#admin-unlock-form").reset();setDialogError("#admin-error");
  $("#admin-status").textContent=allowed() ? "目前已解鎖管理功能，可管理比對標準及整理檢查紀錄。" : state.adminConfigured ? "一般操作可掃描、查看紀錄及訂正本筆文字。輸入管理碼後可管理標準及整理紀錄。" : "尚未設定管理碼，管理功能暫不開放。請由服務管理者設定管理碼後再使用。";
  $("#admin-unlock-form").hidden=allowed() || !state.adminConfigured;$("#admin-lock").hidden=!allowed();$("#admin-dialog").showModal();
}
async function changeAdminRole(unlock=false) {
  if(state.busy)return;
  const password=$("#admin-password").value;if(unlock && (!state.adminConfigured || !password))return;
  setDialogError("#admin-error");setBusy(true);$$("#admin-dialog button").forEach(node=>{node.disabled=true;});
  try {
    const session=await api(unlock ? "/api/admin/unlock" : "/api/admin/lock",{method:"POST",...(unlock ? {body:{password}} : {})});
    applySession(session);$("#admin-password").value="";$("#admin-dialog").close();await loadTemplates();
    toast(unlock ? "管理功能已解鎖。" : "已鎖定管理功能，掃描及本筆訂正仍可使用。");
  }catch(error){setDialogError("#admin-error",error.message);$("#admin-password").value="";}
  finally{setBusy(false);$$("#admin-dialog button").forEach(node=>{node.disabled=false;});}
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function toast(message, error = false) {
  const node = $("#toast"); node.textContent = message; node.className = `toast${error ? " error" : ""}`; node.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { node.hidden = true; }, error ? 9000 : 4500);
}
function setUploadError(kind, message = "") {
  const node = $(kind === "reference" ? "#reference-upload-error" : "#inspect-upload-error");
  node.textContent = message; node.hidden = !message;
}
function reportUploadFailure(kind, error) {
  const message = (typeof error === "string" ? error : error?.message) || "照片辨識未完成，請稍後重試。";
  setUploadError(kind, message); toast(message, true);
}
function retrySlot(kind) { return kind === "reference" ? "reference" : "inspect"; }
function retryIsPending(id) {
  try { return !!id && JSON.parse(sessionStorage.getItem("labelcheck-pending") || "null")?.retry_of === id; }
  catch { return false; }
}
function renderRetryJob(kind) {
  const slot = retrySlot(kind), item = state.retryJobs[slot], button = $(`#${slot}-retry-button`);
  $(`#${slot}-retry`).hidden = !item;
  button.disabled = state.busy || retryIsPending(item?.id); button.onclick = () => retryFailedJob(item);
}
function setRetryJob(kind, item = null) {
  const slot = retrySlot(kind);
  if (item) state.retryJobs[slot] = item;
  else delete state.retryJobs[slot];
  sessionStorage.setItem("labelcheck-failed-jobs", JSON.stringify(state.retryJobs));
  renderRetryJob(kind);
}
function restoreRetryJobs() {
  let saved;
  try { saved = JSON.parse(sessionStorage.getItem("labelcheck-failed-jobs") || "{}"); } catch { saved = {}; }
  for (const slot of ["inspect", "reference"]) {
    if(slot==="reference" && !allowed())continue;
    const item = saved?.[slot];
    if (item?.state !== "failed" || typeof item.id !== "string" || !["inspection", "recognition", "reference"].includes(item.kind)) continue;
    state.retryJobs[retrySlot(item.kind)] = item;
    renderRetryJob(item.kind); setUploadError(item.kind, item.error || "上次辨識未完成，可以使用已保留的照片重試。");
  }
}
function rememberFailedJob(job, kind) {
  let pending;
  try { pending = JSON.parse(sessionStorage.getItem("labelcheck-pending") || "null"); } catch { pending = null; }
  setRetryJob(kind, {id:job.id,kind,state:"failed",error:job.error,image:job.image,created_at:job.created_at,
    supersedes_id:pending?.id === job.id ? pending.supersedes_id || null : null});
  loadFailedJobs();
}
function renderFailedJobs() {
  const list = $("#failed-jobs-list"); list.replaceChildren();
  $("#failed-jobs-panel").hidden = !state.failedJobs.length;
  for (const item of state.failedJobs) {
    const row = element("div", "history-row"), info = element("span");
    if (item.image?.thumbnail) {
      const image = element("img"); image.src = item.image.thumbnail; image.alt = "未完成辨識的照片"; image.loading = "lazy"; row.append(image);
    }
    info.append(element("strong", "", item.kind === "reference" ? "標準照片" : "標籤照片"),
      element("small", "", item.created_at ? when(item.created_at) : "未完成辨識"));
    const button = element("button", "button secondary", retryIsPending(item.id) ? "辨識中" : "重新辨識"); button.type = "button";
    button.dataset.retryJob = item.id; button.disabled = state.busy || retryIsPending(item.id); button.onclick = () => retryFailedJob(item);
    row.append(info, button); list.append(row);
  }
}
async function loadFailedJobs() {
  const request = ++state.failedJobsRequest;
  try {
    const data = await api("/api/jobs/failed?limit=5");
    if (request !== state.failedJobsRequest) return;
    state.failedJobs = (Array.isArray(data.items) ? data.items : []).filter(item =>
      item && typeof item.id === "string" && ["inspection", "recognition", "reference"].includes(item.kind) && (item.kind!=="reference" || allowed())).slice(0, 5);
    $("#failed-jobs-note").textContent = "照片已保留，可沿用原本設定重新辨識。";
    renderFailedJobs();
  } catch (_) {
    if (request !== state.failedJobsRequest) return;
    $("#failed-jobs-panel").hidden = false;
    $("#failed-jobs-note").textContent = "暫時無法讀取未完成的辨識，請稍後重新整理。";
  }
}
function recoveryMessage(ocr) {
  const recovery = ocr?.recovery;
  return recovery?.automatic_retry === true && Number(recovery.attempts) >= 2 ? "系統已自動重試並完成文字辨識。" : "";
}
let memoryRequest = 0, memoryBusy = false, memoryRemoteBusy = false;
function memoryControls() {
  $("#memory-refresh").disabled = state.busy || memoryBusy;
  $("#memory-cleanup").disabled = state.busy || memoryBusy || memoryRemoteBusy;
}
function renderMemory(report) {
  memoryRemoteBusy = !!report.busy || report.status === "unavailable";
  const used = report.service_current_mb, limit = report.service_limit_mb;
  $("#memory-status").textContent = Number.isFinite(used) && Number.isFinite(limit)
    ? `目前使用 ${Math.round(used)} / ${Math.round(limit)} MB${report.busy ? " · 辨識工作處理中" : report.status === "pressure" ? " · 用量偏高，可嘗試清理" : " · 可使用"}`
    : (report.notice || "目前無法讀取服務用量。");
  memoryControls();
}
async function loadMemory() {
  if (memoryBusy) return;
  const token = ++memoryRequest; memoryBusy = true; memoryControls();
  try { const report = await api("/api/memory"); if(token === memoryRequest)renderMemory(report); }
  catch(error) { $("#memory-status").textContent = error.message; }
  finally { memoryBusy = false; memoryControls(); }
}
async function cleanupMemory() {
  if(state.busy || memoryBusy)return;
  memoryBusy=true;memoryControls();$("#memory-feedback").textContent="正在釋放閒置記憶體…";
  try {
    const result=await api("/api/memory/cleanup",{method:"POST"});
    if(result.after)renderMemory(result.after);
    const before=result.before?.service_current_mb, after=result.after?.service_current_mb;
    const released=Number.isFinite(before) && Number.isFinite(after) ? Math.max(0,Math.round(before-after)) : null;
    $("#memory-feedback").textContent=result.status === "partial" ? "已完成可用的清理步驟；部分系統快取仍由主機管理。" : `已完成清理${released ? `，本次用量減少約 ${released} MB` : "，目前沒有可量測的用量下降"}。正在使用的記憶體會保留。`;
  } catch(error) { $("#memory-feedback").textContent=error.message; }
  finally { memoryBusy=false;memoryControls(); }
}
async function retryFailedJob(item) {
  if(item?.kind==="reference" && !requireAdmin())return;
  if (state.busy || !item?.id || !["inspection", "recognition", "reference"].includes(item.kind)) return;
  if (retryIsPending(item.id)) return toast("這張照片已開始辨識，請重新整理接續查看結果。");
  const kind = item.kind, saved = state.retryJobs[retrySlot(kind)], supersedesId = item.supersedes_id || (saved?.id === item.id ? saved.supersedes_id : null);
  if (kind === "reference") {
    const previous = supersedesId ? state.templates.find(template => template.id === supersedesId) : null;
    if (supersedesId && !previous) { showView("standard"); reportUploadFailure(kind, "原標準已更新，請重新選擇最新標準再建立新版。"); return; }
    newStandard(previous);
    $("#reference-recovery").hidden = true;
  } else { showView("inspect"); clearResult(); }
  setUploadError(kind); setBusy(true, kind);
  const progress = $(`#${retrySlot(kind)}-progress span:last-child`);
  progress.textContent = "正在使用已保留的照片重新辨識…";
  try {
    const job = await api(`/api/jobs/${encodeURIComponent(item.id)}/retry`, {method:"POST"});
    sessionStorage.setItem("labelcheck-pending", JSON.stringify({id:job.id,kind,supersedes_id:supersedesId || null,retry_of:item.id}));
    setRetryJob(kind);
    if (kind === "reference" && job.image?.url) { $("#reference-preview").src = job.image.url; $("#reference-preview").hidden = false; }
    await pollJob(job.id, kind);
  } catch (error) { reportUploadFailure(kind, error); }
  finally { setBusy(false); }
}
async function api(path, options = {}) {
  const epoch=state.authEpoch;
  if(isAdminPath(path) && !allowed(path.startsWith("/api/admin/history") ? "cleanup_history" : "manage_standards")){
    const error=new Error("此功能需要管理員權限，請先解鎖管理功能。");error.status=403;error.code="admin_required";throw error;
  }
  const headers = {...options.headers};
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  if (options.body && !(options.body instanceof FormData)) { headers["Content-Type"] = "application/json"; options.body = JSON.stringify(options.body); }
  const response = await fetch(path, {...options, headers});
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && !["/api/login","/api/admin/unlock"].includes(path)) applySession({authenticated:false,role:"anonymous",requires_login:true});
    if(response.status===403 && payload.code==="admin_required"){
      applySession({authenticated:state.authenticated,role:"operator",requires_login:true,admin_configured:state.adminConfigured});
      try{applySession(await api("/api/session"));if(state.authenticated)await loadTemplates();}catch(_){/* Keep management data cleared until a verified session is available. */}
    }
    const error = new Error(payload.error || "連線失敗，請確認網路後重試。"); error.status = response.status; error.code=payload.code; throw error;
  }
  if(epoch!==state.authEpoch && !["/api/session","/api/login","/api/admin/unlock","/api/admin/lock","/api/logout"].includes(path)){
    const error=new Error("登入權限已變更，請重新操作。");error.code="session_changed";throw error;
  }
  return payload;
}
function when(iso) { return new Date(iso).toLocaleString("zh-TW", {timeZone: "Asia/Taipei", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}); }
function badge(status, text) { return element("span", `badge ${status}`, text || statusLabels[status]); }
function isCatalogSource(source) { return source?.source_kind === "catalog" || String(source?.code || "").startsWith("list:"); }
function sourceKindLabel(source) { return source?.source_kind === "manual" || String(source?.code || "").startsWith("manual:") ? "人工文字標準" : isCatalogSource(source) ? "清單" : "系統標籤"; }
function sourceCodeLabel(source) { const code=String(source?.code || "");return code.startsWith("manual:") ? `M-${code.slice(7,15)}` : code.replace(/^list:/, ""); }
function sourceOptionLabel(source) { return `${sourceKindLabel(source)} ${sourceCodeLabel(source)} · ${source.name}`; }
function showView(view) {
  if (!["inspect", "library", "standard", "history"].includes(view)) view = "inspect";
  if(["library","standard"].includes(view) && !allowed())view="inspect";
  $$(".view").forEach(x => { x.hidden = x.id !== `view-${view}`; });
  $$("[data-view]").forEach(x => { x.classList.toggle("active", x.dataset.view === (view === "standard" ? "library" : view)); });
  $("#breadcrumb").textContent = `工作區 / ${{inspect:"檢查標籤",library:"標準標籤庫",standard:"建立標準標籤",history:"檢查紀錄"}[view]}`;
  history.replaceState(null, "", `#${view}`);
  if (view === "history") loadHistory().catch(e => toast(e.message, true));
  if (view === "library") loadManualLibrary(1);
  window.scrollTo({top: 0, behavior: "instant"});
}
function setBusy(busy, kind = "") {
  state.busy = busy;
  $("#admin-access").disabled=busy;
  memoryControls();
  if(!busy && $("#memory-panel").open)loadMemory();
  $$("[data-file]").forEach(b => { b.disabled = busy; });
  $("#scan-button").disabled = busy;
  $("#source-search button").disabled = busy;
  $$("#inspect-source-search input, #inspect-source-search button, #inspect-source-results button, #inspect-source-selected button, .match-candidates button").forEach(button => { button.disabled = busy; });
  $("#template-select").disabled = busy;
  $("#base-date").disabled = busy;
  $("#batch-date").disabled = busy;
  $("#arrival-date").disabled = busy;
  if ($("#recheck-button")) $("#recheck-button").disabled = busy;
  $$("[data-correct-line], [data-edit-standard], [data-toggle-original]").forEach(button => { button.disabled = busy; });
  $$("[data-retry-job]").forEach(button => { button.disabled = busy || retryIsPending(button.dataset.retryJob); });
  for (const slot of ["inspect", "reference"]) $(`#${slot}-retry-button`).disabled = busy || retryIsPending(state.retryJobs[slot]?.id);
  $$("[data-action='new-standard']").forEach(x => { x.disabled = busy; });
  $("#inspect-progress").hidden = !busy || !["inspection", "recognition"].includes(kind);
  $("#reference-progress").hidden = !busy || kind !== "reference";
}
function clearResult() { state.inspection = null; state.resultDirty = false; state.standardSaved=false; $("#result-area").replaceChildren(); $("#result-area").hidden = true; $("#result-placeholder").hidden = false; }
function markResultChanged() {
  if (!state.inspection) return;
  state.resultDirty = true;
  if ($("#recheck-dirty")) $("#recheck-dirty").hidden = false;
}
function validBaseDate() {
  const input = $("#base-date");
  if (!input.value || !input.checkValidity()) { input.reportValidity(); toast("請設定本批基準日。", true); return false; }
  return true;
}
function selectedStandard() {
  const standard = state.templates.find(t => t.id === $("#template-select").value);
  const node = $("#selected-standard"); node.replaceChildren(); node.hidden = !standard;
  $("#recognition-help").hidden = !!standard;
  if (standard) {
    state.inspectSource = null; renderInspectSource();
    $("#template-options").open = true;
    if (standard.image) { const img = element("img"); img.src = standard.image.thumbnail; img.alt = "選定的標準照片"; node.append(img); }
    const info = element("div"); info.append(element("strong", "", standard.fields?.product || standard.name), element("p", "", `第 ${standard.version} 版${standard.approved_by ? ` · ${standard.approved_by} 已確認` : " · 已核准照片標準"}`));
    if(standard.fields){const checked = textFields.filter(key => standard.fields[key]).map(key => fieldLabels[key]);
      if (standard.rules?.dates) checked.push("製造／有效日期");
      if (standard.rules?.arrival) checked.push("到店日");
      info.append(element("p", "help", `核對項目：${checked.join("、")}`));}
    node.append(info);
  }
  setBusy(state.busy);
}
async function loadTemplates(selectedId) {
  const epoch=state.authEpoch,admin=allowed();
  const payload = await api(admin ? "/api/templates" : "/api/inspection-options");if(epoch!==state.authEpoch)return;state.templates = payload.items;
  const select = $("#template-select"), previous = selectedId || select.value;
  select.replaceChildren();
  select.append(new Option("自動對應系統標籤與清單", ""));
  state.templates.forEach(t => select.append(new Option(`${t.name} · 第 ${t.version} 版`, t.id)));
  if (state.templates.some(t => t.id === previous)) select.value = previous;
  $("#nav-count").textContent = String(state.templates.length + manualLibraryTotal);
  selectedStandard(); if(admin){renderLibrary();await loadManualLibrary(1);}
}
async function loadScanConfig() {
  const config = await api("/api/scan-config");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(config.today || "")) throw new Error("無法取得今天日期，請手動設定本批基準日。");
  if (!$("#base-date").value) $("#base-date").value = config.today;
}
function renderInspectSource() {
  const node = $("#inspect-source-selected"); node.replaceChildren(); node.hidden = !state.inspectSource;
  if (!state.inspectSource) return;
  node.append(element("strong", "", `已選擇：${sourceOptionLabel(state.inspectSource)}`));
  const reset = element("button", "quiet", "改用自動對應"); reset.type = "button";
  reset.onclick = () => { if (state.busy) return; state.inspectSource = null; renderInspectSource(); markResultChanged(); };
  node.append(reset); $("#template-options").open = true;
}
function selectInspectSource(item) {
  if (state.busy) return;
  state.inspectSource = {code:item.code,name:item.name,source_kind:item.source_kind}; state.inspectSearchRequest++;
  $("#template-select").value = ""; selectedStandard(); renderInspectSource();
  $("#inspect-source-results").replaceChildren(); $("#inspect-source-note").textContent = isCatalogSource(item) ? "將依這筆清單已有資料核對；未提供的內容不算已確認。" : `掃描或重新核對時將使用選定的${sourceKindLabel(item)}。`;
  markResultChanged(); toast(state.inspection ? "已選擇比對資料，請按重新核對套用。" : "已選擇比對資料，可以開始掃描。");
}
function newStandard(previous = null) {
  if(!requireAdmin())return;
  if (state.busy) return toast("請等待目前照片完成辨識。");
  state.referenceJob = null; state.source = null; state.supersedes = previous;
  $("#source-results").replaceChildren(); $("#source-note").textContent = "";
  $("#standard-form").reset(); $("#standard-fields").disabled = true;
  $("#reference-preview").hidden = true; $("#reference-preview").removeAttribute("src");
  $("#reference-recovery").hidden = true;
  $("#reference-ocr").hidden = true; $("#reference-lines").replaceChildren();
  $("#standard-heading").textContent = previous ? `建立新版標準 · 第 ${previous.version + 1} 版` : "建立標準標籤";
  $("#standard-form").elements.approved_by.value = sessionStorage.getItem("labelcheck-operator") || "";
  toggleDateFields(); showView("standard");
}
function toggleDateFields() {
  const f = $("#standard-form"); const enabled = f.elements.dates.checked && !state.source;
  $("#reference-date-fields").hidden = !enabled;
  ["manufacture", "expiry"].forEach(k => { f.elements[k].required = enabled; });
  f.elements.keep_days.disabled = !f.elements.dates.checked;
  const arrivalEnabled = f.elements.check_arrival.checked && !state.source;
  $("#reference-arrival-field").hidden = !arrivalEnabled;
  f.elements.arrival.required = arrivalEnabled;
}
function renderOCR(lines, container) {
  container.replaceChildren();
  if (!lines.length) return container.append(element("p", "muted", "未辨識到文字，請換一張清楚的照片。"));
  lines.forEach(line => {
    const row = element("div", "ocr-line", line.text);
    if (line.score < .94) row.append(element("small", "", "此行辨識不確定，請對照照片。"));
    container.append(row);
  });
}
function fillReference(job) {
  if(!allowed())return;
  state.referenceJob = job; state.source = null;
  $("#source-note").textContent = "";
  const form = $("#standard-form"), fields = job.result.fields;
  $("#reference-preview").src = job.image.url; $("#reference-preview").hidden = false;
  $("#reference-recovery").textContent = recoveryMessage(job.result.ocr); $("#reference-recovery").hidden = !$("#reference-recovery").textContent;
  $("#reference-ocr").hidden = false; renderOCR(job.result.ocr.lines, $("#reference-lines"));
  $("#standard-fields").disabled = false;
  for (const key of [...textFields, "manufacture", "expiry", "arrival"]) form.elements[key].value = fields[key]?.value || "";
  form.elements.name.value = state.supersedes?.name || fields.product?.value || "";
  form.elements.dates.checked = state.supersedes?.rules.dates ?? !(fields.arrival && !fields.manufacture && !fields.expiry);
  form.elements.check_arrival.checked = state.supersedes ? !!state.supersedes.rules.arrival : !!fields.arrival;
  form.elements.keep_days.value = state.supersedes?.rules.keep_days ?? "";
  form.elements.confirmed.checked = false; toggleDateFields();
  toast("照片已辨識，請對照原圖逐欄確認。" );
}
async function pollJob(jobId, kind) {
  for (let attempts = 0; attempts < 600; attempts++) {
    if(kind==="reference" && !allowed())throw new Error("標準照片已保留，請管理員解鎖後再接續處理。");
    const job = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    if (job.state === "failed") { rememberFailedJob({...job,id:job.id || jobId}, kind); sessionStorage.removeItem("labelcheck-pending"); throw new Error(job.error || "照片辨識未完成，可以使用已保留的照片重試。"); }
    if (job.state === "done") {
      sessionStorage.removeItem("labelcheck-pending");
      setRetryJob(kind); setUploadError(kind); loadFailedJobs();
      if (kind === "reference") fillReference(job);
      else await loadInspection(job.result.inspection_id);
      return;
    }
    if (kind === "reference") { $("#reference-preview").src = job.image.url; $("#reference-preview").hidden = false; }
    const label = $(`#${kind === "reference" ? "reference" : "inspect"}-progress span:last-child`);
    label.textContent = job.state === "pending" ? "照片已收到，等待辨識…" : attempts > 20 ? "正在仔細讀取文字，請稍候…" : "照片辨識中，請稍候…";
    await new Promise(resolve => setTimeout(resolve, 1200));
  }
  throw new Error("辨識仍在處理中，可重新整理頁面接續查看結果。");
}
async function upload(file, kind) {
  if(kind==="reference" && !requireAdmin())return;
  if (!file || state.busy) return;
  setUploadError(kind); setRetryJob(kind);
  if (kind === "reference") $("#reference-recovery").hidden = true;
  if (file.size > maxPhotoBytes) return reportUploadFailure(kind, "照片超過 15 MB，請改選較小的 JPG 照片，並保留標籤文字清晰。");
  const sourceCode = state.inspectSource?.code || "";
  const template = sourceCode ? "" : $("#template-select").value;
  if (kind === "inspection" && !template) kind = "recognition";
  if (kind !== "reference" && !validBaseDate()) { setUploadError(kind, "請設定本批基準日後再上傳。"); return; }
  const form = new FormData(); form.append("photo", file); form.append("kind", kind);
  if (kind !== "reference") { form.append("template_id", template); form.append("source_code", sourceCode); form.append("base_date", $("#base-date").value); form.append("batch_date", $("#batch-date").value); form.append("arrival_date", $("#arrival-date").value); clearResult(); }
  else { state.referenceJob = null; state.source = null; $("#standard-fields").disabled = true; $("#reference-preview").hidden = true; $("#reference-ocr").hidden = true; }
  setBusy(true, kind);
  try {
    const job = await api("/api/jobs", {method: "POST", body: form});
    sessionStorage.setItem("labelcheck-pending", JSON.stringify({id: job.id, kind, supersedes_id:kind === "reference" ? state.supersedes?.id || null : null}));
    await pollJob(job.id, kind);
  } catch (error) { reportUploadFailure(kind, error); }
  finally { setBusy(false); }
}
async function saveStandard(event) {
  event.preventDefault(); if (!requireAdmin() || (!state.referenceJob && !state.source) || state.busy) return;
  const form = event.currentTarget, button = $("button[type=submit]", form); button.disabled = true; setBusy(true);
  try {
    const body = {job_id: state.referenceJob?.id, source_code: state.source?.code, source_revision: state.source?.revision, name: form.elements.name.value.trim(),
      fields: Object.fromEntries(textFields.map(k => [k, form.elements[k].value.trim()])),
      rules: {dates: form.elements.dates.checked, arrival: form.elements.check_arrival.checked, keep_days: form.elements.dates.checked && form.elements.keep_days.value !== "" ? Number(form.elements.keep_days.value) : null},
      reference_dates: {manufacture: form.elements.manufacture.value, expiry: form.elements.expiry.value, arrival: form.elements.arrival.value},
      approved_by: form.elements.approved_by.value.trim(), confirmed: form.elements.confirmed.checked,
      supersedes_id: state.supersedes?.id || null};
    const standard = await api("/api/templates", {method: "POST", body});
    sessionStorage.setItem("labelcheck-operator", body.approved_by);
    state.referenceJob = null; $("#standard-fields").disabled = true;
    await loadTemplates(standard.id); clearResult(); showView("inspect"); toast("標準已啟用，可以開始拍照檢查。" );
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; setBusy(false); }
}
let manualLibraryPage=1,manualLibraryRequest=0,manualLibraryTotal=0;
async function loadManualLibrary(page=1) {
  if(!allowed())return;
  const token=++manualLibraryRequest,query=$("#manual-library-query").value.trim();
  $("#manual-library-status").textContent="讀取人工文字標準…";
  $("#manual-library-prev").disabled=true;$("#manual-library-next").disabled=true;
  try {
    const data=await api(`/api/manual-standards?page=${page}&limit=24&q=${encodeURIComponent(query)}`);if(token!==manualLibraryRequest)return;
    manualLibraryPage=page;
    if(!query){manualLibraryTotal=data.total || 0;$("#nav-count").textContent=String(state.templates.length+manualLibraryTotal);}
    const list=$("#manual-library-list");list.replaceChildren();
    for(const item of data.items || []){
      const card=element("article","panel library-card"),content=element("div","library-card-content");
      content.append(badge("pass",`已確認 · 第 ${item.revision} 版`),element("h3","",item.name),element("p","help",`${sourceCodeLabel(item)} · ${item.reviewer || ""} · ${when(item.created_at)}`));
      const use=element("button","button primary","選用此標準");use.type="button";use.onclick=()=>{if(state.busy)return;selectInspectSource(item);showView("inspect");};
      const history=element("button","button secondary","查看建立紀錄");history.type="button";history.onclick=async()=>{if(state.busy)return;try{await loadInspection(item.inspection_id);}catch(error){toast(error.message,true);}};
      const actions=element("div","library-actions");actions.append(use,history);content.append(actions);card.append(content);list.append(card);
    }
    $("#manual-library-status").textContent=data.items?.length ? `共 ${data.total} 份 · 第 ${page} 頁` : query ? "找不到符合的人工標準。" : "尚未建立人工文字標準。無依據的檢查結果可按「建立文字比對標準」。";
    $("#manual-library-prev").disabled=page<=1;$("#manual-library-next").disabled=!data.has_more;
  } catch(error){if(token===manualLibraryRequest)$("#manual-library-status").textContent=error.message;}
}
function renderLibrary() {
  if(!allowed())return;
  const list = $("#library-list"); list.replaceChildren();
  if (!state.templates.length) {
    const empty = element("div", "empty-state"); empty.append(element("h2", "", "尚未建立照片標準"), element("p", "", "也可以從人工確認過的正確照片建立標準。"));
    const button = element("button", "button primary", "建立第一份標準"); button.onclick = () => newStandard(); empty.append(button); list.append(empty); return;
  }
  state.templates.forEach(standard => {
    const card = element("article", "panel library-card");
    if (standard.image) { const image = element("img"); image.src = standard.image.thumbnail; image.alt = `${standard.name} 標準照片`; image.loading = "lazy"; card.append(image); }
    const content = element("div", "library-card-content"); content.append(badge("pass", `已確認 · 第 ${standard.version} 版`), element("h2", "", standard.name));
    textFields.forEach(key => { if (standard.fields[key]) content.append(element("p", "", `${fieldLabels[key]}：${standard.fields[key]}`)); });
    const dateRules = [];
    if (standard.rules.dates) dateRules.push("製造／有效日期");
    if (standard.rules.arrival) dateRules.push("到店日");
    content.append(element("p", "help", dateRules.length ? `日期檢查：${dateRules.join("、")}` : "未啟用日期檢查"), element("p", "", `${standard.approved_by} · ${when(standard.created_at)}`));
    const actions = element("div", "library-actions"), use = element("button", "button primary", "用此標準檢查"), edit = element("button", "button secondary", "建立新版");
    use.onclick = () => { if(state.busy) return toast("請等待目前辨識完成。"); $("#template-select").value = standard.id; selectedStandard(); markResultChanged(); showView("inspect"); };
    edit.onclick = () => newStandard(standard); actions.append(use, edit); content.append(actions); card.append(content); list.append(card);
  });
}
async function loadInspection(id, restoreSettings = true) {
  const inspection = await api(`/api/inspections/${encodeURIComponent(id)}`); state.inspection = inspection; state.resultDirty = false; state.standardSaved=false;
  state.manualView = true;
  if (restoreSettings) restoreInspectionSettings(inspection);
  renderInspection(inspection); showView("inspect"); $("#result-area").scrollIntoView({block:"start",behavior:"instant"});
}
function restoreInspectionSettings(inspection) {
  const result = inspection.manual_revision?.result || inspection.result, inputs = result.inputs || {};
  if (inputs.base_date) $("#base-date").value = inputs.base_date;
  $("#batch-date").value = inputs.batch_date || ""; $("#arrival-date").value = inputs.arrival_date || "";
  const template = state.templates.find(item => item.id === inspection.template_id);
  $("#template-select").value = template ? template.id : "";
  selectedStandard();
  const match = result.source_match;
  state.inspectSource = !template && (inputs.source_code || match?.status === "matched") ? {...match, code: inputs.source_code || match.code, name: match?.name || inspection.name || inputs.source_code} : null;
  renderInspectSource();
}
const correctionLabels = {ocr_misread:"OCR 辨識讀錯",label_misprint:"標籤實際印錯",uncertain:"看不清楚，待確認"};
function setDialogError(id, message = "") { const node = $(id); node.textContent = message; node.hidden = !message; }
function currentRevision(inspection = state.inspection) { return Number(inspection?.manual_revision?.revision) || 0; }
function currentPatch(lineId) { return (state.inspection?.manual_revision?.patches || []).find(patch => patch.line_id === lineId); }
function correctionKindChanged() {
  const uncertain = $("#correction-kind").value === "uncertain";
  $("#correction-text").required = !uncertain; $("#correction-text").disabled = uncertain;
  $("#correction-text-help").textContent = uncertain ? "不必猜字，會保留目前文字並標記待確認。看清楚後可以再次訂正。" : "依照片逐字填寫，包含標點；即使照片印錯，也請保留實際錯字。";
}
function drawCorrectionPhoto(inspection, line) {
  const canvas = $("#correction-photo"), request = ++state.correctionImageRequest, image = new Image();
  canvas.width = 1; canvas.height = 1; $("#correction-photo-note").textContent = "載入原圖中…";
  $("#correction-full-photo").href = inspection.image.url;
  image.onload = () => {
    if (request !== state.correctionImageRequest) return;
    const points = (Array.isArray(line.box) ? line.box : []).filter(point => Array.isArray(point) && point.length === 2 && point.every(Number.isFinite));
    let x = 0, y = 0, width = image.naturalWidth, height = image.naturalHeight;
    if (points.length >= 3) {
      const xs = points.map(p=>p[0]), ys = points.map(p=>p[1]), padding = Math.max(30,(Math.max(...ys)-Math.min(...ys))*2);
      x = Math.max(0,Math.min(...xs)-padding); y = Math.max(0,Math.min(...ys)-padding);
      width = Math.max(1,Math.min(image.naturalWidth,Math.max(...xs)+padding)-x);
      height = Math.max(1,Math.min(image.naturalHeight,Math.max(...ys)+padding)-y);
    }
    const scale = Math.min(1,1400/width); canvas.width = Math.max(1,Math.round(width*scale)); canvas.height = Math.max(1,Math.round(height*scale));
    const ctx = canvas.getContext("2d"); ctx.drawImage(image,x,y,width,height,0,0,canvas.width,canvas.height);
    if (points.length >= 3) { ctx.strokeStyle="#c84232";ctx.lineWidth=2;ctx.beginPath();points.forEach(([px,py],i)=>i?ctx.lineTo((px-x)*scale,(py-y)*scale):ctx.moveTo((px-x)*scale,(py-y)*scale));ctx.closePath();ctx.stroke(); }
    $("#correction-photo-note").textContent = points.length >= 3 ? "紅框是所選文字；請以照片實際印字為準。" : "此行沒有位置資料，請對照完整原圖。";
  };
  image.onerror = () => { if (request === state.correctionImageRequest) $("#correction-photo-note").textContent = "預覽暫時無法載入，請點選完整原圖確認。"; };
  image.src = inspection.image.url;
}
function openCorrectionDialog(lineId) {
  if (state.busy || !state.inspection) return;
  const inspection = state.inspection, line = inspection.ocr.lines.find(item => item.id === lineId); if (!line) return;
  const patch = currentPatch(lineId), result = inspection.manual_revision?.result || inspection.result;
  state.correction = {inspectionId:inspection.id,lineId,baseRevision:currentRevision(),conflict:false};
  $("#correction-form").reset(); $("#correction-original").value = line.text || "";
  $("#correction-text").value = patch?.text ?? line.text ?? ""; $("#correction-kind").value = patch?.kind || "ocr_misread";
  $("#correction-reviewer").value = sessionStorage.getItem("labelcheck-operator") || "";
  const expected = [...new Set((result.checks || []).filter(check=>(check.line_ids || []).includes(lineId)).map(check=>check.expected).filter(Boolean))];
  $("#correction-standard").textContent = expected.join("\n") || "這行尚無比對標準。"; $("#correction-standard-details").open = false;
  $("#correction-revoke").hidden = !patch; $("#correction-revoke-help").hidden = !patch; $("#correction-reload").hidden = true; $("#correction-save").disabled = false; $("#correction-revoke").disabled = false;
  setDialogError("#correction-error"); correctionKindChanged(); drawCorrectionPhoto(inspection,line);
  if (!$("#correction-dialog").open) $("#correction-dialog").showModal();
}
async function saveCorrection(operation = "replace") {
  const context = state.correction;
  if (state.busy || !context || context.conflict || state.inspection?.id !== context.inspectionId) return;
  const reviewer = $("#correction-reviewer"), note = $("#correction-note");
  if (!reviewer.value.trim() || !note.value.trim()) { setDialogError("#correction-error","請填寫訂正人員與原因。"); return; }
  if (operation === "replace" && !$("#correction-form").reportValidity()) return;
  const body = {base_revision:context.baseRevision,line_id:context.lineId,operation,reviewer:reviewer.value.trim(),note:note.value.trim()};
  if (operation === "replace") { body.kind = $("#correction-kind").value; body.text = body.kind === "uncertain" ? "" : $("#correction-text").value; }
  setDialogError("#correction-error"); setBusy(true);
  $$("#correction-form button, #correction-close").forEach(button=>{button.disabled=true;});
  $$("#correction-form input, #correction-form textarea, #correction-form select").forEach(input=>{input.disabled=true;});
  try {
    const inspection = await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/corrections`,{method:"POST",body});
    sessionStorage.setItem("labelcheck-operator",body.reviewer); state.inspection=inspection;state.manualView=true;
    renderInspection(inspection); $("#correction-dialog").close();
    toast(operation === "revoke" ? "已撤回這行訂正，原紀錄仍保留。" : "人工訂正已保存，判定已更新。");
  } catch (error) {
    if (error.status === 409) {
      context.conflict = true;
      try { state.inspection=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}`);renderInspection(state.inspection); } catch (_) { /* Keep the user's draft if refresh also fails. */ }
      $("#correction-reload").hidden=false;
      setDialogError("#correction-error","其他人已更新這筆訂正。你的輸入仍保留；請先複製需要的文字，再載入最新訂正核對，這次尚未儲存。");
    } else setDialogError("#correction-error",error.message);
  } finally {
    setBusy(false); $$("#correction-form button, #correction-close").forEach(button=>{button.disabled=false;});
    $$("#correction-form input, #correction-form textarea, #correction-form select").forEach(input=>{input.disabled=false;});correctionKindChanged();
    $("#correction-save").disabled=!!context.conflict;$("#correction-revoke").disabled=!!context.conflict;
  }
}
function appendCorrectionHistory(list, items) {
  for (const item of items || []) {
    const row=element("div","review-record"), operation=item.operation === "revoke" ? "撤回訂正" : item.operation === "copy" ? "沿用先前人工訂正" : correctionLabels[item.kind] || "人工訂正";
    row.append(element("strong","",`第 ${item.revision} 版 · ${operation}${item.line_id === null || item.line_id === undefined ? "" : ` · 第 ${item.line_id} 行`}`));
    if (item.text) row.append(element("p","manual-history-text",item.text));
    if (item.note) row.append(element("p","help",item.note));
    row.append(element("small","",`${item.reviewer || ""} · ${when(item.created_at)}`));list.append(row);
  }
}
function renderCorrectionHistory(inspection,area) {
  if (!currentRevision(inspection) && !inspection.correction_history?.length) return;
  const details=element("details","correction-history"),list=element("div");details.append(element("summary","","人工訂正紀錄（保留原始辨識）"),list);
  appendCorrectionHistory(list,inspection.correction_history);area.append(details);
  if (inspection.correction_history_has_more) {
    let page=1; const more=element("button","button secondary","查看更多訂正紀錄"),error=element("p","upload-error");more.type="button";error.hidden=true;error.setAttribute("role","alert");details.append(more,error);
    more.onclick=async()=>{more.disabled=true;error.hidden=true;try{const data=await api(`/api/inspections/${encodeURIComponent(inspection.id)}/corrections?page=${page}`);if(page===1)list.replaceChildren();appendCorrectionHistory(list,data.items);page++;more.hidden=!data.has_more;}catch(e){error.textContent=e.message;error.hidden=false;}finally{more.disabled=false;}};
  }
}
let manualStandard = null;
function invalidateManualPreview() {
  if(manualStandard)manualStandard.preview=null;
  $("#manual-standard-preview").hidden=true;$("#manual-standard-confirm-label").hidden=true;$("#manual-standard-save").hidden=true;$("#manual-standard-confirm").checked=false;
}
async function openManualStandard(inspectionId=state.inspection?.id) {
  if(!requireAdmin())return;
  if(state.busy || !inspectionId)return;
  const context={inspectionId,preview:null};manualStandard=context;
  $("#manual-standard-form").reset();$("#manual-standard-form").hidden=true;invalidateManualPreview();setDialogError("#manual-standard-error");
  $("#manual-standard-notice").textContent="讀取此張照片的參考文字…";$("#manual-standard-dialog").showModal();
  try {
    const data=await api(`/api/inspections/${encodeURIComponent(inspectionId)}/manual-standard`);
    if(manualStandard!==context)return;
    $("#manual-standard-notice").textContent=(data.notice || "請依正確資料逐字核對，辨識原文尚未核准。")+(data.draft_basis==="manual_correction" ? " 已帶入本筆確認為 OCR 讀錯的訂正文字；仍需逐字核准為正確標準。" : "")+(data.excluded_unconfirmed_lines?.length ? ` ${data.excluded_unconfirmed_lines.length} 行印錯或不確定內容未帶入，請依正確資料補齊。` : "");
    if(!data.can_create){
      if(data.existing_code){const source=await api(`/api/source-labels/${encodeURIComponent(data.existing_code)}`);if(manualStandard!==context)return;$("#manual-standard-dialog").close();selectInspectSource(source);toast("這張照片已建立過文字標準，請重新核對套用。");}
      return;
    }
    $("#manual-standard-form").hidden=false;
    $("#manual-standard-name").value=data.suggested_name || "";$("#manual-standard-sku").value=data.suggested_sku || "";
    $("#manual-standard-lines").value=(data.draft_lines || []).map(line=>typeof line === "string" ? line : line.text).join("\n");
    $("#manual-standard-reviewer").value=sessionStorage.getItem("labelcheck-operator") || "";
  } catch(error){if(manualStandard===context)setDialogError("#manual-standard-error",error.message);}
}
function manualStandardBody() {
  const form=$("#manual-standard-form");if(!form.reportValidity())return null;
  const lines=$("#manual-standard-lines").value.split(/\r?\n/).map(text=>text.trim()).filter(Boolean).map(text=>({text}));
  const date_settings=[];for(const kind of ["manufacture","expiry","arrival"]){const value=$(`#manual-standard-${kind}`).value;if(value!=="")date_settings.push({kind,shift_days:Number(value)});}
  return {name:$("#manual-standard-name").value.trim(),sku:$("#manual-standard-sku").value.trim(),lines,
    keep_days:$("#manual-standard-days").value==="" ? null : Number($("#manual-standard-days").value),date_settings};
}
function manualFormBusy(busy){setBusy(busy);$$("#manual-standard-dialog input, #manual-standard-dialog textarea, #manual-standard-dialog button").forEach(node=>{node.disabled=busy;});}
async function previewManualStandard() {
  if(!requireAdmin())return;
  if(state.busy || !manualStandard)return;const body=manualStandardBody();if(!body)return;
  const context=manualStandard;invalidateManualPreview();setDialogError("#manual-standard-error");manualFormBusy(true);
  try {
    const data=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/manual-standard/preview`,{method:"POST",body});
    if(manualStandard!==context)return;
    context.preview={body:JSON.stringify(body),hash:data.preview_hash};
    const preview=$("#manual-standard-preview");preview.replaceChildren(element("h3","","確認日後比對的正確文字"),element("p","",`品名：${data.source?.name || body.name}`));
    if(body.sku)preview.append(element("p","",`貨號：${body.sku}`));
    for(const line of data.source?.lines || body.lines)preview.append(element("p","manual-history-text",line.text));
    const kinds={manufacture:"製造日",expiry:"有效日",arrival:"到店日"};
    for(const item of body.date_settings)preview.append(element("p","",`${kinds[item.kind]}：基準日 ${item.shift_days>=0 ? "+" : ""}${item.shift_days} 天`));
    preview.append(element("p","help",`保存天數：${body.keep_days ?? "未設定"}；未提供的內容不算已確認。`));
    for(const warning of data.warnings || [])preview.append(element("p","help",warning));
    preview.hidden=false;$("#manual-standard-confirm-label").hidden=false;$("#manual-standard-save").hidden=false;
  } catch(error){setDialogError("#manual-standard-error",error.message);}
  finally {manualFormBusy(false);}
}
async function saveManualStandard(event) {
  event.preventDefault();if(!requireAdmin() || state.busy || !manualStandard)return;
  const context=manualStandard,body=manualStandardBody();if(!body)return;
  if(!context.preview || context.preview.body!==JSON.stringify(body)){invalidateManualPreview();setDialogError("#manual-standard-error","內容有變更，請重新預覽後確認。");return;}
  const reviewer=$("#manual-standard-reviewer").value.trim(),note=$("#manual-standard-note").value.trim();
  if(!reviewer || !note || !$("#manual-standard-confirm").checked){setDialogError("#manual-standard-error","請填寫人員、原因，並確認已核對正確文字。");return;}
  manualFormBusy(true);setDialogError("#manual-standard-error");let saved=null;
  try {saved=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/manual-standard`,{method:"POST",body:{...body,preview_hash:context.preview.hash,reviewer,note,confirmed:true}});sessionStorage.setItem("labelcheck-operator",reviewer);$("#manual-standard-dialog").close();manualStandard=null;}
  catch(error){setDialogError("#manual-standard-error",error.message);}
  finally {manualFormBusy(false);}
  if(saved && allowed()){selectInspectSource(saved.source || saved);standardSavedNotice();loadManualLibrary(1);toast("文字標準已儲存，下次可搜尋選用。請重新核對本張照片。");}
}
function invalidateStandardPreview() {
  if (!state.standardEdit) return;
  state.standardEdit.preview = null;
  $("#standard-edit-preview").hidden=true;$("#standard-edit-confirm-label").hidden=true;$("#standard-edit-save").hidden=true;$("#standard-edit-confirm").checked=false;
}
async function openStandardEditor(inspectionId = state.inspection?.id, focusLineIds = []) {
  if(!requireAdmin())return;
  if (state.busy || !inspectionId) return;
  state.standardEdit={inspectionId,loading:true,operation:"update",focusLineIds:Array.isArray(focusLineIds) ? focusLineIds.map(String) : []};
  $$("#standard-edit-dialog button").forEach(button=>{button.disabled=false;});
  $("#standard-edit-form").reset();$("#standard-edit-form").hidden=true;$("#standard-edit-photo-template").hidden=true;$("#standard-edit-reload").hidden=true;$("#standard-edit-reset").hidden=true;$("#standard-edit-operation").hidden=true;
  $("#standard-edit-source").textContent="載入比對標準中…";$("#standard-edit-notice").textContent="";$("#standard-edit-history-list").replaceChildren();$("#standard-edit-history").hidden=true;setDialogError("#standard-edit-error");invalidateStandardPreview();
  if (!$("#standard-edit-dialog").open) $("#standard-edit-dialog").showModal();
  const context=state.standardEdit;
  try {
    const data=await api(`/api/inspections/${encodeURIComponent(inspectionId)}/standard`);
    if (state.standardEdit !== context) return;
    Object.assign(context,{data,loading:false,lineControls:[],dateControls:[],conflict:false});
    $("#standard-edit-source").textContent=`${data.kind === "manual" ? "人工文字標準" : data.kind === "catalog" ? "清單" : data.kind === "photo_template" ? "照片標準" : "系統標籤"} ${sourceCodeLabel(data)} · ${data.name || data.source?.name || "未指定"} · ${data.base_revision ? `比對標準第 ${data.base_revision} 版` : "原始來源"}`;
    $("#standard-edit-notice").textContent=`${data.stale ? "來源資料已更新，請重新核對目前內容。 " : ""}${data.notice || ""}`;
    const history=$("#standard-edit-history-list");
    for(const item of data.history || []){
      const row=element("div","review-record");row.append(element("strong","",`第 ${item.revision} 版 · ${item.operation === "reset" ? "恢復原始來源" : item.operation === "restore" ? "還原歷史版本" : "修改比對標準"}`),element("p","help",item.note || ""),element("small","",`${item.reviewer || ""} · ${when(item.created_at)}`));
      if(data.editable){const restore=element("button","button secondary","還原此版");restore.type="button";restore.dataset.standardRestore=String(item.revision);restore.setAttribute("aria-label",`還原比對標準第 ${item.revision} 版`);restore.disabled=!!data.stale || item.source_revision!==data.source_revision || item.revision===data.base_revision;restore.onclick=()=>selectStandardOperation("restore",item.revision);row.append(restore);if(restore.disabled)row.append(element("small","",item.revision===data.base_revision ? "目前版本" : "原始來源已變更，這版無法直接還原。"));}
      history.append(row);
    }
    $("#standard-edit-history").hidden=!(data.history || []).length;
    if(data.has_more)history.append(element("p","help","此處顯示最近的標準修改紀錄，較早版本仍保留。"));
    if (!data.editable) {
      if(data.kind === "photo_template" && data.photo_template_id){
        const template=state.templates.find(item=>item.id===data.photo_template_id);
        if(template){$("#standard-edit-photo-template").hidden=false;$("#standard-edit-photo-template").onclick=()=>{$("#standard-edit-dialog").close();newStandard(template);};}
      }
      return;
    }
    const source=data.source || {};$("#standard-edit-form").hidden=false;$("#standard-edit-reset").hidden=false;$("#standard-edit-reset").disabled=!data.base_revision;
    $("#standard-edit-name").value=source.name || "";$("#standard-edit-days").value=source.keep_days ?? "";$("#standard-edit-reviewer").value=sessionStorage.getItem("labelcheck-operator") || "";
    const lines=$("#standard-edit-line-fields");lines.replaceChildren();
    (source.lines || []).forEach((line,index)=>{
      const title=`第 ${index+1} 段標準文字`,label=element("label","",title),input=element("textarea");input.rows=2;input.maxLength=2000;input.value=line.text || "";input.dataset.standardLine=String(line.id);label.append(input);lines.append(label);context.lineControls.push({line,input,label,title});
    });
    $("#standard-edit-lines").hidden=!context.lineControls.length;$("#standard-edit-lines").open=false;
    const dates=$("#standard-edit-date-fields");dates.replaceChildren();
    (source.date_settings || []).forEach((setting,index)=>{const label=element("label","",`${setting.content || `日期欄 ${index+1}`}：相對基準日位移天數`),input=element("input");input.type="number";input.step="1";input.min="-3650";input.max="3650";input.required=true;input.value=setting.shift_days ?? 0;label.append(input);dates.append(label);context.dateControls.push({index,setting,input});});
    $("#standard-edit-dates").hidden=!context.dateControls.length;$("#standard-edit-dates").open=false;
    lockStandardContent(false);
    if(context.focusLineIds.length){
      const matched=context.lineControls.filter(item=>context.focusLineIds.includes(String(item.line.id)));
      if(matched.length){
        $("#standard-edit-lines").open=true;matched.forEach(item=>{item.label.className="standard-target-line";item.input.setAttribute("aria-description","這是所選異常對應的標準文字。");});
        $("#standard-edit-notice").textContent+=` 已定位 ${matched.map(item=>item.title).join("、")}，請確認這些標準文字是否正確。`;
        matched[0].input.focus({preventScroll:true});matched[0].label.scrollIntoView({block:"center",behavior:"instant"});
      }else setDialogError("#standard-edit-error","目前標準已變更，找不到原先對應的文字段落。請核對上方來源，並重新選擇要修正的內容。");
    }
  } catch(error){if(state.standardEdit===context){context.loading=false;setDialogError("#standard-edit-error",error.message);$("#standard-edit-reload").hidden=false;}}
}
function lockStandardContent(locked) {
  $("#standard-edit-name").disabled=locked;$("#standard-edit-days").disabled=locked;
  for(const item of state.standardEdit?.lineControls || [])item.input.disabled=locked;
  for(const item of state.standardEdit?.dateControls || [])item.input.disabled=locked;
}
function standardOperationDifferences(before, after, operation, revision) {
  const changes=[{label:"還原操作",before:"目前網站比對標準",after:operation==="reset" ? "恢復目前原始來源；保留先前修改紀錄。" : `採用第 ${revision} 版內容，另建立新版；保留先前修改紀錄。`}];
  function compare(label,oldValue,newValue){if(JSON.stringify(oldValue ?? null)!==JSON.stringify(newValue ?? null))changes.push({label,before:oldValue ?? "未設定",after:newValue ?? "未設定"});}
  compare("標準品名",before.name,after.name);compare("保存天數",before.keep_days,after.keep_days);
  const beforeLines=new Map((before.lines || []).map((line,index)=>[String(line.id),{line,index}])),afterLines=new Map((after.lines || []).map((line,index)=>[String(line.id),{line,index}]));
  for(const id of new Set([...beforeLines.keys(),...afterLines.keys()])){const prior=beforeLines.get(id),next=afterLines.get(id);compare(`第 ${(next?.index ?? prior.index)+1} 段標準文字`,prior?.line.text ?? "（原本沒有這段）",next?.line.text ?? "（此版沒有這段）");}
  const beforeDates=before.date_settings || [],afterDates=after.date_settings || [];
  for(let index=0;index<Math.max(beforeDates.length,afterDates.length);index++){
    const describe=item=>item ? `${item.content || "日期"} · 格式 ${item.format || "未設定"} · 位移 ${item.shift_days ?? 0} 天` : "未設定";
    compare(`第 ${index+1} 項日期規則`,describe(beforeDates[index]),describe(afterDates[index]));
  }
  compare("條碼參考值",(before.barcode_values || []).join("、") || "未設定",(after.barcode_values || []).join("、") || "未設定");
  return changes;
}
function cancelStandardOperation() {
  if(state.busy || !state.standardEdit)return;
  Object.assign(state.standardEdit,{operation:"update",targetRevision:undefined,targetSource:null});
  $("#standard-edit-operation").hidden=true;lockStandardContent(false);invalidateStandardPreview();setDialogError("#standard-edit-error");
}
function restoreStandardOperationButtons() {
  const context=state.standardEdit,data=context?.data;
  $("#standard-edit-reset").disabled=state.busy || !data?.editable || !data.base_revision || !!context.conflict;
  $$("[data-standard-restore]").forEach(button=>{const item=(data?.history || []).find(row=>String(row.revision)===button.dataset.standardRestore);button.disabled=state.busy || !!context?.conflict || !item || !!data.stale || item.source_revision!==data.source_revision || item.revision===data.base_revision;});
}
async function selectStandardOperation(operation, targetRevision) {
  if(!requireAdmin())return;
  const context=state.standardEdit;
  if(state.busy || !context?.data?.editable || context.conflict || !["reset","restore"].includes(operation))return;
  if(operation==="restore"){
    const item=(context.data.history || []).find(row=>row.revision===targetRevision);
    if(!item || context.data.stale || item.source_revision!==context.data.source_revision || targetRevision===context.data.base_revision){setDialogError("#standard-edit-error","這個歷史版本無法直接還原，請重新載入並確認來源。");return;}
  }
  let selected=false;
  invalidateStandardPreview();setDialogError("#standard-edit-error");setBusy(true);$$("#standard-edit-dialog button").forEach(button=>{button.disabled=true;});
  try {
    const query=`operation=${operation}${operation==="restore" ? `&target_revision=${encodeURIComponent(targetRevision)}` : ""}`;
    const data=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/standard/preview?${query}`);
    if(state.standardEdit!==context)return;
    if(data.base_revision!==context.data.base_revision || data.source_revision!==context.data.source_revision){const error=new Error("標準已更新，請重新載入最新標準後確認。");error.status=409;throw error;}
    if(!data.source || data.operation!==operation || (operation==="restore" && data.target_revision!==targetRevision))throw new Error("無法取得完整的還原預覽，尚未修改標準。");
    Object.assign(context,{operation,targetRevision:operation==="restore" ? targetRevision : undefined,targetSource:data.source});
    selected=true;
    lockStandardContent(true);$("#standard-edit-operation").hidden=false;
    $("#standard-edit-operation-note").textContent=`${operation==="reset" ? "準備恢復目前原始來源" : `準備還原第 ${targetRevision} 版`}。欄位暫停編輯，尚未儲存；請核對下方差異，填寫人員及原因後確認。`;
  } catch(error){if(error.status===409){context.conflict=true;$("#standard-edit-reload").hidden=false;}setDialogError("#standard-edit-error",error.message);}
  finally {setBusy(false);$$("#standard-edit-dialog button").forEach(button=>{button.disabled=false;});$("#standard-edit-save").disabled=!!context.conflict;restoreStandardOperationButtons();}
  if(selected && !context.conflict){previewStandardChanges();$("#standard-edit-preview").scrollIntoView({block:"center",behavior:"instant"});}
}
function standardPreviewSignature(collected) {
  const context=state.standardEdit;
  return JSON.stringify({operation:context.operation || "update",target_revision:context.targetRevision,changes:collected.changes,preview:collected.preview});
}
function collectStandardChanges() {
  const context=state.standardEdit;if(!context?.data?.editable || context.conflict)return null;
  if(context.operation && context.operation!=="update"){
    if(!context.targetSource){setDialogError("#standard-edit-error","請先載入要還原的版本內容。");return null;}
    return {changes:{},preview:standardOperationDifferences(context.data.source,context.targetSource,context.operation,context.targetRevision)};
  }
  const source=context.data.source,changes={},preview=[];
  const name=$("#standard-edit-name").value.trim();
  if(!name){setDialogError("#standard-edit-error","請填寫標準品名。");return null;}
  if(name !== source.name){changes.name=name;preview.push({label:"標準品名（主品名文字列會同步更新）",before:source.name,after:name});}
  const daysInput=$("#standard-edit-days");if(!daysInput.checkValidity()){daysInput.reportValidity();return null;}
  const days=daysInput.value === "" ? null : Number(daysInput.value);
  if(days === null && source.keep_days !== null && source.keep_days !== undefined){setDialogError("#standard-edit-error","已設定的保存天數不可清空，請填寫正確天數。");return null;}
  if(days !== (source.keep_days ?? null)){changes.keep_days=days;preview.push({label:"保存天數",before:source.keep_days ?? "未設定",after:days ?? "未設定"});}
  const lines=[];
  for(const {line,input,title} of context.lineControls){if(input.value !== line.text){if(!input.value.trim()){ $("#standard-edit-lines").open=true;input.focus();setDialogError("#standard-edit-error","既有標準文字列不可清空，請填寫正確文字。");return null;}lines.push({id:line.id,text:input.value});preview.push({label:title,before:line.text,after:input.value});}}
  if(lines.length)changes.lines=lines;
  const dates=[];
  for(const {index,setting,input} of context.dateControls){if(!input.checkValidity()){ $("#standard-edit-dates").open=true;input.reportValidity();return null;}const value=Number(input.value);if(value !== Number(setting.shift_days ?? 0)){dates.push({index,shift_days:value});preview.push({label:`${setting.content || `日期欄 ${index+1}`} 位移天數`,before:setting.shift_days ?? 0,after:value});}}
  if(dates.length)changes.date_settings=dates;
  return {changes,preview};
}
function previewStandardChanges() {
  if(!requireAdmin())return;
  if(state.busy)return;
  setDialogError("#standard-edit-error");const collected=collectStandardChanges();if(!collected)return;
  if(!collected.preview.length){invalidateStandardPreview();setDialogError("#standard-edit-error","目前沒有修改內容。");return;}
  const area=$("#standard-edit-preview");area.replaceChildren(element("h3","","請核對修改前後差異"));
  collected.preview.forEach(item=>{const row=element("div","standard-preview-row");row.append(element("strong","",item.label),element("p","before",`修改前：${item.before ?? "未設定"}`),element("p","after",`修改後：${item.after}`));area.append(row);});
  state.standardEdit.preview=standardPreviewSignature(collected);area.hidden=false;$("#standard-edit-confirm").checked=false;$("#standard-edit-confirm-label").hidden=false;$("#standard-edit-save").hidden=false;
}
async function saveStandardEdit(event) {
  event.preventDefault();const context=state.standardEdit;if(!requireAdmin() || state.busy || !context?.data?.editable || context.conflict)return;
  const collected=collectStandardChanges();if(!collected)return;
  if(!context.preview || context.preview !== standardPreviewSignature(collected)){invalidateStandardPreview();setDialogError("#standard-edit-error","內容已變更，請重新預覽修改差異。");return;}
  const reviewer=$("#standard-edit-reviewer").value.trim(),note=$("#standard-edit-note").value.trim();
  if(!reviewer || !note || !$("#standard-edit-confirm").checked){setDialogError("#standard-edit-error","請填寫修改人員、原因，並確認將套用到之後同款標籤。");return;}
  setDialogError("#standard-edit-error");setBusy(true);$$("#standard-edit-dialog button").forEach(button=>{button.disabled=true;});
  $$("#standard-edit-form input, #standard-edit-form textarea").forEach(input=>{input.disabled=true;});
  try {
    const body={base_revision:context.data.base_revision,source_revision:context.data.source_revision,changes:collected.changes,reviewer,note,confirmed:true,operation:context.operation || "update"};
    if(body.operation==="restore")body.target_revision=context.targetRevision;
    await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/standard`,{method:"POST",body});
    sessionStorage.setItem("labelcheck-operator",reviewer);$("#standard-edit-dialog").close();
    if(state.inspection?.id===context.inspectionId)standardSavedNotice();
    toast("新版比對標準已儲存，之後同款會套用；這張照片可再按「重新核對」。");
  } catch(error){
    if(error.status===409){context.conflict=true;$("#standard-edit-reload").hidden=false;setDialogError("#standard-edit-error","標準已被更新。你的輸入仍保留；請先複製需要的文字，再重新載入最新標準核對，這次尚未儲存。");}
    else setDialogError("#standard-edit-error",error.message);
  } finally {setBusy(false);$$("#standard-edit-dialog button").forEach(button=>{button.disabled=false;});$$("#standard-edit-form input, #standard-edit-form textarea").forEach(input=>{input.disabled=false;});lockStandardContent(context.operation!=="update");$("#standard-edit-save").disabled=!!context.conflict;restoreStandardOperationButtons();}
}
function diffNode(check, key) {
  const node = element("span");
  if (!check.diff?.length) { node.textContent = check[key] || "未辨識到"; return node; }
  check.diff.forEach(part => {
    const text = part[key];
    if (text) node.append(element("span", part.kind !== "equal" ? (key === "actual" ? "diff-actual" : "diff-expected") : "", text));
    else if (key === "actual" && part.kind === "delete") node.append(element("span", "diff-delete", "〔漏字〕"));
  });
  if (!check.actual && key === "actual") node.textContent = "未辨識到";
  return node;
}
function drawEvidence(canvas, inspection) {
  const image = new Image(); image.onload = () => {
    canvas.width = image.naturalWidth; canvas.height = image.naturalHeight;
    const ctx = canvas.getContext("2d"); ctx.drawImage(image, 0, 0);
    const ids = new Map(); inspection.result.checks.forEach(c => { if (["fail", "review"].includes(c.status)) (c.line_ids || []).forEach(id => { if (ids.get(id) !== "fail") ids.set(id, c.status); }); });
    for (const line of inspection.ocr.lines) {
      if (!ids.has(line.id)) continue;
      ctx.strokeStyle = ids.get(line.id) === "fail" ? "#c84232" : "#cc981e"; ctx.lineWidth = Math.max(3, image.width / 240);
      ctx.beginPath(); line.box.forEach(([x, y], i) => i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)); ctx.closePath(); ctx.stroke();
    }
  }; image.src = inspection.image.url;
}
function buildResultRows(checks, ocrLines) {
  const rank = {fail:0,review:1,pass:2,read:3}, sources = new Map(), rows = new Map();
  ocrLines.forEach(line => sources.set(line.id, line));
  checks.forEach(check => (check.source_lines || []).forEach(line => sources.set(line.id, {...sources.get(line.id),...line})));
  for (const line of sources.values()) rows.set(`line-${line.id}`, {id:`line-${line.id}`,status:"read",text:line.display_text ?? line.text,checks:[],line_ids:[line.id]});
  checks.forEach((check, index) => {
    const ids = (check.line_ids || []).filter(id => sources.has(id));
    const targets = ids.length ? ids.map(id => rows.get(`line-${id}`)) : [{id:`check-${index}`,status:"read",text:check.display_actual ?? check.display_text ?? check.actual,checks:[],line_ids:[]}];
    for (const row of targets) {
      row.checks.push(check);
      if ((rank[check.status] ?? 1) < rank[row.status]) row.status = check.status;
      if (!ids.length) { row.label = check.label; rows.set(row.id, row); }
    }
  });
  for (const row of rows.values()) {
    // A date substring passing does not verify other words on that same line.
    if (row.status === "pass" && row.checks.some(check => check.status === "read")) {
      row.status = "read"; row.partialPass = true;
    }
  }
  return [...rows.values()].sort((a,b) => rank[a.status] - rank[b.status]);
}
function appendOCRAlternatives(container, item) {
  const targets = new Set(Array.isArray(item.line_ids) ? item.line_ids : []), seen = new Set(), values = [];
  for (const check of item.checks || []) {
    for (const line of Array.isArray(check?.source_lines) ? check.source_lines : []) {
      if (!line || (targets.size && !targets.has(line.id))) continue;
      for (const alternative of Array.isArray(line.alternatives) ? line.alternatives : []) {
        const text = typeof alternative === "string" ? alternative : alternative?.text;
        if (typeof text !== "string" || !text.trim() || text === line.text || seen.has(text)) continue;
        seen.add(text); values.push(text);
      }
    }
  }
  if (!values.length) return;
  const block = element("div", "line-comparison ocr-alternatives");
  block.append(element("strong", "", "另一次辨識（僅供對照，未套用）"));
  values.forEach(text => block.append(element("p", "scan-line-text", text)));
  container.append(block);
}
function resultLine(item) {
  const expandable = ["fail","review"].includes(item.status);
  const row = element(expandable ? "details" : "div", `scan-line ${item.status}`); row.dataset.lineId = item.id;
  const body = expandable ? element("summary", "scan-line-summary") : row;
  const mark = element("span", `line-mark ${item.status}`, {pass:"✓",fail:"✕",review:"?",read:"·"}[item.status]);
  mark.setAttribute("role", "img"); mark.setAttribute("aria-label", {pass:"相符",fail:"有差異",review:"需確認",read:"僅辨識"}[item.status]);
  const content = element("div", "scan-line-content");
  const text = item.text || `${item.label || "內容"}：未辨識到`;
  content.append(element("p", "scan-line-text", item.label && item.text ? `${item.label}：${text}` : text));
  if (item.status === "read") content.append(element("small", "line-note", item.partialPass ? "部分日期檢查已通過，其餘文字尚無比對依據" : "僅辨識，尚無比對依據"));
  const reasons = [...new Set(item.checks.filter(check => check.status === item.status).map(check => check.reason).filter(Boolean))];
  if (expandable && reasons.length) content.append(element("p", "line-reason", reasons[0]));
  body.append(mark, content);
  if (expandable) {
    const hint = element("span", "line-detail-hint", "+"); hint.setAttribute("aria-hidden", "true"); body.append(hint); row.append(body);
    const detail = element("div", "scan-line-detail");
    const checks = item.checks.filter(check => ["fail","review"].includes(check.status));
    for (const check of checks) {
      const block = element("div", "line-comparison");
      if (check.label) block.append(element("strong", "", check.label));
      if (check.reason && check.reason !== reasons[0]) block.append(element("p", "check-reason", check.reason));
      if (check.conversion_changed) block.append(element("p", "display-note", "上方以繁體顯示；以下保留 OCR 原文。"));
      const hasDiff = Array.isArray(check.diff) && check.diff.length > 0;
      for (const [key, label] of [["expected","標準"],["actual",hasDiff ? "差異對照" : "辨識原文"]]) {
        if (key === "expected" && !check.expected) continue;
        const comparison = element("div", "comparison-row"); comparison.append(element("span", "", label), diffNode(check, key)); block.append(comparison);
      }
      if (hasDiff || item.originalLines) {
        const originalLines = item.originalLines?.filter(line => (check.line_ids || []).includes(line.id));
        const raw = originalLines?.length ? originalLines.map(line=>line.text || "").join("\n") : typeof check.raw_actual === "string" ? check.raw_actual : check.actual || "";
        const original = element("div", "comparison-row");
        original.append(element("span", "", item.originalLines ? "原始 OCR" : "辨識原文"), element("span", "scan-line-text", raw || "（未辨識到文字）"));
        block.append(original);
      }
      detail.append(block);
    }
    appendOCRAlternatives(detail, item);
    row.append(detail);
  }
  return row;
}
function renderSourceMatch(match, area, baseDate) {
  if (!match && !baseDate) return;
  const node = element("div", `source-match ${match?.status || "dated"}`); node.id = "result-source-match";
  if (!match) { node.append(element("p", "source-base-date", `基準日：${baseDate}`)); area.append(node); return; }
  if (match.status === "matched") {
    node.append(element("p", "", `${sourceKindLabel(match)}：${sourceCodeLabel(match)} ${match.name}`));
    if (isCatalogSource(match)) {
      const labels = {product:"品名",barcode:"條碼",keep_days:"保存天數",spec:"規格"};
      const known = (match.known_fields || []).map(key => labels[key]).filter(Boolean);
      const scope = element("p", "source-scope", `${known.length ? `核對範圍：${known.join("、")}。` : "依清單已有資料核對。"}清單沒有標籤版面，其他內容不視為已核對。`);
      scope.id = "result-source-scope"; node.append(scope);
    }
    if (match.source_kind === "manual")node.append(element("p","source-scope","僅核對人工已確認的文字與日期規則；未列入的內容不算已核對。"));
  }
  else {
    const text = {ambiguous:"找到多份相似標籤，請選定後重新核對。",unmatched:"尚未找到對應標籤，可手動選擇後重新核對。",unavailable:"暫時無法讀取系統標籤，目前僅檢查可判讀的內容。"}[match.status] || match.reason;
    node.append(element("p", "", text));
    if (match.candidates?.length) {
      const choices = element("div", "match-candidates");
      match.candidates.forEach(item => { const button = element("button", "source-option", sourceOptionLabel(item)); button.type="button"; button.onclick=()=>selectInspectSource(item); choices.append(button); }); node.append(choices);
    } else if (["unmatched","ambiguous"].includes(match.status)) {
      const choose = element("button", "source-match-pick", "選擇比對資料"); choose.type="button";
      choose.onclick=()=>{ $("#template-options").open=true; $("#inspect-source-query").focus(); }; node.append(choose);
    }
  }
  if (baseDate) node.append(element("p", "source-base-date", `基準日：${baseDate}`));
  area.append(node);
}
async function recheckInspection() {
  if (!state.inspection || state.busy || !validBaseDate()) return;
  const identifier = state.inspection.id, button = $("#recheck-button");
  const body = {source_code:state.inspectSource?.code || "",base_date:$("#base-date").value,batch_date:$("#batch-date").value,arrival_date:$("#arrival-date").value};
  setBusy(true); button.textContent = "核對中…";
  try {
    const result = await api(`/api/inspections/${encodeURIComponent(identifier)}/recheck`, {method:"POST",body});
    await loadInspection(result.inspection_id); toast(result.manual_revision ? "已沿用人工訂正，依最新資料重新核對。" : "已使用原辨識文字，依最新系統資料重新核對。");
  } catch (error) { toast(error.message,true); }
  finally { button.textContent = "重新核對"; setBusy(false); }
}
function renderRecheckControls(area) {
  const block = element("div", "recheck-controls"); block.id = "recheck-controls";
  const dirty = element("p", "recheck-dirty", state.standardSaved ? "標準已儲存，之後同款會使用新版。以下仍是上次結果，請重新核對本張照片。" : "設定已變更，以下仍是上次結果，請重新核對。"); dirty.id = "recheck-dirty"; dirty.hidden = !state.resultDirty; dirty.setAttribute("role","status");
  const button = element("button", `button ${state.standardSaved ? "primary" : "secondary"}`, state.standardSaved ? "用新標準重新核對本張" : "重新核對"); button.id = "recheck-button"; button.type = "button"; button.disabled = state.busy; button.onclick = recheckInspection;
  const result=state.inspection?.manual_revision?.result || state.inspection?.result;
  const hasSource=!!state.inspection?.template_id || !!state.inspection?.template_snapshot?.source?.code;
  const edit = element("button","button secondary",hasSource ? "更新比對標準" : "建立文字比對標準");edit.type="button";edit.dataset.editStandard="true";edit.disabled=state.busy;edit.hidden=!allowed() || !!result?.label_scope?.blocked;edit.onclick=()=>hasSource ? openStandardEditor() : openManualStandard();
  const hasPatches = !!state.inspection?.manual_revision?.patches?.length;
  block.append(dirty,button,edit,element("p","recheck-help",hasPatches ? "沿用目前人工訂正，依最新標準與上方本批日期重新核對；原紀錄保留。" : "使用原辨識文字，依最新系統標籤、清單與上方本批日期核對。"));
  block.append(element("p","workflow-help",allowed() ? "訂正辨識文字：按各行「訂正」，只影響本筆。更新比對標準：按「改標準」，影響之後同款掃描。" : "辨識讀錯時，按該行「訂正」，只影響本筆；變更後續比對標準需管理員處理。"));
  area.append(block);
}
function standardSavedNotice(){
  state.standardSaved=true;markResultChanged();
  if(state.inspection)renderInspection(state.inspection);
  $("#recheck-controls")?.scrollIntoView({block:"center",behavior:"instant"});
}
function renderResultLines(rows, area, inspection, manual = false) {
  const list = element("section", "scan-lines"); list.id = "result-lines"; list.setAttribute("aria-label", "逐列檢查結果");
  if (!rows.length) list.append(element("p", "group-empty", "沒有辨識到文字，請重新拍攝清楚的標籤。"));
  rows.forEach(row => {
    if(manual)row.originalLines=inspection.ocr.lines;
    const node=resultLine(row),lineId=row.line_ids.find(id=>inspection?.ocr?.lines?.some(line=>line.id===id));
    const sourceIds=!allowed() || inspection.template_id || !["fail","review"].includes(row.status) ? [] : [...new Set(row.checks.filter(check=>["fail","review"].includes(check.status) && check.source !== "date").flatMap(check=>Array.isArray(check.source_line_ids) ? check.source_line_ids.filter(id=>typeof id==="string" || Number.isInteger(id)) : []))];
    if(lineId === undefined && !sourceIds.length){list.append(node);return;}
    const wrapper=element("div","scan-line-entry"),actions=element("div","scan-line-actions");
    if(lineId !== undefined){const button=element("button","line-correct-button","訂正");button.type="button";button.dataset.correctLine=String(lineId);button.disabled=state.busy;button.setAttribute("aria-label",`訂正這行：${row.text || "未辨識到文字"}`);button.onclick=()=>openCorrectionDialog(lineId);actions.append(button);}
    if(sourceIds.length){const edit=element("button","line-correct-button line-standard-button","改標準");edit.type="button";edit.dataset.editStandard="context";edit.disabled=state.busy;edit.setAttribute("aria-label",`修正這項標準：${row.text || row.label || "未辨識到的文字"}`);edit.onclick=()=>openStandardEditor(inspection.id,sourceIds);actions.append(edit);}
    const patch=(inspection.manual_revision?.patches || []).find(item=>item.line_id===lineId);
    if(patch && manual){const content=$(".scan-line-content",node);content.append(element("small","manual-tag",`已訂正 · ${correctionLabels[patch.kind] || "人工確認"}`));}
    wrapper.append(node,actions);list.append(wrapper);
  }); area.append(list);
}
function renderInspection(inspection) {
  const area = $("#result-area"); area.replaceChildren(); area.hidden = false; $("#result-placeholder").hidden = true;
  const manual=!!(state.manualView && inspection.manual_revision), result = manual ? inspection.manual_revision.result : inspection.result;
  const ocr=manual ? inspection.manual_revision.ocr : inspection.ocr,rows = buildResultRows(result.checks, ocr.lines), header = element("div", `scan-result-header ${result.status}`);
  header.append(element("h2", "", manual ? `人工訂正後 · 第 ${currentRevision(inspection)} 版` : inspection.manual_revision ? "原始辨識結果" : "掃描結果"), element("p", "", when(inspection.created_at)));
  const counts = element("div", "result-counts");
  for (const [status,label] of [["fail","✕ 有差異"],["review","? 需確認"],["pass","✓ 相符"],["read","· 僅辨識"]]) {
    const count = rows.filter(row => row.status === status).length;
    if (count) counts.append(element("span", `count-${status}`, `${label} ${count}`));
  }
  header.append(counts); area.append(header);
  if(inspection.manual_revision){
    const toolbar=element("div","manual-toolbar"),toggle=element("button","button secondary",manual ? "查看原始判定" : "查看人工訂正後判定");toggle.type="button";toggle.dataset.toggleOriginal="true";toggle.disabled=state.busy;toggle.onclick=()=>{state.manualView=!state.manualView;renderInspection(inspection);};
    toolbar.append(element("p","",manual ? "依人工填寫的照片實際文字重新判定；原始 OCR 與原判定仍保留。" : "正在查看第一次機器辨識結果；後續人工訂正另行保留。"),toggle);area.append(toolbar);
    if(manual && inspection.manual_revision.copied_from)area.append(element("p","help","已沿用先前人工訂正，依此次標準與日期重新判定。"));
  }
  const recovery = recoveryMessage(inspection.ocr);
  if (recovery) { const notice = element("p", "result-notes", recovery); notice.setAttribute("role", "status"); area.append(notice); }
  renderSourceMatch(result.source_match, area, result.inputs?.base_date);
  renderRecheckControls(area);
  renderResultLines(rows, area, inspection, manual);
  if (result.notes?.length) { const notes = element("div", "result-notes"); result.notes.forEach(note => notes.append(element("p", "", note))); area.append(notes); }
  renderCorrectionHistory(inspection,area);
  const evidence = element("div", "panel evidence"); evidence.append(element("h2", "", "對照原圖"));
  const pair = element("div", "photo-pair");
  const reference = element("figure"), observed = element("figure"), refScroll = element("div", "photo-scroll"), observedScroll = element("div", "photo-scroll");
  if (inspection.reference_image) {
    const ref = element("img"); ref.src = inspection.reference_image.url; ref.alt = "已確認的標準照片"; refScroll.append(ref);
    reference.append(element("figcaption", "", "標準照片"), refScroll); pair.append(reference);
  }
  const canvas = element("canvas"); canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", "待檢照片；紅框為差異，黃框為待確認文字"); observedScroll.append(canvas);
  observed.append(element("figcaption", "", "待檢照片 · 紅框差異／黃框複核"), observedScroll); pair.append(observed); evidence.append(pair); drawEvidence(canvas, {...inspection,result});
  const details = element("details"), raw = element("div", "ocr-lines"); details.append(element("summary", "", "查看完整辨識原文"), raw); renderOCR(inspection.ocr.lines, raw); evidence.append(details);
  const reviewList = element("div"); inspection.reviews.forEach(review => { const row = element("div", "review-record"); row.append(element("strong", "", reviewLabels[review.decision]), element("p", "", review.note), element("small", "", `${review.reviewer} · ${when(review.created_at)}`)); reviewList.append(row); }); evidence.append(reviewList);
  const review = element("form", "review-form"); review.append(element("h3", "", "人工複核"), element("p", "help", "複核紀錄會另外保留，原始辨識結果不會被覆蓋。"));
  function control(label, input) { const wrap = element("label", "", label); wrap.append(input); review.append(wrap); return input; }
  const decision = element("select"); decision.append(new Option("請選擇複核結果", "")); decision.required=true; Object.entries(reviewLabels).forEach(([v,t]) => decision.append(new Option(t,v))); control("複核結果", decision);
  const reviewer = control("複核人員", element("input")); reviewer.required = true; reviewer.maxLength = 100; reviewer.value = sessionStorage.getItem("labelcheck-operator") || "";
  const note = control("確認原因", element("textarea")); note.required = true; note.maxLength = 2000; note.rows = 2;
  const submit = element("button", "button secondary full", "儲存複核紀錄"); submit.type = "submit"; review.append(submit);
  review.onsubmit = async event => { event.preventDefault(); submit.disabled = true; try { await api(`/api/inspections/${inspection.id}/reviews`, {method:"POST",body:{decision:decision.value,reviewer:reviewer.value,note:note.value}}); sessionStorage.setItem("labelcheck-operator", reviewer.value); const dirty=state.resultDirty;await loadInspection(inspection.id,false);if(dirty)markResultChanged(); toast("複核紀錄已保存。"); } catch(e) { toast(e.message,true); } finally { submit.disabled=false; } };
  evidence.append(review); area.append(evidence);
}
function historyPresentation(item) {
  const name=String(item.name || ""),version=Number(item.version) || 0;
  const generatedManual=version===0 ? /^人工文字標準 manual:[0-9a-f]{32} · (.+)$/i.exec(name) : null;
  return {name:generatedManual ? generatedManual[1] : name,reference:version>0 ? `第 ${version} 版` : generatedManual || item.source_kind==="manual" ? "人工文字標準" : isCatalogSource(item) ? "清單比對" : "系統比對"};
}
async function loadHistory() {
  const filter = $("#history-filter").value, page = state.page;
  const data = await api(`/api/inspections?page=${page}&status=${encodeURIComponent(filter)}`);
  if (page !== state.page || filter !== $("#history-filter").value) return;
  const list = $("#history-list"); list.replaceChildren();
  if (!data.items.length) { const empty = element("div", "empty-state"); empty.append(element("h2", "", "這裡還沒有檢查紀錄"),element("p", "", "完成一次照片檢查後，結果會自動保存在這裡。")); list.append(empty); }
  data.items.forEach(item => { const row = element("button", "history-row"), img = element("img"), text = element("span","history-copy"),statuses=element("span","history-statuses"),display=historyPresentation(item); img.src=item.image.thumbnail; img.alt="待檢標籤縮圖"; img.loading="lazy";text.append(element("strong", "", display.name), element("small", "", `${when(item.created_at)} · ${display.reference}`));statuses.append(badge(item.status,`原始：${statusLabels[item.status] || item.status}`));if(item.manual_revision){text.append(element("small","manual-tag",`已訂正 · 第 ${item.manual_revision} 版`));statuses.append(badge(item.manual_status,`訂正後：${statusLabels[item.manual_status] || "已保存"}`));}row.append(img,text,statuses); row.onclick=() => { if(state.busy) return toast("請等待目前辨識完成。"); loadInspection(item.id).catch(e=>toast(e.message,true)); };
    if(allowed("cleanup_history")){
      const wrap=element("div","history-entry"),label=element("label","history-select"),select=element("input");select.type="checkbox";select.checked=state.historySelection.has(item.id);select.setAttribute("aria-label",`選取紀錄：${display.name}，${when(item.created_at)}`);
      select.onchange=()=>{if(select.checked)state.historySelection.set(item.id,item.name);else state.historySelection.delete(item.id);updateCleanupSelection();};label.append(select);wrap.append(label,row);list.append(wrap);
    }else list.append(row);
  });updateCleanupSelection();
  $("#history-page").textContent=`第 ${page} 頁`; $("#history-prev").disabled=page<=1; $("#history-next").disabled=!data.has_more;
}
function updateCleanupSelection(){
  const count=state.historySelection.size;$("#history-cleanup-selected").textContent=`整理所選 ${count} 筆`;
  $("#history-cleanup-selected").disabled=!allowed("cleanup_history") || !count || state.busy;
}
function clearCleanupPreview(){
  if(cleanupContext){cleanupContext.preview=null;cleanupContext.batch=null;}
  $("#cleanup-confirm-panel").hidden=true;$("#cleanup-confirm").checked=false;$("#cleanup-confirm-save").disabled=true;
  $("#cleanup-items").replaceChildren();$("#cleanup-summary").textContent="";
}
function cleanupBusy(busy){setBusy(busy);$$("#history-cleanup-dialog button, #history-cleanup-dialog input, #history-cleanup-dialog select, #history-cleanup-dialog textarea").forEach(node=>{node.disabled=busy;});if(!busy){cleanupConfirmChanged();$("#cleanup-batch-prev").disabled=(cleanupContext?.page || 1)<=1;$("#cleanup-batch-next").disabled=!cleanupContext?.batchHasMore;}}
function cleanupConfirmChanged(){
  const ready=cleanupContext?.preview?.count>0 || cleanupContext?.batch?.status==="archived";
  $("#cleanup-confirm-save").disabled=state.busy || !allowed("cleanup_history") || !ready || !$("#cleanup-confirm").checked;
}
async function openHistoryCleanup(mode="filters"){
  if(!requireAdmin("cleanup_history") || state.busy)return;
  const ids=mode==="selected" ? [...state.historySelection.keys()] : [];
  if(mode==="selected" && !ids.length)return;
  cleanupContext={mode,ids,page:1,preview:null,batch:null};
  $("#cleanup-filter-form").reset();$("#cleanup-confirm-form").reset();clearCleanupPreview();setDialogError("#cleanup-error");
  $("#cleanup-notice").textContent="";$("#cleanup-batches").replaceChildren();$("#cleanup-reviewer").value=sessionStorage.getItem("labelcheck-operator") || "";
  $("#cleanup-filter-fields").hidden=mode!=="filters";$("#cleanup-filter-form").hidden=mode==="recycle";$("#cleanup-recycle").hidden=mode!=="recycle";
  $("#cleanup-selection-note").textContent=mode==="selected" ? `準備整理已選取的 ${ids.length} 筆紀錄，請先預覽實際清單。` : "依台灣日期（含起訖日）與原始判定篩選；每次最多 500 筆。";
  $("#cleanup-title").textContent=mode==="recycle" ? "紀錄回收區" : "整理檢查紀錄";
  $("#history-cleanup-dialog").showModal();
  if(mode==="recycle")await loadCleanupBatches(1);
}
function cleanupFilters(){
  if(cleanupContext?.mode==="selected")return {ids:[...cleanupContext.ids]};
  const filters={};for(const [key,id] of [["date_from","cleanup-from"],["date_to","cleanup-to"],["status","cleanup-status"]])if($("#"+id).value)filters[key]=$("#"+id).value;
  if(!Object.keys(filters).length)throw new Error("請至少設定日期或原始判定，避免一次整理全部紀錄。");
  if(filters.date_from && filters.date_to && filters.date_from>filters.date_to)throw new Error("開始日期不可晚於結束日期。");
  return filters;
}
function renderCleanupItems(items){
  const list=$("#cleanup-items");list.replaceChildren();
  for(const item of items || []){const row=element("li","cleanup-item");row.append(element("strong","",item.name || "未命名標籤"),element("p","help",`${when(item.created_at)} · 原始：${statusLabels[item.status] || item.status}`));if(item.manual_status)row.append(element("small","",`訂正後：${statusLabels[item.manual_status] || item.manual_status}`));list.append(row);}
}
function describeCleanupFilters(filters){
  if(filters.ids)return `所選 ${filters.ids.length} 筆紀錄`;
  return `${filters.date_from || "不限開始日期"} ～ ${filters.date_to || "不限結束日期"}；原始判定：${statusLabels[filters.status] || "全部"}`;
}
async function previewHistoryCleanup(event){
  event?.preventDefault();if(!requireAdmin("cleanup_history") || state.busy || !cleanupContext)return;
  clearCleanupPreview();setDialogError("#cleanup-error");let filters;
  try{filters=cleanupFilters();}catch(error){setDialogError("#cleanup-error",error.message);return;}
  const context=cleanupContext;cleanupBusy(true);
  try{
    const data=await api("/api/admin/history/preview",{method:"POST",body:{filters}});if(cleanupContext!==context)return;
    context.preview={...data,filters};renderCleanupItems(data.items);
    $("#cleanup-summary").textContent=`預覽 ${data.count} 筆 · ${describeCleanupFilters(filters)}${data.expires_at ? ` · 確認期限 ${when(data.expires_at)}` : ""}`;
    $("#cleanup-notice").textContent=data.count ? "尚未移動資料。請核對下方確切清單，再填寫人員與原因。" : "沒有符合條件的紀錄，尚未修改任何資料。";
    $("#cleanup-confirm-panel").hidden=!data.count;$("#cleanup-confirm-text").textContent=`已確認上述 ${data.count} 筆，移至回收區並保留照片、標準及訂正紀錄。`;$("#cleanup-confirm-save").textContent="確認移至回收區";
  }catch(error){if(cleanupContext===context)setDialogError("#cleanup-error",error.message);}
  finally{cleanupBusy(false);}
}
async function loadCleanupBatches(page=1){
  if(!allowed("cleanup_history") || !cleanupContext)return;
  const context=cleanupContext,request=(context.request || 0)+1;context.request=request;
  try{
    const data=await api(`/api/admin/history/batches?page=${page}`);if(cleanupContext!==context || context.request!==request)return;
    context.page=page;context.batchHasMore=!!data.has_more;const list=$("#cleanup-batches");list.replaceChildren();
    for(const item of data.items || []){
      const row=element("article","review-record");row.append(element("strong","",`${item.count} 筆 · ${item.status==="restored" ? "已還原" : "回收區"}`),element("p","help",`${when(item.created_at)} · ${item.reviewer || ""}`),element("p","",item.note || ""));
      const button=element("button","button secondary",item.status==="archived" ? "查看並還原" : "查看清單");button.type="button";button.onclick=()=>previewHistoryRestore(item.batch_id);row.append(button);list.append(row);
    }
    if(!data.items?.length)list.append(element("p","help","回收區目前沒有紀錄。"));
    $("#cleanup-batch-page").textContent=`第 ${page} 頁`;$("#cleanup-batch-prev").disabled=page<=1;$("#cleanup-batch-next").disabled=!data.has_more;
  }catch(error){if(cleanupContext===context)setDialogError("#cleanup-error",error.message);}
}
async function previewHistoryRestore(batchId){
  if(!requireAdmin("cleanup_history") || state.busy || !cleanupContext)return;
  const context=cleanupContext;clearCleanupPreview();setDialogError("#cleanup-error");cleanupBusy(true);
  try{
    const data=await api(`/api/admin/history/batches/${encodeURIComponent(batchId)}`);if(cleanupContext!==context)return;
    context.batch=data.batch;renderCleanupItems(data.items);
    $("#cleanup-summary").textContent=`${data.batch.count} 筆 · ${data.batch.status==="restored" ? "這批已還原" : "待還原清單"} · ${when(data.batch.created_at)}`;
    $("#cleanup-notice").textContent="還原後會重新出現在檢查紀錄；原本照片、判定與訂正內容均保留。";
    $("#cleanup-confirm-panel").hidden=data.batch.status!=="archived";$("#cleanup-confirm-text").textContent=`已確認將以上 ${data.batch.count} 筆還原到檢查紀錄。`;$("#cleanup-confirm-save").textContent="確認還原這批紀錄";
    $("#cleanup-confirm-panel").scrollIntoView({block:"start",behavior:"instant"});
  }catch(error){if(cleanupContext===context)setDialogError("#cleanup-error",error.message);}
  finally{cleanupBusy(false);}
}
async function commitHistoryCleanup(event){
  event.preventDefault();if(!requireAdmin("cleanup_history") || state.busy || !cleanupContext)return;
  const context=cleanupContext,preview=context.preview,batch=context.batch,reviewer=$("#cleanup-reviewer").value.trim(),note=$("#cleanup-note").value.trim();
  if(!reviewer || !note || !$("#cleanup-confirm").checked || !(preview?.count>0 || batch?.status==="archived")){setDialogError("#cleanup-error","請先預覽清單，填寫人員及原因，再勾選確認。");return;}
  if(preview){let current;try{current=cleanupFilters();}catch(error){clearCleanupPreview();setDialogError("#cleanup-error",error.message);return;}if(JSON.stringify(preview.filters)!==JSON.stringify(current)){clearCleanupPreview();setDialogError("#cleanup-error","篩選已變更，請重新預覽清單。");return;}}
  if(preview?.expires_at && Date.parse(preview.expires_at)<=Date.now()){clearCleanupPreview();setDialogError("#cleanup-error","預覽已過期，請重新預覽再確認。");return;}
  cleanupBusy(true);setDialogError("#cleanup-error");
  try{
    const result=await api(batch ? `/api/admin/history/batches/${encodeURIComponent(batch.batch_id)}/restore` : "/api/admin/history/archive",{method:"POST",body:{reviewer,note,confirmed:true,...(batch ? {base_revision:batch.revision} : {preview_id:preview.preview_id,preview_hash:preview.preview_hash})}});
    if(cleanupContext!==context)return;
    sessionStorage.setItem("labelcheck-operator",reviewer);state.historySelection.clear();clearCleanupPreview();
    $("#cleanup-notice").textContent=batch ? `已還原 ${result.count} 筆，現在可在檢查紀錄查看。` : `已將 ${result.count} 筆移至回收區，照片與完整紀錄均保留，可隨時至回收區還原。`;
    state.page=1;await loadHistory();if(batch)await loadCleanupBatches(context.page);
  }catch(error){if(cleanupContext===context){if([409,410].includes(error.status))clearCleanupPreview();setDialogError("#cleanup-error",error.message);}}
  finally{cleanupBusy(false);}
}
async function initialize() {
  const session = await api("/api/session"); applySession(session);
  if (!session.authenticated) return;
  await Promise.all([loadTemplates(),loadScanConfig(),loadFailedJobs()]); restoreRetryJobs(); showView(location.hash.slice(1));
  const stored = sessionStorage.getItem("labelcheck-pending");
  if (stored) {
    let pending; try { pending=JSON.parse(stored); } catch { sessionStorage.removeItem("labelcheck-pending"); return; }
    if(pending.kind==="reference" && !allowed())return;
    if (pending.supersedes_id) {
      state.supersedes=state.templates.find(t=>t.id===pending.supersedes_id);
      if (!state.supersedes) { sessionStorage.removeItem("labelcheck-pending"); toast("原標準已更新，請重新選擇最新標準再建立新版。",true); return; }
      $("#standard-heading").textContent=`建立新版標準 · 第 ${state.supersedes.version+1} 版`;
    }
    showView(pending.kind === "reference" ? "standard" : "inspect"); setBusy(true,pending.kind);
    try { await pollJob(pending.id,pending.kind); } catch(e) { reportUploadFailure(pending.kind, e); } finally { setBusy(false); }
  }
}
let cameraStream = null, cameraRequest = 0;
function stopCamera() {
  cameraRequest++;
  cameraStream?.getTracks().forEach(track => track.stop()); cameraStream = null;
  $("#camera-video").srcObject = null; $("#camera-capture").disabled = true;
}
function closeCamera() { stopCamera(); if ($("#camera-dialog").open) $("#camera-dialog").close(); }
async function openCamera() {
  if (state.busy) return;
  if (!navigator.mediaDevices?.getUserMedia) { $("#inspect-camera").click(); return; }
  const dialog = $("#camera-dialog"); dialog.showModal();
  $("#camera-message").textContent = "請允許相機權限。";
  const token = ++cameraRequest;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({audio:false, video:{facingMode:{ideal:"environment"}, width:{ideal:3840}, height:{ideal:2160}}});
    if (token !== cameraRequest || !dialog.open) { stream.getTracks().forEach(track => track.stop()); return; }
    cameraStream = stream; const video = $("#camera-video"); video.srcObject = stream;
    await video.play();
    if (token !== cameraRequest || !dialog.open) return;
    $("#camera-capture").disabled = false;
    $("#camera-message").textContent = Math.max(video.videoWidth, video.videoHeight) < 1600
      ? "目前預覽解析度較低，細字建議改用「手機拍照」。讓標籤盡量填滿畫面，保留四邊。"
      : "讓標籤盡量填滿畫面、保留四邊；等文字清晰再拍攝。細字模糊時可改用「手機拍照」。";
  } catch (error) {
    if (token !== cameraRequest || !dialog.open) return;
    stopCamera(); $("#camera-message").textContent = "無法開啟即時相機。請允許權限，或使用「手機拍照」及「選擇照片」。";
  }
}
$("#scan-button").onclick = openCamera;
$("#camera-close").onclick = closeCamera;
$("#camera-dialog").addEventListener("close", stopCamera);
$("#camera-native").onclick = () => { closeCamera(); $("#inspect-camera").click(); };
async function captureCameraPhoto(video, track) {
  if (typeof window.ImageCapture === "function" && track?.readyState === "live") {
    try {
      const photo = await new window.ImageCapture(track).takePhoto();
      if (photo?.size) return photo;
    } catch (_) { /* Keep the full video frame when still capture is unavailable. */ }
  }
  if (!video.videoWidth || !video.videoHeight) throw new Error("相機畫面尚未準備好，請稍候再拍攝。");
  const canvas = document.createElement("canvas");
  canvas.width = video.videoWidth; canvas.height = video.videoHeight;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("無法讀取相機畫面，請改用手機拍照。");
  context.drawImage(video, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise(resolve => canvas.toBlob(resolve, "image/jpeg", .95));
  if (!blob) throw new Error("拍攝失敗，請重新拍照或使用手機拍照。");
  return blob;
}
$("#camera-capture").onclick = async () => {
  const video = $("#camera-video"); if (!video.videoWidth || state.busy) return;
  $("#camera-capture").disabled = true;
  const token = cameraRequest;
  $("#camera-message").textContent = "正在拍攝清晰照片，請保持手機穩定…";
  try {
    const blob = await captureCameraPhoto(video, cameraStream?.getVideoTracks()[0]);
    if (token !== cameraRequest || !$("#camera-dialog").open) return;
    if (blob.size > maxPhotoBytes) throw new Error("照片超過 15 MB，請改用手機拍照並選擇較小的照片尺寸。");
    closeCamera();
    const extension = {"image/png":"png","image/webp":"webp"}[blob.type] || "jpg";
    await upload(new File([blob],`掃描標籤.${extension}`,{type:blob.type || "image/jpeg"}),"inspection");
  } catch (error) {
    if (token === cameraRequest) { $("#camera-message").textContent = error.message; toast(error.message, true); }
  } finally {
    if (token === cameraRequest && $("#camera-dialog").open) $("#camera-capture").disabled = false;
  }
};
window.addEventListener("pagehide", closeCamera);
document.addEventListener("visibilitychange", () => { if(document.hidden) closeCamera(); });
$("#inspect-source-search").onsubmit = async event => {
  event.preventDefault(); if (state.busy) return;
  const query = $("#inspect-source-query").value.trim(); if (!query) return;
  const token = ++state.inspectSearchRequest, button = $("#inspect-source-search button"), results = $("#inspect-source-results");
  button.disabled = true; results.replaceChildren(); $("#inspect-source-note").textContent = "搜尋中…";
  try {
    const data = await api(`/api/source-labels?q=${encodeURIComponent(query)}`);
    if (token !== state.inspectSearchRequest) return;
    $("#inspect-source-note").textContent = !data.available ? "目前無法讀取系統標籤。" : data.items.length ? "選定後，可用原照片重新核對或開始下一次掃描。" : "找不到符合的標籤，請換代碼或品名。";
    data.items.forEach(item => { const choice = element("button", "source-option", sourceOptionLabel(item)); choice.type="button"; choice.disabled=state.busy; choice.onclick=()=>selectInspectSource(item); results.append(choice); });
  } catch (error) { if (token === state.inspectSearchRequest) { $("#inspect-source-note").textContent = error.message; toast(error.message,true); } }
  finally { button.disabled = state.busy; }
};
$("#source-search").onsubmit = async event => {
  event.preventDefault(); if(!requireAdmin() || state.busy) return;
  const results = $("#source-results"); results.replaceChildren(); setBusy(true);
  try {
    const data = await api(`/api/source-labels?q=${encodeURIComponent($("#source-query").value.trim())}`);
    $("#source-note").textContent = !data.available ? "目前尚未連接標籤系統資料庫。" : data.items.length ? "請選擇一份標籤，再核對正確內容。" : "找不到符合的標籤，請換代碼或品名。";
    data.items.forEach(item => { const button = element("button", "source-option", sourceOptionLabel(item)); button.type="button"; button.onclick=()=>importSource(item.code); results.append(button); });
  } catch(error) { toast(error.message,true); } finally { setBusy(false); }
};
async function importSource(code) {
  if(!requireAdmin() || state.busy) return; setBusy(true);
  try {
    const source = await api(`/api/source-labels/${encodeURIComponent(code)}`);
    state.source = source; state.referenceJob = null;
    const form = $("#standard-form"); form.reset(); $("#standard-fields").disabled = false;
    form.elements.name.value = state.supersedes?.name || `${sourceCodeLabel(source)} · ${source.name}`;
    textFields.forEach(key => { form.elements[key].value = source.fields[key] || ""; });
    const sourceDateText = (source.date_settings || []).map(item => item.content).join(" ").replace(/\s+/g, "");
    form.elements.dates.checked = state.supersedes?.rules.dates ?? source.rules?.dates ?? /製造|生產|有效|到期|保存期限/.test(sourceDateText);
    form.elements.check_arrival.checked = state.supersedes ? !!state.supersedes.rules.arrival : (source.rules?.arrival ?? /到店|到貨/.test(sourceDateText));
    form.elements.approved_by.value = sessionStorage.getItem("labelcheck-operator") || "";
    form.elements.keep_days.value = ""; toggleDateFields();
    $("#reference-preview").hidden = true; $("#reference-ocr").hidden = false;
    renderOCR(source.lines,$("#reference-lines"));
    $("#source-note").textContent = `${source.notice} 系統保存天數：${source.keep_days ?? "未設定"}。日期欄位：${source.date_settings.map(d=>`${d.content}（位移 ${d.shift_days ?? 0} 天）`).join("、") || "未設定"}。`;
    toast("資料已帶入，請逐欄確認後再啟用。");
  } catch(error) { toast(error.message,true); } finally { setBusy(false); }
}
$$("[data-view]").forEach(b=>b.onclick=()=>showView(b.dataset.view));
$$("[data-go]").forEach(b=>b.onclick=()=>showView(b.dataset.go));
$$("[data-action='new-standard']").forEach(b=>b.onclick=()=>newStandard());
$$("[data-file]").forEach(b=>b.onclick=()=>$("#"+b.dataset.file).click());
for (const id of ["inspect-file","inspect-camera","reference-file","reference-camera"]) $("#"+id).onchange=event=>{ const file=event.target.files[0]; event.target.value=""; upload(file,id.startsWith("inspect")?"inspection":"reference"); };
for (const [id,kind] of [["inspect-drop","inspection"],["reference-drop","reference"]]) { const zone=$("#"+id); zone.ondragover=e=>{ e.preventDefault(); zone.classList.add("dragging"); }; zone.ondragleave=()=>zone.classList.remove("dragging"); zone.ondrop=e=>{ e.preventDefault(); zone.classList.remove("dragging"); upload(e.dataTransfer.files[0],kind); }; }
$("#template-select").onchange=()=>{ state.inspectSource=null; renderInspectSource(); selectedStandard(); markResultChanged(); };
$("#base-date").onchange=markResultChanged;
$("#batch-date").onchange=markResultChanged;
$("#arrival-date").onchange=markResultChanged;
$("#standard-form").onsubmit=saveStandard;
$("#standard-form").addEventListener("input",event=>{if(event.target.name!=="confirmed") $("#standard-form").elements.confirmed.checked=false;});
$("#standard-form").elements.dates.onchange=toggleDateFields;
$("#standard-form").elements.check_arrival.onchange=toggleDateFields;
$("#correction-form").onsubmit=event=>{event.preventDefault();saveCorrection();};
$("#correction-kind").onchange=correctionKindChanged;
$("#correction-revoke").onclick=()=>saveCorrection("revoke");
$("#correction-close").onclick=()=>{if(!state.busy)$("#correction-dialog").close();};
$("#correction-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();});
$("#correction-reload").onclick=async()=>{const context=state.correction;if(!context || state.busy)return;try{state.inspection=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}`);renderInspection(state.inspection);openCorrectionDialog(context.lineId);}catch(error){setDialogError("#correction-error",error.message);}};
$("#standard-edit-form").onsubmit=saveStandardEdit;
$("#standard-edit-form").addEventListener("input",event=>{if(!["standard-edit-confirm","standard-edit-reviewer","standard-edit-note"].includes(event.target.id))invalidateStandardPreview();});
$("#standard-edit-preview-button").onclick=previewStandardChanges;
$("#standard-edit-reset").onclick=()=>selectStandardOperation("reset");
$("#standard-edit-operation-cancel").onclick=cancelStandardOperation;
$("#standard-edit-reload").onclick=()=>openStandardEditor(state.standardEdit?.inspectionId,state.standardEdit?.focusLineIds);
$("#standard-edit-close").onclick=()=>{if(!state.busy){state.standardEdit=null;$("#standard-edit-dialog").close();}};
$("#standard-edit-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();else state.standardEdit=null;});
$("#history-filter").setAttribute("aria-label","依原始判定篩選檢查結果");
$("#history-filter").options[0].textContent="全部原始判定";
$("#history-filter").onchange=()=>{ state.page=1; loadHistory().catch(e=>toast(e.message,true)); };
$("#history-prev").onclick=()=>{ state.page=Math.max(1,state.page-1); loadHistory().catch(e=>toast(e.message,true)); };
$("#history-next").onclick=()=>{ state.page++; loadHistory().catch(e=>toast(e.message,true)); };
$("#admin-access").onclick=openAdminDialog;
$("#admin-close").onclick=()=>{if(!state.busy)$("#admin-dialog").close();};
$("#admin-dialog").addEventListener("close",()=>{$("#admin-password").value="";});
$("#admin-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();});
$("#admin-unlock-form").onsubmit=event=>{event.preventDefault();changeAdminRole(true);};
$("#admin-lock").onclick=()=>changeAdminRole(false);
$("#admin-logout").onclick=()=>$("#logout").click();
$("#history-cleanup-filter").onclick=()=>openHistoryCleanup("filters");
$("#history-cleanup-selected").onclick=()=>openHistoryCleanup("selected");
$("#history-recycle").onclick=()=>openHistoryCleanup("recycle");
$("#cleanup-close").onclick=()=>{if(!state.busy){cleanupContext=null;$("#history-cleanup-dialog").close();}};
$("#history-cleanup-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();else cleanupContext=null;});
$("#cleanup-filter-form").onsubmit=previewHistoryCleanup;
$("#cleanup-filter-form").addEventListener("input",clearCleanupPreview);
$("#cleanup-confirm-form").onsubmit=commitHistoryCleanup;
$("#cleanup-confirm").onchange=cleanupConfirmChanged;
$("#cleanup-batch-prev").onclick=()=>loadCleanupBatches(Math.max(1,(cleanupContext?.page || 1)-1));
$("#cleanup-batch-next").onclick=()=>loadCleanupBatches((cleanupContext?.page || 1)+1);
window.addEventListener("hashchange",()=>{if(state.authenticated)showView(location.hash.slice(1));});
$("#login-form").onsubmit=async e=>{ e.preventDefault(); const form=e.currentTarget, button=$("button",form); button.disabled=true; try { const result=await api("/api/login",{method:"POST",body:{password:form.elements.password.value}}); state.csrf=result.csrf; form.reset(); $("#login-error").textContent=""; await initialize(); } catch(error) { $("#login-error").textContent=error.message; } finally { button.disabled=false; } };
$("#logout").onclick=async()=>{ if(state.busy) return toast("請等待目前辨識完成。"); try { await api("/api/logout",{method:"POST"}); applySession({authenticated:false,requires_login:true});location.reload(); } catch(e) { toast(e.message,true); } };
$("#memory-panel").addEventListener("toggle",()=>{if($("#memory-panel").open)loadMemory();});
$("#memory-refresh").onclick=loadMemory;
$("#memory-cleanup").onclick=cleanupMemory;
$("#manual-standard-close").onclick=()=>{if(!state.busy){manualStandard=null;$("#manual-standard-dialog").close();}};
$("#manual-standard-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();else manualStandard=null;});
$("#manual-standard-form").addEventListener("input",event=>{if(!["manual-standard-confirm","manual-standard-reviewer","manual-standard-note"].includes(event.target.id))invalidateManualPreview();});
$("#manual-standard-preview-button").onclick=previewManualStandard;
$("#manual-standard-form").onsubmit=saveManualStandard;
$("#manual-library-search").onsubmit=event=>{event.preventDefault();loadManualLibrary(1);};
$("#manual-library-prev").onclick=()=>loadManualLibrary(Math.max(1,manualLibraryPage-1));
$("#manual-library-next").onclick=()=>loadManualLibrary(manualLibraryPage+1);
initialize().catch(e=>toast(e.message,true));
