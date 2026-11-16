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
Object.assign(state, {role:"anonymous", authenticated:false, permissions:{}, adminConfigured:false, authEpoch:0, historySelection:new Map(), standardSaved:false,crop:null,sampleRequest:0,recognition:{cloud_available:false,default_engine:"local"},referencePhoto:null,uploadRequests:{},libraryDetail:null,libraryCategories:[],libraryCategoryRequest:0,libraryCategoryContext:null});
let cleanupContext = null;

function allowed(permission = "manage_standards") { return state.role === "admin" && state.permissions[permission] === true; }
function requireAdmin(permission = "manage_standards") {
  if (allowed(permission)) return true;
  toast("此功能需管理員解鎖；掃描與本筆訂正仍可使用。", true); return false;
}
function isAdminPath(path) {
  return /^\/api\/(?:templates(?:[/?]|$)|standard-library(?:[/?]|$)|manual-standards(?:[/?]|$)|admin\/(?:history|recognition-samples)(?:[/?]|$)|source-labels\/)/.test(path)
    || /^\/api\/reference-photos(?:[/?]|$)/.test(path) || /^\/api\/inspections\/[^/]+\/(?:standard|manual-standard|reference-photo)(?:[/?]|$)/.test(path);
}
function purgeAdminData() {
  closeDraftScopeDialog();closeLibraryCategory(true);closeLibraryDetail(true);state.libraryCategoryRequest++;state.libraryCategories=[];populateLibraryCategories();
  state.standardEdit = null; manualStandard = null; cleanupContext = null;
  state.referencePhoto=null;if($("#reference-photo-dialog").open)$("#reference-photo-dialog").close();$("#reference-photo-form").reset();$("#reference-photo-list").replaceChildren();$("#reference-photo-source").textContent="";$("#reference-photo-image").removeAttribute("src");$("#reference-photo-error").textContent="";
  $("#manual-draft-fields").replaceChildren();$("#manual-equivalent-references").replaceChildren();$("#manual-photo-canvas").width=1;$("#manual-photo-link").removeAttribute("href");
  $("#standard-text-locations").replaceChildren();$("#standard-regroup-text").textContent="";$("#standard-regroup-preview").hidden=true;$("#standard-photo-canvas").width=1;$("#standard-photo-link").removeAttribute("href");
  state.referenceJob = null; state.source = null; state.supersedes = null; state.historySelection.clear();
  delete state.uploadRequests.reference;$("#reference-upload-resend").hidden=true;
  manualLibraryRequest++; manualLibraryTotal = 0;
  pendingStandardsRequest++;pendingStandardsPage=1;pendingStandardsItems=[];pendingStandardsSelection.clear();pendingStandardsLoading=false;pendingStandardsHasMore=false;$("#pending-standard-list").replaceChildren();$("#pending-standard-status").textContent="";$("#pending-standard-count").textContent="";$("#pending-standard-range").value="today";$("#pending-standard-state").value="active";$("#pending-standard-notice").textContent="";$("#pending-standard-notice").hidden=true;updatePendingControls();
  state.sampleRequest++;$("#recognition-sample-summary").textContent="";$("#recognition-sample-note").textContent="";$("#recognition-sample-download").hidden=true;$("#recognition-samples").hidden=true;
  $$(".history-select").forEach(node=>node.remove());
  state.templates = state.templates.map(({id,name,version}) => ({id,name,version}));
  for (const id of ["standard-edit-dialog","manual-standard-dialog","history-cleanup-dialog"]) { const node=$("#"+id); if(node.open)node.close(); }
  for (const id of ["standard-form","standard-edit-form","manual-standard-form","cleanup-filter-form","cleanup-confirm-form"]) $("#"+id).reset();
  $$("#standard-edit-dialog input, #standard-edit-dialog textarea, #manual-standard-dialog input, #manual-standard-dialog textarea, #history-cleanup-dialog input, #history-cleanup-dialog textarea").forEach(node=>{node.value="";node.checked=false;});
  for(const id of ["standard-library-list","source-results","reference-lines","standard-edit-line-fields","standard-edit-date-fields","standard-edit-history-list","standard-edit-preview","manual-standard-preview","cleanup-items","cleanup-batches"]) $("#"+id).replaceChildren();
  for(const id of ["standard-edit-source","standard-edit-notice","standard-edit-error","manual-standard-notice","manual-standard-error","source-note","standard-library-status","cleanup-error","cleanup-notice","cleanup-summary","cleanup-selection-note"]) $("#"+id).textContent="";
  $("#reference-preview").removeAttribute("src"); $("#reference-preview").hidden=true; $("#reference-ocr").hidden=true; $("#standard-fields").disabled=true;
  $("#standard-library-query").value="";$("#standard-library-total").textContent="";$("#standard-library-page").textContent="";$("#standard-library-category").value="all";$("#standard-library-state").value="active"; $("#source-query").value=""; $("#nav-count").textContent="0";
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
    state.uploadRequests={};$("#inspect-upload-resend").hidden=true;$("#reference-upload-resend").hidden=true;
    for(const id of ["result-area","history-list","inspect-source-results","inspect-source-selected","selected-standard","failed-jobs-list"])$("#"+id).replaceChildren();
    $("#template-select").replaceChildren(new Option("自動對應系統標籤與清單",""));
    $("#correction-form").reset();$("#correction-original").value="";$("#correction-text").value="";$("#correction-standard").textContent="";$("#correction-full-photo").removeAttribute("href");
    const canvas=$("#correction-photo");canvas.width=canvas.width;
    closeCropDialog();
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
  $("#recognition-samples").hidden=!allowed();if(allowed())loadRecognitionSamples();
}
async function loadRecognitionSamples(){
  if(!allowed())return;const token=++state.sampleRequest;$("#recognition-sample-summary").textContent="正在整理候選摘要…";$("#recognition-sample-download").hidden=true;
  try{const data=await api("/api/admin/recognition-samples");if(token!==state.sampleRequest || !allowed())return;
    const counts=data.counts || {};$("#recognition-sample-summary").textContent=`候選 ${Number(counts.candidates) || 0} 筆 · 合併重複 ${Number(counts.duplicate_observations) || 0} 筆 · 排除答案衝突 ${Number(counts.conflict_groups) || 0} 組`;
    $("#recognition-sample-note").textContent=data.notice || "這些是待審查候選資料，不是已核准訓練集，也不會自動訓練。";$("#recognition-sample-download").hidden=data.download_available!==true;
  }catch(error){if(token===state.sampleRequest)$("#recognition-sample-summary").textContent=error.message;}
}
async function downloadRecognitionSamples(){
  if(!requireAdmin())return;const epoch=state.authEpoch,button=$("#recognition-sample-download");button.disabled=true;
  try{const response=await fetch("/api/admin/recognition-samples/export");if(!response.ok){const payload=await response.json().catch(()=>({}));if(response.status===401 || (response.status===403 && payload.code==="admin_required"))applySession(await api("/api/session"));throw new Error(payload.error || "無法下載候選資料，請重新確認管理權限。");}
    const blob=await response.blob();if(epoch!==state.authEpoch || !allowed())return;
    const url=URL.createObjectURL(blob),link=element("a");link.href=url;link.download="ocr-recognition-candidates.jsonl";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }catch(error){if(allowed())$("#recognition-sample-note").textContent=error.message;else toast(error.message,true);}finally{button.disabled=false;}
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
  const slot = retrySlot(kind), item = state.retryJobs[slot], button = $(`#${slot}-retry-button`),local=$(`#${slot}-retry-local`),cloud=item?.request?.recognition_engine==="cloud";
  $(`#${slot}-retry`).hidden = !item;
  button.disabled = state.busy || retryIsPending(item?.id); button.onclick = () => retryFailedJob(item);
  button.textContent=cloud ? "雲端重試（使用額度）" : "重新辨識這張照片";
  local.hidden=!cloud;local.disabled=state.busy || retryIsPending(item?.id);local.onclick=()=>retryFailedJob(item,"local");
  $(`#${slot}-retry-help`).textContent=cloud ? "照片已保留。雲端重試會使用額度；也可自行改用一般辨識，不會自動切換。" : "照片已保留，將沿用原本比對設定。";
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
    request:job.result?.request || job.request || {},
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
    const cloud=item.request?.recognition_engine==="cloud",actions=element("div","retry-actions");
    const button = element("button", "button secondary", retryIsPending(item.id) ? "辨識中" : cloud ? "雲端重試（使用額度）" : "重新辨識"); button.type = "button";
    button.dataset.retryJob = item.id; button.disabled = state.busy || retryIsPending(item.id); button.onclick = () => retryFailedJob(item);
    actions.append(button);
    if(cloud){const local=element("button","button secondary","改用一般辨識這張照片");local.type="button";local.dataset.retryJob=item.id;local.dataset.retryEngine="local";local.disabled=state.busy || retryIsPending(item.id);local.onclick=()=>retryFailedJob(item,"local");actions.append(local);}
    row.append(info,actions); list.append(row);
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
async function retryFailedJob(item,engineOverride="") {
  if(item?.kind==="reference" && !requireAdmin())return;
  if(engineOverride && (engineOverride!=="local" || item?.request?.recognition_engine!=="cloud"))return;
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
  progress.textContent = engineOverride==="local" ? "正在使用一般辨識讀取已保留的照片…" : item.request?.recognition_engine==="cloud" ? "正在使用雲端辨識重試，這次會使用額度…" : "正在使用已保留的照片重新辨識…";
  try {
    const job = await api(`/api/jobs/${encodeURIComponent(item.id)}/retry`, {method:"POST",...(engineOverride ? {body:{recognition_engine:engineOverride}} : {})});
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
function sourceKindLabel(source) { if(source?.comparison_scope==="approved_text")return isCatalogSource(source) ? "清單完整標準" : "已核准文字標準";return source?.source_kind === "manual" || String(source?.code || "").startsWith("manual:") ? "人工文字標準" : isCatalogSource(source) ? "清單" : "系統標籤"; }
function sourceCodeLabel(source) { const code=String(source?.code || "");return code.startsWith("manual:") ? `M-${code.slice(7,15)}` : code.startsWith("photo:") ? `P-${code.slice(6,14)}` : code.replace(/^list:/, ""); }
function sourceOptionLabel(source) { return `${sourceKindLabel(source)} ${sourceCodeLabel(source)} · ${source.name}`; }
function showView(view) {
  if (!["inspect", "library", "standard", "history"].includes(view)) view = "inspect";
  if(["library","standard"].includes(view) && !allowed())view="inspect";
  $$(".view").forEach(x => { x.hidden = x.id !== `view-${view}`; });
  $$("[data-view]").forEach(x => { x.classList.toggle("active", x.dataset.view === (view === "standard" ? "library" : view)); });
  $("#breadcrumb").textContent = `工作區 / ${{inspect:"檢查標籤",library:"標準標籤庫",standard:"建立標準標籤",history:"檢查紀錄"}[view]}`;
  history.replaceState(null, "", `#${view}`);
  if (view === "history") loadHistory().catch(e => toast(e.message, true));
  if (view === "library") {loadLibraryCategories().catch(e=>toast(e.message,true));loadManualLibrary(1);loadPendingStandards(1);}
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
  for(const prefix of ["","reference-","crop-"])for(const key of ["recognition-engine","label-scope"])$("#"+prefix+key).disabled=busy;
  if(state.crop?.manualScope)$("#crop-label-scope").disabled=true;
  if ($("#recheck-button")) $("#recheck-button").disabled = busy;
  $$("[data-correct-line], [data-edit-standard], [data-toggle-original], [data-recognition-action]").forEach(button => { button.disabled = busy; });
  $$("[data-retry-job]").forEach(button => { button.disabled = busy || retryIsPending(button.dataset.retryJob); });
  for (const slot of ["inspect", "reference"]) for(const suffix of ["retry-button","retry-local"]) $(`#${slot}-${suffix}`).disabled = busy || retryIsPending(state.retryJobs[slot]?.id);
  $$("[data-action='new-standard']").forEach(x => { x.disabled = busy; });
  $("#inspect-progress").hidden = !busy || !["inspection", "recognition"].includes(kind);
  $("#reference-progress").hidden = !busy || kind !== "reference";
  updatePendingControls();
}
function clearResult() { state.inspection = null; state.resultDirty = false; state.standardSaved=false; $("#result-area").replaceChildren(); $("#result-area").hidden = true; $("#result-placeholder").hidden = false; }
function markResultChanged(preserveSaved = false) {
  if (preserveSaved !== true) state.standardSaved = false;
  if (!state.inspection) return;
  state.resultDirty = true;
  if ($("#recheck-dirty")) $("#recheck-dirty").hidden = false;
  if ($("#result-maintenance")) $("#result-maintenance").open = true;
  refreshResultStandardOffer();
}
function validBaseDate() {
  const input = $("#base-date");
  if (!input.value || !input.checkValidity()) { input.reportValidity(); toast("請設定本批基準日。", true); return false; }
  return true;
}
function selectedStandard() {
  const standard = state.templates.find(t => t.id === $("#template-select").value);
  const node = $("#selected-standard"), missing = !standard && !!$("#template-select").value; node.replaceChildren(); node.hidden = !standard && !missing;
  $("#recognition-help").hidden = !!standard || missing;
  if (missing) {
    state.inspectSource=null;renderInspectSource();$("#template-options").open=true;
    const warning=element("p","recheck-dirty","這筆使用的照片標準已非可選用版本，可能已更新或移除。已保留原選擇，請改選有效照片標準後再核對；也可明確改選自動對應。");warning.id="unavailable-photo-standard";warning.setAttribute("role","status");node.append(warning);
  }
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
  else if(previous) retainUnavailableTemplate(previous,state.inspection?.template_id===previous ? state.inspection.template_snapshot : null);
  $("#nav-count").textContent = String(manualLibraryTotal);
  selectedStandard(); if(admin)await loadManualLibrary(1);
}
function retainUnavailableTemplate(identifier, snapshot) {
  const select=$("#template-select");
  const options=Array.from(select.options || select.children);
  if(!options.some(option=>option.value===identifier))select.append(new Option(`${snapshot?.name || "歷史照片標準"}${snapshot?.version ? ` · 第 ${snapshot.version} 版` : ""}（請改選有效版本）`,identifier));
  select.value=identifier;
}
function validPhotoTemplateChoice() {
  const identifier=$("#template-select").value;
  if(!identifier || state.inspectSource?.code || state.templates.some(item=>item.id===identifier))return true;
  selectedStandard();$("#template-options").open=true;$("#template-select").focus();toast("原照片標準已非可選用版本。請先選擇有效版本，或明確改選自動對應。",true);return false;
}
async function loadScanConfig() {
  const config = await api("/api/scan-config");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(config.today || "")) throw new Error("無法取得今天日期，請手動設定本批基準日。");
  if (!$("#base-date").value) $("#base-date").value = config.today;
  configureRecognition(config.recognition || {});
}
function configureRecognition(config){
  state.recognition={...config,cloud_available:config.cloud_available===true,default_engine:config.default_engine==="cloud" ? "cloud" : "local"};
  for(const prefix of ["","reference-","crop-"]){
    const input=$("#"+prefix+"recognition-engine"),previous=input.value;
    const selected=input.dataset.recognitionInitialized==="true" && ["local","cloud"].includes(previous) ? previous : state.recognition.default_engine==="cloud" && state.recognition.cloud_available ? "cloud" : "local";
    input.replaceChildren(new Option("一般辨識", "local"),new Option(config.cloud_available ? "雲端辨識（付費）" : "雲端辨識（暫不可用）","cloud"));
    if(input.options?.[1])input.options[1].disabled=!state.recognition.cloud_available;
    input.value=selected;input.dataset.recognitionInitialized="true";
    if(!["sticker","full"].includes($("#"+prefix+"label-scope").value))$("#"+prefix+"label-scope").value="sticker";
    recognitionChoiceNote(prefix);
  }
}
function recognitionSettings(prefix=""){
  const engine=$("#"+prefix+"recognition-engine").value || "local",scope=$("#"+prefix+"label-scope").value || "sticker";
  if(!["local","cloud"].includes(engine) || !["sticker","full"].includes(scope))throw new Error("請選擇辨識方式與照片範圍。");
  if(engine==="cloud" && !state.recognition.cloud_available)throw new Error("目前無法使用雲端辨識，未送出照片。請自行改用一般辨識，或待雲端恢復可用後再送出。");
  return {recognition_engine:engine,label_scope:scope};
}
function recognitionChoiceNote(prefix=""){
  const cloud=$("#"+prefix+"recognition-engine").value==="cloud",config=state.recognition;
  const quota=Number.isInteger(config.cloud_remaining) ? `目前剩餘 ${config.cloud_remaining}${Number.isInteger(config.cloud_limit) ? `／${config.cloud_limit}` : ""} 次試用。` : "";
  $("#"+prefix+"recognition-choice-note").textContent=cloud ? config.cloud_available ? `這次送出會使用雲端付費辨識。${quota}照片將交由雲端服務讀取，仍需核對文字。` : `雲端辨識目前未開放或額度已用完。${quota}已保留雲端選擇，不會自動改用一般辨識；請自行選擇一般辨識，或待雲端恢復可用後再送出。` : `使用本站一般辨識，不呼叫付費雲端服務。${config.cloud_available ? quota : "雲端辨識目前未開放或額度已用完。"}`;
  if(prefix==="crop-"){if(state.crop && !state.crop.manualScope)state.crop.wholeScope=$("#crop-label-scope").value || "sticker";invalidateCropPreview();}
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
function renderOCR(lines, container, threshold=.65) {
  container.replaceChildren();
  if (!lines.length) return container.append(element("p", "muted", "未辨識到文字，請換一張清楚的照片。"));
  lines.forEach(line => {
    const row = element("div", "ocr-line", line.text);
    if(line.human_uncertain || (!line.human_verified && (line.ambiguous || (Number.isFinite(line.score) && line.score < threshold))))row.append(element("small", "", line.ambiguity_reason==="line_retry_disagrees" ? "局部重讀結果不同，請對照原圖。" : line.ambiguous ? "不同次辨識有差異，請對照照片。" : "此行需對照照片確認。"));
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
  $("#reference-ocr").hidden = false; renderOCR(job.result.ocr.lines, $("#reference-lines"),ocrLowScoreThreshold(job.result.ocr));
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
    if (job.state === "failed") { rememberFailedJob({...job,id:job.id || jobId}, kind); sessionStorage.removeItem("labelcheck-pending");loadScanConfig().catch(()=>{}); throw new Error(job.error || "照片辨識未完成，可以使用已保留的照片重試。"); }
    if (job.state === "done") {
      sessionStorage.removeItem("labelcheck-pending");
      setRetryJob(kind); setUploadError(kind); loadFailedJobs();
      loadScanConfig().catch(()=>{});
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
function newRequestId(){return [...window.crypto.getRandomValues(new Uint8Array(16))].map(value=>value.toString(16).padStart(2,"0")).join("");}
function uploadRequest(file,kind,body){
  const slot=retrySlot(kind),signature=JSON.stringify(body),old=state.uploadRequests[slot];
  if(old?.file===file && old.signature===signature)return old;
  return state.uploadRequests[slot]={file,kind,signature,id:newRequestId()};
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
  if (kind !== "reference" && !validPhotoTemplateChoice()) { setUploadError(kind,"請先選擇有效照片標準，或明確改選自動對應。"); return; }
  if (kind !== "reference" && !validBaseDate()) { setUploadError(kind, "請設定本批基準日後再上傳。"); return; }
  let settings;try{settings=recognitionSettings(kind==="reference" ? "reference-" : "");}catch(error){reportUploadFailure(kind,error);return;}
  const pending=uploadRequest(file,kind,{kind,template,sourceCode,...settings,base_date:$("#base-date").value,batch_date:$("#batch-date").value,arrival_date:$("#arrival-date").value,supersedes:state.supersedes?.id || ""});
  const slot=retrySlot(kind);$("#"+slot+"-upload-resend").hidden=true;
  const form = new FormData(); form.append("photo", file); form.append("kind", kind);form.append("request_id",pending.id);for(const [key,value] of Object.entries(settings))form.append(key,value);
  if (kind !== "reference") { form.append("template_id", template); form.append("source_code", sourceCode); form.append("base_date", $("#base-date").value); form.append("batch_date", $("#batch-date").value); form.append("arrival_date", $("#arrival-date").value); clearResult(); }
  else { state.referenceJob = null; state.source = null; $("#standard-fields").disabled = true; $("#reference-preview").hidden = true; $("#reference-ocr").hidden = true; }
  setBusy(true, kind);
  try {
    const job = await api("/api/jobs", {method: "POST", body: form});
    if(state.uploadRequests[slot]===pending)delete state.uploadRequests[slot];
    sessionStorage.setItem("labelcheck-pending", JSON.stringify({id: job.id, kind, supersedes_id:kind === "reference" ? state.supersedes?.id || null : null}));
    await pollJob(job.id, kind);
  } catch (error) { reportUploadFailure(kind, error);if(state.authenticated && state.uploadRequests[slot]===pending && (!error.status || error.status>=500 || error.status===429))$("#"+slot+"-upload-resend").hidden=false; }
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
let pendingStandardsPage=1,pendingStandardsRequest=0,pendingStandardsItems=[],pendingStandardsLoading=false,pendingStandardsHasMore=false;
const pendingStandardsSelection=new Map();
function pendingViewState(){return $("#pending-standard-state").value==="removed" ? "removed" : "active";}
function updatePendingControls(){
  const blocked=!allowed() || state.busy || pendingStandardsLoading,removed=pendingViewState()==="removed",count=pendingStandardsSelection.size;
  $("#pending-standard-selected-count").textContent=`已選 ${count} 筆`;
  const all=$("#pending-standard-select-all");all.disabled=blocked || !pendingStandardsItems.length;all.checked=!!pendingStandardsItems.length && count===pendingStandardsItems.length;all.indeterminate=count>0 && count<pendingStandardsItems.length;
  $("#pending-standard-remove-selected").hidden=removed;$("#pending-standard-restore-selected").hidden=!removed;
  $("#pending-standard-remove-selected").disabled=blocked || !count;$("#pending-standard-restore-selected").disabled=blocked || !count;
  $("#pending-standard-prev").disabled=blocked || pendingStandardsPage<=1;$("#pending-standard-next").disabled=blocked || !pendingStandardsHasMore;
  for(const id of ["pending-standard-range","pending-standard-state","pending-standard-refresh"])$("#"+id).disabled=blocked;
  $$("#pending-standard-list input, #pending-standard-list button").forEach(node=>{node.disabled=blocked;});
}
function pendingNotice(text="",error=false){const node=$("#pending-standard-notice");node.textContent=text;node.hidden=!text;node.setAttribute("role",error ? "alert" : "status");node.className=error ? "upload-error" : "help pending-action-notice";}
function selectPendingPage(selected){
  if(!allowed() || state.busy || pendingStandardsLoading)return;
  pendingStandardsSelection.clear();if(selected)pendingStandardsItems.forEach(item=>pendingStandardsSelection.set(item.inspection_id,item));
  $$("#pending-standard-list input[data-pending-select]").forEach(input=>{input.checked=!!selected;});updatePendingControls();
}
async function changePendingState(operation,items=[...pendingStandardsSelection.values()]){
  if(!allowed() || state.busy || pendingStandardsLoading || !["remove","restore"].includes(operation) || !items.length)return;
  if((operation==="restore")!==(pendingViewState()==="removed"))return;
  const current=items.every(item=>pendingStandardsItems.some(row=>row.inspection_id===item.inspection_id && row.image_id===item.image_id && row.pending_revision===item.pending_revision));
  if(!current){pendingNotice("清單已更新，請重新勾選要處理的草稿。",true);return;}
  const epoch=state.authEpoch;pendingNotice();setBusy(true);
  try{
    const result=await api("/api/manual-standards/pending/state",{method:"POST",body:{operation,items:items.map(item=>({inspection_id:item.inspection_id,image_id:item.image_id,base_revision:item.pending_revision})),note:operation==="remove" ? "從待建立標準清單移除草稿" : "還原待建立標準草稿"}});
    if(epoch!==state.authEpoch || !allowed())return;
    await loadPendingStandards(1);if(epoch!==state.authEpoch || !allowed())return;
    pendingNotice(operation==="remove" ? `已移除 ${result.count} 筆草稿。只移出待建清單，照片、檢查紀錄與標準都保留；可到「已移除」還原。` : `已還原 ${result.count} 筆草稿。仍符合建立條件的照片會回到待確認；已建立標準的照片不會重複列入。`);
  }catch(error){
    if(epoch!==state.authEpoch || !allowed())return;
    if(error.status===409){await loadPendingStandards(1);if(epoch===state.authEpoch && allowed())pendingNotice("清單已被更新，這次整批操作未套用。已重新載入，請重新勾選。",true);}
    else pendingNotice(`未取得操作完成回應：${error.message}。請重新整理清單確認結果。`,true);
  }finally{setBusy(false);updatePendingControls();}
}
async function loadPendingStandards(page=1){
  if(!allowed())return;
  const token=++pendingStandardsRequest,epoch=state.authEpoch,range=$("#pending-standard-range").value==="all" ? "all" : "today",viewState=pendingViewState(),removed=viewState==="removed";
  pendingStandardsSelection.clear();pendingStandardsItems=[];pendingStandardsLoading=true;pendingStandardsHasMore=false;updatePendingControls();
  $("#pending-standard-title").textContent=removed ? "已移除草稿" : "待建立標準";
  $("#pending-standard-list").replaceChildren();$("#pending-standard-status").textContent="讀取待建立標準的檢查紀錄…";$("#pending-standard-count").textContent="";
  try{
    const data=await api(`/api/manual-standards/pending?state=${viewState}&range=${range}&page=${page}&limit=24`);
    if(token!==pendingStandardsRequest || epoch!==state.authEpoch || !allowed())return;
    pendingStandardsPage=page;const items=(Array.isArray(data.items) ? data.items : []).filter(item=>item?.inspection_id && item?.image_id).map(item=>({...item,pending_revision:Number.isInteger(item.pending_revision) ? item.pending_revision : 0})),total=Number.isInteger(data.total) ? data.total : items.length;pendingStandardsItems=items;pendingStandardsHasMore=!!data.has_more;
    $("#pending-standard-count").textContent=`${removed ? "已移除 · " : ""}${range==="today" ? "今天" : "全部"} ${total} 筆`;
    for(const item of items){
      const row=element("article","pending-standard-row"),image=element("img"),copy=element("div","pending-standard-copy"),name=item.name || "未命名標籤";
      const selectLabel=element("label","pending-standard-check"),select=element("input");select.type="checkbox";select.dataset.pendingSelect=item.inspection_id;select.setAttribute("aria-label",`選取草稿：${name}`);select.onchange=()=>{if(select.checked)pendingStandardsSelection.set(item.inspection_id,item);else pendingStandardsSelection.delete(item.inspection_id);updatePendingControls();};selectLabel.append(select);
      if(item.thumbnail)image.src=item.thumbnail;image.alt=`${name}的待確認照片`;image.loading="lazy";
      copy.append(element("strong","",name),element("small","",when(item.created_at)));
      if(removed && item.pending_updated_at)copy.append(element("small","",`移除：${when(item.pending_updated_at)}`));
      const actions=element("div","pending-row-actions");
      if(!removed){const open=element("button","button secondary","開啟草稿");open.type="button";open.dataset.editStandard="pending";open.disabled=state.busy;open.setAttribute("aria-label",`開啟標準草稿：${name}`);open.onclick=()=>state.busy ? undefined : openManualStandard(item.inspection_id);actions.append(open);}
      const action=element("button","button secondary",removed ? "還原草稿" : "移除草稿");action.type="button";action.dataset.pendingOperation=removed ? "restore" : "remove";action.setAttribute("aria-label",`${removed ? "還原" : "移除"}草稿：${name}`);action.onclick=()=>changePendingState(removed ? "restore" : "remove",[item]);actions.append(action);
      row.append(selectLabel,image,copy,actions);$("#pending-standard-list").append(row);
    }
    $("#pending-standard-status").textContent=items.length ? removed ? `第 ${page} 頁 · 草稿只從待建清單移除，照片與檢查紀錄保留，可逐筆或勾選還原。` : `第 ${page} 頁 · 可移除重複草稿；開啟後會自動帶入分區文字，核准前尚非正式標準。` : `目前${range==="today" ? "今天" : "全部"}範圍內沒有${removed ? "已移除" : "待建立標準"}的草稿。${range==="today" ? "可切換「全部」查看較早紀錄。" : ""}`;
  }catch(error){if(token===pendingStandardsRequest && epoch===state.authEpoch && allowed())$("#pending-standard-status").textContent=error.message;}
  finally{if(token===pendingStandardsRequest && epoch===state.authEpoch){pendingStandardsLoading=false;updatePendingControls();}}
}
function libraryPath(data){return `/api/standard-library/${encodeURIComponent(data.kind)}/${encodeURIComponent(data.key)}`;}
function libraryTextMode(data){return data?.supports_line_replacement===true || data?.kind!=="photo";}
function libraryKindLabel(kind,sourceKind){return kind==="photo" ? "照片標準" : kind==="source" ? sourceKind==="catalog" ? "清單完整標準" : "系統完整標準" : "文字標準";}
function libraryIdentity(item){const identity=item.identity || {},parts=[];if(identity.spec)parts.push(`規格：${identity.spec}`);if(identity.barcode)parts.push(`條碼：${identity.barcode}`);if(identity.sku)parts.push(`貨號：${identity.sku}`);parts.push(item.kind!=="photo" ? sourceCodeLabel({code:item.key}) : `P-${String(item.key || "").slice(0,8)} · 第 ${item.base_revision ?? item.template?.version ?? 1} 版`);return parts;}
function populateLibraryCategories(){
  const categories=state.libraryCategories || [];
  for(const [id,filter] of [["standard-library-category",true],["library-detail-category",false]]){const input=$("#"+id),previous=input.value;input.replaceChildren();if(filter)input.append(new Option("全部分類","all"));input.append(new Option("未分類",filter ? "uncategorized" : ""));categories.forEach(item=>input.append(new Option(item.name,item.id)));if([...categories.map(item=>String(item.id)),filter ? "all" : "",filter ? "uncategorized" : ""].includes(previous))input.value=previous;}
}
async function loadLibraryCategories(){
  if(!allowed())return;const epoch=state.authEpoch,request=++state.libraryCategoryRequest;const data=await api("/api/standard-library/categories");if(epoch!==state.authEpoch || request!==state.libraryCategoryRequest || !allowed())return;
  state.libraryCategories=(data.items || []).filter(item=>item?.id && typeof item.name==="string");populateLibraryCategories();
}
async function loadManualLibrary(page=1) {
  if(!allowed())return;const token=++manualLibraryRequest,epoch=state.authEpoch,query=$("#standard-library-query").value.trim(),category=$("#standard-library-category").value || "all",removed=$("#standard-library-state").value==="removed";
  $("#standard-library-status").textContent="讀取已建立標準…";$("#standard-library-prev").disabled=true;$("#standard-library-next").disabled=true;
  try{
    const data=await api(`/api/standard-library?kind=all&state=${removed ? "removed" : "active"}&category_id=${encodeURIComponent(category)}&q=${encodeURIComponent(query)}&page=${page}&limit=24`);
    if(token!==manualLibraryRequest || epoch!==state.authEpoch || !allowed())return;manualLibraryPage=page;
    if(!query && category==="all" && !removed){manualLibraryTotal=data.total || 0;$("#nav-count").textContent=String(manualLibraryTotal);}
    $("#standard-library-total").textContent=`${data.total || 0} 份${removed ? "已刪除" : "標準"}`;const list=$("#standard-library-list");list.replaceChildren();
    for(const item of data.items || []){
      if(!["manual","photo","source"].includes(item.kind) || !item.key)continue;const card=element("article","panel library-card unified-standard-card"),cover=element("div","standard-card-cover");
      if(item.image?.thumbnail || item.image?.url){const img=element("img");img.src=item.image.thumbnail || item.image.url;img.alt=`${item.name} 參考照片`;img.loading="lazy";cover.append(img);}else cover.append(element("span","help","尚無參考照片"));
      const content=element("div","library-card-content"),chips=element("div","standard-card-chips");chips.append(element("span","standard-chip",item.category_name || "未分類"),element("span","standard-chip subtle",libraryKindLabel(item.kind,item.source_kind)));if(item.removed)chips.append(badge("review","已刪除"));
      content.append(chips,element("h3","",item.name || "未命名標準"));libraryIdentity(item).forEach(value=>content.append(element("p","standard-card-identity",value)));if(item.photo_count>1)content.append(element("p","help",`${item.photo_count} 張參考照片`));
      const button=element("button","button primary","查看內容");button.type="button";button.onclick=()=>openLibraryDetail(item.kind,item.key);content.append(button);card.append(cover,content);list.append(card);
    }
    $("#standard-library-status").textContent=data.items?.length ? "點「查看內容」可對照照片、編輯、分類或還原標準。" : removed ? "沒有符合條件的已刪除標準。" : query || category!=="all" ? "找不到符合條件的標準，可調整搜尋或分類。" : "尚無已建立標準，可展開下方待確認草稿，對照照片後核准。";
    $("#standard-library-page").textContent=`第 ${page} 頁`;$("#standard-library-prev").disabled=page<=1;$("#standard-library-next").disabled=!data.has_more;
  }catch(error){if(token===manualLibraryRequest && epoch===state.authEpoch && allowed())$("#standard-library-status").textContent=error.message;}
}
function closeLibraryDetail(force=false){if(state.busy && !force)return;state.libraryDetail=null;if($("#library-detail-dialog").open)$("#library-detail-dialog").close();$("#library-detail-image").removeAttribute("src");$("#library-detail-original").removeAttribute("href");for(const id of ["library-detail-view","library-detail-photos","library-detail-history","library-edit-preview","library-edit-photo-fields","library-edit-date-fields"])$("#"+id).replaceChildren();$("#library-detail-form").reset();$$("#library-detail-dialog input, #library-detail-dialog textarea").forEach(input=>{input.value="";input.checked=false;});$("#library-detail-body").hidden=true;for(const id of ["library-detail-title","library-detail-meta","library-detail-notice","library-detail-photo-note","library-detail-error","library-state-title","library-state-note","library-state-confirm-text"])$("#"+id).textContent="";for(const id of ["library-content-text","library-nutrition-text","library-uncertain-text","library-full-text","library-edit-name","library-edit-reviewer","library-edit-note"])$("#"+id).value="";}
function librarySections(rows){const compact=rows.map(row=>row.text.replace(/\s+/g,"")),hasContext=compact.some(nutritionHeader) || compact.filter(fullNutrientRow).length>=2;return rows.map(row=>({...row,section:row.sectionPinned ? row.section : classifyTextSection(row,hasContext)}));}
function showLibraryPhoto(index){const context=state.libraryDetail;if(!context)return;const photo=context.photos[index];if(!photo?.url)return;context.photoIndex=index;$("#library-detail-image").src=photo.url;$("#library-detail-image").hidden=false;$("#library-detail-original").href=photo.url;$("#library-detail-original").hidden=false;$("#library-detail-photo-note").textContent=`參考照片 ${index+1}／${context.photos.length}${photo.stale ? " · 較早版本，請依目前標準內容核對" : ""}`;[...$("#library-detail-photos").children].forEach((node,i)=>node.setAttribute("aria-pressed",String(i===index)));}
function renderLibraryDetail(data){
  const context=state.libraryDetail;if(!context)return;context.data=data;context.editing=false;context.preview=null;context.operation=null;context.conflict=false;context.rows=librarySections((data.source?.lines || []).map(row=>({text:row.text || "",row_type:row.row_type})));context.photos=[];
  const candidates=[data.current_image,...(data.photos || []).map(item=>item.image || item),data.image],seen=new Set();for(const photo of candidates){if(!photo?.url || seen.has(photo.url))continue;seen.add(photo.url);context.photos.push(photo);}
  $("#library-detail-title").textContent=data.name || data.source?.name || data.template?.name || "標準內容";$("#library-detail-meta").textContent=`${libraryKindLabel(data.kind,data.source_kind || data.source?.source_kind)} · ${libraryIdentity(data).join(" · ")}${data.category_name ? ` · ${data.category_name}` : ""}`;
  $("#library-detail-notice").textContent=data.removed ? "這份標準已刪除，不用於新掃描；照片、內容及歷史均保留，可還原。" : "此處顯示目前核准內容。修改會建立新版，既有檢查紀錄保留。";
  $("#library-detail-body").hidden=false;$("#library-detail-form").hidden=true;$("#library-detail-view").hidden=false;$("#library-detail-actions").hidden=false;$("#library-state-preview").hidden=true;$("#library-state-confirm").checked=false;$("#library-detail-reload").hidden=true;$("#library-detail-category").value=data.category_id || "";
  $("#library-detail-edit").hidden=data.removed || data.editable===false;$("#library-detail-remove").hidden=!!data.removed;$("#library-detail-restore").hidden=!data.removed;$("#library-detail-use").hidden=!!data.removed;$("#library-detail-advanced").open=false;
  const photos=$("#library-detail-photos");photos.replaceChildren();$("#library-detail-image").hidden=!context.photos.length;$("#library-detail-original").hidden=!context.photos.length;$("#library-detail-photo-note").textContent=context.photos.length ? "" : "尚無可讀取的參考照片；標準文字仍保留。";
  context.photos.forEach((photo,index)=>{const button=element("button","library-photo-choice");button.type="button";button.setAttribute("aria-label",`查看第 ${index+1} 張參考照片`);const img=element("img");img.src=photo.thumbnail || photo.url;img.alt="";button.append(img);button.onclick=()=>showLibraryPhoto(index);photos.append(button);});if(context.photos.length)showLibraryPhoto(0);
  const view=$("#library-detail-view");view.replaceChildren();
  if(libraryTextMode(data))for(const section of ["content","nutrition","uncertain"]){const rows=context.rows.filter(row=>row.section===section);if(!rows.length)continue;const block=element("section",`library-content-block ${section}`);block.append(element("h3","",textSectionLabels[section]));rows.forEach(row=>block.append(element("p","library-text-line",row.text)));view.append(block);}
  else{const block=element("section","library-content-block");block.append(element("h3","","標籤內容"));for(const key of textFields){const value=data.template?.fields?.[key];if(value)block.append(element("p","library-text-line",`${fieldLabels[key]}：${value}`));}view.append(block);}
  const dates=element("section","library-content-block"),source=data.source || {},template=data.template || {};dates.append(element("h3","","日期規則"));const days=libraryTextMode(data) ? source.keep_days : template.rules?.keep_days;dates.append(element("p","",days===null || days===undefined ? "保存天數未設定" : `保存天數：${days} 天`));
  if(libraryTextMode(data)){for(const rule of source.date_settings || [])dates.append(element("p","",source.source_kind==="desktop" ? `${rule.content || "日期"}：沿用標籤系統日期規則，位移 ${rule.shift_days || 0} 天` : `${rule.content || "日期"}：本批基準日 ${Number(rule.shift_days || 0)>=0 ? "+" : ""}${rule.shift_days || 0} 天`));if(!source.date_settings?.length)dates.append(element("p","help","未設定日期位移；不推定每日日期。"));}
  else dates.append(element("p","",`製造／有效日期：${template.rules?.dates ? "檢查" : "未啟用"}；到店日：${template.rules?.arrival ? "檢查" : "未啟用"}`));view.append(dates);
  const history=$("#library-detail-history");history.replaceChildren(element("h3","","版本紀錄"));for(const entry of data.history || []){const row=element("div","review-record");row.append(element("strong","",`第 ${entry.revision} 版 · ${{update:"修改",create:"建立",restore:"還原",reset:"恢復來源",remove:"刪除"}[entry.operation] || "標準紀錄"}`),element("p","help",`${entry.reviewer || ""}${entry.created_at ? ` · ${when(entry.created_at)}` : ""}`));if(entry.note)row.append(element("p","",entry.note));history.append(row);}if(!data.history?.length)history.append(element("p","help","尚無額外修改紀錄。"));libraryDetailControls();
}
async function openLibraryDetail(kind,key){
  if(!requireAdmin() || state.busy || !["manual","photo","source"].includes(kind) || !key)return;const context={kind,key,data:null,editing:false,preview:null};state.libraryDetail=context;$("#library-detail-body").hidden=true;$("#library-detail-title").textContent="讀取標準內容…";$("#library-detail-meta").textContent="";$("#library-detail-notice").textContent="";$("#library-detail-reload").hidden=true;setDialogError("#library-detail-error");if(!$("#library-detail-dialog").open)$("#library-detail-dialog").showModal();
  try{await loadLibraryCategories();const data=await api(libraryPath(context));if(state.libraryDetail!==context || !allowed())return;renderLibraryDetail(data);}catch(error){if(state.libraryDetail===context)setDialogError("#library-detail-error",error.message);}
}
function libraryDetailControls(){const context=state.libraryDetail,busy=state.busy;for(const node of $$("#library-detail-dialog button, #library-detail-dialog input, #library-detail-dialog textarea, #library-detail-dialog select"))node.disabled=busy;for(const id of ["library-detail-category","library-detail-category-save","library-detail-add-category"])$("#"+id).disabled=busy || !!context?.editing;$("#library-edit-preview-button").disabled=busy || !!context?.conflict;$("#library-edit-save").disabled=busy || !!context?.conflict;}
function libraryBusy(value){setBusy(value);libraryDetailControls();}
function renderLibraryEditSections(preserve=null){const context=state.libraryDetail;if(!context)return;context.rows=librarySections(context.rows);for(const section of ["content","nutrition","uncertain"]){const rows=context.rows.filter(row=>row.section===section);if(section!==preserve)$("#library-"+section+"-text").value=rows.map(row=>row.text).join("\n");if(section!=="content")$("#library-"+section+"-zone").hidden=!rows.length && preserve!==section;}$("#library-full-text").value=context.rows.map(row=>row.text).join("\n");}
function invalidateLibraryPreview(){const context=state.libraryDetail;if(context){context.preview=null;context.previewNonce=(context.previewNonce || 0)+1;}$("#library-edit-preview").hidden=true;$("#library-edit-confirm-label").hidden=true;$("#library-edit-confirm").checked=false;$("#library-edit-save").hidden=true;}
function changeLibrarySection(section){const context=state.libraryDetail;if(!context?.editing || state.busy)return;const prior=context.rows,next=plainTextRows($("#library-"+section+"-text").value).map(row=>({text:row.text,section,sectionPinned:true})),last=prior.map(row=>row.section).lastIndexOf(section),rows=[];let index=0;prior.forEach((row,i)=>{if(row.section!==section)rows.push(row);else{if(index<next.length)rows.push(next[index++]);if(i===last)rows.push(...next.slice(index));}});if(last<0)rows.push(...next);context.rows=rows;renderLibraryEditSections(section);invalidateLibraryPreview();}
function changeLibraryFullText(){if(!state.libraryDetail?.editing || state.busy)return;state.libraryDetail.rows=plainTextRows($("#library-full-text").value).map(row=>({text:row.text}));renderLibraryEditSections();invalidateLibraryPreview();}
function toggleLibraryPhotoDates(){const hasSource=!!state.libraryDetail?.data?.template?.rules?.source,dates=$("#library-photo-dates").checked && !hasSource,arrival=$("#library-photo-arrival-check").checked && !hasSource;$("#library-photo-date-fields").hidden=!dates;$("#library-photo-arrival-field").hidden=!arrival;$("#library-photo-manufacture").required=dates;$("#library-photo-expiry").required=dates;$("#library-photo-arrival").required=arrival;}
function beginLibraryEdit(){
  const context=state.libraryDetail,data=context?.data;if(!requireAdmin() || state.busy || !data || data.removed || data.editable===false)return;context.editing=true;context.conflict=false;context.rows=librarySections((data.source?.lines || []).map(row=>({text:row.text || "",row_type:row.row_type})));context.dateControls=[];context.fieldControls=[];invalidateLibraryPreview();setDialogError("#library-detail-error");$("#library-detail-view").hidden=true;$("#library-detail-form").hidden=false;$("#library-detail-actions").hidden=true;$("#library-state-preview").hidden=true;$("#library-detail-reload").hidden=true;
  $("#library-edit-date-fields").replaceChildren();$("#library-edit-photo-fields").replaceChildren();for(const key of ["manufacture","expiry","arrival"])$("#library-photo-"+key).required=false;$("#library-edit-name").value=data.name || data.source?.name || data.template?.name || "";$("#library-edit-reviewer").value=sessionStorage.getItem("labelcheck-operator") || "";$("#library-edit-note").value="依標籤照片核對並更新標準";$("#library-edit-manual").hidden=!libraryTextMode(data);$("#library-edit-photo").hidden=libraryTextMode(data);
  if(libraryTextMode(data)){renderLibraryEditSections();$("#library-edit-days").value=data.source?.keep_days ?? "";const area=$("#library-edit-date-fields");area.replaceChildren();(data.source?.date_settings || []).forEach((setting,index)=>{const label=element("label","",`${setting.content || "日期"}位移天數`),input=element("input");input.type="number";input.min="-3650";input.max="3650";input.step="1";input.value=setting.shift_days ?? 0;input.required=true;label.append(input);area.append(label);context.dateControls.push({setting,index,input});});if(!context.dateControls.length)area.append(element("p","help","目前未設定固定日期位移，保留動態日期檢查。"));}
  else{const template=data.template || {},area=$("#library-edit-photo-fields");area.replaceChildren();for(const key of textFields){const label=element("label","",fieldLabels[key]),input=element(key==="address" ? "textarea" : "input");input.value=template.fields?.[key] || "";input.maxLength=500;input.required=["product","origin","address"].includes(key);input.setAttribute("aria-label",fieldLabels[key]);label.append(input);area.append(label);context.fieldControls.push({key,input});}$("#library-photo-dates").checked=!!template.rules?.dates;$("#library-photo-arrival-check").checked=!!template.rules?.arrival;$("#library-photo-days").value=template.rules?.keep_days ?? "";for(const key of ["manufacture","expiry","arrival"])$("#library-photo-"+key).value=template.reference_dates?.[key] || "";toggleLibraryPhotoDates();}
  libraryDetailControls();$("#library-edit-name").focus();
}
function collectLibraryChanges(){
  const context=state.libraryDetail,data=context?.data;if(!context?.editing || !data || context.conflict)return null;const changes={},preview=[],name=$("#library-edit-name").value.trim();if(!name)throw new Error("請填寫標準名稱。");if(name!==data.name){changes.name=name;preview.push({label:"標準名稱",before:data.name,after:name});}
  const changed=(key,before,after,label)=>{if(JSON.stringify(before)!==JSON.stringify(after)){changes[key]=after;preview.push({label,before:typeof before==="object" ? JSON.stringify(before) : before,after:typeof after==="object" ? JSON.stringify(after) : after});}};
  if(libraryTextMode(data)){const source=data.source || {},rows=context.rows.map(row=>({text:row.text.trim()})).filter(row=>row.text);if(!rows.length || rows.length>150)throw new Error("請保留 1 至 150 行正確標準文字。");const before=(source.lines || []).map(row=>row.text).join("\n"),after=rows.map(row=>row.text).join("\n");if(before!==after){changes.replace_lines=rows;preview.push({label:`標準全文（${rows.length} 行）`,before,after});}const daysInput=$("#library-edit-days");if(!daysInput.checkValidity())throw new Error("保存天數需為 0 至 3650 的整數。");const days=daysInput.value==="" ? null : Number(daysInput.value);changed("keep_days",source.keep_days ?? null,days,"保存天數");const dates=[];for(const {index,setting,input} of context.dateControls){if(!input.checkValidity() || input.value==="")throw new Error("請填寫有效的日期位移整數。");const value=Number(input.value);if(value!==Number(setting.shift_days ?? 0)){dates.push({index,shift_days:value});preview.push({label:`${setting.content}位移天數`,before:setting.shift_days ?? 0,after:value});}}if(dates.length)changes.date_settings=dates;}
  else{const template=data.template || {},fields={...template.fields};for(const {key,input} of context.fieldControls){if(!input.checkValidity())throw new Error(`請確認${fieldLabels[key]}。`);fields[key]=input.value.trim();if(fields[key]!==template.fields?.[key])preview.push({label:fieldLabels[key],before:template.fields?.[key] || "",after:fields[key]});}if(JSON.stringify(fields)!==JSON.stringify(template.fields))changes.fields=fields;const daysInput=$("#library-photo-days");if(!daysInput.checkValidity())throw new Error("保存天數需為 0 至 3650 的整數。");const rules={dates:$("#library-photo-dates").checked,arrival:$("#library-photo-arrival-check").checked,keep_days:daysInput.value==="" ? null : Number(daysInput.value)},ruleChanges={};for(const [key,label] of [["dates","檢查製造／有效日期"],["arrival","檢查到店日"],["keep_days","保存天數"]]){const before=template.rules?.[key] ?? (key==="keep_days" ? null : false);if(rules[key]!==before){ruleChanges[key]=rules[key];preview.push({label,before:typeof before==="boolean" ? before ? "啟用" : "未啟用" : before,after:typeof rules[key]==="boolean" ? rules[key] ? "啟用" : "未啟用" : rules[key]});}}if(Object.keys(ruleChanges).length)changes.rules=ruleChanges;const dates={};for(const [key,label] of [["manufacture","製造日期"],["expiry","有效日期"],["arrival","到店日"]]){const input=$("#library-photo-"+key);if(!input.checkValidity())throw new Error("請填寫已啟用檢查的參考照片日期。");const value=input.value.trim();if(value!==(template.reference_dates?.[key] || "")){dates[key]=value;preview.push({label:`參考照片的${label}`,before:template.reference_dates?.[key] || "未設定",after:value || "未設定"});}}if(Object.keys(dates).length)changes.reference_dates=dates;}
  return {changes,preview};
}
function libraryVersionBody(context){const data=context.data;return {item_revision:data.item_revision,base_revision:data.base_revision,source_revision:data.source_revision};}
function showLibraryError(error){const context=state.libraryDetail;if(error.status===409 && context){context.conflict=true;invalidateLibraryPreview();$("#library-detail-reload").hidden=false;}setDialogError("#library-detail-error",`${error.message}${error.status===409 ? " 你的編輯仍保留，請先複製需要的修改，再重新載入最新內容。" : ""}`);}
async function previewLibraryChanges(){
  const context=state.libraryDetail;if(!requireAdmin() || state.busy || !context?.editing || context.conflict)return;setDialogError("#library-detail-error");let collected;try{collected=collectLibraryChanges();if(!collected?.preview.length)throw new Error("目前沒有修改內容。");}catch(error){setDialogError("#library-detail-error",error.message);return;}invalidateLibraryPreview();const signature=JSON.stringify(collected.changes),nonce=context.previewNonce;libraryBusy(true);
  try{const data=await api(libraryPath(context)+"/preview",{method:"POST",body:{...libraryVersionBody(context),changes:collected.changes}});if(state.libraryDetail!==context || context.previewNonce!==nonce || !allowed())return;if(!data.preview_hash)throw new Error("未取得預覽版本，請重新預覽。");context.preview={signature,hash:data.preview_hash};const area=$("#library-edit-preview");area.replaceChildren(element("h3","","確認修改前後差異"));for(const item of collected.preview){const row=element("div","standard-preview-row");row.append(element("strong","",item.label),element("p","before",`修改前：${item.before ?? "未設定"}`),element("p","after",`修改後：${item.after ?? "未設定"}`));area.append(row);}renderNutritionPreview(area,data.nutrition_checks);area.hidden=false;$("#library-edit-confirm-label").hidden=false;$("#library-edit-save").hidden=false;area.scrollIntoView({block:"start",behavior:"instant"});}
  catch(error){if(state.libraryDetail===context)showLibraryError(error);}finally{libraryBusy(false);}
}
async function saveLibraryChanges(event){
  event?.preventDefault();const context=state.libraryDetail;if(!requireAdmin() || state.busy || !context?.editing || context.conflict)return;let collected;try{collected=collectLibraryChanges();}catch(error){showLibraryError(error);return;}if(!context.preview || context.preview.signature!==JSON.stringify(collected?.changes)){invalidateLibraryPreview();setDialogError("#library-detail-error","內容有變更，請重新預覽後確認。");return;}const reviewer=$("#library-edit-reviewer").value.trim(),note=$("#library-edit-note").value.trim();if(!reviewer || !note || !$("#library-edit-confirm").checked){setDialogError("#library-detail-error","請填寫修改人員、原因，並勾選確認。");return;}libraryBusy(true);setDialogError("#library-detail-error");
  try{const data=await api(libraryPath(context)+"/save",{method:"POST",body:{...libraryVersionBody(context),changes:collected.changes,preview_hash:context.preview.hash,reviewer,note,confirmed:true}});if(state.libraryDetail!==context || !allowed())return;sessionStorage.setItem("labelcheck-operator",reviewer);renderLibraryDetail(data);$("#library-detail-notice").textContent="已儲存新版標準，之後同款掃描會使用最新內容；既有檢查紀錄保留。";await loadTemplates();}
  catch(error){if(state.libraryDetail===context)showLibraryError(error);}finally{libraryBusy(false);}
}
function previewLibraryState(operation){const context=state.libraryDetail;if(!requireAdmin() || state.busy || !context?.data || context.editing || !["remove","restore"].includes(operation))return;context.operation=operation;const removing=operation==="remove";$("#library-state-title").textContent=removing ? "刪除此標準（可還原）" : "還原此標準";$("#library-state-note").textContent=removing ? "刪除後不會用於新掃描；原照片、文字版本及檢查紀錄保留，可至「已刪除」還原。" : "還原後會重新出現在已建立標準，可選用於後續掃描。";$("#library-state-confirm-text").textContent=`確認${removing ? "刪除" : "還原"}「${context.data.name}」。`;$("#library-state-confirm").checked=false;$("#library-state-save").textContent=removing ? "確認刪除，可還原" : "確認還原";$("#library-state-preview").hidden=false;$("#library-state-preview").scrollIntoView({block:"start",behavior:"instant"});}
async function saveLibraryState(){const context=state.libraryDetail;if(!requireAdmin() || state.busy || !context?.operation || !$("#library-state-confirm").checked)return;libraryBusy(true);setDialogError("#library-detail-error");try{const data=await api(libraryPath(context)+"/state",{method:"POST",body:{item_revision:context.data.item_revision,base_revision:context.data.base_revision,operation:context.operation,note:context.operation==="remove" ? "由標準庫移除，可還原" : "由標準庫還原"}});if(state.libraryDetail!==context || !allowed())return;if(data.removed && state.inspectSource?.code===data.key){state.inspectSource=null;renderInspectSource();markResultChanged();}renderLibraryDetail(data);await loadTemplates();}catch(error){if(state.libraryDetail===context)showLibraryError(error);}finally{libraryBusy(false);}}
async function saveLibraryCategory(){const context=state.libraryDetail;if(!requireAdmin() || state.busy || context?.editing || !context?.data)return;const value=$("#library-detail-category").value || null,category=(state.libraryCategories || []).find(item=>String(item.id)===value);if(value && !category){setDialogError("#library-detail-error","分類已變更，請重新開啟標準。");return;}if(value===(context.data.category_id || null)){setDialogError("#library-detail-error","分類沒有變更。");return;}libraryBusy(true);setDialogError("#library-detail-error");try{const data=await api(libraryPath(context)+"/category",{method:"POST",body:{item_revision:context.data.item_revision,category_id:value,...(category ? {category_revision:category.revision} : {})}});if(state.libraryDetail!==context || !allowed())return;renderLibraryDetail(data);$("#library-detail-notice").textContent="分類已更新；標準文字與照片未變更。";await loadManualLibrary(manualLibraryPage);}catch(error){if(state.libraryDetail===context)showLibraryError(error);}finally{libraryBusy(false);}}
function openLibraryCategory(target="filter"){if(!requireAdmin() || state.busy || (target==="detail" && state.libraryDetail?.editing))return;state.libraryCategoryContext={target,detail:state.libraryDetail};$("#library-category-form").reset();$("#library-category-name").value="";setDialogError("#library-category-error");$("#library-category-dialog").showModal();$("#library-category-name").focus();}
function closeLibraryCategory(force=false){if(state.busy && !force)return;state.libraryCategoryContext=null;if($("#library-category-dialog").open)$("#library-category-dialog").close();$("#library-category-name").value="";setDialogError("#library-category-error");}
async function saveLibraryNewCategory(event){event.preventDefault();const context=state.libraryCategoryContext;if(!requireAdmin() || state.busy || !context)return;const name=$("#library-category-name").value.trim();if(!name){setDialogError("#library-category-error","請填寫分類名稱。");return;}setBusy(true);$("#library-category-save").disabled=true;setDialogError("#library-category-error");try{const data=await api("/api/standard-library/categories",{method:"POST",body:{name}});if(state.libraryCategoryContext!==context || !allowed())return;await loadLibraryCategories();if(context.target==="detail" && state.libraryDetail===context.detail){$("#library-detail-category").value=data.id;$("#library-detail-notice").textContent="分類已建立；按「儲存分類」將此標準加入。";}else{await loadManualLibrary(manualLibraryPage);if(state.libraryCategoryContext!==context || !allowed())return;const message="分類已建立，開啟標準內容可指定分類。";$("#standard-library-status").textContent=message;toast(message);}closeLibraryCategory(true);}catch(error){if(state.libraryCategoryContext===context)setDialogError("#library-category-error",error.message);}finally{setBusy(false);$("#library-category-save").disabled=false;}}
async function useLibraryStandard(){const context=state.libraryDetail,data=context?.data;if(!requireAdmin() || state.busy || !data || data.removed)return;if(data.kind!=="photo")selectInspectSource({code:data.key,name:data.name,source_kind:data.source_kind || data.source?.source_kind || "manual"});else{await loadTemplates(data.template?.id);if(state.libraryDetail!==context || !allowed())return;state.inspectSource=null;$("#template-select").value=data.template.id;renderInspectSource();selectedStandard();markResultChanged();}closeLibraryDetail();showView("inspect");}
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
  state.inspectSource=null;
  if(inspection.template_id && !template)retainUnavailableTemplate(inspection.template_id,inspection.template_snapshot);
  else $("#template-select").value = template ? template.id : "";
  selectedStandard();
  const match = result.source_match;
  state.inspectSource = !inspection.template_id && (inputs.source_code || match?.status === "matched") ? {...match, code: inputs.source_code || match.code, name: match?.name || inspection.name || inputs.source_code} : null;
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
  $("#manual-equivalent-references").replaceChildren();
}
function textEditorContext(kind){return kind==="manual" ? manualStandard : state.standardEdit;}
function textEditorInput(kind,section="full"){return section==="full" ? $(kind==="manual" ? "#manual-standard-lines" : "#standard-edit-text") : $("#"+kind+"-"+section+"-text");}
const textSectionLabels={content:"標籤內容",nutrition:"營養標示",uncertain:"待確認文字",full:"整份文字"};
function nutritionHeader(text){return /^(?:營養標示|营养标示|營養成分|营养成分|營養資訊|营养信息)$/.test(text) || /^(?:每一份量|每份量|本包裝含|本包装含|每份(?:$|每100)|每100(?:公克|克|g|毫升|ml))/i.test(text);}
function nutrientLabel(text){return /^(?:熱量|热量|能量|蛋白質|蛋白质|脂肪|飽和脂肪(?:酸)?|饱和脂肪(?:酸)?|反式脂肪(?:酸)?|碳水化合物|糖|鈉|钠|膳食纖維|膳食纤维|膽固醇|胆固醇)(?:[:：0-9０-９<>＜＞≤≥±]|$)/.test(text);}
function fullNutrientRow(text){return nutrientLabel(text) && (text.match(/[0-9０-９]+(?:[.．][0-9０-９]+)?(?:公克|毫克|微克|克|大卡|千卡|mg|g|kcal)/gi) || []).length>=2;}
function classifyTextSection(line,hasNutritionContext=false){
  const text=String(typeof line==="string" ? line : line?.text || "").replace(/\s+/g,"");
  if(line?.row_type==="nutrition_values")return "uncertain";
  if(line?.row_type==="text" && text==="糖")return "content";
  if(line?.row_type==="nutrition" && hasNutritionContext)return "nutrition";
  if(nutritionHeader(text))return "nutrition";
  if(nutrientLabel(text) && (hasNutritionContext || fullNutrientRow(text)))return "nutrition";
  if(/^\d{8,14}$/.test(text))return "content";
  if(!text || /^(?:(?:[0-9０-９.,，．+\-±<>＜＞≤≥%％()（）/]+)|(?:公克|毫克|微克|克|大卡|千卡|毫升|公升|份|mg|mcg|kg|g|kcal|kj|ml|l))+$/i.test(text))return "uncertain";
  return "content";
}
function plainTextRows(value){
  let offset=0;return String(value || "").split("\n").map(text=>{const row={text:text.replace(/\r$/, ""),start:offset,end:offset+text.length,ids:[]};offset+=text.length+1;return row;}).filter(row=>row.text.trim());
}
function draftTextRow(line){return {text:typeof line==="string" ? line : line.text || "",row_type:line?.row_type,section:classifyTextSection(line),ids:Array.isArray(line?.source_line_ids) ? [...line.source_line_ids] : line?.id!==null && line?.id!==undefined ? [line.id] : []};}
function reconcileTextRows(previous,value){
  const next=plainTextRows(value),old=previous || [];let head=0,tail=0;
  const keepMeta=(nextRow,oldRow)=>Object.assign(nextRow,{ids:oldRow.ids || [],section:oldRow.section,row_type:oldRow.row_type,sectionPinned:oldRow.sectionPinned});
  while(head<old.length && head<next.length && old[head].text===next[head].text){keepMeta(next[head],old[head]);head++;}
  while(tail<old.length-head && tail<next.length-head && old[old.length-1-tail].text===next[next.length-1-tail].text){keepMeta(next[next.length-1-tail],old[old.length-1-tail]);tail++;}
  const prior=old.slice(head,old.length-tail),changed=next.slice(head,next.length-tail);
  // A single edited, merged or split row retains its photo evidence. Ambiguous multi-row replacements do not guess a location.
  if(prior.length===1 || changed.length===1){const ids=[...new Set(prior.flatMap(row=>row.ids || []))];changed.forEach(row=>{row.ids=ids;});}
  else for(const row of changed){const matches=prior.filter(item=>item.text===row.text);if(matches.length===1)row.ids=matches[0].ids || [];}
  const oldCounts=new Map(),newCounts=new Map();old.forEach(row=>oldCounts.set(row.text,(oldCounts.get(row.text)||0)+1));next.forEach(row=>newCounts.set(row.text,(newCounts.get(row.text)||0)+1));
  const ambiguous=new Set([...new Set([...oldCounts.keys(),...newCounts.keys()])].filter(text=>Math.max(oldCounts.get(text)||0,newCounts.get(text)||0)>1 && oldCounts.get(text)!==newCounts.get(text)));
  const ambiguousIds=new Set(old.filter(row=>ambiguous.has(row.text)).flatMap(row=>row.ids || []));
  next.forEach(row=>{if(ambiguous.has(row.text) || row.ids.some(id=>ambiguousIds.has(id)))row.ids=[];});
  return next;
}
function renderSectionEditors(kind,preserveSection=null){
  const context=textEditorContext(kind);if(!context)return;context.sectionRows={};
  const compact=context.textRows.map(row=>row.text.replace(/\s+/g,"")),hasNutritionContext=compact.some(nutritionHeader) || compact.filter(fullNutrientRow).length>=2;
  context.textRows.forEach(row=>{if(!row.sectionPinned || !textSectionLabels[row.section] || row.section==="full")row.section=classifyTextSection(row,hasNutritionContext);});
  for(const section of ["content","nutrition","uncertain"]){
    const items=context.textRows.map((row,index)=>({...row,canonicalIndex:index})).filter(row=>row.section===section),input=textEditorInput(kind,section);
    if(section!==preserveSection)input.value=items.map(row=>row.text).join("\n");
    context.sectionRows[section]=plainTextRows(input.value).map((row,index)=>({...row,ids:items[index]?.ids || [],canonicalIndex:items[index]?.canonicalIndex,section}));
    $("#"+kind+"-"+section+"-count").textContent=items.length ? `${items.length} 行` : "未帶入，可留空";
    if(section!==preserveSection)input.rows=Math.min(section==="nutrition" ? 14 : 9,Math.max(section==="uncertain" ? 3 : 4,items.length+1));
    if(section==="uncertain")$("#"+kind+"-uncertain-zone").hidden=!items.length && preserveSection!==section;
    if(section==="nutrition"){$("#"+kind+"-nutrition-zone").hidden=!items.length && preserveSection!==section;$("#"+kind+"-no-nutrition").hidden=!!items.length || preserveSection===section;$("#"+kind+"-add-nutrition").hidden=!!items.length || preserveSection===section;}
  }
}
function updateCanonicalText(kind,rows){
  const context=textEditorContext(kind);if(!context)return;const kept=rows.filter(row=>row.text.trim());
  textEditorInput(kind).value=kept.map(row=>row.text).join("\n");context.textRows=plainTextRows(textEditorInput(kind).value).map((row,index)=>({...row,ids:kept[index].ids || [],section:kept[index].section || classifyTextSection(kept[index]),row_type:kept[index].row_type,sectionPinned:kept[index].sectionPinned}));
}
function changeSectionEditor(kind,section){
  const context=textEditorContext(kind);if(!context || !["content","nutrition","uncertain"].includes(section))return;
  const prior=context.textRows || [],next=reconcileTextRows(prior.filter(row=>row.section===section),textEditorInput(kind,section).value).map(row=>({...row,section,sectionPinned:true}));
  const last=prior.map(row=>row.section).lastIndexOf(section),rows=[];let position=0;
  prior.forEach((row,index)=>{if(row.section!==section)rows.push(row);else{if(position<next.length)rows.push(next[position++]);if(index===last)rows.push(...next.slice(position));}});
  if(last<0)rows.push(...next);
  updateCanonicalText(kind,rows);context.activeTextSection=section;renderSectionEditors(kind,section);renderTextRowLocations(kind);
  if(kind==="manual")invalidateManualPreview();else invalidateStandardPreview();
}
function moveTextSelection(kind,target){
  const context=textEditorContext(kind),section="uncertain";if(state.busy || !context || (kind==="standard" && (context.conflict || context.operation!=="update")))return;
  const input=textEditorInput(kind,section),start=input.selectionStart ?? 0,end=input.selectionEnd ?? start,rows=section==="full" ? context.textRows.map((row,index)=>({...row,canonicalIndex:index})) : context.sectionRows?.[section] || [];
  const selected=rows.filter(row=>end>start ? row.end>=start && row.start<end : start>=row.start && start<=row.end);if(!selected.length)return;
  selected.forEach(row=>{context.textRows[row.canonicalIndex].section=target;context.textRows[row.canonicalIndex].sectionPinned=true;});renderSectionEditors(kind);renderTextRowLocations(kind);context.activeTextSection=target;
  const index=selected[0].canonicalIndex;focusTextEditorRow(kind,index);
}
function drawTextEditorPhoto(kind,ids=[]){
  const context=textEditorContext(kind);if(!context?.inspection?.image)return;const request=(context.photoRequest || 0)+1;context.photoRequest=request;
  const photo=context.draftScopeSelection ? {...context.inspection,ocr:{...context.inspection.ocr,label_scope:{status:"selected"},label_region:{...context.draftScopeSelection,method:"manual_draft",auto_selected:false}}} : context.inspection;
  drawEvidence($("#"+kind+"-photo-canvas"),{...photo,result:{checks:ids.length ? [{status:"review",line_ids:ids}] : []}},false,()=>textEditorContext(kind)===context && context.photoRequest===request);
  $("#"+kind+"-photo-note").textContent=ids.length ? "黃色框是所選文字在原照的位置，請對照全文修正。" : "點照片文字可定位編輯區；也可選文字行對照原圖。帶入文字仍需逐字確認。";
}
function drawManualDraftPhoto(lineId=null){drawTextEditorPhoto("manual",lineId===null ? [] : Array.isArray(lineId) ? lineId : [lineId]);}
function focusTextEditorRow(kind,index){
  const context=textEditorContext(kind),row=context?.textRows?.[index];if(!row)return;
  const section=row.section || "full",local=context.sectionRows?.[section]?.find(item=>item.canonicalIndex===index) || row,input=textEditorInput(kind,section);context.activeTextSection=section;
  input.focus({preventScroll:true});input.setSelectionRange?.(local.start,local.end);drawTextEditorPhoto(kind,row.ids);
  $("#"+kind+"-text-selection").textContent=`${textSectionLabels[section]} · 共 ${context.textRows.length} 行 · 已定位所選文字${row.ids.length ? "；黃色框可對照原圖。" : "；新增或重排內容沒有確定的原圖定位。"}`;
}
function textEditorSelection(kind,section="full"){
  const context=textEditorContext(kind);if(!context || state.busy)return;
  context.activeTextSection=section;const position=textEditorInput(kind,section).selectionStart ?? 0,rows=section==="full" ? context.textRows : context.sectionRows?.[section] || [],index=rows.findIndex(row=>position>=row.start && position<=row.end);
  if(index>=0){const row=rows[index];drawTextEditorPhoto(kind,row.ids);$("#"+kind+"-text-selection").textContent=`${textSectionLabels[section]} · 第 ${index+1} 行${row.ids.length ? " · 可對照原圖黃色框" : " · 請對照完整原圖"}`;}
}
function renderTextRowLocations(kind){
  const context=textEditorContext(kind);if(!context)return;
  const area=$(kind==="manual" ? "#manual-draft-fields" : "#standard-text-locations");area.replaceChildren();
  (context.textRows || []).forEach((row,index)=>{const button=element("button","text-row-location",`${index+1}. ${row.text}`);button.type="button";button.setAttribute("aria-label",`定位第 ${index+1} 行：${row.text}`);button.onclick=()=>focusTextEditorRow(kind,index);area.append(button);});
  $("#"+kind+"-text-selection").textContent=`共 ${context.textRows?.length || 0} 行 · 空白行不會儲存。點文字行可對照照片。`;
}
function changeTextEditor(kind){
  const context=textEditorContext(kind);if(!context)return;
  context.textRows=reconcileTextRows(context.textRows,textEditorInput(kind).value).map(row=>({...row,section:classifyTextSection(row),sectionPinned:false}));context.activeTextSection="full";renderSectionEditors(kind);renderTextRowLocations(kind);
  if(kind==="manual")invalidateManualPreview();else invalidateStandardPreview();
}
function editTextSelection(kind,operation,section="full"){
  const context=textEditorContext(kind);if(state.busy || !context || (kind==="standard" && (context.conflict || context.operation!=="update")))return;
  const input=textEditorInput(kind,section),text=input.value,start=input.selectionStart ?? 0,end=input.selectionEnd ?? start;
  const first=start>0 ? text.lastIndexOf("\n",start-1)+1 : 0,lastBreak=text.indexOf("\n",Math.max(start,end-1));
  let next,caret;
  if(operation==="delete"){const from=lastBreak<0 && first>0 ? first-1 : first,to=lastBreak<0 ? text.length : lastBreak+1;next=text.slice(0,from)+text.slice(to);caret=from;}
  else if(operation==="merge"){if(!first)return;next=text.slice(0,first-1)+" "+text.slice(first);caret=first;}
  else {next=text.slice(0,start)+"\n"+text.slice(start);caret=start+1;}
  input.value=next;if(section==="full")changeTextEditor(kind);else changeSectionEditor(kind,section);input.focus({preventScroll:true});input.setSelectionRange?.(caret,caret);textEditorSelection(kind,section);
}
function renderManualDraftFields(lines){
  const context=manualStandard;if(!context)return;const mapped=lines.map(draftTextRow);
  context.textRows=reconcileTextRows(mapped,$("#manual-standard-lines").value);context.activeTextSection="content";renderSectionEditors("manual");renderTextRowLocations("manual");
}
function syncManualCanonical(){changeTextEditor("manual");}
function manualBulkChanged(){changeTextEditor("manual");}
function textEditorPhotoClicked(kind,event){
  const context=textEditorContext(kind);if(state.busy || !context?.inspection?.image)return;
  const rect=$("#"+kind+"-photo-canvas").getBoundingClientRect(),x=(event.clientX-rect.left)/rect.width*context.inspection.image.width,y=(event.clientY-rect.top)/rect.height*context.inspection.image.height;
  const candidates=(context.inspection.ocr?.lines || []).filter(line=>Array.isArray(line.box) && line.box.length>=3).map(line=>{const xs=line.box.map(p=>p[0]),ys=line.box.map(p=>p[1]);return {line,left:Math.min(...xs),right:Math.max(...xs),top:Math.min(...ys),bottom:Math.max(...ys)};}).filter(item=>x>=item.left && x<=item.right && y>=item.top && y<=item.bottom).sort((a,b)=>(a.right-a.left)*(a.bottom-a.top)-(b.right-b.left)*(b.bottom-b.top));
  if(!candidates.length)return;const id=candidates[0].line.id,index=(context.textRows || []).findIndex(row=>row.ids.includes(id));
  if(index>=0)focusTextEditorRow(kind,index);
  else {drawTextEditorPhoto(kind,[id]);$("#"+kind+"-text-selection").textContent="已框選照片文字；目前編輯區沒有確定對應，請直接在全文補齊或修正。";}
}
function manualPhotoClicked(event){textEditorPhotoClicked("manual",event);}
function renderEquivalentReferences(items,inspectionId){
  const area=$("#manual-equivalent-references");area.replaceChildren();if(!Array.isArray(items) || !items.length)return;
  area.append(element("strong","","已有相同內容的標準"),element("p","help","若只是光線或拍攝角度不同，可附加照片至既有標準；不必重複建立。"));
  for(const item of items){if(!item?.code)continue;const button=element("button","button secondary",`附加到：${item.name || sourceCodeLabel(item)}`);button.type="button";button.onclick=()=>{if(state.busy)return;$("#manual-standard-dialog").close();manualStandard=null;openReferencePhoto(inspectionId,item.code);};area.append(button);}
}
async function openManualStandard(inspectionId=state.inspection?.id) {
  if(!requireAdmin())return;
  if(state.busy || !inspectionId)return;
  const context={inspectionId,preview:null};manualStandard=context;
  $("#manual-standard-form").reset();$("#manual-standard-form").hidden=true;invalidateManualPreview();setDialogError("#manual-standard-error");
  $("#manual-bulk-text").open=false;
  $("#manual-scope-undo").hidden=true;$("#manual-scope-note").textContent="框選只篩選這份草稿，不會重新辨識或刪除原照片。";
  $("#manual-standard-notice").textContent="讀取此張照片的參考文字…";$("#manual-standard-dialog").showModal();
  try {
    const data=await api(`/api/inspections/${encodeURIComponent(inspectionId)}/manual-standard`);
    if(manualStandard!==context)return;
    $("#manual-standard-notice").textContent=(data.notice || "請依正確資料逐字核對，辨識原文尚未核准。")+(data.draft_basis==="manual_correction" ? " 已帶入本筆確認為 OCR 讀錯的訂正文字；仍需逐字核准為正確標準。" : "")+(data.excluded_unconfirmed_lines?.length ? ` ${data.excluded_unconfirmed_lines.length} 行未確認內容未帶入，請對照照片確認；圖案或裝飾不需補入，實際印字才需補齊。` : "");
    if(data.manual_standard_eligibility?.eligible===false && data.manual_standard_eligibility.reason)$("#manual-standard-notice").textContent+=` ${data.manual_standard_eligibility.reason}`;
    if(!data.can_create){
      if(data.existing_code){const source=await api(`/api/source-labels/${encodeURIComponent(data.existing_code)}`);if(manualStandard!==context)return;if(state.inspection?.id!==inspectionId){const inspection=await api(`/api/inspections/${encodeURIComponent(inspectionId)}`);if(manualStandard!==context)return;state.inspection=inspection;state.manualView=true;state.resultDirty=false;restoreInspectionSettings(inspection);renderInspection(inspection);showView("inspect");}$("#manual-standard-dialog").close();manualStandard=null;selectInspectSource(source);loadPendingStandards(1);toast("這張照片已建立過文字標準，請重新核對套用。");}
      return;
    }
    $("#manual-standard-form").hidden=false;
    $("#manual-standard-name").value=data.suggested_name || "";$("#manual-standard-sku").value=data.suggested_sku || "";
    $("#manual-standard-lines").value=(data.draft_lines || []).map(line=>typeof line === "string" ? line : line.text).join("\n");
    $("#manual-standard-reviewer").value=sessionStorage.getItem("labelcheck-operator") || "";
    if(!$("#manual-standard-note").value.trim())$("#manual-standard-note").value="依照片核對文字，建立比對標準";
    context.draftLines=(data.draft_lines || []).map(line=>typeof line==="string" ? {text:line,id:null} : line);context.rawLines=data.ocr_lines || state.inspection?.ocr?.lines || [];
    context.inspection=state.inspection?.id===inspectionId ? state.inspection : await api(`/api/inspections/${encodeURIComponent(inspectionId)}`);if(manualStandard!==context)return;
    $("#manual-photo-link").href=context.inspection.image?.url || "";renderManualDraftFields(context.draftLines);drawManualDraftPhoto();renderEquivalentReferences(data.equivalent_references,inspectionId);
  } catch(error){if(manualStandard===context)setDialogError("#manual-standard-error",error.message);}
}
function manualStandardBody() {
  if(!$("#manual-standard-lines").value.trim()){$("#manual-content-text").focus();setDialogError("#manual-standard-error","請至少保留一行正確標籤文字。");return null;}
  const form=$("#manual-standard-form");if(!form.reportValidity())return null;
  const lines=$("#manual-standard-lines").value.split(/\r?\n/).map(text=>text.trim()).filter(Boolean).map(text=>({text}));
  if(lines.length>150){setDialogError("#manual-standard-error","標準文字最多 150 行，請合併同一列內容後再預覽。");return null;}
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
    renderNutritionPreview(preview,data.nutrition_checks);
    renderEquivalentReferences(data.equivalent_references,context.inspectionId);
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
  if(saved && allowed()){
    if(state.inspection?.id!==context.inspectionId && context.inspection){state.inspection=context.inspection;state.manualView=true;state.resultDirty=false;restoreInspectionSettings(context.inspection);showView("inspect");}
    selectInspectSource(saved.source || saved);standardSavedNotice();loadManualLibrary(1);loadPendingStandards(1);let linked=false,errorMessage="";setBusy(true);
    try{const reference=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/reference-photo?source_code=${encodeURIComponent(saved.code)}`);if(!reference.source_revision || !Number.isInteger(reference.base_revision))throw new Error("無法取得參考照關聯版本。");await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/reference-photo`,{method:"POST",body:{source_code:saved.code,source_revision:reference.source_revision,base_revision:reference.base_revision,reviewer,note,confirmed:true}});linked=true;}
    catch(error){errorMessage=error.message;}finally{setBusy(false);}
    if(!allowed())return;
    const feedback=element("p",linked ? "help" : "upload-error",linked ? "文字標準與這張參考照已儲存；請重新核對本張照片。" : `文字標準已儲存，但參考照尚未附加：${errorMessage}`);feedback.id="standard-photo-feedback";$("#result-area").append(feedback);
    if(!linked){const retry=element("button","button secondary","補掛這張參考照");retry.type="button";retry.onclick=()=>openReferencePhoto(context.inspectionId,saved.code);$("#result-area").append(retry);}toast(linked ? "文字標準及參考照已儲存。" : "標準已儲存，參考照可稍後補掛。",!linked);
  }
}
async function openReferencePhoto(inspectionId=state.inspection?.id,sourceCode=""){
  if(!requireAdmin() || state.busy || !inspectionId)return;
  const context={inspectionId,sourceCode,data:null};state.referencePhoto=context;$("#reference-photo-form").reset();$("#reference-photo-form").hidden=true;$("#reference-photo-list").replaceChildren();$("#reference-photo-image").removeAttribute("src");$("#reference-photo-source").textContent="讀取比對標準…";setDialogError("#reference-photo-error");$("#reference-photo-dialog").showModal();
  try{
    const data=await api(`/api/inspections/${encodeURIComponent(inspectionId)}/reference-photo${sourceCode ? `?source_code=${encodeURIComponent(sourceCode)}` : ""}`);if(state.referencePhoto!==context)return;
    context.data=data;context.sourceCode=data.source_code || data.source?.code;
    if(!context.sourceCode || !data.source_revision){$("#reference-photo-source").textContent=data.notice || "請先選定一份人工、系統或清單標準，再附加參考照片。";return;}
    $("#reference-photo-source").textContent=`附加至：${data.source?.name || context.sourceCode} · ${data.base_revision ? `比對標準第 ${data.base_revision} 版` : "原始標準"}`;
    const inspection=state.inspection?.id===inspectionId ? state.inspection : await api(`/api/inspections/${encodeURIComponent(inspectionId)}`);if(state.referencePhoto!==context)return;
    $("#reference-photo-image").src=inspection.image.url;$("#reference-photo-form").hidden=false;$("#reference-photo-reviewer").value=sessionStorage.getItem("labelcheck-operator") || "";
    const photos=data.linked_photos || {};$("#reference-photo-count").textContent=`目前已有 ${photos.total ?? photos.items?.length ?? 0} 張參考照片`;
    for(const item of photos.items || []){if(!item.image?.thumbnail)continue;const image=element("img");image.src=item.image.thumbnail;image.alt=item.stale ? "較早版本的參考照片，仍需依目前標準核對" : "既有參考照片";image.loading="lazy";$("#reference-photo-list").append(image);}
    if((photos.items || []).some(item=>item.stale))$("#reference-photo-count").textContent+="；部分照片屬較早版本，仍需依目前標準核對。";
  }catch(error){if(state.referencePhoto===context)setDialogError("#reference-photo-error",error.message);}
}
async function saveReferencePhoto(event){
  event.preventDefault();const context=state.referencePhoto;if(!requireAdmin() || state.busy || !context?.data?.source_revision)return;
  const reviewer=$("#reference-photo-reviewer").value.trim(),note=$("#reference-photo-note").value.trim();if(!reviewer || !note || !$("#reference-photo-confirm").checked){setDialogError("#reference-photo-error","請填寫人員、原因，並確認照片屬於同一份標準內容。");return;}
  setBusy(true);$$("#reference-photo-dialog button").forEach(node=>{node.disabled=true;});setDialogError("#reference-photo-error");
  try{const saved=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/reference-photo`,{method:"POST",body:{source_code:context.sourceCode,source_revision:context.data.source_revision,base_revision:context.data.base_revision,reviewer,note,confirmed:true}});if(state.referencePhoto!==context)return;sessionStorage.setItem("labelcheck-operator",reviewer);$("#reference-photo-dialog").close();state.referencePhoto=null;toast(saved.created===false ? "這張照片已附加，沒有重複建立。" : "已附加參考照片；標準文字與日期規則未變更。");await loadPendingStandards(1);}
  catch(error){if(state.referencePhoto===context)setDialogError("#reference-photo-error",`${error.message}${error.status===409 ? " 請重新開啟以核對最新標準。" : ""}`);}
  finally{setBusy(false);$$("#reference-photo-dialog button").forEach(node=>{node.disabled=false;});}
}
function invalidateStandardPreview() {
  if (!state.standardEdit) return;
  state.standardEdit.preview = null;
  state.standardEdit.previewNonce=(state.standardEdit.previewNonce || 0)+1;
  $("#standard-edit-preview").hidden=true;$("#standard-edit-confirm-label").hidden=true;$("#standard-edit-save").hidden=true;$("#standard-edit-confirm").checked=false;
}
function standardEditorRows(source,inspection,allowMapped=true){
  const raw=inspection?.ocr?.lines || [],checks=(inspection?.manual_revision?.result || inspection?.result)?.checks || [];
  return (source.lines || []).map(line=>{
    let ids=allowMapped ? [...new Set(checks.filter(check=>(check.source_line_ids || []).some(id=>String(id)===String(line.id))).flatMap(check=>check.line_ids || []))].filter(id=>raw.some(item=>item.id===id)) : [];
    if(!ids.length){const matches=raw.filter(item=>item.text?.trim()===line.text?.trim());if(matches.length===1)ids=[matches[0].id];}
    return {text:line.text || "",ids,section:classifyTextSection(line),row_type:line.row_type};
  });
}
function standardDraftOptions(context=state.standardEdit){
  if(!context?.textMode || context.operation!=="update")return {};
  return {...(context.draftMode==="latest" ? {draft_manual_revision:context.data.regrouped_manual_revision} : {}),use_inspection_photo:!!$("#standard-use-photo").checked};
}
function updateStandardDraftControls(){
  const context=state.standardEdit;if(!context?.textMode)return;const latest=context.draftMode==="latest",locked=state.busy || context.operation!=="update" || context.conflict;
  $("#standard-draft-latest").setAttribute("aria-pressed",String(latest));$("#standard-draft-current").setAttribute("aria-pressed",String(!latest));$("#standard-draft-latest").disabled=locked || !context.canUseLatest;$("#standard-draft-current").disabled=locked;$("#standard-use-photo").disabled=locked || !context.inspection?.image?.url;
  $("#standard-photo-option").hidden=context.operation!=="update";
  const dates=context.data.regrouped_excluded_date_lines?.length || 0,unconfirmed=context.data.regrouped_excluded_unconfirmed_lines?.length || 0,barcodes=context.data.regrouped_excluded_barcode_lines?.length || 0;
  $("#standard-draft-status").textContent=latest ? `目前編輯本次辨識草稿${context.data.regrouped_manual_revision ? "（含已確認的辨識訂正）" : ""}，尚未核准。${dates ? `已略過 ${dates} 行本批日期。` : ""}${unconfirmed ? `另有 ${unconfirmed} 行未確認內容未帶入，請對照照片確認；圖案或裝飾不需補入，實際印字才需補齊。` : ""}${barcodes ? "本批條碼可能含批次資料，未自動寫入固定文字；仍照常檢查條碼格式。" : ""}保存天數與日期規則沿用現行標準；未讀到的舊文字不會自動補回，請確認完整內容。` : `目前編輯已核准的現行標準。${context.canUseLatest ? "可切回本次辨識草稿，兩邊的未存文字各自保留。" : `${context.data.regrouped_eligibility?.reason || "本次沒有可安全帶入的辨識草稿"}；請對照照片手動修正，或重新辨識。`}`;
  $("#standard-editor-intro").textContent=latest ? "本次辨識文字已自動分區帶入。只需對照照片修正錯處，預覽後確認存成同一份標準的新版。" : "現行核准文字已分區帶入。修改後先預覽差異，再確認更新同一份標準。";
}
function selectStandardDraft(mode,replacement=null,initial=false){
  const context=state.standardEdit;if(!requireAdmin() || state.busy || !context?.textMode || context.operation!=="update" || context.conflict || !["latest","current"].includes(mode) || (mode==="latest" && !context.canUseLatest))return;
  context.textDrafts ||= {};context.photoChoices ||= {latest:true,current:false};
  if(context.draftMode){context.textDrafts[context.draftMode]={text:$("#standard-edit-text").value,rows:JSON.parse(JSON.stringify(context.textRows || []))};context.photoChoices[context.draftMode]=$("#standard-use-photo").checked;}
  if(replacement)context.textDrafts[mode]={text:replacement.map(row=>row.text).join("\n"),rows:JSON.parse(JSON.stringify(replacement))};
  const draft=context.textDrafts[mode];if(!draft)return;context.draftMode=mode;$("#standard-edit-text").value=draft.text;context.textRows=JSON.parse(JSON.stringify(draft.rows));context.activeTextSection="content";$("#standard-use-photo").checked=!!context.photoChoices[mode] && !!context.inspection?.image?.url;
  renderSectionEditors("standard");renderTextRowLocations("standard");invalidateStandardPreview();context.regroupPreview=null;$("#standard-regroup-preview").hidden=true;drawTextEditorPhoto("standard");updateStandardDraftControls();
  if(!initial)$("#standard-text-selection").textContent=mode==="latest" ? "已切到本次辨識草稿；文字尚未核准，請預覽後確認儲存。" : "已切到現行標準；本次草稿的未存修改仍保留。";
}
function previewRegroupedStandard(){
  const context=state.standardEdit;if(state.busy || !requireAdmin() || !context?.textMode || !context.canUseLatest || context.operation!=="update" || context.conflict)return;
  const rows=(context.data.regrouped_draft_lines || []).map(draftTextRow);if(!rows.length)return;
  const dates=context.data.regrouped_excluded_date_lines?.length || 0,unconfirmed=context.data.regrouped_excluded_unconfirmed_lines?.length || 0,barcodes=context.data.regrouped_excluded_barcode_lines?.length || 0;
  $("#standard-regroup-notice").textContent=`共 ${rows.length} 行。${dates ? `已略過 ${dates} 行本批日期，日期請另外設定規則。` : ""}${unconfirmed ? `另有 ${unconfirmed} 行未確認內容未帶入，請對照照片確認；圖案或裝飾不需補入，實際印字才需補齊。` : ""}${barcodes ? "本批條碼可能含批次資料，未自動寫入固定文字。" : ""}`;
  context.regroupPreview=rows;$("#standard-regroup-text").textContent=rows.map(row=>row.text).join("\n");$("#standard-regroup-preview").hidden=false;
  $("#standard-regroup-preview").scrollIntoView({block:"nearest",behavior:"instant"});
}
function applyRegroupedStandard(){
  const context=state.standardEdit;if(state.busy || !requireAdmin() || !context?.regroupPreview || context.operation!=="update" || context.conflict)return;
  const rows=context.regroupPreview;selectStandardDraft("latest",rows);
  if(!$("#standard-edit-note").value.trim())$("#standard-edit-note").value="依本次照片重新整理完整文字列";
  focusTextEditorRow("standard",0);$("#standard-text-selection").textContent="已分區帶入本次照片草稿，尚未儲存。只需修正錯處，再預覽修改差異。";
}
async function openStandardEditor(inspectionId = state.inspection?.id, focusLineIds = []) {
  if(!requireAdmin())return;
  if (state.busy || !inspectionId) return;
  $("#standard-edit-title").textContent="更新比對標準";
  state.standardEdit={inspectionId,loading:true,operation:"update",focusLineIds:Array.isArray(focusLineIds) ? focusLineIds.map(String) : []};
  $$("#standard-edit-dialog button").forEach(button=>{button.disabled=false;});
  $("#standard-edit-form").reset();$("#standard-edit-form").hidden=true;$("#standard-edit-photo-template").hidden=true;$("#standard-edit-reload").hidden=true;$("#standard-edit-reset").hidden=true;$("#standard-edit-operation").hidden=true;$("#standard-text-workspace").hidden=true;$("#standard-regroup-preview").hidden=true;$("#standard-text-selection").textContent="";
  $("#standard-full-text").open=false;$("#standard-draft-choice").hidden=true;$("#standard-use-photo").checked=false;
  $("#standard-edit-source").textContent="載入比對標準中…";$("#standard-edit-notice").textContent="";$("#standard-edit-history-list").replaceChildren();$("#standard-edit-history").hidden=true;setDialogError("#standard-edit-error");invalidateStandardPreview();
  if (!$("#standard-edit-dialog").open) $("#standard-edit-dialog").showModal();
  const context=state.standardEdit;
  try {
    const data=await api(`/api/inspections/${encodeURIComponent(inspectionId)}/standard`);
    if (state.standardEdit !== context) return;
    Object.assign(context,{data,loading:false,lineControls:[],dateControls:[],conflict:false});
    $("#standard-edit-title").textContent=data.kind==="catalog" && !(data.source?.web_text_approved || data.source?.comparison_scope==="approved_text") ? "建立完整標準" : "更新比對標準";
    $("#standard-edit-source").textContent=`${data.kind === "manual" ? "人工文字標準" : data.kind === "catalog" ? "清單" : data.kind === "photo_template" ? "照片標準" : "系統標籤"} ${sourceCodeLabel(data)} · ${data.name || data.source?.name || "未指定"} · ${data.base_revision ? `比對標準第 ${data.base_revision} 版` : "原始來源"}`;
    $("#standard-edit-notice").textContent=`${data.stale ? "來源資料已更新，請重新核對目前內容。 " : ""}${data.notice || ""}`;
    const history=$("#standard-edit-history-list");
    for(const item of data.history || []){
      const row=element("div","review-record");row.append(element("strong","",`第 ${item.revision} 版 · ${item.operation === "reset" ? "恢復原始來源" : item.operation === "restore" ? "還原歷史版本" : "修改比對標準"}`),element("p","help",item.note || ""),element("small","",`${item.reviewer || ""} · ${when(item.created_at)}`));
      if(data.editable && data.supports_history_restore!==false){const restore=element("button","button secondary","還原此版");restore.type="button";restore.dataset.standardRestore=String(item.revision);restore.setAttribute("aria-label",`還原比對標準第 ${item.revision} 版`);restore.disabled=!!data.stale || item.source_revision!==data.source_revision || item.revision===data.base_revision;restore.onclick=()=>selectStandardOperation("restore",item.revision);row.append(restore);if(restore.disabled)row.append(element("small","",item.revision===data.base_revision ? "目前版本" : "原始來源已變更，這版無法直接還原。"));}
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
    const source=data.source || {};$("#standard-edit-form").hidden=false;$("#standard-edit-reset").hidden=data.supports_history_restore===false;$("#standard-edit-reset").disabled=!data.base_revision;
    $("#standard-edit-name").value=source.name || "";$("#standard-edit-days").value=source.keep_days ?? "";$("#standard-edit-reviewer").value=sessionStorage.getItem("labelcheck-operator") || "";
    if(!$("#standard-edit-note").value.trim())$("#standard-edit-note").value="核對正確資料，更新比對標準";
    context.textMode=data.supports_line_replacement===true;
    const lines=$("#standard-edit-line-fields");lines.replaceChildren();
    if(context.textMode){
      context.inspection=state.inspection?.id===inspectionId ? state.inspection : await api(`/api/inspections/${encodeURIComponent(inspectionId)}`);if(state.standardEdit!==context)return;
      $("#standard-text-workspace").hidden=false;$("#standard-draft-choice").hidden=false;
      const currentRows=standardEditorRows(source,context.inspection,!data.focus_ids_stale),latestRows=(data.regrouped_draft_lines || []).map(draftTextRow);
      context.canUseLatest=data.regrouped_can_apply===true && latestRows.length>0 && Number.isInteger(data.regrouped_manual_revision) && (!data.regrouped_inspection_id || data.regrouped_inspection_id===inspectionId);
      context.currentTextRows=currentRows;context.textDrafts={current:{text:currentRows.map(row=>row.text).join("\n"),rows:currentRows},latest:{text:latestRows.map(row=>row.text).join("\n"),rows:latestRows}};context.photoChoices={latest:true,current:false};
      $("#standard-photo-link").href=context.inspection.image?.url || "";selectStandardDraft(context.canUseLatest && !context.focusLineIds.length ? "latest" : "current",null,true);
      $("#standard-regroup-button").hidden=!context.canUseLatest;
      if(context.draftMode==="latest")$("#standard-edit-note").value="依本次照片核對完整文字，更新原標準";
    }else (source.lines || []).forEach((line,index)=>{
      const title=`第 ${index+1} 段標準文字`,label=element("label","",title),input=element("textarea");input.rows=2;input.maxLength=2000;input.value=line.text || "";input.dataset.standardLine=String(line.id);label.append(input);lines.append(label);context.lineControls.push({line,input,label,title});
    });
    $("#standard-edit-lines").hidden=!context.lineControls.length;$("#standard-edit-lines").open=false;
    const dates=$("#standard-edit-date-fields");dates.replaceChildren();
    (source.date_settings || []).forEach((setting,index)=>{const label=element("label","",`${setting.content || `日期欄 ${index+1}`}：${source.source_kind==="desktop" ? "既有日期規則位移天數" : "相對基準日位移天數"}`),input=element("input");input.type="number";input.step="1";input.min="-3650";input.max="3650";input.required=true;input.value=setting.shift_days ?? 0;label.append(input);dates.append(label);context.dateControls.push({index,setting,input});});
    $("#standard-edit-dates").hidden=!context.dateControls.length;$("#standard-edit-dates").open=false;
    lockStandardContent(false);
    if(context.focusLineIds.length && data.focus_ids_stale){
      $("#standard-edit-notice").textContent+=" 標準已更新，原先異常的定位可能已改變，請重新選擇文字。";
    }else if(context.focusLineIds.length){
      if(context.textMode){
        let index=(source.lines || []).findIndex(line=>context.focusLineIds.includes(String(line.id)));
        if(context.draftMode==="latest"){const evidence=new Set((source.lines || []).flatMap((line,i)=>context.focusLineIds.includes(String(line.id)) ? context.currentTextRows[i]?.ids || [] : []));index=context.textRows.findIndex(row=>(row.ids || []).some(id=>evidence.has(id)));}
        if(index>=0){focusTextEditorRow("standard",index);$("#standard-edit-notice").textContent+=` 已選取本次照片對應的第 ${index+1} 行，請核對內容。`;}
        else $("#standard-edit-notice").textContent+=" 原先異常沒有確定對應到目前草稿，請直接核對完整文字；不按舊行號猜測位置。";
      }else{
      const matched=context.lineControls.filter(item=>context.focusLineIds.includes(String(item.line.id)));
      if(matched.length){
        $("#standard-edit-lines").open=true;matched.forEach(item=>{item.label.className="standard-target-line";item.input.setAttribute("aria-description","這是所選異常對應的標準文字。");});
        $("#standard-edit-notice").textContent+=` 已定位 ${matched.map(item=>item.title).join("、")}，請確認這些標準文字是否正確。`;
        matched[0].input.focus({preventScroll:true});matched[0].label.scrollIntoView({block:"center",behavior:"instant"});
      }else setDialogError("#standard-edit-error","目前標準已變更，找不到原先對應的文字段落。請核對上方來源，並重新選擇要修正的內容。");
      }
    }
  } catch(error){if(state.standardEdit===context){context.loading=false;setDialogError("#standard-edit-error",error.message);$("#standard-edit-reload").hidden=false;}}
}
function lockStandardContent(locked) {
  $("#standard-edit-name").disabled=locked;$("#standard-edit-days").disabled=locked;
  $("#standard-edit-text").disabled=locked;
  for(const section of ["content","nutrition","uncertain"])textEditorInput("standard",section).disabled=locked;
  for(const id of ["standard-move-content","standard-move-nutrition","standard-add-nutrition"])$("#"+id).disabled=locked || !!state.standardEdit?.conflict;
  for(const id of ["standard-text-delete","standard-text-merge","standard-text-split","standard-regroup-button","standard-regroup-apply"])$("#"+id).disabled=locked || !!state.standardEdit?.conflict;
  for(const item of state.standardEdit?.lineControls || [])item.input.disabled=locked;
  for(const item of state.standardEdit?.dateControls || [])item.input.disabled=locked;
  updateStandardDraftControls();
}
function standardOperationDifferences(before, after, operation, revision) {
  const changes=[{label:"還原操作",before:"目前網站比對標準",after:operation==="reset" ? "恢復目前原始來源；保留先前修改紀錄。" : `採用第 ${revision} 版內容，另建立新版；保留先前修改紀錄。`}];
  function compare(label,oldValue,newValue){if(JSON.stringify(oldValue ?? null)!==JSON.stringify(newValue ?? null))changes.push({label,before:oldValue ?? "未設定",after:newValue ?? "未設定"});}
  compare("標準品名",before.name,after.name);compare("保存天數",before.keep_days,after.keep_days);
  if((before.reference_image_id || null)!==(after.reference_image_id || null))changes.push({label:"目前標準照片",before:"目前顯示的標準照片",after:after.reference_image_id ? "改用此版本指定的標準照片；舊照片仍保留。" : "恢復建立標準時的參考照片；之後附加的照片仍保留。"});
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
  Object.assign(state.standardEdit,{operation:"update",targetRevision:undefined,targetSource:null,targetNutrition:null});
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
    Object.assign(context,{operation,targetRevision:operation==="restore" ? targetRevision : undefined,targetSource:data.source,targetNutrition:data.nutrition_checks});
    selected=true;
    lockStandardContent(true);$("#standard-edit-operation").hidden=false;
    $("#standard-edit-operation-note").textContent=`${operation==="reset" ? "準備恢復目前原始來源" : `準備還原第 ${targetRevision} 版`}。欄位暫停編輯，尚未儲存；請核對下方差異，填寫人員及原因後確認。`;
  } catch(error){if(error.status===409){context.conflict=true;$("#standard-edit-reload").hidden=false;}setDialogError("#standard-edit-error",error.message);}
  finally {setBusy(false);$$("#standard-edit-dialog button").forEach(button=>{button.disabled=false;});lockStandardContent(context.operation!=="update");$("#standard-edit-save").disabled=!!context.conflict;restoreStandardOperationButtons();}
  if(selected && !context.conflict){previewStandardChanges();$("#standard-edit-preview").scrollIntoView({block:"center",behavior:"instant"});}
}
function standardPreviewSignature(collected) {
  const context=state.standardEdit;
  return JSON.stringify({operation:context.operation || "update",target_revision:context.targetRevision,changes:collected.changes,preview:collected.preview,draftMode:context.draftMode,...standardDraftOptions(context)});
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
  if(context.textMode){
    const rows=plainTextRows($("#standard-edit-text").value).map(row=>({text:row.text.trim()}));
    if(!rows.length || rows.length>150){setDialogError("#standard-edit-error","請保留 1 至 150 行正確標準文字；空白行不會儲存。");$("#standard-content-text").focus();return null;}
    const before=(source.lines || []).map(line=>line.text || "").join("\n"),after=rows.map(line=>line.text).join("\n");
    if(before!==after){changes.replace_lines=rows;preview.push({label:`標準全文（修改後 ${rows.length} 行；空白行不保留）`,before,after});}
  }else{
    const lines=[];
    for(const {line,input,title} of context.lineControls){if(input.value !== line.text){lines.push({id:line.id,text:input.value});preview.push({label:title,before:line.text,after:input.value.trim() ? input.value : "（刪除此段文字）"});}}
    if(lines.length)changes.lines=lines;
  }
  const dates=[];
  for(const {index,setting,input} of context.dateControls){if(!input.checkValidity()){ $("#standard-edit-dates").open=true;input.reportValidity();return null;}const value=Number(input.value);if(value !== Number(setting.shift_days ?? 0)){dates.push({index,shift_days:value});preview.push({label:`${setting.content || `日期欄 ${index+1}`} 位移天數`,before:setting.shift_days ?? 0,after:value});}}
  if(dates.length)changes.date_settings=dates;
  if(standardDraftOptions(context).use_inspection_photo)preview.push({label:"目前標準照片",before:"現行標準照片（將保留）",after:"改用本次檢查照片，舊照片仍保留"});
  return {changes,preview};
}
function appendStandardPhotoPreview(area,context){
  if(!standardDraftOptions(context).use_inspection_photo)return;
  const photos=element("div","standard-photo-comparison");
  for(const [label,photo] of [["目前標準照片（保留）",context.data.current_reference_image],["本次照片（儲存後設為目前照片）",context.inspection?.image]]){const figure=element("figure");figure.append(element("figcaption","",label));if(photo?.url){const image=element("img");image.src=photo.thumbnail || photo.url;image.alt=label;figure.append(image);}else figure.append(element("p","help","尚無可讀取的照片"));photos.append(figure);}area.append(photos);
}
function previewStandardChanges() {
  if(!requireAdmin())return;
  if(state.busy || state.standardEdit?.previewLoading)return;
  setDialogError("#standard-edit-error");const collected=collectStandardChanges();if(!collected)return;
  if(!collected.preview.length){invalidateStandardPreview();setDialogError("#standard-edit-error","目前沒有修改內容。");return;}
  invalidateStandardPreview();const context=state.standardEdit,nonce=context.previewNonce,signature=standardPreviewSignature(collected);
  const area=$("#standard-edit-preview");area.replaceChildren(element("h3","","請核對修改前後差異"));if(context.draftMode==="latest" && context.operation==="update")area.append(element("p","note","這次會以本次草稿完整取代原標準固定文字；未帶入的舊文字也會移除。請對照照片確認沒有漏字、漏欄，日期規則另外保留。"));
  appendStandardPhotoPreview(area,context);
  collected.preview.forEach(item=>{const row=element("div","standard-preview-row");row.append(element("strong","",item.label),element("p","before",`修改前：${item.before ?? "未設定"}`),element("p","after",`修改後：${item.after}`));area.append(row);});
  const finish=checks=>{if(state.standardEdit!==context || context.previewNonce!==nonce)return;renderNutritionPreview(area,checks);context.preview=signature;area.hidden=false;$("#standard-edit-confirm").checked=false;$("#standard-edit-confirm-label").hidden=false;$("#standard-edit-save").hidden=false;};
  if(!context.textMode || context.operation!=="update"){finish(context.operation!=="update" ? context.targetNutrition : null);return;}
  context.previewLoading=true;$("#standard-edit-preview-button").disabled=true;$("#standard-edit-preview-button").textContent="檢查草稿中…";
  return api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/standard/preview`,{method:"POST",body:{base_revision:context.data.base_revision,source_revision:context.data.source_revision,changes:collected.changes,...standardDraftOptions(context)}}).then(data=>{
    if(state.standardEdit!==context || context.previewNonce!==nonce)return;
    if(data.base_revision!==context.data.base_revision || data.source_revision!==context.data.source_revision){const error=new Error("標準已更新，請重新載入最新標準後確認。");error.status=409;throw error;}
    if(data.use_inspection_photo!==undefined && data.use_inspection_photo!==standardDraftOptions(context).use_inspection_photo)throw new Error("照片更新選項已變更，請重新預覽。");
    if(data.source?.name && data.source.name!==$("#standard-edit-name").value.trim()){const nameRow=element("div","standard-preview-row");nameRow.append(element("strong","","文字中的品名會同步更新"),element("p","before",`目前標準品名：${context.data.source.name}`),element("p","after",`實際儲存品名：${data.source.name}`));area.append(nameRow);}
    if(data.source?.lines){const actual=element("details");actual.append(element("summary","","查看實際將儲存的完整標準文字"),element("pre","standard-full-text",data.source.lines.map(line=>line.text || "").join("\n")));area.append(actual);}
    finish(data.nutrition_checks);
  }).catch(error=>{if(state.standardEdit!==context || context.previewNonce!==nonce)return;if(error.status===409){context.conflict=true;$("#standard-edit-reload").hidden=false;}setDialogError("#standard-edit-error",`${error.message}${error.status===409 ? " 你的編輯仍保留，這次尚未儲存。" : ""}`);}).finally(()=>{context.previewLoading=false;if(state.standardEdit===context){$("#standard-edit-preview-button").disabled=false;$("#standard-edit-preview-button").textContent="預覽修改差異";}});
}
function renderNutritionPreview(area,checks){
  if(!Array.isArray(checks) || !checks.length)return;
  const block=element("section","nutrition-preview"),issues=checks.filter(check=>check.status!=="pass"),passed=checks.filter(check=>check.status==="pass");block.append(element("h3","",issues.length ? `營養數值提醒 · ${issues.length} 項` : "營養數值邏輯"));
  const rowFor=check=>{const row=element("div",`logic-check ${check.status}`);row.append(badge(check.status,check.status==="pass" ? "✓ 相符" : check.status==="fail" ? "✕ 有差異" : "? 需確認"),element("strong","",check.label || "營養檢查"));if(check.reason)row.append(element("p","help",check.reason));if(check.actual)row.append(element("p","",`讀到：${check.actual}`));if(check.expected)row.append(element("p","help",`依據：${check.expected}`));return row;};
  issues.forEach(check=>block.append(rowFor(check)));
  if(passed.length){const details=element("details");details.append(element("summary","",`查看 ${passed.length} 項邏輯相符檢查`));passed.forEach(check=>details.append(rowFor(check)));block.append(details);}
  block.append(element("p","help","數值邏輯檢查僅協助發現疑點，不能代替照片校對或確認營養標示正確。"));area.append(block);
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
    const body={base_revision:context.data.base_revision,source_revision:context.data.source_revision,changes:collected.changes,reviewer,note,confirmed:true,operation:context.operation || "update",...standardDraftOptions(context)};
    if(body.operation==="restore")body.target_revision=context.targetRevision;
    const saved=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/standard`,{method:"POST",body});
    if(context.data.kind==="photo_template" || context.data.kind==="photo"){const templateId=saved.photo_template_id || saved.template?.id;if(templateId){state.inspectSource=null;renderInspectSource();try{await loadTemplates(templateId);}catch(error){toast("新版照片標準已儲存，請重新整理頁面後選用新版。",true);}}}
    sessionStorage.setItem("labelcheck-operator",reviewer);$("#standard-edit-dialog").close();
    if(state.inspection?.id===context.inspectionId)standardSavedNotice();
    toast(body.use_inspection_photo ? "新版文字與目前標準照片已一併更新，舊照片保留；可重新核對本張。" : "新版比對標準已儲存，之後同款會套用；這張照片可再按「重新核對」。");
    if(context.textMode)loadManualLibrary(1);
  } catch(error){
    if(error.status===409){context.conflict=true;$("#standard-edit-reload").hidden=false;setDialogError("#standard-edit-error",`${error.message} 你的輸入仍保留；請先複製需要的文字，再重新載入最新資料核對，這次尚未儲存。`);}
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
function selectedLabelRegion(inspection){
  if(["no_clear_sticker","multiple","full"].includes(inspection?.ocr?.label_scope?.status))return null;
  const region=inspection?.ocr?.label_region,width=Number(inspection?.image?.width),height=Number(inspection?.image?.height);
  if(!region || !["x","y","width","height"].every(key=>Number.isFinite(region[key])) || region.x<0 || region.y<0 || region.width<=0 || region.height<=0 || (width>0 && region.x+region.width>width+1) || (height>0 && region.y+region.height>height+1))return null;
  return region;
}
function drawEvidence(canvas, inspection, focusRegion=false,stillCurrent=null) {
  const image = new Image(); image.onload = () => {
    if(stillCurrent && !stillCurrent())return;
    const region=selectedLabelRegion(inspection),crop=focusRegion && region ? region : {x:0,y:0,width:image.naturalWidth,height:image.naturalHeight},scale=Math.min(1,1400/crop.width);
    canvas.width = Math.max(1,Math.round(crop.width*scale)); canvas.height = Math.max(1,Math.round(crop.height*scale));
    const ctx = canvas.getContext("2d");if(!ctx)return;ctx.drawImage(image,crop.x,crop.y,crop.width,crop.height,0,0,canvas.width,canvas.height);
    if(region){ctx.strokeStyle="#237b50";ctx.lineWidth=3;ctx.strokeRect((region.x-crop.x)*scale,(region.y-crop.y)*scale,region.width*scale,region.height*scale);}
    const ids = new Map(); inspection.result.checks.forEach(c => { if (["fail", "review"].includes(c.status)) (c.line_ids || []).forEach(id => { if (ids.get(id) !== "fail") ids.set(id, c.status); }); });
    for (const line of inspection.ocr.lines) {
      if (!ids.has(line.id)) continue;
      if(!Array.isArray(line.box) || line.box.length<3)continue;
      ctx.strokeStyle = ids.get(line.id) === "fail" ? "#c84232" : "#cc981e"; ctx.lineWidth = Math.max(2, canvas.width / 300);
      ctx.beginPath(); line.box.forEach(([x, y], i) => i ? ctx.lineTo((x-crop.x)*scale, (y-crop.y)*scale) : ctx.moveTo((x-crop.x)*scale, (y-crop.y)*scale)); ctx.closePath(); ctx.stroke();
    }
  }; image.src = inspection.image.url;
}
function buildResultRows(checks, ocrLines) {
  const rank = {fail:0,review:1,pass:2,read:3}, sources = new Map(), rows = new Map();
  ocrLines.forEach(line => sources.set(line.id, line));
  checks.forEach(check => (check.source_lines || []).forEach(line => sources.set(line.id, {...sources.get(line.id),...line})));
  for (const line of sources.values()) rows.set(`line-${line.id}`, {id:`line-${line.id}`,status:"read",text:line.display_text ?? line.text,checks:[],line_ids:[line.id],source_lines:[line]});
  checks.forEach((check, index) => {
    if(isNutritionCheck(check))return;
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
function isNutritionCheck(check){return check?.incomplete_standard===true || ((check?.source==="logic" || !check?.source) && /^nutrition_/.test(check?.key || ""));}
function nutritionProblemRows(result){return (result.checks || []).filter(check=>isNutritionCheck(check) && ["fail","review"].includes(check.status)).map(check=>({id:`logic-${check.key}`,status:check.status,text:check.label || "營養數值檢查",checks:[check],line_ids:[],logicKey:check.key}));}
function groupedResultRows(rows,displayRows){
  if(!Array.isArray(displayRows) || !displayRows.length)return rows;
  const byId=new Map(),used=new Set(),grouped=[],rank={fail:0,review:1,read:2,pass:3};
  rows.forEach(row=>row.line_ids.forEach(id=>byId.set(id,row)));
  for(const [index,display] of displayRows.entries()){
    const ids=Array.isArray(display?.source_line_ids) ? [...new Set(display.source_line_ids)] : [];
    if(!ids.length || !display.text || ids.some(id=>!byId.has(id) || used.has(id)))continue;
    const parts=[...new Set(ids.map(id=>byId.get(id)))],checks=[...new Set(parts.flatMap(row=>row.checks))],status=parts.reduce((value,row)=>rank[row.status]<rank[value] ? row.status : value,"pass");
    grouped.push({id:`display-${index}`,status,text:display.display_text || display.text,checks,line_ids:ids,source_lines:parts.flatMap(row=>row.source_lines || []),partialPass:status==="read" && parts.some(row=>row.status==="pass" || row.partialPass)});ids.forEach(id=>used.add(id));
  }
  grouped.push(...rows.filter(row=>!row.line_ids.length || !row.line_ids.some(id=>used.has(id))));
  return grouped.sort((a,b)=>rank[a.status]-rank[b.status]);
}
function alternativeEvidence(item){
  const targets=new Set(Array.isArray(item.line_ids) ? item.line_ids : []),lines=Array.isArray(item.source_lines) ? [...item.source_lines] : [];
  for(const check of item.checks || [])if(Array.isArray(check?.source_lines))lines.push(...check.source_lines);
  return lines.filter(line=>line && (!targets.size || targets.has(line.id)));
}
function hasLocalRetryDifference(item){return alternativeEvidence(item).some(line=>line.ambiguity_reason==="line_retry_disagrees" || (Array.isArray(line.alternatives) && line.alternatives.some(value=>value?.method==="stroke_thin_2x2")));}
function appendOCRAlternatives(container, item) {
  const seen = new Set(), values = [];
  for (const line of alternativeEvidence(item)) {
      for (const alternative of Array.isArray(line.alternatives) ? line.alternatives : []) {
        const text = typeof alternative === "string" ? alternative : alternative?.text;
        if (typeof text !== "string" || !text.trim() || text === line.text || seen.has(text)) continue;
        seen.add(text); values.push(text);
      }
  }
  if (!values.length) return;
  const block = element("div", "line-comparison ocr-alternatives");
  block.append(element("strong", "", hasLocalRetryDifference(item) ? "局部重讀候選（僅供對照，未套用）" : "另一次辨識（僅供對照，未套用）"));
  if(hasLocalRetryDifference(item))block.append(element("p","help","局部重讀結果不同，請對照原圖；候選可能更不準確，原始辨識文字仍保留。"));
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
  if (item.status === "read") content.append(element("small", "line-note", item.partialPass ? "部分內容已核對，其餘文字尚無比對依據" : "僅辨識，尚無比對依據"));
  const reasons = [...new Set(item.checks.filter(check => check.status === item.status).map(check => check.reason).filter(Boolean))];
  if(item.status==="review" && hasLocalRetryDifference(item))reasons.unshift("局部重讀結果不同，請對照原圖。");
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
function renderUnmatchedDates(inspection,result,area){
  if(inspection.template_id || result.source_match?.status==="matched" || (!result.source_match && inspection.template_snapshot?.source?.code))return;
  const checks=(result.checks || []).filter(check=>check.source==="date" || /^(manufacture|expiry|arrival)(_|$)|^date_|^keep_days$|^batch$|^expired$|^future_manufacture$/.test(check.key || ""));
  const keyGroups={manufacture:["manufacture","date_order","arrival_manufacture","keep_days","batch","future_manufacture"],expiry:["expiry","date_order","arrival_expiry","keep_days","expired"],arrival:["arrival","arrival_manufacture","arrival_expiry"]},weights={fail:3,review:2,pass:1,read:0};
  const panel=element("section","result-date-first");panel.id="result-date-first";panel.setAttribute("aria-label","日期先看");panel.append(element("h3","","日期先看"));
  const list=element("dl","date-first-list"),related=new Set();
  for(const [key,label] of [["manufacture","製造日期"],["expiry","有效日期"],["arrival","到店日"]]){
    const field=result.fields?.[key],direct=checks.find(check=>check.key===key),value=field?.display_value || field?.value || direct?.display_actual || direct?.actual;
    if(typeof value!=="string" || !value.trim())continue;
    const identifiers=field?.line_ids || direct?.line_ids || [],rowChecks=checks.filter(check=>{
      if(keyGroups[key].some(prefix=>check.key===prefix || check.key?.startsWith(prefix+"_")))return true;
      // Several dates can share one OCR row. Known field checks must not leak across dates.
      if(/^(manufacture|expiry|arrival)(_|$)|^date_order$|^keep_days$|^batch$|^expired$|^future_manufacture$/.test(check.key || ""))return false;
      return (check.line_ids || []).some(id=>identifiers.includes(id) && Object.keys(keyGroups).every(other=>other===key || !(result.fields?.[other]?.line_ids || checks.find(item=>item.key===other)?.line_ids || []).includes(id)));
    });
    rowChecks.forEach(check=>related.add(check));const status=rowChecks.reduce((worst,check)=>(weights[check.status] ?? 0)>(weights[worst] ?? 0) ? check.status : worst,"read"),row=element("div",`date-first-row ${status}`);row.dataset.dateField=key;
    row.append(element("dt","",label),element("dd","date-first-value",value),element("dd","date-first-status",{pass:"✓ 已做基本檢查",fail:"✕ 有異常",review:"? 需確認",read:"· 尚未核對"}[status] || "· 尚未核對"));list.append(row);
  }
  if(list.children.length)panel.append(list);else panel.append(element("p","date-first-empty","未辨識到可列出的製造、有效或到店日期，請對照照片確認；不代表日期已通過。"));
  const problems=[...related].filter(check=>["fail","review"].includes(check.status)).sort((a,b)=>(weights[b.status] || 0)-(weights[a.status] || 0)),reasons=new Set();
  for(const check of problems){const reason=check.reason || check.label;if(!reason || reasons.has(reason))continue;reasons.add(reason);panel.append(element("p",`date-first-reason ${check.status}`,`${check.status==="fail" ? "✕" : "?"} ${reason}`));}
  panel.append(element("p","date-first-scope","尚無確定比對標準。這裡只顯示已執行的日期格式、先後與基準日檢查；不代表已確認保存期限或完整排程。"));
  if(result.inputs?.base_date)panel.append(element("p","help",`本批基準日：${result.inputs.base_date}`));
  if(related.size){const detail=element("details","date-first-details");detail.append(element("summary","","查看日期檢查依據"));for(const check of related){const row=element("p","");row.append(element("strong","",`${check.label || "日期檢查"}：`),element("span","",`${check.reason || "未提供判定說明"}${check.display_expected || check.expected ? ` 依據：${check.display_expected || check.expected}` : ""}`));detail.append(row);}panel.append(detail);}
  area.append(panel);
}
function renderSourceMatch(match, area, baseDate) {
  if (!match && !baseDate) return;
  const node = element("div", `source-match ${match?.status || "dated"}`); node.id = "result-source-match";
  if (!match) { node.append(element("p", "source-base-date", `基準日：${baseDate}`)); area.append(node); return; }
  if (match.status === "matched") {
    node.append(element("p", "", `${sourceKindLabel(match)}：${sourceCodeLabel(match)} ${match.name}`));
    if(match.comparison_scope==="approved_text")node.append(element("p","source-scope","依人工核准的完整文字與既有日期規則核對；未列入的內容仍需人工確認。"));
    else if (isCatalogSource(match)) {
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
  if (!state.inspection || state.busy || !validBaseDate() || !validPhotoTemplateChoice()) return;
  const identifier = state.inspection.id, button = $("#recheck-button");
  const body = {source_code:state.inspectSource?.code || "",base_date:$("#base-date").value,batch_date:$("#batch-date").value,arrival_date:$("#arrival-date").value};
  if(!body.source_code && $("#template-select").value)body.template_id=$("#template-select").value;
  setBusy(true); button.textContent = "核對中…";
  try {
    const result = await api(`/api/inspections/${encodeURIComponent(identifier)}/recheck`, {method:"POST",body});
    await loadInspection(result.inspection_id); toast(result.manual_revision ? "已沿用人工訂正，依最新資料重新核對。" : "已使用原辨識文字，依最新系統資料重新核對。");
  } catch (error) { toast(error.message,true); }
  finally { button.textContent = "重新核對"; setBusy(false); }
}
function renderRecheckControls(area) {
  const disclosure=element("details","result-maintenance");disclosure.id="result-maintenance";disclosure.open=!!state.resultDirty;disclosure.append(element("summary","","比對設定與重新核對"));
  const block = element("div", "recheck-controls"); block.id = "recheck-controls";
  const dirty = element("p", "recheck-dirty", state.standardSaved ? "標準已儲存，之後同款會使用新版。以下仍是上次結果，請重新核對本張照片。" : "設定已變更，以下仍是上次結果，請重新核對。"); dirty.id = "recheck-dirty"; dirty.hidden = !state.resultDirty; dirty.setAttribute("role","status");
  const button = element("button", `button ${state.standardSaved ? "primary" : "secondary"}`, state.standardSaved ? "用新標準重新核對本張" : "重新核對"); button.id = "recheck-button"; button.type = "button"; button.disabled = state.busy; button.onclick = recheckInspection;
  const result=state.inspection?.manual_revision?.result || state.inspection?.result;
  const hasSource=!!state.inspection?.template_id || !!state.inspection?.template_snapshot?.source?.code;
  const edit = element("button","button secondary",hasSource ? "更新比對標準" : "建立文字比對標準");edit.type="button";edit.dataset.editStandard="true";edit.disabled=state.busy;edit.hidden=true;edit.onclick=()=>hasSource ? openStandardEditor() : openManualStandard();
  const hasPatches = !!state.inspection?.manual_revision?.patches?.length;
  block.append(dirty,button,edit,element("p","recheck-help",hasPatches ? "沿用目前人工訂正，依最新標準與上方本批日期重新核對；原紀錄保留。" : "使用原辨識文字，依最新系統標籤、清單與上方本批日期核對。"));
  const referenceCode=state.inspectSource?.code || state.inspection?.template_snapshot?.source?.code || (result?.source_match?.status==="matched" ? result.source_match.code : "");
  if(allowed() && referenceCode && !result?.label_scope?.blocked && state.inspection?.ocr?.label_scope?.status!=="multiple"){const attach=element("button","button secondary","附加這張參考照");attach.type="button";attach.dataset.editStandard="reference-photo";attach.disabled=state.busy;attach.onclick=()=>openReferencePhoto(state.inspection.id,referenceCode);block.append(attach);}
  block.append(element("p","workflow-help",allowed() ? "訂正辨識文字：按各行「訂正」，只影響本筆。更新比對標準：按「改標準」，影響之後同款掃描。" : "辨識讀錯時，按該行「訂正」，只影響本筆；變更後續比對標準需管理員處理。"));
  disclosure.append(block);area.append(disclosure);
}
function resultStandardAction(inspection,result){
  if(!allowed())return null;
  const match=result.source_match || {},source=inspection.template_snapshot?.source || {},eligibility=inspection.manual_standard_eligibility,photo=!!inspection.template_id;
  if(result.label_scope?.blocked || inspection.ocr?.label_scope?.status==="multiple")return {blocked:"請先框選一張完整標籤，再確認要建立或更新的標準。",action:"crop",label:"調整標籤範圍"};
  if(eligibility?.eligible===false)return {blocked:`${eligibility.reason || "本次沒有足夠可用文字"}，請先重新拍攝或辨識。`,action:"retake",label:"重新拍攝",invalid:true};
  if(state.inspection?.id===inspection.id && state.resultDirty)return {blocked:state.standardSaved ? "標準已儲存；重新核對本張照片即可看到最新結果。" : "比對設定已變更，請先重新核對，確認這次要更新的來源。",action:"recheck",label:state.standardSaved ? "用新標準重新核對" : "先重新核對來源"};
  if(photo && state.inspection?.id===inspection.id && $("#template-select").value===inspection.template_id && !state.templates.some(item=>item.id===inspection.template_id))return {blocked:"這筆使用的照片標準已非可選用版本。請先選擇有效版本；不會自動改用其他來源。",action:"photo",label:"選擇有效照片標準"};
  if(!photo && ["ambiguous","unavailable"].includes(match.status))return {blocked:match.status==="ambiguous" ? "有多份可能來源，請先選定正確標籤並重新核對，避免更新錯份標準。" : "目前無法確認比對來源，請先選擇來源或稍後重新核對。",action:"source",label:"選擇正確來源"};
  const code=source.code || (match.status==="matched" ? match.code : ""),kind=source.source_kind || match.source_kind || (String(code).startsWith("list:") ? "catalog" : String(code).startsWith("manual:") ? "manual" : "desktop");
  if(photo || code){const complete=kind==="catalog" && !(source.web_text_approved || source.comparison_scope==="approved_text" || match.comparison_scope==="approved_text");return {action:"update",label:complete ? "建立完整標準" : "更新標準",title:complete ? "這份清單還缺完整標籤文字" : "用本次照片更新這份標準",description:complete ? "目前只知道清單的部分資料。可自動帶入這次文字與照片，對照後核准成完整比對依據。" : "自動帶入本次可用文字與照片，分區確認後存成原標準新版，舊版與舊照片保留。",identity:photo ? inspection.template_snapshot?.name || "本次選用的照片標準" : `${sourceCodeLabel({code})} · ${source.name || match.name || "本次比對來源"}`};}
  if(match.status!=="unmatched" || eligibility?.eligible!==true || state.inspectSource?.code || !(inspection.ocr?.lines || []).length)return null;
  return {action:"create",label:"新建標準",title:"這張標籤尚無比對依據",description:eligibility.needs_review ? "已存檢查紀錄，仍有文字需要確認。可開啟自動分區草稿，只修正讀錯處；核准前不會成為正式依據。" : "文字與照片已備妥，可直接開啟分區草稿；核准前不會成為正式依據。"};
}
function performResultStandardAction(action,inspection){
  if(!requireAdmin() || state.busy || state.inspection?.id!==inspection.id)return;
  const current=state.inspection,currentResult=state.manualView && current.manual_revision ? current.manual_revision.result : current.result,choice=resultStandardAction(current,currentResult);
  if(!choice)return;
  action=choice.action;inspection=current;
  if(action==="create")return openManualStandard(inspection.id);
  if(action==="update")return openStandardEditor(inspection.id);
  if(action==="recheck")return recheckInspection();
  if(action==="crop")return openCropDialog(inspection);
  if(action==="retake")return openCamera();
  if(action==="photo"){$("#template-options").open=true;$("#template-select").focus();$("#template-select").scrollIntoView({block:"center",behavior:"instant"});return;}
  if(action==="source"){$("#template-options").open=true;$("#inspect-source-query").focus();$("#inspect-source-search").scrollIntoView({block:"center",behavior:"instant"});}
}
function renderPendingStandardOffer(inspection,result,area){
  const action=resultStandardAction(inspection,result);if(!action)return;
  const offer=element("section",`result-standard-offer${action.action==="create" ? " pending-standard-offer" : ""}${action.blocked ? " blocked" : ""}`);offer.id="result-standard-action";offer.setAttribute("aria-label","標準建立與更新");
  const copy=element("div","result-standard-copy");if(action.title)copy.append(element("strong","",action.title));if(action.identity)copy.append(element("p","standard-action-identity",action.identity));const text=element("p",action.invalid ? "help draft-ineligible-note" : "help",action.description || action.blocked);if(action.invalid)text.id="draft-ineligible-note";copy.append(text);
  const button=element("button","button primary",action.label);button.id=action.action==="create" ? "confirm-standard-draft" : "result-standard-primary";button.type="button";button.disabled=state.busy;button.dataset.editStandard=action.action;button.onclick=()=>performResultStandardAction(action.action,inspection);offer.append(copy,button);area.append(offer);
}
function refreshResultStandardOffer(){
  if(!state.inspection)return;
  const area=$("#result-area"),old=area.querySelector("#result-standard-action"),holder=element("div"),inspection=state.inspection,result=state.manualView && inspection.manual_revision ? inspection.manual_revision.result : inspection.result;
  renderPendingStandardOffer(inspection,result,holder);const next=holder.children[0];
  if(old){if(next)old.replaceWith(next);else old.remove();}
  else if(next){const overview=area.querySelector(".result-overview");if(overview)area.insertBefore(next,overview);else area.append(next);}
}
function standardSavedNotice(){
  state.standardSaved=true;markResultChanged(true);
  if(state.inspection)renderInspection(state.inspection);
  $("#recheck-controls")?.scrollIntoView({block:"center",behavior:"instant"});
}
function renderResultLines(rows, area, inspection, manual = false) {
  const list = element("section", "scan-lines"); list.id = "result-lines"; list.setAttribute("aria-label", "逐列檢查結果");
  if (!rows.length) list.append(element("p", "group-empty", "沒有辨識到文字，請重新拍攝清楚的標籤。"));
  rows.forEach(row => {
    if(manual)row.originalLines=inspection.ocr.lines;
    const node=resultLine(row),lineIds=row.line_ids.filter(id=>inspection?.ocr?.lines?.some(line=>line.id===id)),lineId=lineIds[0];
    const sourceIds=!allowed() || inspection.template_id || !["fail","review"].includes(row.status) ? [] : [...new Set(row.checks.filter(check=>["fail","review"].includes(check.status) && check.source !== "date").flatMap(check=>Array.isArray(check.source_line_ids) ? check.source_line_ids.filter(id=>typeof id==="string" || Number.isInteger(id)) : []))];
    if(lineId === undefined && !sourceIds.length){list.append(node);return;}
    const wrapper=element("div","scan-line-entry"),actions=element("div","scan-line-actions");
    if(lineIds.length>1){
      const choices=element("details","line-correction-options"),summary=element("summary","line-correct-button","訂正");summary.setAttribute("aria-label",`選擇要訂正的原始文字：${row.text}`);choices.append(summary,element("p","help","選擇讀錯的原始片段，再對照照片訂正。"));
      for(const id of lineIds){const original=inspection.ocr.lines.find(line=>line.id===id),button=element("button","button secondary",original?.text || "（未讀到文字）");button.type="button";button.dataset.correctLine=String(id);button.disabled=state.busy;button.onclick=()=>openCorrectionDialog(id);choices.append(button);}actions.append(choices);
    }else if(lineId !== undefined){const button=element("button","line-correct-button","訂正");button.type="button";button.dataset.correctLine=String(lineId);button.disabled=state.busy;button.setAttribute("aria-label",`訂正這行：${row.text || "未辨識到文字"}`);button.onclick=()=>openCorrectionDialog(lineId);actions.append(button);}
    if(sourceIds.length){const edit=element("button","line-correct-button line-standard-button","改標準");edit.type="button";edit.dataset.editStandard="context";edit.disabled=state.busy;edit.setAttribute("aria-label",`修正這項標準：${row.text || row.label || "未辨識到的文字"}`);edit.onclick=()=>openStandardEditor(inspection.id,sourceIds);actions.append(edit);}
    const patch=(inspection.manual_revision?.patches || []).find(item=>lineIds.includes(item.line_id));
    if(patch && manual){const content=$(".scan-line-content",node);content.append(element("small","manual-tag",`已訂正 · ${correctionLabels[patch.kind] || "人工確認"}`));}
    wrapper.append(node,actions);list.append(wrapper);
  }); area.append(list);
}
function resultCoverage(inspection,result){
  const matched=result.source_match?.status==="matched" || !!inspection.template_id || !!inspection.template_snapshot?.source?.code;
  const partial=["catalog_fields","manual_text"].includes(result.verified_scope) || result.counts?.read>0;
  return {matched,status:!matched && result.status==="pass" ? "review" : result.status,
    title:!matched ? result.status==="fail" ? "發現差異 · 尚無比對標準" : "尚無比對標準" : statusLabels[result.status] || "需要確認",
    note:!matched ? "目前只做可判讀的日期、條碼等邏輯檢查；沒有標準，不能確認整張標籤正確。" : partial ? "只確認已設定的內容；沒有比對依據的文字仍需人工核對。" : "依本次選用的標準及日期規則核對；請確認選到的貼紙範圍完整。"};
}
function openResultRow(identifier){
  $("#result-text-details").open=true;const row=$$("#result-lines [data-line-id]").find(node=>node.dataset.lineId===identifier);
  if(row){if(row.tagName==="DETAILS")row.open=true;row.scrollIntoView({block:"center",behavior:"instant"});}
}
function renderResultOverview(inspection,result,rows,area){
  const block=element("section","result-overview"),photo=element("figure","result-label-photo"),canvas=element("canvas"),region=selectedLabelRegion(inspection);
  canvas.id="result-label-canvas";canvas.setAttribute("role","img");canvas.setAttribute("aria-label",region ? "本次選中的貼紙，綠框為辨識範圍" : "待檢照片與問題位置");
  let focused=!!region;drawEvidence(canvas,{...inspection,result},focused);photo.append(canvas);
  const caption=element("figcaption","",inspection.ocr?.label_scope?.status==="no_clear_sticker" ? "未能自動選出貼紙，這次辨識整張照片；可手動框選。" : region ? `${region.auto_selected ? "已自動選取貼紙" : "已選定貼紙範圍"} · 原圖保留` : inspection.ocr?.label_scope?.status==="multiple" ? "照片含多個可能貼紙，請選定一張。" : "本次照片 · 可調整貼紙範圍");photo.append(caption);
  const controls=element("div","photo-summary-actions"),adjust=element("button","button secondary","調整貼紙範圍");adjust.type="button";adjust.dataset.recognitionAction="true";adjust.disabled=state.busy;adjust.onclick=()=>openCropDialog(inspection);controls.append(adjust);
  if(region){const toggle=element("button","button secondary","看原圖與選取框");toggle.type="button";toggle.onclick=()=>{focused=!focused;drawEvidence(canvas,{...inspection,result},focused);toggle.textContent=focused ? "看原圖與選取框" : "只看選取貼紙";};controls.append(toggle);}
  photo.append(controls);block.append(photo);
  const issues=element("div","result-primary-issues"),problems=[...rows.filter(row=>["fail","review"].includes(row.status)),...nutritionProblemRows(result)].sort((a,b)=>(a.status==="fail"?0:1)-(b.status==="fail"?0:1));issues.id="result-primary-issues";
  issues.append(element("h3","",problems.length ? `需要處理 · ${problems.length} 項` : "本次核對摘要"));
  if(problems.length)issues.append(element("p","help","點選問題查看依據與訂正文字。"));
  for(const row of problems.slice(0,3)){
    const button=element("button",`issue-link ${row.status}`);button.type="button";button.append(element("strong","",`${row.status==="fail" ? "✕" : "?"} ${String(row.text || row.label || "待確認內容").slice(0,100)}`));
    const reasons=[...new Set(row.checks.filter(check=>["fail","review"].includes(check.status)).map(check=>check.reason).filter(Boolean))];if(reasons.length)button.append(element("span","",reasons[0]));if(reasons.length>1)button.append(element("small","",`另有 ${reasons.length-1} 項說明，點選查看`));button.onclick=()=>{if(row.logicKey){$("#result-logic-details").open=true;const target=$$(".logic-check").find(item=>item.dataset.checkKey===row.logicKey);(target || $("#result-logic-details")).scrollIntoView({block:"center",behavior:"instant"});}else openResultRow(row.id);};issues.append(button);
  }
  if(problems.length>3){const more=element("button","button secondary",`查看其餘 ${problems.length-3} 項問題`);more.type="button";more.onclick=()=>{$("#result-text-details").open=true;if(nutritionProblemRows(result).length)$("#result-logic-details").open=true;$("#result-text-details").scrollIntoView({block:"start",behavior:"instant"});};issues.append(more);}
  if(!problems.length)issues.append(element("p","help",rows.some(row=>row.status==="read") ? "有文字尚無比對依據，請展開貼紙文字確認。" : resultCoverage(inspection,result).note));
  block.append(issues);area.append(block);
}
function renderLogicChecks(result,area){
  const checks=(result.checks || []).filter(check=>check.source==="date" || isNutritionCheck(check) || /barcode|^date_|^keep_days$|^batch$/.test(check.key || "") || /條碼/.test(check.label || ""));
  const details=element("details","logic-checks");details.id="result-logic-details";details.append(element("summary","",`日期、條碼與營養檢查 · ${checks.length} 項`));
  if(!checks.length)details.append(element("p","help","本筆沒有可核對的日期、條碼或營養資料，不代表這些項目已通過。"));
  for(const check of checks){const row=element("div",`logic-check ${check.status}`);row.dataset.checkKey=check.key || "";row.append(badge(check.status,({pass:"✓ 相符",fail:"✕ 有差異",review:"? 需確認",read:"僅辨識"})[check.status]),element("strong","",check.label || "檢查項目"));
    if(check.display_actual || check.actual)row.append(element("p","",`讀到：${check.display_actual || check.actual}`));if(check.display_expected || check.expected)row.append(element("p","help",`依據：${check.display_expected || check.expected}`));if(check.reason)row.append(element("p","help",check.reason));details.append(row);}
  area.append(details);
}
function renderInspection(inspection) {
  const area = $("#result-area"); area.replaceChildren(); area.hidden = false; $("#result-placeholder").hidden = true;
  const manual=!!(state.manualView && inspection.manual_revision), result = manual ? inspection.manual_revision.result : inspection.result;
  const ocr=manual ? inspection.manual_revision.ocr : inspection.ocr,rows = groupedResultRows(buildResultRows(result.checks, ocr.lines),result.display_rows),coverage=resultCoverage(inspection,result), header = element("div", `scan-result-header ${coverage.status}`),summaryRows=[...rows,...nutritionProblemRows(result)];
  header.append(element("h2", "", manual ? `人工訂正後 · 第 ${currentRevision(inspection)} 版` : inspection.manual_revision ? "原始辨識結果" : "掃描結果"), element("p", "", when(inspection.created_at)));
  const counts = element("div", "result-counts");
  for (const [status,label] of [["fail","✕ 有差異"],["review","? 需確認"],["read","· 尚無依據"]]) {
    const count = summaryRows.filter(row => row.status === status).length;
    if (count) counts.append(element("span", `count-${status}`, `${label} ${count}`));
  }
  header.append(element("strong","result-verdict",coverage.title),counts,element("p","result-coverage",coverage.note)); area.append(header);
  renderUnmatchedDates(inspection,result,area);
  if(inspection.manual_revision){
    const toolbar=element("div","manual-toolbar"),toggle=element("button","button secondary",manual ? "查看原始判定" : "查看人工訂正後判定");toggle.type="button";toggle.dataset.toggleOriginal="true";toggle.disabled=state.busy;toggle.onclick=()=>{state.manualView=!state.manualView;renderInspection(inspection);};
    toolbar.append(element("p","",manual ? "依人工填寫的照片實際文字重新判定；原始 OCR 與原判定仍保留。" : "正在查看第一次機器辨識結果；後續人工訂正另行保留。"),toggle);area.append(toolbar);
    if(manual && inspection.manual_revision.copied_from)area.append(element("p","help","已沿用先前人工訂正，依此次標準與日期重新判定。"));
  }
  const recovery = recoveryMessage(inspection.ocr);
  if (recovery) { const notice = element("p", "result-notes", recovery); notice.setAttribute("role", "status"); area.append(notice); }
  renderSourceMatch(result.source_match, area, result.inputs?.base_date);
  renderPendingStandardOffer(inspection,result,area);
  renderResultOverview(inspection,result,rows,area);
  renderRecheckControls(area);
  const passed=rows.filter(row=>row.status==="pass").length;
  const textDetails=element("details","result-text-details");textDetails.id="result-text-details";textDetails.append(element("summary","",`查看貼紙全文與訂正 · ${rows.length} 行${passed ? `（${passed} 行已核對相符）` : ""}`));renderResultLines(rows,textDetails,inspection,manual);area.append(textDetails);
  renderLogicChecks(result,area);renderRecognitionInfo(inspection,result,rows,area);
  if (result.notes?.length) { const notes = element("details", "result-notes");notes.append(element("summary","","本次判定說明")); result.notes.forEach(note => notes.append(element("p", "", note))); area.append(notes); }
  renderCorrectionHistory(inspection,area);
  const evidence = element("details", "panel evidence"); evidence.append(element("summary", "", "原圖、原始文字與人工複核"));
  const pair = element("div", "photo-pair");
  const reference = element("figure"), observed = element("figure"), refScroll = element("div", "photo-scroll"), observedScroll = element("div", "photo-scroll");
  if (inspection.reference_image) {
    const ref = element("img"); ref.src = inspection.reference_image.url; ref.alt = "已確認的標準照片"; refScroll.append(ref);
    reference.append(element("figcaption", "", "標準照片"), refScroll); pair.append(reference);
  }
  const canvas = element("canvas"); canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", "待檢照片；紅框為差異，黃框為待確認文字"); observedScroll.append(canvas);
  observed.append(element("figcaption", "", "待檢照片 · 紅框差異／黃框複核"), observedScroll); pair.append(observed); evidence.append(pair); drawEvidence(canvas, {...inspection,result});
  const details = element("details"), raw = element("div", "ocr-lines"); details.append(element("summary", "", "查看完整辨識原文"), raw); renderOCR(inspection.ocr.lines, raw,ocrLowScoreThreshold(inspection.ocr)); evidence.append(details);
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
function ocrLowScoreThreshold(ocr){const threshold=ocr?.diagnostics?.low_score_threshold;return Number.isFinite(threshold) && threshold>=0 && threshold<=1 ? threshold : .65;}
function isCloudOCR(ocr){return ocr?.recognition_engine==="cloud" || (ocr?.lines || []).some(line=>line.score_kind==="uncertainty_gate");}
function recognitionInfo(inspection,result,rows){
  const ocr=inspection.ocr || {},diagnostics=ocr.diagnostics || {},pre=ocr.preprocessing || {},lines=Array.isArray(ocr.lines) ? ocr.lines : [];
  const count=value=>Number.isInteger(value) && value>=0 ? value : null;
  const width=Number(inspection.image?.width),height=Number(inspection.image?.height),threshold=ocrLowScoreThreshold(ocr);
  const low=count(diagnostics.low_score_count) ?? lines.filter(line=>Number.isFinite(line.score) && line.score<threshold).length;
  const ambiguous=count(diagnostics.ambiguous_line_count) ?? lines.filter(line=>line.ambiguous===true).length;
  const small=count(diagnostics.small_text_line_count),review=rows.filter(row=>row.status==="review").length;
  const facts=[],warnings=[],cloud=isCloudOCR(ocr);
  if(width>0 && height>0)facts.push(`保存照片：${width} × ${height} 像素`);
  facts.push(`原始辨識：${count(diagnostics.line_count) ?? lines.length} 行；目前需確認：${review} 項`);
  if(cloud)facts.push("辨識方式：雲端讀取；需確認標記不是信心分數。");
  else if(typeof ocr.engine==="string" && ocr.engine)facts.push(`辨識引擎：${ocr.engine}`);
  if(Number.isInteger(pre.passes) && pre.passes>0)facts.push(`本次整圖讀取：${pre.passes} 次${Number(pre.selected_rotation) ? `；採用旋轉 ${pre.selected_rotation}° 的讀取結果` : ""}`);
  if(count(diagnostics.line_retry_count)>0)facts.push(`局部文字重讀：${diagnostics.line_retry_count} 行`);
  if(count(diagnostics.rotation_retry_count)>0 && !(Number(pre.passes)>1))facts.push(`旋轉重讀：${diagnostics.rotation_retry_count} 次`);
  if(Number.isFinite(ocr.elapsed) && ocr.elapsed>=0)facts.push(`辨識耗時：${ocr.elapsed} 秒`);
  if(pre.scale_x>1 || pre.scale_y>1)facts.push("小圖曾放大供辨識；放大不能補回原照缺少的細節。");
  if(result.label_scope?.blocked)warnings.push(result.label_scope.reason || "照片內的標籤範圍不明，請框選一張完整標籤後重新辨識。");
  if(small>0)warnings.push(`有 ${small} 行字框較小${Number.isFinite(diagnostics.small_text_height_threshold_px) ? `（短邊小於 ${diagnostics.small_text_height_threshold_px} 像素）` : ""}，請放大原照確認細字；必要時靠近重拍。`);
  if(low>0)warnings.push(cloud ? `雲端讀取有 ${low} 行標記需確認，請對照原照。` : `原始 OCR 有 ${low} 行低於辨識分數門檻 ${threshold}，請依照片核對；這不是整張標籤的正確率。`);
  if(ambiguous>0)warnings.push(`有 ${ambiguous} 行不同次讀取不一致，請查看該行明細或重拍。`);
  if(width>0 && height>0 && Math.max(width,height)<1000)warnings.push("保存照片較小，細字可能缺少細節；請優先選原始照片或靠近重拍。");
  if(!lines.length)warnings.push("沒有辨識到文字，請確認照片清楚且只有一張完整標籤。");
  return {facts,warnings,review};
}
function renderRecognitionInfo(inspection,result,rows,area){
  const info=recognitionInfo(inspection,result,rows),panel=element("details","recognition-info");panel.id="recognition-info";panel.open=!!result.label_scope?.blocked;
  panel.append(element("summary","",`照片與辨識資訊${info.warnings.length ? " · 有拍攝／讀取提醒" : ""}`));
  const list=element("ul","recognition-facts");info.facts.forEach(text=>list.append(element("li","",text)));panel.append(list);
  if(info.warnings.length){const warnings=element("div","recognition-warnings");info.warnings.forEach(text=>warnings.append(element("p","",text)));panel.append(warnings);}
  panel.append(element("p","help","辨識分數與照片尺寸只用來協助判讀，不能保證無錯字；標籤內容仍依逐行比對結果判定。"));
  if(isCloudOCR(inspection.ocr)){
    const usage=element("details","cloud-usage"),data=inspection.ocr.usage || {};usage.append(element("summary","","雲端辨識用量來源"));usage.append(element("p","help",`來源：${inspection.ocr.provider || "雲端服務"}${inspection.ocr.model ? ` · ${inspection.ocr.model}` : ""}`));
    for(const [key,label] of [["input_tokens","輸入用量"],["output_tokens","輸出用量"],["total_tokens","總用量"]])if(Number.isInteger(data[key]))usage.append(element("p","help",`${label}：${data[key]} tokens`));panel.append(usage);
  }
  const recovery=result.recognition_of;
  if(recovery?.inspection_id)panel.append(element("p","help",recovery.crop ? "本筆使用先前照片的人工選定範圍重新辨識；原紀錄保留，未帶入先前人工訂正。" : "本筆重新讀取先前整張照片；原紀錄保留，未帶入先前人工訂正。"));
  area.append(panel);
  const actionDetails=element("details","reprocess-options");actionDetails.open=inspection.manual_standard_eligibility?.eligible===false && result.source_match?.status==="unmatched";actionDetails.append(element("summary","","重新辨識或重拍"));const actions=element("div","recognition-actions"),crop=element("button","button secondary","裁切單張後重新辨識"),retake=element("button","button secondary","重新拍攝"),choose=element("button","button secondary","改選清楚照片");
  for(const button of [crop,retake,choose]){button.type="button";button.disabled=state.busy;button.dataset.recognitionAction="true";}
  crop.onclick=()=>openCropDialog(inspection);retake.onclick=()=>openCamera();choose.onclick=()=>{if(!state.busy)$("#inspect-file").click();};actions.append(crop,retake,choose);
  actions.append(element("p","help","重新核對會沿用現有文字；重新辨識才會讀取照片。多張標籤請先裁切單張；模糊反光請重拍。"));actionDetails.append(actions);area.append(actionDetails);
}
function historyPresentation(item) {
  const name=String(item.name || ""),version=Number(item.version) || 0;
  const generatedManual=version===0 ? /^人工文字標準 manual:[0-9a-f]{32} · (.+)$/i.exec(name) : null;
  const product=typeof item.product==="string" ? item.product.trim() : "";
  return {name:product || (generatedManual ? generatedManual[1] : name),reference:version>0 ? `第 ${version} 版` : generatedManual || item.source_kind==="manual" ? "人工文字標準" : isCatalogSource(item) ? "清單比對" : "系統比對"};
}
function historyProblemSummary(item){
  const counts=item.manual_counts || item.counts,prefix=item.manual_revision && !item.manual_counts ? "原始：" : "";
  if(!counts || !Number.isInteger(counts.fail) || !Number.isInteger(counts.review))return "展開查看判定明細";
  return counts.fail || counts.review ? `${prefix}差異 ${counts.fail} 項 · 待確認 ${counts.review} 個檢查點` : counts.read>0 ? `${prefix}${counts.read} 項尚無比對依據` : `${prefix}已核對項目無差異`;
}
async function loadHistory() {
  const filter = $("#history-filter").value, page = state.page;
  const data = await api(`/api/inspections?page=${page}&status=${encodeURIComponent(filter)}`);
  if (page !== state.page || filter !== $("#history-filter").value) return;
  const list = $("#history-list"); list.replaceChildren();
  if (!data.items.length) { const empty = element("div", "empty-state"); empty.append(element("h2", "", "這裡還沒有檢查紀錄"),element("p", "", "完成一次照片檢查後，結果會自動保存在這裡。")); list.append(empty); }
  data.items.forEach(item => { const row = element("button", "history-row"), img = element("img"), text = element("span","history-copy"),statuses=element("span","history-statuses"),display=historyPresentation(item); img.src=item.image.thumbnail; img.alt="待檢標籤縮圖"; img.loading="lazy";text.append(element("strong", "", display.name), element("small", "", `${item.base_date ? `本批 ${item.base_date}` : when(item.created_at)} · ${display.reference}`),element("span","history-problems",historyProblemSummary(item)));statuses.append(badge(item.status,`原始：${statusLabels[item.status] || item.status}`));if(item.manual_revision){text.append(element("small","manual-tag",`已訂正 · 第 ${item.manual_revision} 版`));statuses.append(badge(item.manual_status,`訂正後：${statusLabels[item.manual_status] || "已保存"}`));}row.append(img,text,statuses); row.onclick=() => { if(state.busy) return toast("請等待目前辨識完成。"); loadInspection(item.id).catch(e=>toast(e.message,true)); };
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
function cropBounds(selection,width,height){
  if(!selection || !["x","y","width","height"].every(key=>Number.isFinite(selection[key])))throw new Error("請填寫完整的裁切座標與尺寸。");
  if(selection.x<0 || selection.y<0 || selection.width<100 || selection.height<100)throw new Error("每個裁切範圍至少需要 100 × 100 像素；請框住完整標籤。");
  if(selection.x+selection.width>width || selection.y+selection.height>height)throw new Error("裁切範圍超出照片，請調整座標或尺寸。");
  return {...selection};
}
function selectionFromPoints(first,last,width,height){
  const point=value=>({x:Math.round(Math.max(0,Math.min(width,value.x))),y:Math.round(Math.max(0,Math.min(height,value.y)))}),a=point(first),b=point(last);
  return {x:Math.min(a.x,b.x),y:Math.min(a.y,b.y),width:Math.abs(b.x-a.x),height:Math.abs(b.y-a.y)};
}
function draftScopeSignature(owner){return JSON.stringify({text:$("#manual-standard-lines").value,rows:(owner.textRows || []).map(row=>({text:row.text,ids:row.ids || []}))});}
function trustedDraftBounds(row,owner,width,height){
  const ids=[...new Set(row.ids || [])];if(!ids.length)return null;
  const signature=JSON.stringify([...ids].sort()),matches=(owner.draftLines || []).filter(line=>{const source=draftTextRow(line);return source.text===row.text && JSON.stringify([...new Set(source.ids)].sort())===signature;});
  if(matches.length!==1)return null;
  const boxes=[];for(const id of ids){const sources=(owner.inspection?.ocr?.lines || []).filter(line=>line.id===id);if(sources.length!==1 || !Array.isArray(sources[0].box) || sources[0].box.length<3)return null;
    const points=sources[0].box;if(points.some(point=>!Array.isArray(point) || point.length<2 || !Number.isFinite(point[0]) || !Number.isFinite(point[1]) || point[0]<0 || point[1]<0 || point[0]>width || point[1]>height))return null;
    const xs=points.map(point=>point[0]),ys=points.map(point=>point[1]),box={left:Math.min(...xs),top:Math.min(...ys),right:Math.max(...xs),bottom:Math.max(...ys)};if(box.left>=box.right || box.top>=box.bottom)return null;boxes.push(box);
  }
  return {left:Math.min(...boxes.map(box=>box.left)),top:Math.min(...boxes.map(box=>box.top)),right:Math.max(...boxes.map(box=>box.right)),bottom:Math.max(...boxes.map(box=>box.bottom))};
}
function filterDraftRowsByScope(owner,selection,width,height){
  const kept=[],removed=[],uncertain=[];const right=selection.x+selection.width,bottom=selection.y+selection.height;
  for(const row of owner.textRows || []){const bounds=trustedDraftBounds(row,owner,width,height);
    if(!bounds){kept.push(row);uncertain.push({row,reason:"文字已修改、新增或沒有可信的照片位置，保守保留。"});continue;}
    const inside=bounds.left>=selection.x && bounds.top>=selection.y && bounds.right<=right && bounds.bottom<=bottom;
    const outside=bounds.right<=selection.x || bounds.left>=right || bounds.bottom<=selection.y || bounds.top>=bottom;
    if(outside)removed.push(row);else {kept.push(row);if(!inside)uncertain.push({row,reason:"這行跨越框線，保守保留，請確認主標籤範圍是否完整。"});}
  }
  return {kept,removed,uncertain};
}
function invalidateDraftScopePreview(){const context=state.draftScope;if(context)context.preview=null;$("#draft-scope-preview").hidden=true;$("#draft-scope-confirm").checked=false;$("#draft-scope-apply").disabled=true;}
function closeDraftScopeDialog(){state.draftScope=null;if($("#draft-scope-dialog").open)$("#draft-scope-dialog").close();$("#draft-scope-canvas").width=1;$("#draft-scope-canvas").height=1;for(const id of ["draft-scope-removed","draft-scope-kept","draft-scope-uncertain"])$("#"+id).replaceChildren();$("#draft-scope-source-note").textContent="";invalidateDraftScopePreview();}
function drawDraftScopeSelection(){
  const context=state.draftScope;if(!context?.photo)return;const canvas=$("#draft-scope-canvas"),scale=Math.min(1,1400/context.width);canvas.width=Math.max(1,Math.round(context.width*scale));canvas.height=Math.max(1,Math.round(context.height*scale));const ctx=canvas.getContext("2d");if(!ctx)return;ctx.drawImage(context.photo,0,0,canvas.width,canvas.height);
  const s=context.selection;if(!s)return;const x=s.x*scale,y=s.y*scale,w=s.width*scale,h=s.height*scale;ctx.fillStyle="rgba(0,0,0,.48)";ctx.fillRect(0,0,canvas.width,y);ctx.fillRect(0,y,x,h);ctx.fillRect(x+w,y,canvas.width-x-w,h);ctx.fillRect(0,y+h,canvas.width,canvas.height-y-h);ctx.strokeStyle="#f2df6a";ctx.lineWidth=Math.max(2,canvas.width/350);ctx.strokeRect(x,y,w,h);
}
function updateDraftScopeSelection(selection){const context=state.draftScope;if(!context)return;context.selection={...selection};for(const key of ["x","y","width","height"])$("#draft-scope-"+key).value=selection[key];invalidateDraftScopePreview();drawDraftScopeSelection();}
function draftScopeInput(){const context=state.draftScope,result={};for(const key of ["x","y","width","height"]){const value=$("#draft-scope-"+key).value;if(value==="")throw new Error("請填寫完整的保留範圍。");result[key]=Number(value);}return cropBounds(result,context.width,context.height);}
function openDraftScope(){
  const owner=manualStandard;if(!requireAdmin() || state.busy || !owner?.inspection?.image?.url || !owner.textRows?.length)return;
  const context={owner,signature:draftScopeSignature(owner),photo:null,width:0,height:0,selection:null,preview:null};state.draftScope=context;
  $("#draft-scope-fields").disabled=true;$("#draft-scope-preview-button").disabled=true;$("#draft-scope-reset").disabled=true;$("#draft-scope-source-note").textContent="載入原照片中…";invalidateDraftScopePreview();setDialogError("#draft-scope-error");$("#draft-scope-dialog").showModal();
  const photo=new Image();photo.onload=()=>{if(state.draftScope!==context || manualStandard!==owner || !allowed())return;const width=Number(owner.inspection.image.width) || photo.naturalWidth,height=Number(owner.inspection.image.height) || photo.naturalHeight;if(width<100 || height<100){setDialogError("#draft-scope-error","照片太小，請重新拍攝清楚的主標籤。");return;}Object.assign(context,{photo,width,height});for(const key of ["x","width"])$("#draft-scope-"+key).max=width;for(const key of ["y","height"])$("#draft-scope-"+key).max=height;$("#draft-scope-fields").disabled=false;$("#draft-scope-preview-button").disabled=false;$("#draft-scope-reset").disabled=false;$("#draft-scope-source-note").textContent=`原照片 ${width} × ${height} 像素。請框住同張標籤的內容、營養欄與廠商資訊。`;const region=owner.draftScopeSelection || selectedLabelRegion(owner.inspection);updateDraftScopeSelection(region ? {x:region.x,y:region.y,width:region.width,height:region.height} : {x:0,y:0,width,height});};
  photo.onerror=()=>{if(state.draftScope===context)setDialogError("#draft-scope-error","無法載入原照片，草稿尚未變更。");};photo.src=owner.inspection.image.url;
}
function previewDraftScope(){
  const context=state.draftScope;if(state.busy || !allowed() || !context?.photo || manualStandard!==context.owner)return;
  invalidateDraftScopePreview();setDialogError("#draft-scope-error");if(draftScopeSignature(context.owner)!==context.signature){setDialogError("#draft-scope-error","草稿內容已變更，請關閉並重新開啟範圍選取。");return;}
  let selection;try{selection=draftScopeInput();}catch(error){setDialogError("#draft-scope-error",error.message);return;}context.selection=selection;drawDraftScopeSelection();
  const result=filterDraftRowsByScope(context.owner,selection,context.width,context.height);context.preview={...result,selection:{...selection},signature:context.signature};
  $("#draft-scope-summary").textContent=`保留 ${result.kept.length} 行 · 排除 ${result.removed.length} 行 · ${result.uncertain.length} 行位置待確認`;
  for(const [id,rows] of [["draft-scope-kept",result.kept],["draft-scope-removed",result.removed]]){const area=$("#"+id);area.replaceChildren();rows.forEach(row=>area.append(element("p","manual-history-text",row.text)));if(!rows.length)area.append(element("p","help","沒有文字。"));}
  const area=$("#draft-scope-uncertain");area.replaceChildren();result.uncertain.forEach(item=>area.append(element("p","manual-history-text",item.row.text),element("p","help",item.reason)));$("#draft-scope-uncertain-details").hidden=!result.uncertain.length;$("#draft-scope-uncertain-details").open=!!result.uncertain.length;$("#draft-scope-preview").hidden=false;
  if(!result.kept.length)setDialogError("#draft-scope-error","範圍內沒有可保留文字，請重新框選完整主標籤。");else if(!result.removed.length)setDialogError("#draft-scope-error","沒有可安全排除的文字。跨框、已修改或無位置的文字會保留，可回草稿直接修正。");
  $("#draft-scope-preview").scrollIntoView({block:"start",behavior:"instant"});
}
function applyDraftScope(){
  const context=state.draftScope,preview=context?.preview;if(state.busy || !allowed() || !preview || manualStandard!==context.owner || !$("#draft-scope-confirm").checked || !preview.kept.length || !preview.removed.length)return;
  let selection;try{selection=draftScopeInput();}catch(error){setDialogError("#draft-scope-error",error.message);return;}
  if(draftScopeSignature(context.owner)!==preview.signature || JSON.stringify(selection)!==JSON.stringify(preview.selection)){invalidateDraftScopePreview();setDialogError("#draft-scope-error","草稿或範圍已變更，請重新預覽，尚未套用。");return;}
  const owner=context.owner;owner.scopeUndo={text:$("#manual-standard-lines").value,rows:JSON.parse(JSON.stringify(owner.textRows)),sections:Object.fromEntries(["content","nutrition","uncertain"].map(section=>[section,textEditorInput("manual",section).value])),sectionRows:JSON.parse(JSON.stringify(owner.sectionRows || {})),selection:owner.draftScopeSelection || null};
  updateCanonicalText("manual",preview.kept);owner.draftScopeSelection={...preview.selection};renderSectionEditors("manual");renderTextRowLocations("manual");invalidateManualPreview();owner.scopeUndo.afterSignature=draftScopeSignature(owner);$("#manual-scope-undo").hidden=false;$("#manual-scope-note").textContent=`已排除 ${preview.removed.length} 行框外文字，${preview.uncertain.length} 行位置不確定仍保留。只改目前草稿，尚未儲存。`;closeDraftScopeDialog();drawManualDraftPhoto();
}
function undoDraftScope(){
  const owner=manualStandard,undo=owner?.scopeUndo;if(!requireAdmin() || state.busy || !undo)return;
  if(draftScopeSignature(owner)!==undo.afterSignature){setDialogError("#manual-standard-error","篩選後已有文字修改，為保留你的編輯，不直接覆蓋。可先複製文字，再重新開啟原草稿。");return;}
  owner.textRows=JSON.parse(JSON.stringify(undo.rows));$("#manual-standard-lines").value=undo.text;owner.draftScopeSelection=undo.selection;renderSectionEditors("manual");for(const section of ["content","nutrition","uncertain"])textEditorInput("manual",section).value=undo.sections[section];owner.sectionRows=JSON.parse(JSON.stringify(undo.sectionRows));renderTextRowLocations("manual");owner.scopeUndo=null;$("#manual-scope-undo").hidden=true;$("#manual-scope-note").textContent="已撤回範圍篩選，恢復篩選前的草稿文字；尚未儲存。";invalidateManualPreview();drawManualDraftPhoto();
}
function draftScopeConfirmChanged(){const preview=state.draftScope?.preview;$("#draft-scope-apply").disabled=state.busy || !allowed() || !$("#draft-scope-confirm").checked || !preview?.kept.length || !preview?.removed.length;}
function draftScopeFieldsChanged(){invalidateDraftScopePreview();setDialogError("#draft-scope-error");try{updateDraftScopeSelection(draftScopeInput());}catch(error){setDialogError("#draft-scope-error",error.message);}}
function draftScopePoint(event){const context=state.draftScope,rect=$("#draft-scope-canvas").getBoundingClientRect();return {x:(event.clientX-rect.left)/rect.width*context.width,y:(event.clientY-rect.top)/rect.height*context.height};}
function startDraftScopePointer(event){const context=state.draftScope;if(state.busy || !context?.photo || event.isPrimary===false || (event.pointerType==="mouse" && event.button!==0))return;event.preventDefault();context.drag={pointer:event.pointerId,start:draftScopePoint(event)};$("#draft-scope-canvas").setPointerCapture?.(event.pointerId);}
function moveDraftScopePointer(event){const context=state.draftScope;if(!context?.drag || context.drag.pointer!==event.pointerId || state.busy)return;event.preventDefault();updateDraftScopeSelection(selectionFromPoints(context.drag.start,draftScopePoint(event),context.width,context.height));}
function endDraftScopePointer(event){const context=state.draftScope;if(!context?.drag || context.drag.pointer!==event.pointerId)return;moveDraftScopePointer(event);context.drag=null;if($("#draft-scope-canvas").hasPointerCapture?.(event.pointerId))$("#draft-scope-canvas").releasePointerCapture(event.pointerId);}
function cropInputSelection(){
  const result={};for(const key of ["x","y","width","height"]){const value=$("#crop-"+key).value;if(value==="")throw new Error("請填寫完整的裁切座標與尺寸。");result[key]=Number(value);}
  return cropBounds(result,state.crop.width,state.crop.height);
}
function invalidateCropPreview(){
  if(state.crop)state.crop.preview=null;$("#crop-preview-panel").hidden=true;$("#crop-submit").disabled=true;
}
function syncCropScope(selection=null){
  const context=state.crop;if(!context)return;const input=$("#crop-label-scope");
  if(!context.wholeScope)context.wholeScope=["sticker","full"].includes(input.value) ? input.value : "sticker";
  context.manualScope=!!selection && !(selection.x===0 && selection.y===0 && selection.width===context.width && selection.height===context.height);
  if(context.manualScope){input.replaceChildren(new Option("辨識整個手動選取範圍","full"));input.value="full";input.disabled=true;}
  else{input.replaceChildren(new Option("標籤主要區域（自動選取）","sticker"),new Option("整張照片","full"));input.value=context.wholeScope;input.disabled=state.busy;}
  $("#crop-scope-note").textContent=context.manualScope ? "將辨識整個手動選取範圍，請保留此標籤完整文字與相鄰營養欄。" : "目前選取整張照片，可選自動找主標籤範圍或讀取全圖。";
}
function updateCropSelection(selection){
  const context=state.crop;if(!context)return;context.selection={...selection};invalidateCropPreview();
  for(const key of ["x","y","width","height"])$("#crop-"+key).value=selection[key];
  syncCropScope(selection);
  $("#crop-selection-note").textContent=`選取：左 ${selection.x}、上 ${selection.y}，${selection.width} × ${selection.height} 像素。`;
  drawCropSelection();
}
function drawCropSelection(){
  const context=state.crop;if(!context?.photo)return;
  const canvas=$("#crop-canvas"),scale=Math.min(1,1400/context.width);canvas.width=Math.max(1,Math.round(context.width*scale));canvas.height=Math.max(1,Math.round(context.height*scale));
  const drawing=canvas.getContext("2d");if(!drawing)return;drawing.drawImage(context.photo,0,0,canvas.width,canvas.height);
  const s=context.selection;if(!s)return;
  const sx=canvas.width/context.width,sy=canvas.height/context.height,x=s.x*sx,y=s.y*sy,w=s.width*sx,h=s.height*sy;
  drawing.fillStyle="rgba(0,0,0,.48)";drawing.fillRect(0,0,canvas.width,y);drawing.fillRect(0,y,x,h);drawing.fillRect(x+w,y,canvas.width-x-w,h);drawing.fillRect(0,y+h,canvas.width,canvas.height-y-h);
  drawing.strokeStyle="#f2df6a";drawing.lineWidth=Math.max(2,canvas.width/350);drawing.strokeRect(x,y,w,h);
}
function cropPointerPoint(event){const rect=$("#crop-canvas").getBoundingClientRect();return {x:(event.clientX-rect.left)/rect.width*state.crop.width,y:(event.clientY-rect.top)/rect.height*state.crop.height};}
function startCropPointer(event){
  const context=state.crop;if(state.busy || !context?.photo || event.isPrimary===false || (event.pointerType==="mouse" && event.button!==0))return;
  event.preventDefault();context.drag={pointer:event.pointerId,start:cropPointerPoint(event)};$("#crop-canvas").setPointerCapture?.(event.pointerId);setDialogError("#crop-error");
}
function moveCropPointer(event){const context=state.crop;if(!context?.drag || context.drag.pointer!==event.pointerId || state.busy)return;event.preventDefault();updateCropSelection(selectionFromPoints(context.drag.start,cropPointerPoint(event),context.width,context.height));}
function endCropPointer(event){const context=state.crop;if(!context?.drag || context.drag.pointer!==event.pointerId)return;moveCropPointer(event);context.drag=null;if($("#crop-canvas").hasPointerCapture?.(event.pointerId))$("#crop-canvas").releasePointerCapture(event.pointerId);}
function closeCropDialog(){state.crop=null;if($("#crop-dialog").open)$("#crop-dialog").close();for(const id of ["crop-canvas","crop-preview-canvas"]){const canvas=$("#"+id);canvas.width=1;canvas.height=1;}}
function openCropDialog(inspection=state.inspection){
  if(state.busy || !inspection?.image?.url)return;
  const context={inspectionId:inspection.id,photo:null,width:0,height:0,selection:null,preview:null,region:selectedLabelRegion(inspection),wholeScope:$("#label-scope").value || "sticker"};state.crop=context;
  $("#crop-recognition-engine").value=$("#recognition-engine").value || "local";syncCropScope();recognitionChoiceNote("crop-");
  $("#crop-source-note").textContent="載入保存照片中…";$("#crop-selection-note").textContent="";$("#crop-selection-fields").disabled=true;$("#crop-preview-button").disabled=true;$("#crop-reset").disabled=true;
  invalidateCropPreview();setDialogError("#crop-error");for(const id of ["crop-canvas","crop-preview-canvas"]){$("#"+id).width=1;$("#"+id).height=1;}
  $("#crop-dialog").showModal();const photo=new Image();
  photo.onload=()=>{if(state.crop!==context)return;const width=Number(inspection.image.width) || photo.naturalWidth,height=Number(inspection.image.height) || photo.naturalHeight;if(!(width>=100 && height>=100)){setDialogError("#crop-error","照片尺寸不足，請重新拍攝清楚標籤。");return;}
    Object.assign(context,{photo,width,height});$("#crop-source-note").textContent=`保存照片 ${width} × ${height} 像素。框選時請保留此標籤完整文字。`;
    for(const key of ["x","width"])$("#crop-"+key).max=width;for(const key of ["y","height"])$("#crop-"+key).max=height;
    $("#crop-selection-fields").disabled=false;$("#crop-preview-button").disabled=false;$("#crop-reset").disabled=false;const region=context.region;updateCropSelection(region ? {x:region.x,y:region.y,width:region.width,height:region.height} : {x:0,y:0,width,height});
    if(region)$("#crop-source-note").textContent+=" 已帶入本次選中的貼紙框，可重新調整。";
  };
  photo.onerror=()=>{if(state.crop===context)setDialogError("#crop-error","無法載入保存照片，請稍後再試或重新拍攝。");};photo.src=inspection.image.url;
}
function previewCrop(){
  const context=state.crop;if(state.busy || !context?.photo)return;setDialogError("#crop-error");let selection,settings;
  try{selection=cropInputSelection();syncCropScope(selection);settings=recognitionSettings("crop-");}catch(error){invalidateCropPreview();setDialogError("#crop-error",error.message);return;}
  context.selection=selection;drawCropSelection();
  const whole=selection.x===0 && selection.y===0 && selection.width===context.width && selection.height===context.height;
  const signature=JSON.stringify({crop:whole ? null : selection,...settings}),prior=context.lastRequest;
  const requestId=prior?.signature===signature ? prior.id : newRequestId();
  context.lastRequest={signature,id:requestId};context.preview={selection:{...selection},settings,body:{...(whole ? {} : {crop:selection}),...settings,request_id:requestId}};
  const canvas=$("#crop-preview-canvas"),scale=Math.min(1,1400/selection.width);canvas.width=Math.max(1,Math.round(selection.width*scale));canvas.height=Math.max(1,Math.round(selection.height*scale));
  canvas.getContext("2d").drawImage(context.photo,selection.x,selection.y,selection.width,selection.height,0,0,canvas.width,canvas.height);
  $("#crop-preview-title").textContent=whole ? "預覽：整張照片重新辨識" : `預覽：${selection.width} × ${selection.height} 像素的選取範圍`;
  $("#crop-preview-note").textContent=whole ? "目前選的是整張照片。使用相同照片重新辨識不保證改善；模糊反光請重拍，多張標籤請先框選單張。" : "請確認已保留此標籤完整文字，且沒有包含另一張標籤。";
  $("#crop-preview-panel").hidden=false;$("#crop-submit").disabled=false;$("#crop-submit").textContent=settings.recognition_engine==="cloud" ? "使用雲端重新辨識（付費）" : whole ? "整張重新辨識" : "依此範圍重新辨識";$("#crop-preview-panel").scrollIntoView({block:"start",behavior:"instant"});
}
async function recognizeCrop(){
  const context=state.crop;if(state.busy || !context?.preview)return;let selection,settings;
  try{selection=cropInputSelection();syncCropScope(selection);settings=recognitionSettings("crop-");}catch(error){invalidateCropPreview();setDialogError("#crop-error",error.message);return;}
  if(JSON.stringify(selection)!==JSON.stringify(context.preview.selection) || JSON.stringify(settings)!==JSON.stringify(context.preview.settings)){invalidateCropPreview();setDialogError("#crop-error","範圍或辨識方式已變更，請重新預覽後送出。");return;}
  setDialogError("#crop-error");setBusy(true);$$("#crop-dialog button").forEach(node=>{node.disabled=true;});$("#crop-selection-fields").disabled=true;setUploadError("inspection");
  try{const job=await api(`/api/inspections/${encodeURIComponent(context.inspectionId)}/recognize`,{method:"POST",body:context.preview.body});
    if(state.crop!==context)return;sessionStorage.setItem("labelcheck-pending",JSON.stringify({id:job.id,kind:"recognition"}));closeCropDialog();showView("inspect");setBusy(true,"recognition");$("#inspect-progress span:last-child").textContent="正在重新讀取照片；原紀錄仍保留…";await pollJob(job.id,"recognition");
  }catch(error){if(state.crop===context)setDialogError("#crop-error",error.message);else reportUploadFailure("inspection",error);}
  finally{setBusy(false);$$("#crop-dialog button").forEach(node=>{node.disabled=false;});$("#crop-selection-fields").disabled=false;$("#crop-submit").disabled=!state.crop?.preview;}
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
$("#crop-close").onclick=()=>{if(!state.busy)closeCropDialog();};
$("#crop-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();else closeCropDialog();});
$("#crop-canvas").onpointerdown=startCropPointer;$("#crop-canvas").onpointermove=moveCropPointer;$("#crop-canvas").onpointerup=endCropPointer;
$("#crop-canvas").onpointercancel=()=>{if(state.crop)state.crop.drag=null;};
$("#crop-selection-fields").addEventListener("input",()=>{if(state.busy)return;invalidateCropPreview();setDialogError("#crop-error");try{const selection=cropInputSelection();updateCropSelection(selection);}catch(_){/* Keep typed values while the user completes the coordinate. */}});
$("#crop-preview-button").onclick=previewCrop;$("#crop-submit").onclick=recognizeCrop;
$("#crop-reset").onclick=()=>{const context=state.crop;if(!state.busy && context?.photo){setDialogError("#crop-error");updateCropSelection({x:0,y:0,width:context.width,height:context.height});}};
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
for(const prefix of ["","reference-","crop-"])for(const name of ["recognition-engine","label-scope"])$("#"+prefix+name).onchange=()=>{if(name==="recognition-engine")$("#"+prefix+name).dataset.recognitionInitialized="true";recognitionChoiceNote(prefix);};
for(const slot of ["inspect","reference"])$("#"+slot+"-upload-resend").onclick=()=>{const pending=state.uploadRequests[slot];if(pending && !state.busy)upload(pending.file,slot==="reference" ? "reference" : "inspection");};
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
$("#standard-edit-text").oninput=()=>changeTextEditor("standard");
$("#standard-photo-canvas").onclick=event=>textEditorPhotoClicked("standard",event);
$("#standard-regroup-button").onclick=previewRegroupedStandard;
$("#standard-draft-latest").onclick=()=>selectStandardDraft("latest");
$("#standard-draft-current").onclick=()=>selectStandardDraft("current");
$("#standard-use-photo").onchange=invalidateStandardPreview;
$("#standard-regroup-apply").onclick=applyRegroupedStandard;
$("#standard-regroup-cancel").onclick=()=>{if(!state.busy){if(state.standardEdit)state.standardEdit.regroupPreview=null;$("#standard-regroup-preview").hidden=true;}};
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
$("#recognition-sample-refresh").onclick=loadRecognitionSamples;
$("#recognition-sample-download").onclick=downloadRecognitionSamples;
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
$("#manual-standard-close").onclick=()=>{if(!state.busy){closeDraftScopeDialog();manualStandard=null;$("#manual-standard-dialog").close();}};
$("#manual-standard-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();else{closeDraftScopeDialog();manualStandard=null;}});
$("#manual-standard-form").addEventListener("input",event=>{if(!["manual-standard-confirm","manual-standard-reviewer","manual-standard-note"].includes(event.target.id))invalidateManualPreview();});
$("#manual-standard-preview-button").onclick=previewManualStandard;
$("#manual-standard-lines").oninput=manualBulkChanged;
$("#manual-photo-canvas").onclick=manualPhotoClicked;
$("#manual-scope-open").onclick=openDraftScope;
$("#manual-scope-undo").onclick=undoDraftScope;
$("#draft-scope-close").onclick=closeDraftScopeDialog;
$("#draft-scope-dialog").addEventListener("cancel",event=>{event.preventDefault();closeDraftScopeDialog();});
$("#draft-scope-canvas").onpointerdown=startDraftScopePointer;
$("#draft-scope-canvas").onpointermove=moveDraftScopePointer;
$("#draft-scope-canvas").onpointerup=endDraftScopePointer;
$("#draft-scope-canvas").onpointercancel=()=>{if(state.draftScope)state.draftScope.drag=null;};
$("#draft-scope-fields").oninput=draftScopeFieldsChanged;
$("#draft-scope-preview-button").onclick=previewDraftScope;
$("#draft-scope-reset").onclick=()=>{const context=state.draftScope;if(context?.photo)updateDraftScopeSelection({x:0,y:0,width:context.width,height:context.height});};
$("#draft-scope-confirm").onchange=draftScopeConfirmChanged;
$("#draft-scope-apply").onclick=applyDraftScope;
for(const kind of ["manual","standard"]){
  for(const section of ["full","content","nutrition","uncertain"]){const input=textEditorInput(kind,section);input.onclick=input.onkeyup=input.onselect=input.onfocus=()=>textEditorSelection(kind,section);if(section!=="full")input.oninput=()=>changeSectionEditor(kind,section);}
  for(const action of ["delete","merge"])$("#"+kind+"-text-"+action).onclick=()=>editTextSelection(kind,action,textEditorContext(kind)?.activeTextSection || "content");
  for(const target of ["content","nutrition"])$("#"+kind+"-move-"+target).onclick=()=>moveTextSelection(kind,target);
  $("#"+kind+"-add-nutrition").onclick=()=>{if(state.busy || !textEditorContext(kind) || (kind==="standard" && (state.standardEdit.conflict || state.standardEdit.operation!=="update")))return;$("#"+kind+"-nutrition-zone").hidden=false;$("#"+kind+"-no-nutrition").hidden=true;$("#"+kind+"-add-nutrition").hidden=true;textEditorInput(kind,"nutrition").focus();textEditorSelection(kind,"nutrition");};
}
$("#manual-add-line").onclick=()=>editTextSelection("manual","split",manualStandard?.activeTextSection || "content");
$("#standard-text-split").onclick=()=>editTextSelection("standard","split",state.standardEdit?.activeTextSection || "content");
$("#manual-standard-form").onsubmit=saveManualStandard;
$("#reference-photo-form").onsubmit=saveReferencePhoto;
$("#reference-photo-close").onclick=()=>{if(!state.busy){state.referencePhoto=null;$("#reference-photo-dialog").close();}};
$("#reference-photo-dialog").addEventListener("cancel",event=>{if(state.busy)event.preventDefault();else state.referencePhoto=null;});
$("#standard-library-search").onsubmit=event=>{event.preventDefault();loadManualLibrary(1);};
$("#standard-library-prev").onclick=()=>loadManualLibrary(Math.max(1,manualLibraryPage-1));
$("#standard-library-next").onclick=()=>loadManualLibrary(manualLibraryPage+1);
for(const id of ["standard-library-category","standard-library-state"])$("#"+id).onchange=()=>loadManualLibrary(1);
$("#standard-library-add-category").onclick=()=>openLibraryCategory("filter");
$("#library-detail-add-category").onclick=()=>openLibraryCategory("detail");
$("#library-category-close").onclick=()=>closeLibraryCategory();
$("#library-category-dialog").addEventListener("cancel",event=>{event.preventDefault();closeLibraryCategory();});
$("#library-category-form").onsubmit=saveLibraryNewCategory;
$("#library-detail-close").onclick=()=>closeLibraryDetail();
$("#library-detail-dialog").addEventListener("cancel",event=>{event.preventDefault();closeLibraryDetail();});
$("#library-detail-edit").onclick=beginLibraryEdit;
$("#library-edit-cancel").onclick=()=>{if(!state.busy && state.libraryDetail?.data){renderLibraryDetail(state.libraryDetail.data);setDialogError("#library-detail-error");}};
for(const section of ["content","nutrition","uncertain"])$("#library-"+section+"-text").oninput=()=>changeLibrarySection(section);
$("#library-full-text").oninput=changeLibraryFullText;
for(const id of ["library-photo-dates","library-photo-arrival-check"])$("#"+id).onchange=toggleLibraryPhotoDates;
$("#library-detail-form").addEventListener("input",event=>{if(!["library-edit-reviewer","library-edit-note","library-edit-confirm"].includes(event.target.id))invalidateLibraryPreview();});
$("#library-edit-preview-button").onclick=previewLibraryChanges;
$("#library-detail-form").onsubmit=saveLibraryChanges;
$("#library-detail-remove").onclick=()=>previewLibraryState("remove");
$("#library-detail-restore").onclick=()=>previewLibraryState("restore");
$("#library-state-cancel").onclick=()=>{if(!state.busy){if(state.libraryDetail)state.libraryDetail.operation=null;$("#library-state-preview").hidden=true;}};
$("#library-state-save").onclick=saveLibraryState;
$("#library-detail-category-save").onclick=saveLibraryCategory;
$("#library-detail-reload").onclick=()=>{const context=state.libraryDetail;if(context)openLibraryDetail(context.kind,context.key);};
$("#library-detail-use").onclick=useLibraryStandard;
for(const id of ["pending-standard-range","pending-standard-state"])$("#"+id).onchange=()=>{pendingNotice();loadPendingStandards(1);};
$("#pending-standard-refresh").onclick=()=>{pendingNotice();loadPendingStandards(1);};
$("#pending-standard-prev").onclick=()=>loadPendingStandards(Math.max(1,pendingStandardsPage-1));
$("#pending-standard-next").onclick=()=>loadPendingStandards(pendingStandardsPage+1);
$("#pending-standard-select-all").onchange=event=>selectPendingPage(event.target.checked);
$("#pending-standard-remove-selected").onclick=()=>changePendingState("remove");
$("#pending-standard-restore-selected").onclick=()=>changePendingState("restore");
initialize().catch(e=>toast(e.message,true));
