"use strict";
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = {csrf: "", templates: [], referenceJob: null, source: null, supersedes: null, busy: false, page: 1, inspection: null};
const statusLabels = {pass: "已核對項目相符", fail: "發現差異", review: "需要人工複核", read: "僅辨識"};
const reviewLabels = {confirmed_good: "人工確認正確", confirmed_bad: "人工確認異常", retake: "需要重拍"};
const textFields = ["product", "spec", "storage", "origin", "company", "address", "phone"];
const fieldLabels = {product: "品名", spec: "規格", storage: "保存條件", origin: "產地", company: "公司名稱", address: "地址", phone: "電話"};
let toastTimer;

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
async function api(path, options = {}) {
  const headers = {...options.headers};
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  if (options.body && !(options.body instanceof FormData)) { headers["Content-Type"] = "application/json"; options.body = JSON.stringify(options.body); }
  const response = await fetch(path, {...options, headers});
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") { $("#login").hidden = false; $("#app-shell").hidden = true; }
    throw new Error(payload.error || "連線失敗，請確認網路後重試。");
  }
  return payload;
}
function when(iso) { return new Date(iso).toLocaleString("zh-TW", {timeZone: "Asia/Taipei", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}); }
function badge(status, text) { return element("span", `badge ${status}`, text || statusLabels[status]); }
function showView(view) {
  if (!["inspect", "library", "standard", "history"].includes(view)) view = "inspect";
  $$(".view").forEach(x => { x.hidden = x.id !== `view-${view}`; });
  $$("[data-view]").forEach(x => { x.classList.toggle("active", x.dataset.view === (view === "standard" ? "library" : view)); });
  $("#breadcrumb").textContent = `工作區 / ${{inspect:"檢查標籤",library:"標準標籤庫",standard:"建立標準標籤",history:"檢查紀錄"}[view]}`;
  history.replaceState(null, "", `#${view}`);
  if (view === "history") loadHistory().catch(e => toast(e.message, true));
  window.scrollTo({top: 0, behavior: "instant"});
}
function setBusy(busy, kind = "") {
  state.busy = busy;
  $$("[data-file]").forEach(b => { b.disabled = busy; });
  $("#scan-button").disabled = busy;
  $("#source-search button").disabled = busy;
  $("#template-select").disabled = busy;
  $("#batch-date").disabled = busy;
  $("#arrival-date").disabled = busy;
  $$("[data-action='new-standard']").forEach(x => { x.disabled = busy; });
  $("#inspect-progress").hidden = !busy || !["inspection", "recognition"].includes(kind);
  $("#reference-progress").hidden = !busy || kind !== "reference";
}
function clearResult() { state.inspection = null; $("#result-area").replaceChildren(); $("#result-area").hidden = true; $("#result-placeholder").hidden = false; }
function selectedStandard() {
  const standard = state.templates.find(t => t.id === $("#template-select").value);
  const node = $("#selected-standard"); node.replaceChildren(); node.hidden = !standard;
  $("#recognition-help").hidden = !!standard;
  if (standard) {
    $("#template-options").open = true;
    if (standard.image) { const img = element("img"); img.src = standard.image.thumbnail; img.alt = "選定的標準照片"; node.append(img); }
    const info = element("div"); info.append(element("strong", "", standard.fields.product), element("p", "", `第 ${standard.version} 版 · ${standard.approved_by} 已確認`));
    const checked = textFields.filter(key => standard.fields[key]).map(key => fieldLabels[key]);
    if (standard.rules.dates) checked.push("製造／有效日期");
    if (standard.rules.arrival) checked.push("到店日");
    info.append(element("p", "help", `核對項目：${checked.join("、")}`));
    node.append(info);
  }
  setBusy(state.busy);
}
async function loadTemplates(selectedId) {
  const payload = await api("/api/templates"); state.templates = payload.items;
  const select = $("#template-select"), previous = selectedId || select.value;
  select.replaceChildren();
  select.append(new Option("直接掃描（固定文字與日期檢查）", ""));
  state.templates.forEach(t => select.append(new Option(`${t.name} · 第 ${t.version} 版`, t.id)));
  if (state.templates.some(t => t.id === previous)) select.value = previous;
  $("#nav-count").textContent = String(state.templates.length);
  selectedStandard(); renderLibrary();
}
async function loadScanConfig() {
  const config = await api("/api/scan-config"), list = $("#scan-standards");
  list.replaceChildren();
  config.standards.forEach(item => {
    const row = element("p", "fixed-standard");
    row.append(element("span", "fixed-standard-label", item.label), element("span", "", item.value));
    list.append(row);
  });
}
function newStandard(previous = null) {
  if (state.busy) return toast("請等待目前照片完成辨識。");
  state.referenceJob = null; state.source = null; state.supersedes = previous;
  $("#source-results").replaceChildren(); $("#source-note").textContent = "";
  $("#standard-form").reset(); $("#standard-fields").disabled = true;
  $("#reference-preview").hidden = true; $("#reference-preview").removeAttribute("src");
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
  state.referenceJob = job; state.source = null;
  $("#source-note").textContent = "";
  const form = $("#standard-form"), fields = job.result.fields;
  $("#reference-preview").src = job.image.url; $("#reference-preview").hidden = false;
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
    const job = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    if (job.state === "failed") { sessionStorage.removeItem("labelcheck-pending"); throw new Error(job.error); }
    if (job.state === "done") {
      sessionStorage.removeItem("labelcheck-pending");
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
  if (!file || state.busy) return;
  if (file.size > 15 * 1024 * 1024) return toast("照片超過 15 MB，請縮小後上傳。", true);
  const template = $("#template-select").value;
  if (kind === "inspection" && !template) kind = "recognition";
  const form = new FormData(); form.append("photo", file); form.append("kind", kind);
  if (kind !== "reference") { form.append("template_id", template); form.append("batch_date", $("#batch-date").value); form.append("arrival_date", $("#arrival-date").value); clearResult(); }
  else { state.referenceJob = null; state.source = null; $("#standard-fields").disabled = true; $("#reference-preview").hidden = true; $("#reference-ocr").hidden = true; }
  setBusy(true, kind);
  try {
    const job = await api("/api/jobs", {method: "POST", body: form});
    sessionStorage.setItem("labelcheck-pending", JSON.stringify({id: job.id, kind, supersedes_id:kind === "reference" ? state.supersedes?.id || null : null}));
    await pollJob(job.id, kind);
  } catch (error) { toast(error.message, true); }
  finally { setBusy(false); }
}
async function saveStandard(event) {
  event.preventDefault(); if ((!state.referenceJob && !state.source) || state.busy) return;
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
function renderLibrary() {
  const list = $("#library-list"); list.replaceChildren();
  if (!state.templates.length) {
    const empty = element("div", "empty-state"); empty.append(element("h2", "", "尚未建立標準標籤"), element("p", "", "從一張人工確認過的正確照片開始。"));
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
    use.onclick = () => { if(state.busy) return toast("請等待目前辨識完成。"); $("#template-select").value = standard.id; selectedStandard(); clearResult(); showView("inspect"); };
    edit.onclick = () => newStandard(standard); actions.append(use, edit); content.append(actions); card.append(content); list.append(card);
  });
}
async function loadInspection(id) {
  const inspection = await api(`/api/inspections/${encodeURIComponent(id)}`); state.inspection = inspection;
  renderInspection(inspection); showView("inspect");
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
function resultLine(check, expandable) {
  const row = element(expandable ? "details" : "div", `result-line ${check.status}`);
  const body = expandable ? element("summary", "result-line-summary") : row;
  const title = element("div", "result-line-title");
  title.append(element("span", "result-line-label", check.label || "辨識文字"), badge(check.status, {pass:"相符",fail:"有差異",review:"需確認",read:"僅辨識"}[check.status]));
  const shown = check.display_actual ?? check.display_text ?? check.actual;
  body.append(title, element("p", "result-line-text", shown || "未辨識到"));
  if (!expandable && check.status === "pass" && /日期|到店/.test(check.label || "") && check.reason) body.append(element("p", "result-line-reason", check.reason));
  if (expandable) {
    body.append(element("span", "result-line-expand", "展開查看原因與原文")); row.append(body);
    const detail = element("div", "result-line-detail");
    if (check.reason) detail.append(element("p", "check-reason", check.reason));
    if (check.conversion_changed) detail.append(element("p", "display-note", "上方以繁體顯示；下方保留 OCR 原文，請對照照片確認。"));
    for (const [key, label] of [["expected", "標準"], ["actual", "原文"]]) {
      if (key === "expected" && !check.expected) continue;
      const comparison = element("div", "comparison-row"); comparison.append(element("span", "", label), diffNode(check, key)); detail.append(comparison);
    }
    if (check.source_lines?.length) {
      const original = element("details", "source-lines"), list = element("div", "ocr-lines");
      original.append(element("summary", "", "對應照片的完整原文"), list); renderOCR(check.source_lines, list); detail.append(original);
    }
    row.append(detail);
  }
  return row;
}
function renderResultGroups(result, ocrLines, area) {
  const groups = element("div", "result-groups"); groups.id = "result-groups";
  for (const [id, title, statuses, empty] of [
    ["matched", "相符", ["pass"], "目前沒有可確認相符的項目。"],
    ["attention", "有差異／需確認", ["fail", "review"], "目前沒有發現差異或待確認項目。"]
  ]) {
    const section = element("section", `result-group result-group-${id}`); section.id = `result-${id}`;
    const checks = result.checks.filter(check => statuses.includes(check.status));
    const heading = element("h2", "result-group-heading", title); heading.append(element("span", "group-count", String(checks.length))); section.append(heading);
    if (!checks.length) section.append(element("p", "group-empty", empty));
    checks.forEach(check => section.append(resultLine(check, id === "attention")));
    groups.append(section);
  }
  area.append(groups);
  const reads = result.checks.filter(check => check.status === "read");
  const covered = new Set(result.checks.flatMap(check => check.line_ids || []));
  // Older saved results may not account for text outside recognized fields.
  const extra = ocrLines.filter(line => !covered.has(line.id)).map(line => ({key:`line-${line.id}`,label:"辨識文字",status:line.score < .94 ? "review" : "read",actual:line.text,display_actual:line.display_text ?? line.text,line_ids:[line.id],reason:"尚無比對依據，請對照原圖確認。"}));
  const extraIssues = extra.filter(check => check.status === "review");
  if (extraIssues.length) {
    const attention = $("#result-attention", groups); $(".group-empty", attention)?.remove();
    extraIssues.forEach(check => attention.append(resultLine(check, true)));
    $(".group-count", attention).textContent = String(result.checks.filter(check => ["fail","review"].includes(check.status)).length + extraIssues.length);
  }
  const other = [...reads, ...extra.filter(check => check.status === "read")];
  if (other.length) {
    const section = element("section", "result-read"); section.id = "result-read";
    const heading = element("h2", "result-group-heading", "其他已辨識文字"); heading.append(element("span", "group-count", String(other.length)));
    section.append(heading, element("p", "read-help", "以下僅完成文字辨識，尚無比對依據，不能據此確認正確。"));
    other.forEach(check => section.append(resultLine(check, false))); area.append(section);
  }
}
function renderInspection(inspection) {
  const area = $("#result-area"); area.replaceChildren(); area.hidden = false; $("#result-placeholder").hidden = true;
  const result = inspection.result, header = element("div", `result-header ${result.status}`);
  header.append(badge(result.status), element("h2", "", result.status === "pass" ? "已核對的項目相符" : result.status === "fail" ? "請確認標示差異" : "有內容需要再確認"), element("p", "", `${inspection.template_snapshot.name}${inspection.template_snapshot.version ? ` · 第 ${inspection.template_snapshot.version} 版` : ""} · ${when(inspection.created_at)}`));
  const counts = element("div", "result-counts"); counts.append(element("span", "", `${result.counts.pass} 項相符`), element("span", "", `${result.counts.fail} 項差異`), element("span", "", `${result.counts.review} 項待確認`));
  if (result.counts.read) counts.append(element("span", "", `${result.counts.read} 項僅辨識`)); header.append(counts); area.append(header);
  renderResultGroups(result, inspection.ocr.lines, area);
  if (result.notes.length) { const notes = element("div", "result-notes"); result.notes.forEach(note => notes.append(element("p", "", note))); area.append(notes); }
  const evidence = element("div", "panel evidence"); evidence.append(element("h2", "", "對照原圖"));
  const pair = element("div", "photo-pair");
  const reference = element("figure"), observed = element("figure"), refScroll = element("div", "photo-scroll"), observedScroll = element("div", "photo-scroll");
  if (inspection.reference_image) {
    const ref = element("img"); ref.src = inspection.reference_image.url; ref.alt = "已確認的標準照片"; refScroll.append(ref);
    reference.append(element("figcaption", "", "標準照片"), refScroll); pair.append(reference);
  }
  const canvas = element("canvas"); canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", "待檢照片；紅框為差異，黃框為待確認文字"); observedScroll.append(canvas);
  observed.append(element("figcaption", "", "待檢照片 · 紅框差異／黃框複核"), observedScroll); pair.append(observed); evidence.append(pair); drawEvidence(canvas, inspection);
  const details = element("details"), raw = element("div", "ocr-lines"); details.append(element("summary", "", "查看完整辨識原文"), raw); renderOCR(inspection.ocr.lines, raw); evidence.append(details);
  const reviewList = element("div"); inspection.reviews.forEach(review => { const row = element("div", "review-record"); row.append(element("strong", "", reviewLabels[review.decision]), element("p", "", review.note), element("small", "", `${review.reviewer} · ${when(review.created_at)}`)); reviewList.append(row); }); evidence.append(reviewList);
  const review = element("form", "review-form"); review.append(element("h3", "", "人工複核"), element("p", "help", "複核紀錄會另外保留，原始辨識結果不會被覆蓋。"));
  function control(label, input) { const wrap = element("label", "", label); wrap.append(input); review.append(wrap); return input; }
  const decision = element("select"); decision.append(new Option("請選擇複核結果", "")); decision.required=true; Object.entries(reviewLabels).forEach(([v,t]) => decision.append(new Option(t,v))); control("複核結果", decision);
  const reviewer = control("複核人員", element("input")); reviewer.required = true; reviewer.maxLength = 100; reviewer.value = sessionStorage.getItem("labelcheck-operator") || "";
  const note = control("確認原因", element("textarea")); note.required = true; note.maxLength = 2000; note.rows = 2;
  const submit = element("button", "button secondary full", "儲存複核紀錄"); submit.type = "submit"; review.append(submit);
  review.onsubmit = async event => { event.preventDefault(); submit.disabled = true; try { await api(`/api/inspections/${inspection.id}/reviews`, {method:"POST",body:{decision:decision.value,reviewer:reviewer.value,note:note.value}}); sessionStorage.setItem("labelcheck-operator", reviewer.value); await loadInspection(inspection.id); toast("複核紀錄已保存。"); } catch(e) { toast(e.message,true); } finally { submit.disabled=false; } };
  evidence.append(review); area.append(evidence);
}
async function loadHistory() {
  const filter = $("#history-filter").value, page = state.page;
  const data = await api(`/api/inspections?page=${page}&status=${encodeURIComponent(filter)}`);
  if (page !== state.page || filter !== $("#history-filter").value) return;
  const list = $("#history-list"); list.replaceChildren();
  if (!data.items.length) { const empty = element("div", "empty-state"); empty.append(element("h2", "", "這裡還沒有檢查紀錄"),element("p", "", "完成一次照片檢查後，結果會自動保存在這裡。")); list.append(empty); }
  data.items.forEach(item => { const row = element("button", "history-row"), img = element("img"), text = element("span"); img.src=item.image.thumbnail; img.alt="待檢標籤縮圖"; img.loading="lazy"; text.append(element("strong", "", item.name), element("small", "", `${when(item.created_at)} · 第 ${item.version} 版`)); row.append(img,text,badge(item.status)); row.onclick=() => { if(state.busy) return toast("請等待目前辨識完成。"); loadInspection(item.id).catch(e=>toast(e.message,true)); }; list.append(row); });
  $("#history-page").textContent=`第 ${page} 頁`; $("#history-prev").disabled=page<=1; $("#history-next").disabled=!data.has_more;
}
async function initialize() {
  const session = await api("/api/session"); state.csrf = session.csrf;
  $("#logout").hidden=!session.requires_login;
  $("#login").hidden=session.authenticated; $("#app-shell").hidden=!session.authenticated;
  if (!session.authenticated) return;
  await Promise.all([loadTemplates(), loadScanConfig()]); showView(location.hash.slice(1));
  const stored = sessionStorage.getItem("labelcheck-pending");
  if (stored) {
    let pending; try { pending=JSON.parse(stored); } catch { sessionStorage.removeItem("labelcheck-pending"); return; }
    if (pending.supersedes_id) {
      state.supersedes=state.templates.find(t=>t.id===pending.supersedes_id);
      if (!state.supersedes) { sessionStorage.removeItem("labelcheck-pending"); toast("原標準已更新，請重新選擇最新標準再建立新版。",true); return; }
      $("#standard-heading").textContent=`建立新版標準 · 第 ${state.supersedes.version+1} 版`;
    }
    showView(pending.kind === "reference" ? "standard" : "inspect"); setBusy(true,pending.kind);
    try { await pollJob(pending.id,pending.kind); } catch(e) { toast(e.message,true); } finally { setBusy(false); }
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
    const stream = await navigator.mediaDevices.getUserMedia({audio:false, video:{facingMode:{ideal:"environment"}, width:{ideal:1920}, height:{ideal:1440}}});
    if (token !== cameraRequest || !dialog.open) { stream.getTracks().forEach(track => track.stop()); return; }
    cameraStream = stream; const video = $("#camera-video"); video.srcObject = stream;
    await video.play();
    if (token !== cameraRequest || !dialog.open) return;
    $("#camera-capture").disabled = false; $("#camera-message").textContent = "對準標籤，避開反光；按下拍攝後才會上傳辨識。";
  } catch (error) {
    if (token !== cameraRequest || !dialog.open) return;
    stopCamera(); $("#camera-message").textContent = "無法開啟即時相機。請允許權限，或使用「手機拍照」及「選擇照片」。";
  }
}
$("#scan-button").onclick = openCamera;
$("#camera-close").onclick = closeCamera;
$("#camera-dialog").addEventListener("close", stopCamera);
$("#camera-native").onclick = () => { closeCamera(); $("#inspect-camera").click(); };
$("#camera-capture").onclick = async () => {
  const video = $("#camera-video"); if (!video.videoWidth || state.busy) return;
  $("#camera-capture").disabled = true;
  const canvas = document.createElement("canvas"), scale = Math.min(1,2400 / Math.max(video.videoWidth,video.videoHeight));
  canvas.width = Math.round(video.videoWidth*scale); canvas.height = Math.round(video.videoHeight*scale);
  canvas.getContext("2d").drawImage(video,0,0,canvas.width,canvas.height);
  const blob = await new Promise(resolve=>canvas.toBlob(resolve,"image/jpeg",.95));
  closeCamera();
  if (blob) await upload(new File([blob],"掃描標籤.jpg",{type:"image/jpeg"}),"inspection");
  else toast("拍攝失敗，請重新拍照。",true);
};
window.addEventListener("pagehide", closeCamera);
document.addEventListener("visibilitychange", () => { if(document.hidden) closeCamera(); });
$("#source-search").onsubmit = async event => {
  event.preventDefault(); if(state.busy) return;
  const results = $("#source-results"); results.replaceChildren(); setBusy(true);
  try {
    const data = await api(`/api/source-labels?q=${encodeURIComponent($("#source-query").value.trim())}`);
    $("#source-note").textContent = !data.available ? "目前尚未連接標籤系統資料庫。" : data.items.length ? "請選擇一份標籤，再核對正確內容。" : "找不到符合的標籤，請換代碼或品名。";
    data.items.forEach(item => { const button = element("button", "source-option", `${item.code} · ${item.name}`); button.type="button"; button.onclick=()=>importSource(item.code); results.append(button); });
  } catch(error) { toast(error.message,true); } finally { setBusy(false); }
};
async function importSource(code) {
  if(state.busy) return; setBusy(true);
  try {
    const source = await api(`/api/source-labels/${encodeURIComponent(code)}`);
    state.source = source; state.referenceJob = null;
    const form = $("#standard-form"); form.reset(); $("#standard-fields").disabled = false;
    form.elements.name.value = state.supersedes?.name || `${source.code} · ${source.name}`;
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
$("#template-select").onchange=()=>{ selectedStandard(); clearResult(); };
$("#batch-date").onchange=clearResult;
$("#arrival-date").onchange=clearResult;
$("#standard-form").onsubmit=saveStandard;
$("#standard-form").addEventListener("input",event=>{if(event.target.name!=="confirmed") $("#standard-form").elements.confirmed.checked=false;});
$("#standard-form").elements.dates.onchange=toggleDateFields;
$("#standard-form").elements.check_arrival.onchange=toggleDateFields;
$("#history-filter").onchange=()=>{ state.page=1; loadHistory().catch(e=>toast(e.message,true)); };
$("#history-prev").onclick=()=>{ state.page=Math.max(1,state.page-1); loadHistory().catch(e=>toast(e.message,true)); };
$("#history-next").onclick=()=>{ state.page++; loadHistory().catch(e=>toast(e.message,true)); };
$("#login-form").onsubmit=async e=>{ e.preventDefault(); const form=e.currentTarget, button=$("button",form); button.disabled=true; try { const result=await api("/api/login",{method:"POST",body:{password:form.elements.password.value}}); state.csrf=result.csrf; form.reset(); $("#login-error").textContent=""; await initialize(); } catch(error) { $("#login-error").textContent=error.message; } finally { button.disabled=false; } };
$("#logout").onclick=async()=>{ if(state.busy) return toast("請等待目前辨識完成。"); try { await api("/api/logout",{method:"POST"}); location.reload(); } catch(e) { toast(e.message,true); } };
initialize().catch(e=>toast(e.message,true));
