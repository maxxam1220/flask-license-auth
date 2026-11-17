"""Evidence-only additions shared by first scan and human-corrected rechecks."""
from collections import Counter
from barcode_checks import checks_for
from nutrition_checks import checks_for as nutrition_checks
from text_rows import group_observed_rows


def augment(result, ocr):
    # Re-evaluation is idempotent; never re-use conclusions from another OCR pass.
    checks=[x for x in result.get("checks",[]) if x.get("key") != "source_identity_conflict" and (x.get("source")=="database" or
            not x.get("key","").startswith(("barcode_", "cloud_word_", "photo_scope", "nutrition_")))]
    match = result.get("source_match") or {}
    if match.get("status") == "source_conflict":
        selected = match.get("selected_source") or {}
        evidence = match.get("identity_evidence") or []
        checks.insert(0, {"key":"source_identity_conflict", "label":"選用標準與照片不同", "status":"review",
            "actual":"；".join(str(item.get("actual", "")) for item in evidence),
            "expected":selected.get("name", ""), "source":"source_selection", "score":None,
            "line_ids":list(dict.fromkeys(identifier for item in evidence for identifier in item.get("line_ids", []))),
            "reason":match.get("reason") or "照片品名與選用標準衝突，請改回自動對應或重新選擇；尚未套用該標準。"})
    checks.extend(checks_for(ocr))
    checks.extend(nutrition_checks(ocr))
    result["display_rows"] = [{key: row[key] for key in
        ("id", "text", "source_line_ids", "box", "confidence_ok", "row_type")}
        for row in group_observed_rows(ocr.get("lines", []))]
    if ocr.get("label_scope",{}).get("status")=="multiple":
        checks.append({"key":"photo_scope", "label":"標籤範圍", "status":"review", "actual":"偵測到多張可能的貼紙",
            "reason":"請裁切要檢查的那一張，避免混用不同貼紙的文字。", "line_ids":[]})
    for index,line in enumerate(ocr.get("lines",[])):
        if line.get("suspected_typo") and not line.get("human_verified"):
            checks.append({"key":f"cloud_word_{index}", "label":"文字疑點", "status":"review", "actual":line["text"],
                "reason":"雲端辨識提出可能錯字，請核對原圖與實際標準；未自動改字。", "line_ids":[line.get("id")]})
    if ocr.get("label_scope",{}).get("status")=="multiple":
        for check in checks:
            if check["status"]=="pass":
                check.update(status="review",reason="照片範圍包含多張可能的貼紙，請裁切單張後重新確認。")
    result["checks"]=checks
    counts=Counter(x.get("status","unknown") for x in checks)
    result["counts"]={k:counts[k] for k in ("pass","fail","review","read")}
    result["status"]="fail" if counts["fail"] else "review" if not checks or counts["review"] or counts["read"] else "pass"
    if ocr.get("provider")=="openai":
        for check in checks:
            check["score_kind"]="uncertainty_gate"
            check["score"]=None
            for line in check.get("source_lines",[]):
                line["score_kind"]="uncertainty_gate"
                line["score"]=None
    return result
