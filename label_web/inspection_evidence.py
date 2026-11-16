"""Evidence-only additions shared by first scan and human-corrected rechecks."""
from collections import Counter
from barcode_checks import checks_for


def augment(result, ocr):
    # Re-evaluation is idempotent; never re-use conclusions from another OCR pass.
    checks=[x for x in result.get("checks",[]) if not x.get("key","").startswith(("barcode_", "cloud_word_", "photo_scope"))]
    checks.extend(checks_for(ocr))
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
