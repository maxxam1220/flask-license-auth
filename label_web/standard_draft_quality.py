"""Readability gate for offering a draft, never a label correctness decision."""
import math
import re


_LETTERS = re.compile(r"[\u3400-\u9fffA-Za-z]")
_FIELD = re.compile(r"^\s*(?:品名|產品名稱|商品名稱|產品品名|名稱|製造廠商|製造商|公司名稱|地址|產地|內容物|成分|規格|保存條件|保存方式)\s*[:：]?\s*(.+)$")


def eligibility(ocr, patches=None, result=None):
    """Use observed readability; business failures and printed typos stay useful.

    Local scores only gate low quality. Cloud uncertainty_gate scores are not
    probabilities and are ignored in favour of explicit uncertainty metadata.
    Confirmed OCR corrections may supply draft evidence without changing raw OCR.
    """
    ocr = ocr if isinstance(ocr, dict) else {}
    result = result if isinstance(result, dict) else {}
    observed_scope = ocr.get("label_scope") or {}
    evaluated_scope = result.get("label_scope") or {}
    source_match = result.get("source_match") or {}
    if isinstance(source_match, dict) and source_match.get("status") == "source_conflict":
        return {"eligible":False, "reason_code":"source_conflict",
                "reason":"選用標準與照片不同，請先自動重新核對或選擇正確標準，再建立草稿。",
                "needs_review":True, "usable_line_count":0, "uncertain_line_count":0,
                "total_line_count":len(ocr.get("lines") or [])}
    blocked = (ocr.get("image_status") == "multiple_labels" or
               (isinstance(observed_scope, dict) and observed_scope.get("status") == "multiple") or
               (isinstance(evaluated_scope, dict) and bool(evaluated_scope.get("blocked"))) or
               (isinstance(source_match, dict) and source_match.get("status") == "scope_review"))
    lines = ocr.get("lines") if isinstance(ocr.get("lines"), list) else []
    active = {p.get("line_id"): p for p in patches or [] if isinstance(p, dict)}
    readable, uncertain_count, total, strong = {}, 0, 0, False
    for original in lines:
        if not isinstance(original, dict):
            continue
        line = dict(original)
        patch = active.get(line.get("id"))
        if patch and patch.get("kind") == "ocr_misread":
            line.update(text=patch.get("text"), human_verified=True, human_uncertain=False)
        elif patch and patch.get("kind") == "uncertain":
            line["human_uncertain"] = True
        text = line.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        text = text.strip()
        total += 1
        printed_typo = bool(line.get("suspected_typo")) and line.get("ambiguity_reason") == "cloud_suspected_typo"
        cloud = line.get("score_kind") == "uncertainty_gate" or ocr.get("recognition_engine") == "cloud"
        score = line.get("score")
        low = (not cloud and isinstance(score, (int, float)) and
               (not math.isfinite(score) or score < .65))
        unclear = (bool(line.get("human_uncertain")) or "□" in text or "\ufffd" in text or
                   (not line.get("human_verified") and (bool(line.get("uncertain")) or
                    bool(line.get("alternatives")) or (bool(line.get("ambiguous")) and not printed_typo) or low)))
        if unclear:
            uncertain_count += 1
            continue
        letters = _LETTERS.findall(text)
        if len(letters) < 2 or len(set(letters)) < 2:
            continue  # Dates, phone digits, punctuation and repeated noise alone are not a draft.
        readable[text] = len(letters)
        field = _FIELD.match(text)
        if field and len(_LETTERS.findall(field[1])) >= 2:
            strong = True
    enough = strong or (len(readable) >= 2 and sum(readable.values()) >= 8) or any(n >= 12 for n in readable.values())
    failed = ocr.get("image_status") in {"unreadable", "no_text", "failed"} or ocr.get("state") == "failed"
    eligible = bool(enough and not failed and not blocked)
    reason_code = "multiple_labels" if blocked else "usable_content" if eligible else "no_text" if not total else "insufficient_readable_content"
    reason = ("仍有可讀標籤內容，可準備草稿；請逐字確認後才建立標準。" if eligible else
              "沒有足夠可用的標籤文字，請先裁切或重拍清楚的照片再建立標準。")
    if blocked:
        reason = "照片中的標籤範圍無法可靠區分，請先裁切單張標籤並重新辨識，再建立標準。"
    return {"eligible": eligible, "reason_code": reason_code, "reason": reason,
            "needs_review": bool(uncertain_count or blocked),
            "usable_line_count": len(readable), "uncertain_line_count": uncertain_count,
            "total_line_count": total}
