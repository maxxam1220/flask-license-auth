"""Evidence-only additions shared by first scan and human-corrected rechecks."""
from collections import Counter
from barcode_checks import checks_for
from text_rows import group_observed_rows, nutrition_line_ids


NUTRITION_POLICY = "excluded-v1"


def _recount(result):
    counts=Counter(check.get("status") for check in result["checks"])
    result["counts"]={k:counts[k] for k in ("pass","fail","review","read")}
    result["status"]="fail" if counts["fail"] else "review" if not result["checks"] or counts["review"] or counts["read"] else "pass"


def without_nutrition(result, ocr, source=None):
    """Project saved or current evidence without changing its raw snapshot."""
    result=dict(result or {},nutrition_policy=NUTRITION_POLICY)
    # Early snapshots sometimes contain text with no stable OCR identifier.
    # Keep that original text on ocr.lines without assigning synthetic evidence IDs.
    lines=[line for line in (ocr or {}).get("lines") or [] if isinstance(line,dict)
           and isinstance(line.get("id"),(str,int)) and isinstance(line.get("text"),str)]
    rows=group_observed_rows(lines) if lines else [row for row in result.get("display_rows") or []
        if isinstance(row,dict) and isinstance(row.get("id"),(str,int)) and isinstance(row.get("text"),str)]
    ignored=nutrition_line_ids(lines, rows)
    if not lines and rows:
        row_ids=nutrition_line_ids(rows)
        ignored={i for row in rows if row.get("id") in row_ids for i in row.get("source_line_ids",[])}
    if any(line.get("original_ocr_text") and (line.get("human_correction") or {}).get("kind") in {"label_misprint","uncertain"} for line in lines):
        original=[dict(line,text=line.get("original_ocr_text",line["text"])) for line in lines]
        ignored.update(nutrition_line_ids(original).intersection(line["id"] for line in lines
            if (line.get("human_correction") or {}).get("kind") in {"label_misprint","uncertain"}))
    result["display_rows"]=[{**{key:row[key] for key in ("id","text","source_line_ids","box","confidence_ok","row_type") if key in row},
                             "nutrition_display_only":bool(row.get("nutrition_display_only") or
                                row.get("source_line_ids") and ignored.issuperset(row["source_line_ids"]))}
                            for row in rows]
    if not isinstance(result.get("checks"),list):
        return result
    # _source_rows used its stored list index when legacy standard text had no ID.
    reference_lines=[dict(line,id=line.get("id",i)) for i,line in enumerate((source or {}).get("lines",[]))
                     if isinstance(line,dict) and isinstance(line.get("text"),str)]
    reference_ids=nutrition_line_ids(reference_lines)
    def counted(check):
        key=str(check.get("key") or "")
        if key.startswith(("nutrition_", "source_nutrition_")) or check.get("incomplete_standard"):
            return False
        expected_ids=check.get("source_line_ids") or []
        if expected_ids and reference_ids.issuperset(expected_ids):
            return False
        actual_ids=check.get("line_ids") or []
        if not lines and not rows and not reference_lines and key.startswith(("text_line_","source_line_","source_text_","cloud_word_","manual_")):
            text=check.get("expected") or check.get("actual")
            if text and nutrition_line_ids([{"id":0,"text":text}]):
                return False
        return not (actual_ids and ignored.issuperset(actual_ids) and
                    (not expected_ids or not reference_lines))
    result["checks"]=[check for check in result["checks"] if isinstance(check,dict) and counted(check)]
    if isinstance(result.get("fields"),dict):
        result["fields"]={k:v for k,v in result["fields"].items() if k!="nutrition"}
    if ignored and "coverage" in result:
        eligible={line["id"] for line in lines}-ignored
        covered={identifier for check in result["checks"] for identifier in check.get("line_ids",[])}
        result["coverage"]={"total_lines":len(eligible),"covered_lines":len(eligible & covered)}
    _recount(result)
    return result


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
    projected=without_nutrition(dict(result,checks=checks),ocr)
    checks=projected["checks"]
    result.update(projected)
    ignored={identifier for row in projected["display_rows"] if row["nutrition_display_only"] for identifier in row["source_line_ids"]}
    lines=[line for line in ocr.get("lines",[]) if line["id"] not in ignored]
    checks.extend(checks_for(dict(ocr,lines=lines)))
    if ocr.get("label_scope",{}).get("status")=="multiple":
        checks.append({"key":"photo_scope", "label":"標籤範圍", "status":"review", "actual":"偵測到多張可能的貼紙",
            "reason":"請裁切要檢查的那一張，避免混用不同貼紙的文字。", "line_ids":[]})
    for index,line in enumerate(ocr.get("lines",[])):
        if line["id"] not in ignored and line.get("suspected_typo") and not line.get("human_verified"):
            checks.append({"key":f"cloud_word_{index}", "label":"文字疑點", "status":"review", "actual":line["text"],
                "reason":"雲端辨識提出可能錯字，請核對原圖與實際標準；未自動改字。", "line_ids":[line.get("id")]})
    if ocr.get("label_scope",{}).get("status")=="multiple":
        for check in checks:
            if check["status"]=="pass":
                check.update(status="review",reason="照片範圍包含多張可能的貼紙，請裁切單張後重新確認。")
    result["checks"]=checks
    _recount(result)
    if ocr.get("provider")=="openai":
        for check in checks:
            check["score_kind"]="uncertainty_gate"
            check["score"]=None
            for line in check.get("source_lines",[]):
                line["score_kind"]="uncertainty_gate"
                line["score"]=None
    return result
