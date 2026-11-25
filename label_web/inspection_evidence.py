"""Evidence-only additions shared by first scan and human-corrected rechecks."""
from collections import Counter
from barcode_checks import checks_for
from text_rows import group_observed_rows, nutrition_line_ids
from validation import traditional_display


NUTRITION_POLICY = "literal-text-v2"
BARCODE_POLICY = "external-reader-v1"


def _recount(result):
    counts=Counter(check.get("status") for check in result["checks"] if isinstance(check,dict))
    result["counts"]={k:counts[k] for k in ("pass","fail","review","read")}
    result["status"]="fail" if counts["fail"] else "pass" if counts["pass"] and counts["pass"]==len(result["checks"]) else "review"


def project_barcode(result):
    """Present a saved inspection under the current barcode policy without changing its snapshot."""
    projected = dict(result, barcode_policy=BARCODE_POLICY)
    original = result.get("checks")
    if isinstance(original, list):
        checks = [check for check in original if not (isinstance(check, dict) and
                  check.get("key") == "barcode_unread" and check.get("status") == "review")]
        if len(checks) != len(original):
            projected["checks"] = checks
            _recount(projected)
    return projected


def _group_unverified_nutrition(checks, rows):
    """Count one unreferenced printed row while retaining every OCR cell and its location."""
    by_cell = {check["line_ids"][0]:check for check in checks if check.get("source") == "ocr"
               and str(check.get("key", "")).startswith("text_line_") and len(check.get("line_ids", [])) == 1}
    replacements = {}
    for row in rows:
        ids = row.get("source_line_ids") or []
        if not row["nutrition_text"] or len(ids) < 2 or not all(i in by_cell for i in ids):
            continue
        cells = [by_cell[i] for i in ids]
        representative = next((check for check in cells if check["status"] == "review"), cells[0])
        text = row["text"]
        display = traditional_display(text)
        grouped = dict(representative, key=cells[0]["key"], actual=text, raw_actual=text, display_actual=display,
                       conversion_changed=text != display, line_ids=ids, score=None,
                       source_lines=[line for check in cells for line in check.get("source_lines",[])])
        if not row.get("confidence_ok"):
            grouped.update(status="review", reason="這行的文字或分欄位置不清楚，請對照原圖確認。")
        replacements.update({cell["key"]: None for cell in cells})
        replacements[cells[0]["key"]] = grouped
    return [replacement for check in checks if (replacement := replacements.get(check.get("key"), check)) is not None]


def project_nutrition_text(result, ocr, source=None, recovered_checks=None):
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
                             "nutrition_text":bool(row.get("nutrition_text") or row.get("nutrition_display_only") or
                                row.get("source_line_ids") and ignored.issuperset(row["source_line_ids"]))}
                            for row in rows]
    if not isinstance(result.get("checks"),list):
        return result

    def literal(check):
        return isinstance(check,dict) and not (str(check.get("key") or "").startswith("nutrition_") and
                                                check.get("source") in (None,"","logic"))
    checks=[check for check in result["checks"] if literal(check)]
    if recovered_checks is not None:
        # An excluded-v1 snapshot omitted the literal checks. Replace only checks
        # about the nutrition rows of this observation or its contemporary standard.
        reference_lines=[dict(line,id=line.get("id",i)) for i,line in enumerate((source or {}).get("lines",[]))
                         if isinstance(line,dict) and isinstance(line.get("text"),str)]
        reference_ids=nutrition_line_ids(reference_lines)
        def nutrition_text_check(check):
            key=str(check.get("key") or "")
            if key.startswith(("source_nutrition_", "nutrition_")) or check.get("incomplete_standard"):
                return True
            expected=check.get("source_line_ids") or []
            if expected and reference_lines:
                return reference_ids.issuperset(expected)
            actual=check.get("line_ids") or []
            return bool(actual and ignored.issuperset(actual))
        checks=[check for check in checks if not nutrition_text_check(check)]
        checks.extend(check for check in recovered_checks if literal(check) and nutrition_text_check(check))
    result["checks"]=checks
    if lines and "coverage" in result:
        identifiers={line["id"] for line in lines}
        covered={i for check in checks for i in check.get("line_ids",[])}
        result["coverage"]={"total_lines":len(lines),"covered_lines":len(identifiers & covered)}
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
    projected=project_nutrition_text(dict(result,checks=checks),ocr)
    checks=_group_unverified_nutrition(projected["checks"],projected["display_rows"])
    result.update(projected)
    ignored={identifier for row in projected["display_rows"] if row["nutrition_text"] for identifier in row["source_line_ids"]}
    lines=[line for line in ocr.get("lines",[]) if line["id"] not in ignored]
    checks.extend(checks_for(dict(ocr,lines=lines)))
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
    _recount(result)
    if ocr.get("provider")=="openai":
        for check in checks:
            check["score_kind"]="uncertainty_gate"
            check["score"]=None
            for line in check.get("source_lines",[]):
                line["score_kind"]="uncertainty_gate"
                line["score"]=None
    result["barcode_policy"]=BARCODE_POLICY
    return result
