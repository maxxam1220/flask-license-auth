"""Append-only human observations evaluated against an inspection's own snapshot."""
from copy import deepcopy

from sqlalchemy import select, func
import database as db
from source_validation import evaluate_source
from validation import evaluate, traditional_display


KINDS = {"ocr_misread", "label_misprint", "uncertain"}


class CorrectionInputError(ValueError):
    pass


def validate_request(body, original):
    if not isinstance(body, dict):
        raise CorrectionInputError("請填寫訂正內容。")
    base = body.get("base_revision")
    identifier = body.get("line_id")
    if type(base) is not int or base < 0:
        raise CorrectionInputError("訂正版本不正確，請重新載入。")
    if type(identifier) is not int or identifier not in {line.get("id") for line in original["ocr"]["lines"]}:
        raise CorrectionInputError("只能訂正這張照片已辨識的文字行。")
    operation = body.get("operation", "replace")
    if not isinstance(operation, str) or operation not in {"replace", "revoke"}:
        raise CorrectionInputError("訂正操作不正確。")
    reviewer, note = body.get("reviewer"), body.get("note", "")
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 100 or '\x00' in reviewer:
        raise CorrectionInputError("請填寫訂正人員，最多 100 字。")
    if not isinstance(note, str) or not note.strip() or len(note) > 2000 or '\x00' in note:
        raise CorrectionInputError("請填寫訂正原因，最多 2,000 字。")
    kind, value = body.get("kind"), body.get("text", "")
    if operation == "replace":
        if not isinstance(kind, str) or kind not in KINDS:
            raise CorrectionInputError("請選擇辨識錯誤、標籤印錯或照片看不清楚。")
        if not isinstance(value, str) or len(value) > 1000 or '\x00' in value or (kind != "uncertain" and not value.strip()):
            raise CorrectionInputError("請填寫照片實際印出的文字，最多 1,000 字。")
    return {"base_revision":base, "line_id":identifier, "operation":operation,
            "kind":kind, "text":value, "reviewer":reviewer.strip(), "note":note}


def latest(conn, inspection_id):
    row = conn.execute(select(db.corrections).where(db.corrections.c.inspection_id == inspection_id)
                       .order_by(db.corrections.c.revision.desc()).limit(1)).mappings().first()
    return dict(row) if row else None


def latest_summaries(conn, identifiers):
    if not identifiers:
        return {}
    table = db.corrections
    maximum = select(table.c.inspection_id, func.max(table.c.revision).label("revision")).where(
        table.c.inspection_id.in_(identifiers)).group_by(table.c.inspection_id).subquery()
    rows = conn.execute(select(table.c.inspection_id, table.c.revision, table.c.status).join(maximum,
        (maximum.c.inspection_id == table.c.inspection_id) & (maximum.c.revision == table.c.revision))).mappings()
    return {row["inspection_id"]:dict(row) for row in rows}


def public_revision(row):
    if not row:
        return None
    result = {key:row[key] for key in ("revision", "patches", "result", "ocr", "reviewer", "note", "created_at", "status")}
    if row["change"].get("copied_from"):
        result["copied_from"] = deepcopy(row["change"]["copied_from"])
    return result


def history(conn, inspection_id, page=1, size=20):
    rows = conn.execute(select(db.corrections.c.revision, db.corrections.c.change,
        db.corrections.c.status, db.corrections.c.reviewer, db.corrections.c.note, db.corrections.c.created_at)
        .where(db.corrections.c.inspection_id == inspection_id).order_by(db.corrections.c.revision.desc())
        .offset((page-1)*size).limit(size+1)).mappings().all()
    return {"items":[{**dict(row["change"]), **{key:row[key] for key in
        ("revision", "status", "reviewer", "note", "created_at")}} for row in rows[:size]],
        "page":page, "has_more":len(rows)>size}


def build_revision(original, current, action, created_at):
    revision = (current["revision"] if current else 0) + 1
    patches = {patch["line_id"]:deepcopy(patch) for patch in (current or {}).get("patches", [])}
    identifier = action.get("line_id")
    original_lines = original["ocr"]["lines"]
    if action["operation"] == "copy":
        change = {"operation":"copy", "line_id":None, "kind":"copy", "text":"",
                  "copied_from":deepcopy(action["copied_from"])}
    elif action["operation"] == "revoke":
        if identifier not in patches:
            raise CorrectionInputError("這行目前沒有可撤回的訂正。")
        previous = patches.pop(identifier)
        change = {"operation":"revoke", "line_id":identifier, "kind":previous["kind"], "text":previous["text"]}
    else:
        original_line = next(line for line in original_lines if line["id"] == identifier)
        value = action["text"]
        if action["kind"] == "uncertain":
            value = patches.get(identifier, {}).get("text", original_line["text"])
        patch = {"line_id":identifier, "kind":action["kind"], "text":value,
                 "reviewer":action["reviewer"], "note":action["note"], "created_at":created_at}
        patches[identifier] = patch
        change = {"operation":"replace", **{key:patch[key] for key in ("line_id", "kind", "text")}}
    ocr = deepcopy(original["ocr"])
    for line in ocr["lines"]:
        patch = patches.get(line["id"])
        if not patch:
            continue
        line["original_ocr_text"] = line["text"]
        line["original_ocr_ambiguous"] = bool(line.get("ambiguous", False))
        line["text"] = patch["text"]
        line["human_verified"] = patch["kind"] != "uncertain"
        line["human_uncertain"] = patch["kind"] == "uncertain"
        line["human_correction"] = deepcopy(patch)
    ocr["human_revision"] = revision
    ocr["original_engine"] = original["ocr"].get("engine")
    inputs = deepcopy(original["result"].get("inputs") or {})
    standard = deepcopy(original["template_snapshot"])
    if standard.get("mode") == "system_label" or "source" in standard:
        result = evaluate_source(ocr["lines"], standard.get("source"), inputs.get("batch_date", ""),
            inputs.get("arrival_date", ""), base_date=inputs.get("base_date", ""),
            ocr_capabilities=original["ocr"].get("capabilities"))
    else:
        result = evaluate(ocr["lines"], standard, inputs.get("batch_date", ""), inputs.get("arrival_date", ""))
    affected = set(patches)
    for check in result["checks"]:
        corrected_ids = [value for value in check.get("line_ids", []) if value in affected]
        if corrected_ids:
            check["human_corrected_line_ids"] = corrected_ids
            check["human_assessment"] = True
            check["confidence_note"] = "此結果包含人工逐字確認；顯示的信心分數仍是原始 OCR 分數。"
    for patch in patches.values():
        if patch["kind"] == "ocr_misread":
            continue
        status = "fail" if patch["kind"] == "label_misprint" else "review"
        result["checks"].append({"key":f"manual_{patch['line_id']}", "label":"人工確認標籤印錯" if status == "fail" else "人工標記待確認",
            "status":status, "expected":"", "actual":patch["text"], "raw_actual":patch["text"],
            "display_actual":traditional_display(patch["text"]), "display_expected":"", "line_ids":[patch["line_id"]],
            "diff":[], "score":None, "source":"human", "human_assessment":True,
            "reason":"訂正人員確認標籤本身印錯；不會因文字與標準相同而自動改判通過。" if status == "fail" else "訂正人員表示照片看不清楚，仍需人工確認。"})
    result["counts"] = {status:sum(check["status"]==status for check in result["checks"]) for status in ("pass", "fail", "review", "read")}
    counts = result["counts"]
    result["status"] = "fail" if counts["fail"] else "review" if not result["checks"] or counts["review"] or counts["read"] else "pass"
    result.update(inputs=inputs, human_revision=revision, human_assessment=True,
                  original_inspection_id=original["id"], original_status=original["status"],
                  source_match=deepcopy(original["result"].get("source_match")),
                  evaluation_basis="original_inspection_snapshot")
    result.setdefault("notes", []).insert(0, "本版含人工訂正，依這筆檢查原有標準快照與日期重新核對；原始照片與 OCR 紀錄未改動。")
    if action.get("copied_from"):
        result["copied_from"] = deepcopy(action["copied_from"])
    return {"id":db.uid(), "inspection_id":original["id"], "revision":revision,
            "change":change, "patches":[patches[line["id"]] for line in original_lines if line["id"] in patches],
            "ocr":ocr, "result":result, "status":result["status"], "reviewer":action["reviewer"],
            "note":action["note"], "created_at":created_at}
