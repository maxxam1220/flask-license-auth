"""Explicitly approved website text references, independent of printer layouts."""
from copy import deepcopy
import hashlib
import json
import re
import unicodedata

from flask import abort, jsonify, request
from sqlalchemy import inspect, select, insert, func, or_, cast, Text
from sqlalchemy.exc import IntegrityError

import database as db
from validation import extract_fields, TEXT_FIELDS
from source_validation import HEADINGS, _kind, normalize_text


PREFIX = "manual:"
DATE_LABELS = {"manufacture": "製造日期", "expiry": "有效日期", "arrival": "到店日"}
LIMITATIONS = ["只核對人員已確認並列入的文字與日期規則；沒有建立印標版面。",
               "未列入標準的文字仍屬未核對，不代表整張標籤已確認正確。"]
DEFINITION_KEYS = {"name", "sku", "lines", "keep_days", "date_settings"}


def _fixed_manual_text(value):
    from standard_reference import _fixed_text
    value = _fixed_text(value)
    if re.fullmatch(r"\s*\d{1,2}\s*[./-]\s*\d{1,2}(?:\s+\d{1,2}[:：]\d{2})?\s*", unicodedata.normalize("NFKC", value)):
        abort(400, description="像日期的獨立月日不能存成永久標準；請使用日期位移規則。")
    return value


def fixed_line_text(value):
    """The same fixed-text contract applies to creation and later revisions."""
    from standard_reference import _text
    value = _fixed_manual_text(_text(value, "標準文字", 2000))
    if "\n" in value or "\r" in value:
        abort(400, description="請將標準文字逐行分開，不要合併成一段。")
    if _kind(value) in DATE_LABELS:
        abort(400, description="製造日、有效日與到店日請填日期規則，不要存成固定文字。")
    return value


def _stored(engine):
    inspector = inspect(engine, raiseerr=False)
    return inspector is not None and inspector.has_table(db.manual_sources.name)


def available(engine):
    if not _stored(engine):
        return False
    with engine.connect() as conn:
        return conn.execute(select(db.manual_sources.c.code).where(db.manual_sources.c.active.is_(True)).limit(1)).first() is not None


def records(engine):
    if not _stored(engine):
        return []
    with engine.connect() as conn:
        return [dict(row) for row in conn.execute(select(db.manual_sources).where(db.manual_sources.c.active.is_(True))
            .order_by(db.manual_sources.c.created_at, db.manual_sources.c.code)).mappings()]


def draft(engine, code):
    if not str(code).startswith(PREFIX) or not _stored(engine):
        return None
    with engine.connect() as conn:
        row = conn.execute(select(db.manual_sources.c.snapshot).where(
            (db.manual_sources.c.code == str(code)) & db.manual_sources.c.active.is_(True))).first()
    return deepcopy(row.snapshot) if row else None


def listing(engine, query="", page=1, limit=24):
    """Return only current list metadata; snapshots stay in the database."""
    import standard_reference as standards
    if not isinstance(query, str) or len(query) > 100:
        abort(400, description="搜尋文字最多 100 字。")
    page = standards._integer(page, "頁碼", 1, 1_000_000)
    limit = standards._integer(limit, "每頁筆數", 1, 100)
    sources, heads, versions = db.manual_sources, standards.heads, standards.versions
    joined = sources.outerjoin(heads, heads.c.code == sources.c.code).outerjoin(versions,
        (versions.c.code == heads.c.code) & (versions.c.revision == heads.c.revision))
    current_name = func.coalesce(versions.c.snapshot["name"].as_string(), sources.c.name)
    clauses = [sources.c.active.is_(True)]
    query = query.strip()
    if query:
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        # SKU is an explicitly approved static line. Query its current JSON text
        # in SQL so pagination never loads every standard's snapshot into memory.
        current_lines = func.coalesce(cast(versions.c.snapshot["lines"], Text), cast(sources.c.snapshot["lines"], Text))
        clauses.append(or_(current_name.ilike(pattern, escape="\\"), sources.c.code.ilike(pattern, escape="\\"),
                           current_lines.ilike(pattern, escape="\\")))
    statement = select(sources.c.code, current_name.label("name"),
        func.coalesce(heads.c.revision, 1).label("revision"),
        func.coalesce(versions.c.reviewer, sources.c.reviewer).label("reviewer"),
        func.coalesce(versions.c.created_at, sources.c.created_at).label("created_at"),
        sources.c.inspection_id).select_from(joined).where(*clauses).order_by(sources.c.created_at.desc(), sources.c.code)
    with engine.connect() as conn:
        total = conn.execute(select(func.count()).select_from(joined).where(*clauses)).scalar_one()
        rows = conn.execute(statement.offset((page-1)*limit).limit(limit)).mappings().all()
    return {"items": [dict(row, source_kind="manual") for row in rows], "total": total,
            "has_more": page*limit < total, "page": page}


def fields_from_lines(lines, name):
    """Text-only references have no invented geometry or neighbouring columns."""
    candidates = {key: set() for key in TEXT_FIELDS}
    for line in lines:
        value = line["text"]
        key = _kind(value)
        if key not in candidates:
            continue
        heading = HEADINGS.get(key)
        content = re.sub(r"^\s*" + heading + r"\s*[：:]?\s*", "", value, count=1) if heading else value
        if content.strip():
            candidates[key].add(content.strip())
    fields = {key: next(iter(values)) if len(values) == 1 else "" for key, values in candidates.items()}
    fields["product"] = name
    return fields


def validate_date_rules(source):
    """Reject contradictory explicitly supplied rules, without inventing missing ones."""
    if source.get("source_kind") != "manual":
        return
    # Restore/reset also pass here: a historical fixed batch date must not
    # bypass today's creation/edit validation just because it was saved before.
    for row in source.get("lines", []):
        fixed_line_text(row["text"])
    offsets = {_kind(setting.get("content", "")): setting["shift_days"]
               for setting in source.get("date_settings", []) if _kind(setting.get("content", "")) in DATE_LABELS}
    for first, second, message in (
        ("manufacture", "expiry", "有效日位移不可早於製造日位移，請確認日期規則。"),
        ("manufacture", "arrival", "到店日位移不可早於製造日位移，請確認日期規則。"),
        ("arrival", "expiry", "到店日位移不可晚於有效日位移，請確認日期規則。"),
    ):
        if first in offsets and second in offsets and offsets[second] < offsets[first]:
            abort(400, description=message)
    if source.get("keep_days") is not None and all(key in offsets for key in ("manufacture", "expiry")):
        if offsets["expiry"] - offsets["manufacture"] != source["keep_days"]:
            abort(400, description="製造日與有效日位移的間隔不等於保存天數，請修正後再預覽。")


def _context(engine, inspection):
    with engine.connect() as conn:
        prior = conn.execute(select(db.manual_sources.c.code).where(
            db.manual_sources.c.inspection_id == inspection["id"])).first()
    existing = prior.code if prior else ""
    source = (inspection.get("template_snapshot") or {}).get("source")
    has_source = bool(inspection.get("template_id") or (source and source.get("code")))
    if has_source:
        return False, existing, "這筆檢查已有比對來源，請使用「修正比對標準」建立新版。"
    if existing:
        return False, existing, "這張照片已建立人工文字標準，請選用既有標準重新核對。"
    return True, "", "辨識文字只是草稿，請逐字修正後核准；日期請另填相對基準日規則。"


def payload(engine, inspection):
    from label_source import _identifiers, _SKU_LABEL
    import corrections
    can_create, existing, notice = _context(engine, inspection)
    original_lines = deepcopy(inspection.get("ocr", {}).get("lines", []))
    lines = deepcopy(original_lines)
    with engine.connect() as conn:
        correction = corrections.latest(conn, inspection["id"])
    patches = {patch["line_id"]: patch for patch in (correction or {}).get("patches", [])}
    excluded_unconfirmed, applied = [], []
    for line in lines:
        patch = patches.get(line.get("id"))
        if not patch:
            continue
        if patch["kind"] == "ocr_misread":
            # A confirmed reading is draft input, never an approved standard or
            # a replacement of the original OCR stored with the inspection.
            line.update(text=patch["text"], human_verified=True, human_uncertain=False)
            applied.append(line["id"])
        else:
            line["human_uncertain"] = True
            excluded_unconfirmed.append({"id": line["id"], "text": patch["text"], "kind": patch["kind"],
                "reason": "此行已確認標籤印錯，不能直接作為正確標準。" if patch["kind"] == "label_misprint"
                          else "此行已標記看不清楚，請確認正確文字後另外填入。"})
    excluded_ids = {line["id"] for line in excluded_unconfirmed}
    try:
        fields = extract_fields(lines)
    except (KeyError, ValueError, TypeError):
        fields = {}
    dynamic = {identifier for key in DATE_LABELS for identifier in fields.get(key, {}).get("line_ids", [])}
    draft_lines, excluded = [], []
    from werkzeug.exceptions import HTTPException
    for line in lines:
        if line.get("id") in excluded_ids:
            continue
        value = str(line.get("text", "")).strip()
        if not value:
            continue
        try:
            _fixed_manual_text(value)
            safe = line.get("id") not in dynamic and _kind(value) not in DATE_LABELS
        except HTTPException:
            safe = False
        (draft_lines if safe else excluded).append({"id": line.get("id"), "text": value})
    skus = {value for line in lines if line.get("id") not in excluded_ids
            for value in _identifiers(line.get("text", ""), _SKU_LABEL, normalize=lambda v:v)}
    product = fields.get("product", {})
    suggested_name = "" if excluded_ids.intersection(product.get("line_ids", [])) else product.get("value", "")
    return {"can_create": can_create, "existing_code": existing, "notice": notice,
            "suggested_name": suggested_name,
            "suggested_sku": next(iter(skus)) if len(skus) == 1 else "",
            "ocr_lines": original_lines, "draft_lines": draft_lines, "excluded_date_lines": excluded,
            "manual_revision": correction["revision"] if correction else 0,
            "draft_basis": "manual_correction" if applied else "original_ocr",
            "excluded_unconfirmed_lines": excluded_unconfirmed,
            "warning": (f"草稿已套用第 {correction['revision']} 版中確認的辨識訂正，仍未核准為標準；請逐字確認後再儲存。" if applied
                        else "這是辨識原文，尚未核准；請逐字修正後，確認要作為之後同款標籤的比對標準。")}


def definition(body):
    from standard_reference import _text, _integer, _fixed_text
    from label_source import _fixed_barcodes, _identifiers, _SKU_LABEL
    if not isinstance(body, dict):
        abort(400, description="請填寫人工標準內容。")
    name = _fixed_text(_text(body.get("name"), "品名", 200))
    sku = body.get("sku", "")
    if not isinstance(sku, str) or len(sku) > 100:
        abort(400, description="貨號最多 100 字。")
    sku = unicodedata.normalize("NFKC", sku.strip())
    if sku and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/\-]*", sku):
        abort(400, description="貨號請填完整英數字，可包含 . _ / -，不要填標題或日期。")
    supplied = body.get("lines")
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= 150:
        abort(400, description="請逐字確認 1 至 150 段標準文字。")
    texts = []
    for item in supplied:
        if not isinstance(item, dict) or set(item) != {"text"}:
            abort(400, description="每段標準文字只能提供 text。")
        text = fixed_line_text(item["text"])
        if _kind(text) == "product" and normalize_text(text) != normalize_text(name):
            abort(400, description="品名與標準文字中的品名不同，請逐字修正後再預覽。")
        if text not in texts:
            texts.append(text)
    if not any(normalize_text(text) == normalize_text(name) for text in texts):
        texts.insert(0, "品名：" + name)
    listed_skus = {value for text in texts for value in _identifiers(text, _SKU_LABEL, normalize=lambda v:v)}
    if sku and listed_skus and listed_skus != {sku}:
        abort(400, description="貨號與標準文字中的貨號不同，請確認。")
    if sku and not listed_skus:
        texts.insert(1, "貨號：" + sku)
    keep_days = body.get("keep_days")
    if keep_days is not None:
        keep_days = _integer(keep_days, "保存天數", 0, 3650)
    settings, kinds = [], set()
    supplied_dates = body.get("date_settings", [])
    if not isinstance(supplied_dates, list) or len(supplied_dates) > 3:
        abort(400, description="日期規則最多包含製造日、有效日與到店日。")
    for item in supplied_dates:
        if (not isinstance(item, dict) or set(item) != {"kind", "shift_days"}
                or not isinstance(item.get("kind"), str) or item["kind"] not in DATE_LABELS or item["kind"] in kinds):
            abort(400, description="每種日期只能設定一次，並填寫相對本批基準日的位移天數。")
        kinds.add(item["kind"])
        settings.append({"content": DATE_LABELS[item["kind"]], "format": "A",
                         "shift_days": _integer(item["shift_days"], "日期位移", -3650, 3650)})
    lines = [{"id": index, "text": fixed_line_text(value), "score": 1., "box": []} for index, value in enumerate(texts)]
    fields = fields_from_lines(lines, name)
    source = {"name": name, "source_kind": "manual", "comparison_scope": "manual_text",
              "fields": fields, "lines": lines, "rules": {"dates": bool(kinds & {"manufacture", "expiry"}), "arrival": "arrival" in kinds},
              "keep_days": keep_days, "keep_days_source": "manual_confirmation", "date_settings": settings,
              "barcode_config": {}, "barcode_values": sorted({value for text in texts for value in _fixed_barcodes(text)}),
              "known_fields": [key for key, value in fields.items() if value], "limitations": LIMITATIONS,
              "notice": "人工確認的獨立文字標準；只核對已列入的內容，不代表具有完整印標版面。"}
    validate_date_rules(source)
    digest = hashlib.sha256(json.dumps(source, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source.update(revision=digest)
    return source, digest


def preview(engine, inspection, body):
    allowed = DEFINITION_KEYS
    if not isinstance(body, dict) or set(body) - allowed:
        abort(400, description="預覽只接受品名、貨號、標準文字、保存天數及日期規則。")
    can_create, _, notice = _context(engine, inspection)
    if not can_create:
        abort(409, description=notice)
    source, digest = definition(body)
    return {"source": source, "preview_hash": digest, "warnings": LIMITATIONS + ["日期位移直接相對本批基準日；不會自動加上保存天數。"]}


def save(engine, inspection, body):
    import standard_reference as standards
    if not isinstance(body, dict) or set(body) - (DEFINITION_KEYS | {"preview_hash", "reviewer", "note", "confirmed"}):
        abort(400, description="人工標準內容格式不正確。")
    if body.get("confirmed") is not True:
        abort(400, description="請確認已逐字核對，並將套用到之後同款標籤。")
    can_create, _, notice = _context(engine, inspection)
    if not can_create:
        abort(409, description=notice)
    reviewer = standards._text(body.get("reviewer"), "確認人員", 100)
    note = standards._text(body.get("note"), "確認原因", 2000)
    source, digest = definition(body)
    if body.get("preview_hash") != digest:
        abort(409, description="內容尚未預覽或已變更，請重新預覽並確認後儲存。")
    code, created = PREFIX + db.uid(), db.now()
    source.update(code=code, provenance={"inspection_id": inspection["id"], "reviewer": reviewer, "created_at": created})
    try:
        with engine.begin() as conn:
            standards._lock_active_inspection(conn, inspection["id"])
            conn.execute(insert(db.manual_sources).values(code=code, name=source["name"], inspection_id=inspection["id"],
                reference_hash=digest, snapshot=source, active=True, reviewer=reviewer, note=note, created_at=created))
            conn.execute(insert(standards.heads).values(code=code, revision=1))
            conn.execute(insert(standards.versions).values(id=db.uid(), code=code, revision=1,
                source_revision=digest, operation="create", snapshot=source, changes={},
                inspection_id=inspection["id"], reviewer=reviewer, note=note, created_at=created))
    except IntegrityError:
        abort(409, description="這張照片或相同標準內容已建立，請搜尋並選用既有標準，不會重複新增。")
    return {"code": code, "name": source["name"], "source_kind": "manual", "comparison_scope": "manual_text",
            "source": source, "revision": 1}


def register_routes(app, engine):
    from standard_reference import _inspection
    @app.get("/api/manual-standards")
    def list_manual_references():
        try:
            page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 24))
        except ValueError:
            abort(400, description="頁碼與每頁筆數須為整數。")
        return jsonify(listing(engine, request.args.get("q", ""), page, limit))

    @app.get("/api/inspections/<identifier>/manual-standard")
    def get_manual_reference(identifier):
        return jsonify(payload(engine, _inspection(engine, identifier)))

    @app.post("/api/inspections/<identifier>/manual-standard/preview")
    def preview_manual_reference(identifier):
        return jsonify(preview(engine, _inspection(engine, identifier), request.get_json(silent=True)))

    @app.post("/api/inspections/<identifier>/manual-standard")
    def create_manual_reference(identifier):
        return jsonify(save(engine, _inspection(engine, identifier), request.get_json(silent=True))), 201
