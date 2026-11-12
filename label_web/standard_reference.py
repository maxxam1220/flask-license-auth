"""Approved web comparison standards; never update the desktop printer tables."""
from copy import deepcopy
import hashlib
import json
import re
import unicodedata

from flask import abort, jsonify, request
from sqlalchemy import Column, Integer, JSON, String, Table, Text, UniqueConstraint, inspect, select, insert, update
from sqlalchemy.exc import IntegrityError

import database as db
from validation import extract_fields, TEXT_FIELDS
from source_validation import normalize_text


heads = Table("labelcheck_standard_heads", db.metadata,
    Column("code", String(80), primary_key=True), Column("revision", Integer, nullable=False))
versions = Table("labelcheck_standard_versions", db.metadata,
    Column("id", String(32), primary_key=True), Column("code", String(80), nullable=False, index=True),
    Column("revision", Integer, nullable=False), Column("source_revision", String(128), nullable=False),
    Column("operation", String(20), nullable=False), Column("snapshot", JSON, nullable=False),
    Column("changes", JSON, nullable=False), Column("inspection_id", String(32), nullable=False),
    Column("reviewer", String(100), nullable=False), Column("note", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint("code", "revision", name="uq_labelcheck_standard_revision"))


def _storage_available(engine):
    inspector = inspect(engine, raiseerr=False)
    return inspector is not None and inspector.has_table(heads.name) and inspector.has_table(versions.name)


def current_versions(engine):
    """Only current versions, not the growing audit history, enter source lookup."""
    if not _storage_available(engine):
        return {}
    with engine.connect() as conn:
        rows = conn.execute(select(versions).join(heads,
            (heads.c.code == versions.c.code) & (heads.c.revision == versions.c.revision))).mappings()
        return {row["code"]: dict(row) for row in rows}


def _current(engine, code):
    if not _storage_available(engine):
        return None
    with engine.connect() as conn:
        row = conn.execute(select(versions).join(heads,
            (heads.c.code == versions.c.code) & (heads.c.revision == versions.c.revision))
            .where(versions.c.code == code)).mappings().first()
        return dict(row) if row else None


def apply_current(engine, base, version=None):
    if base is None:
        return None
    version = _current(engine, str(base["code"])) if version is None else version
    if not version:
        return deepcopy(base)
    stale = version["source_revision"] != str(base["revision"])
    active = not stale and version["operation"] != "reset"
    result = deepcopy(version["snapshot"] if active else base)
    result["standard_reference"] = {
        "state": "stale" if stale else "approved" if active else "base",
        "revision": version["revision"], "source_revision": str(base["revision"]),
        "approved_source_revision": version["source_revision"],
        "reviewer": version["reviewer"], "created_at": version["created_at"]}
    if active:
        result["revision"] = hashlib.sha256(json.dumps({"base": base["revision"], "version": version["revision"],
            "snapshot": version["snapshot"]}, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()
        result["notice"] = "使用已人工確認的網站比對標準；原列印系統資料未變更。"
    elif stale:
        result["notice"] = "原始來源已變更，舊網站標準已停用；請開啟比對標準重新確認後建立新版。"
    return result


def _text(value, label, maximum=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        abort(400, description=f"{label}不可空白，且長度須在 {maximum} 字以內。")
    return value.strip()


def _integer(value, label, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        abort(400, description=f"{label}須為 {low} 至 {high} 的整數。")
    return value


def _fixed_text(value, allow_numeric_barcode=False):
    # Date offsets belong to date_settings. Saving one inspection's date as
    # permanent printed text would incorrectly approve future labels.
    prepared = unicodedata.normalize("NFKC", value)
    if re.search(r"(?<!\d)\d{3,4}\s*(?:[./-]\s*\d{1,2}\s*[./-]\s*\d{1,2}|年\s*\d{1,2}月\s*\d{1,2}日)(?!\d)", prepared) or re.search(
            r"(?:製造日|生產日|有效日|有效期|到期日|到店日|到貨日).*\d", prepared) or (
            not allow_numeric_barcode and re.fullmatch(r"(?:19|20)\d{2}[01]\d[0-3]\d", prepared)):
        abort(400, description="本批日期不可存為固定標準文字；請調整保存天數或日期位移。")
    return value


def _product_rows(source):
    wanted = {normalize_text(source.get("name", "")), normalize_text(source.get("fields", {}).get("product", ""))} - {""}
    return [row for row in source.get("lines", []) if normalize_text(row.get("text", "")) in wanted]


def changed_snapshot(base, current, changes):
    from label_source import _fixed_barcodes
    if not isinstance(changes, dict) or set(changes) - {"name", "lines", "keep_days", "date_settings"}:
        abort(400, description="標準只可修改品名、既有文字列、保存天數及日期位移。")
    result = deepcopy(current)
    result.pop("standard_reference", None)
    result.pop("base_date", None)
    result["revision"] = base["revision"]
    original_product_rows = _product_rows(current)
    rows = {str(row["id"]): row for row in result.get("lines", [])}
    changed_ids = set()
    if "lines" in changes:
        if not isinstance(changes["lines"], list) or len(changes["lines"]) > len(rows):
            abort(400, description="文字列修改格式不正確。")
        for patch in changes["lines"]:
            if not isinstance(patch, dict) or set(patch) != {"id", "text"} or isinstance(patch["id"], bool):
                abort(400, description="每列只能提供既有 id 與文字。")
            identifier = str(patch["id"])
            if identifier not in rows or identifier in changed_ids:
                abort(400, description="文字列不存在或重複，請重新載入標準。")
            barcode_row = identifier in {str(value) for value in result.get("catalog_barcode_line_ids", [])} or bool(_fixed_barcodes(rows[identifier]["text"]))
            rows[identifier]["text"] = _fixed_text(_text(patch["text"], "標準文字"), allow_numeric_barcode=barcode_row)
            changed_ids.add(identifier)
    if "name" in changes:
        name = _fixed_text(_text(changes["name"], "品名", 200))
        if not original_product_rows:
            abort(400, description="找不到原標準的品名文字列，請先確認來源資料。")
        for original in original_product_rows:
            target = rows[str(original["id"])]
            heading = re.match(r"\s*(?:產品名稱|商品名稱|產品品名|品名)\s*[：:]?\s*", original["text"])
            value = (heading[0] if heading else "") + name
            if str(original["id"]) in changed_ids and normalize_text(target["text"]) != normalize_text(value):
                abort(400, description="品名與品名文字列的修改內容不一致。")
            target["text"] = value
        result["name"] = name
    elif original_product_rows and any(str(row["id"]) in changed_ids for row in original_product_rows):
        names = {re.sub(r"^\s*(?:產品名稱|商品名稱|產品品名|品名)\s*[：:]?\s*", "", rows[str(row["id"])]["text"])
                 for row in original_product_rows}
        if len(names) != 1:
            abort(400, description="同款標準中的品名不一致，請一併修改。")
        result["name"] = next(iter(names))
    if "keep_days" in changes:
        result["keep_days"] = _integer(changes["keep_days"], "保存天數", 0, 3660)
        result["keep_days_source"] = "web_standard"
    if "date_settings" in changes:
        patches = changes["date_settings"]
        if not isinstance(patches, list):
            abort(400, description="日期位移格式不正確。")
        seen = set()
        for patch in patches:
            if not isinstance(patch, dict) or set(patch) != {"index", "shift_days"}:
                abort(400, description="日期設定只能修改既有項目的位移天數。")
            index = _integer(patch["index"], "日期項目", 0, len(result.get("date_settings", [])) - 1)
            if index in seen:
                abort(400, description="日期項目不可重複。")
            seen.add(index)
            result["date_settings"][index]["shift_days"] = _integer(patch["shift_days"], "位移天數", -3660, 3660)
    if result.get("source_kind") == "catalog":
        result["fields"] = {"product": result["name"]}
        barcode_ids = result.get("catalog_barcode_line_ids", [])
        for identifier in barcode_ids:
            if str(identifier) not in changed_ids:
                continue
            value = rows[str(identifier)]["text"]
            kind = str(result.get("barcode_config", {}).get("kind", ""))
            length = {"1": 13, "2": 12, "3": 8}.get(kind)
            if length and (not value.isascii() or not value.isdigit() or len(value) != length):
                abort(400, description=f"此類型條碼須為 {length} 位半形數字；不會自動補碼或修正字元。")
        if barcode_ids:
            result["barcode_values"] = [rows[str(identifier)]["text"] for identifier in barcode_ids]
        result["known_fields"] = list(dict.fromkeys([*result.get("known_fields", []), *(["keep_days"] if result.get("keep_days") is not None else [])]))
    elif result.get("source_kind") == "manual":
        from manual_reference import fields_from_lines
        result["fields"] = fields_from_lines(result.get("lines", []), result["name"])
        result["known_fields"] = [key for key, value in result["fields"].items() if value]
    else:
        fields = extract_fields(result.get("lines", []))
        result["fields"] = {key: fields.get(key, {}).get("value", "") for key in TEXT_FIELDS}
        result["fields"]["product"] = result["name"]
    # Static barcode annotations may have been edited, but composed runtime
    # barcodes remain owned by their untouched original barcode configuration.
    if result.get("source_kind") != "catalog":
        result["barcode_values"] = sorted({value for row in result.get("lines", []) for value in _fixed_barcodes(row["text"])})
    return result


def _inspection(engine, identifier):
    with engine.connect() as conn:
        row = conn.execute(select(db.inspections).where(db.inspections.c.id == identifier)).mappings().first()
    if row is None:
        abort(404, description="找不到這筆辨識紀錄。")
    return dict(row)


def _context(engine, inspection):
    from label_source import raw_draft
    snapshot = inspection.get("template_snapshot") or {}
    source = snapshot.get("source")
    if not source or not source.get("code"):
        from manual_reference import _context as manual_context
        can_create, existing_code, _ = manual_context(engine, inspection)
        return None, {"editable": False, "kind": "photo_template" if inspection.get("template_id") else "unmatched",
            "photo_template_id": inspection.get("template_id") or "", "base_revision": 0, "history": [], "has_more": False,
            "can_create_manual": can_create, "manual_reference_code": existing_code,
            "notice": "此紀錄使用照片標準，請從照片標準管理建立新版。" if inspection.get("template_id") else "請先選定唯一的比對來源，再修正標準。"}
    base = raw_draft(engine, str(source["code"]))
    if base is None:
        abort(409, description="原始來源已移除，無法建立此款標準。")
    if base.get("source_kind") == "catalog" and base.get("barcode_values"):
        # Catalogs have known literal barcodes but no printer layout. Expose
        # only those existing values as fixed editor IDs, never invent an
        # unknown barcode or turn a desktop's dated barcode into static text.
        base = deepcopy(base)
        identifiers = []
        for index, value in enumerate(base["barcode_values"]):
            identifier = "catalog_barcode" if index == 0 else f"catalog_barcode_{index}"
            base["lines"].append({"id": identifier, "text": str(value), "score": 1.})
            identifiers.append(identifier)
        base["catalog_barcode_line_ids"] = identifiers
    return base, None


def payload(engine, inspection):
    base, unsupported = _context(engine, inspection)
    if unsupported:
        return unsupported
    current = _current(engine, str(base["code"]))
    effective = apply_current(engine, base, current or {})
    notice = effective.get("notice", "")
    if effective.get("standard_reference", {}).get("state") not in {"approved", "stale"}:
        notice = ("目前使用商品清單的已知資料作為比對依據；沒有版面的欄位與日期排程不會推造。"
                  if base["source_kind"] == "catalog" else "目前使用人工確認的文字標準，只核對已列入內容及日期規則；沒有印標版面。"
                  if base["source_kind"] == "manual" else
                  "目前使用標籤系統原始資料作為比對依據；有日期設定時會依本批基準日核對。修改後另存網站比對標準版本。")
    with engine.connect() as conn:
        history = conn.execute(select(versions.c.revision, versions.c.operation, versions.c.reviewer,
            versions.c.note, versions.c.created_at, versions.c.source_revision,
            versions.c.snapshot["name"].as_string().label("name")).where(versions.c.code == base["code"])
            .order_by(versions.c.revision.desc()).limit(11)).mappings().all()
    return {"editable": True, "kind": base["source_kind"], "code": base["code"], "name": effective["name"],
            "base_revision": current["revision"] if current else 0, "source_revision": str(base["revision"]),
            "stale": effective.get("standard_reference", {}).get("state") == "stale",
            "notice": notice, "source": effective,
            "history": [dict(row) for row in history[:10]], "has_more": len(history) > 10}


def preview(engine, inspection, operation, target_revision=None):
    """Read the real restore/reset target without appending a version."""
    if not isinstance(operation, str) or operation not in {"reset", "restore"}:
        abort(400, description="請選擇還原原始來源或既有標準版本。")
    base, unsupported = _context(engine, inspection)
    if unsupported:
        abort(409, description=unsupported["notice"])
    current = _current(engine, str(base["code"]))
    current_revision = current["revision"] if current else 0
    result = {"base_revision": current_revision, "source_revision": str(base["revision"]),
              "operation": operation, "source": deepcopy(base)}
    if operation == "restore":
        if isinstance(target_revision, str) and re.fullmatch(r"[0-9]{1,10}", target_revision):
            target_revision = int(target_revision)
        target = _integer(target_revision, "還原版本", 1, current_revision)
        with engine.connect() as conn:
            previous = conn.execute(select(versions.c.snapshot, versions.c.source_revision)
                .where((versions.c.code == str(base["code"])) & (versions.c.revision == target))).mappings().first()
        if previous is None or previous["source_revision"] != str(base["revision"]):
            abort(409, description="舊版本對應的來源已變更，請重新確認文字後建立新版。")
        result.update(target_revision=target, source=deepcopy(previous["snapshot"]))
    elif target_revision is not None:
        abort(400, description="還原原始來源不需指定歷史版本。")
    return result


def save(engine, inspection, body):
    if not isinstance(body, dict) or body.get("confirmed") is not True:
        abort(400, description="請明確確認此標準將用於後續同款標籤。")
    if set(body) - {"base_revision", "source_revision", "changes", "reviewer", "note", "confirmed", "operation", "target_revision"}:
        abort(400, description="不支援的標準修改欄位。")
    base_revision = _integer(body.get("base_revision"), "版本", 0, 2**31-2)
    reviewer, note = _text(body.get("reviewer"), "確認人", 100), _text(body.get("note"), "修改原因", 2000)
    operation = body.get("operation", "update")
    if not isinstance(operation, str) or operation not in {"update", "reset", "restore"}:
        abort(400, description="不支援的版本操作。")
    base, unsupported = _context(engine, inspection)
    if unsupported:
        abort(409, description=unsupported["notice"])
    if body.get("source_revision") != str(base["revision"]):
        abort(409, description="原始來源已變更，請重新載入後確認；未套用舊文字列修改。")
    code = str(base["code"])
    try:
        with engine.begin() as conn:
            head = conn.execute(select(heads).where(heads.c.code == code).with_for_update()).mappings().first()
            current_revision = head["revision"] if head else 0
            if current_revision != base_revision:
                abort(409, description="另一位使用者已建立新版，請重新載入後修改。")
            prior = conn.execute(select(versions).where((versions.c.code == code) &
                (versions.c.revision == current_revision))).mappings().first() if current_revision else None
            effective = apply_current(engine, base, dict(prior) if prior else {})
            if operation == "reset":
                if body.get("changes"):
                    abort(400, description="還原原始來源時不可同時修改欄位。")
                snapshot = deepcopy(base)
            elif operation == "restore":
                target = _integer(body.get("target_revision"), "還原版本", 1, current_revision)
                previous = conn.execute(select(versions).where((versions.c.code == code) & (versions.c.revision == target))).mappings().first()
                if previous is None or previous["source_revision"] != str(base["revision"]):
                    abort(409, description="舊版本對應的來源已變更，請重新確認文字後建立新版。")
                if body.get("changes"):
                    abort(400, description="還原舊版本時不可同時修改欄位。")
                snapshot = deepcopy(previous["snapshot"])
            else:
                snapshot = changed_snapshot(base, effective, body.get("changes", {}))
            if snapshot.get("source_kind") == "manual":
                from manual_reference import validate_date_rules
                validate_date_rules(snapshot)
            new_revision = current_revision + 1
            conn.execute(insert(versions).values(id=db.uid(), code=code, revision=new_revision,
                source_revision=str(base["revision"]), operation=operation, snapshot=snapshot,
                changes=body.get("changes", {}), inspection_id=inspection["id"], reviewer=reviewer, note=note, created_at=db.now()))
            if head:
                changed = conn.execute(update(heads).where((heads.c.code == code) & (heads.c.revision == current_revision)).values(revision=new_revision))
                if changed.rowcount != 1:
                    abort(409, description="標準版本已變更，請重新載入。")
            else:
                conn.execute(insert(heads).values(code=code, revision=new_revision))
    except IntegrityError:
        abort(409, description="另一位使用者已建立新版，請重新載入後修改。")
    return payload(engine, inspection)


def register_routes(app, engine):
    from manual_reference import register_routes as register_manual_routes
    register_manual_routes(app, engine)
    @app.get("/api/inspections/<identifier>/standard")
    def get_comparison_standard(identifier):
        return jsonify(payload(engine, _inspection(engine, identifier)))

    @app.get("/api/inspections/<identifier>/standard/preview")
    def preview_comparison_standard(identifier):
        return jsonify(preview(engine, _inspection(engine, identifier), request.args.get("operation"),
                               request.args.get("target_revision")))

    @app.post("/api/inspections/<identifier>/standard")
    def update_comparison_standard(identifier):
        return jsonify(save(engine, _inspection(engine, identifier), request.get_json(silent=True))), 201
