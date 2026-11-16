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
import history_cleanup
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
    if not isinstance(changes, dict) or set(changes) - {"name", "lines", "replace_lines", "keep_days", "date_settings"}:
        abort(400, description="標準只可修改品名、既有文字列、保存天數及日期位移。")
    result = deepcopy(current)
    result.pop("standard_reference", None)
    result.pop("base_date", None)
    result["revision"] = base["revision"]
    original_product_rows = _product_rows(current)
    rows = {str(row["id"]): row for row in result.get("lines", [])}
    changed_ids = set()
    replacing = "replace_lines" in changes
    if replacing:
        if result.get("source_kind") not in {"manual","catalog","desktop","photo"} or "lines" in changes:
            abort(400, description="此來源不支援整份文字替換，或同時傳送了逐列修改。")
        supplied = changes["replace_lines"]
        if not isinstance(supplied, list) or not 1 <= len(supplied) <= 150:
            abort(400, description="請提供 1 至 150 行完整標準文字；空白行請直接刪除。")
        from manual_reference import fixed_line_text
        replacements, used = [], set()
        for index, item in enumerate(supplied):
            if not isinstance(item, dict) or set(item) != {"text"}:
                abort(400, description="整份文字的每行只能提供 text。")
            value = fixed_line_text(item["text"])
            prior = [row for row in current.get("lines", []) if row["text"] == value]
            # Reuse only a unique unchanged row's ID. New/merged/split rows get
            # IDs that cannot point a historical highlight at a different row.
            if len(prior)==1 and str(prior[0]["id"]) not in used:
                identifier = prior[0]["id"]
            else:
                seed=json.dumps([current.get("revision"),index,value],ensure_ascii=False)
                identifier="web_"+hashlib.sha256(seed.encode()).hexdigest()[:24]
            used.add(str(identifier))
            replacements.append({"id":identifier,"text":value,"score":1.,"box":[]})
        result["lines"] = replacements
        result.pop("catalog_barcode_line_ids",None)
        if result.get("source_kind") != "manual":
            result.update(web_text_approved=True,comparison_scope="approved_text",
                limitations=["只核對已人工確認的網站文字與原有日期、條碼規則；未建立或改動列印版面。"])
        rows = {str(row["id"]):row for row in replacements}
        changed_ids = set(rows)
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
            if isinstance(patch["text"], str) and not patch["text"].strip():
                from source_validation import _kind, DATE_KEYS
                if result.get("source_kind") != "manual" and (barcode_row or _kind(rows[identifier]["text"]) in DATE_KEYS
                        or any(str(row["id"])==identifier for row in original_product_rows)):
                    abort(400, description="系統或清單來源的品名、條碼及日期欄不可刪除；可修正其內容。")
                del rows[identifier]
                changed_ids.add(identifier)
                continue
            rows[identifier]["text"] = _fixed_text(_text(patch["text"], "標準文字"), allow_numeric_barcode=barcode_row)
            changed_ids.add(identifier)
        result["lines"]=[row for row in result["lines"] if str(row["id"]) in rows]
        if not result["lines"]:
            abort(400, description="標準至少須保留一行文字。")
    if replacing:
        heading=r"^\s*(?:產品名稱|商品名稱|產品品名|品名)\s*[：:]?\s*"
        named=[row for row in result["lines"] if re.match(heading,row["text"])]
        names={re.sub(heading,"",row["text"],count=1).strip() for row in named}
        if len(names)>1 or "" in names:
            abort(400, description="標準中的品名不一致或空白，請確認後再儲存。")
        name=_fixed_text(_text(changes["name"],"品名",200)) if "name" in changes else next(iter(names),result["name"])
        if names and names != {name}:
            abort(400, description="品名與完整標準文字不一致，請一併修正。")
        prior_names={normalize_text(row["text"]) for row in original_product_rows}
        if any(normalize_text(row["text"]) in prior_names and normalize_text(row["text"]) != normalize_text(name)
               for row in result["lines"]):
            # Full replacement is authoritative: never silently rewrite a
            # retained bare product name or revive a deliberately deleted row.
            abort(400, description="完整標準文字仍保留舊品名，請與品名欄一併修正。")
        result["name"]=name
    elif "name" in changes:
        name = _fixed_text(_text(changes["name"], "品名", 200))
        original_product_rows=[row for row in original_product_rows if str(row["id"]) in rows]
        if not original_product_rows and result.get("source_kind") != "manual":
            abort(400, description="找不到原標準的品名文字列，請先確認來源資料。")
        for original in original_product_rows:
            target = rows[str(original["id"])]
            heading = re.match(r"\s*(?:產品名稱|商品名稱|產品品名|品名)\s*[：:]?\s*", original["text"])
            value = (heading[0] if heading else "") + name
            if str(original["id"]) in changed_ids and normalize_text(target["text"]) != normalize_text(value):
                abort(400, description="品名與品名文字列的修改內容不一致。")
            target["text"] = value
        result["name"] = name
    elif original_product_rows and any(str(row["id"]) in changed_ids and str(row["id"]) in rows for row in original_product_rows):
        names = {re.sub(r"^\s*(?:產品名稱|商品名稱|產品品名|品名)\s*[：:]?\s*", "", rows[str(row["id"])]["text"])
                 for row in original_product_rows if str(row["id"]) in rows}
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
    if result.get("source_kind") == "catalog" and not result.get("web_text_approved"):
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
    elif result.get("source_kind") in {"manual","photo"} or result.get("web_text_approved"):
        from manual_reference import fields_from_lines
        result["fields"] = fields_from_lines(result.get("lines", []), result["name"])
        result["known_fields"] = [key for key, value in result["fields"].items() if value]
    else:
        fields = extract_fields(result.get("lines", []))
        result["fields"] = {key: fields.get(key, {}).get("value", "") for key in TEXT_FIELDS}
        result["fields"]["product"] = result["name"]
    # Static barcode annotations may have been edited, but composed runtime
    # barcodes remain owned by their untouched original barcode configuration.
    if result.get("source_kind") == "manual":
        result["barcode_values"] = sorted({value for row in result.get("lines", []) for value in _fixed_barcodes(row["text"])})
    elif result.get("source_kind") != "catalog" and not result.get("web_text_approved"):
        result["barcode_values"] = sorted({value for row in result.get("lines", []) for value in _fixed_barcodes(row["text"])})
    if any(key in changes for key in ("date_settings","keep_days")):
        from manual_reference import validate_date_rules
        validate_date_rules(result,include_external=True)
    return result


def _inspection(engine, identifier):
    with engine.connect() as conn:
        row = conn.execute(select(db.inspections).where(db.inspections.c.id == identifier)).mappings().first()
    if row is None:
        abort(404, description="找不到這筆辨識紀錄。")
    return dict(row)


def _lock_active_inspection(conn, identifier):
    """Serialize writes with reversible history cleanup, not only route guards."""
    existing = conn.execute(select(db.inspections.c.id).where(db.inspections.c.id == identifier)
                            .with_for_update()).scalar_one_or_none()
    if existing is None:
        abort(404, description="找不到這筆辨識紀錄。")
    history_cleanup.ensure_active(conn, identifier)


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
    from standard_library import removed_source_codes
    if str(source["code"]) in removed_source_codes(engine):
        current=_current(engine,str(source["code"]))
        return None,{"editable":False,"kind":source.get("source_kind","desktop"),"code":source["code"],"removed":True,
            "base_revision":current["revision"] if current else 0,"history":[],"has_more":False,
            "source":apply_current(engine,base,current or {}) if base else source,
            "notice":"這份網站標準已移除；請先從標準庫還原後再編輯。"}
    if base is None:
        if str(source["code"]).startswith("manual:"):
            with engine.connect() as conn:
                removed=conn.execute(select(db.manual_sources).where(db.manual_sources.c.code==str(source["code"]))).mappings().first()
            if removed and not removed["active"]:
                current=_current(engine,str(source["code"]))
                return None,{"editable":False,"kind":"manual","code":source["code"],"removed":True,
                    "name":removed["name"],"base_revision":current["revision"] if current else 0,"history":[],"has_more":False,
                    "source":apply_current(engine,removed["snapshot"],current or {}),
                    "notice":"此標準已移除，內容與歷史仍保留；請先從標準庫還原後再編輯。"}
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


def _inspection_draft_barcodes(rows, source, ocr):
    """Do not turn a newly observed batch barcode into permanent text.

    Only complete stand-alone valid GTINs or independently decoded literals
    qualify. Ordinary numeric lines, SKUs and nutrition quantities stay intact.
    """
    from barcode_checks import gtin_valid
    decoded = {str(item.get("text", "")) for item in (ocr.get("barcodes") or {}).get("items", [])}
    def value(text):
        text = unicodedata.normalize("NFKC", str(text)).strip()
        text = re.sub(r"^(?:條碼|条码|Barcode|EAN|GTIN)\s*[:：]?\s*", "", text, count=1, flags=re.I)
        compact = re.sub(r"\s+", "", text)
        return compact if gtin_valid(compact) is True else text if text in decoded else ""
    approved = {str(item) for item in source.get("barcode_values", [])}
    approved.update(found for row in source.get("lines", []) if (found := value(row.get("text", ""))))
    kept, excluded = [], []
    for row in rows:
        found = value(row.get("text", ""))
        config=source.get("barcode_config") or {}
        composed=bool(config.get("barcode") or config.get("solar") or config.get("front") or config.get("back"))
        if found and (composed or found not in approved):
            excluded.append(dict(row, value=found,
                reason="條碼可能含批次資料，未自動寫入固定文字；原始辨識與條碼檢查仍保留。"))
        else:
            kept.append(row)
    return kept, excluded


def inspection_draft_fields(engine,inspection,effective):
    from manual_reference import payload as authoring_payload
    draft=authoring_payload(engine,inspection)
    draft_rows,excluded_barcodes=_inspection_draft_barcodes(draft["draft_lines"],effective,inspection.get("ocr") or {})
    return dict(regrouped_draft_lines=draft_rows,regrouped_excluded_barcode_lines=excluded_barcodes,
        regrouped_excluded_date_lines=draft["excluded_date_lines"],
        regrouped_excluded_unconfirmed_lines=draft["excluded_unconfirmed_lines"],
        regrouped_manual_revision=draft["manual_revision"],regrouped_inspection_id=inspection["id"],
        regrouped_draft_basis=draft["draft_basis"],regrouped_suggested_name=draft["suggested_name"],
        regrouped_eligibility=draft["manual_standard_eligibility"],
        regrouped_can_apply=bool(draft_rows) and draft["manual_standard_eligibility"]["eligible"],
        regrouped_notice="這是依本張照片及已確認辨識訂正整理的草稿；不會自動取代目前已核准的文字。")


def payload(engine, inspection):
    base, unsupported = _context(engine, inspection)
    if unsupported:
        if inspection.get("template_id"):
            with engine.connect() as conn:
                if conn.execute(select(db.templates.c.id).where(db.templates.c.id==inspection["template_id"])).first() is None:
                    return unsupported
            import photo_standard_authoring
            return photo_standard_authoring.payload(engine,inspection)
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
    extra={"supports_line_replacement":base.get("source_kind") in {"manual","catalog","desktop"},
           "focus_ids_stale":str(((inspection.get("template_snapshot") or {}).get("source") or {}).get("revision", "")) != str(effective["revision"])}
    if extra["supports_line_replacement"]:
        from reference_photos import current_image
        extra.update(inspection_draft_fields(engine,inspection,effective),current_reference_image=current_image(engine,effective))
    return {"editable": True, "kind": base["source_kind"], "code": base["code"], "name": effective["name"],
            "base_revision": current["revision"] if current else 0, "source_revision": str(base["revision"]),
            "stale": effective.get("standard_reference", {}).get("state") == "stale",
            "notice": notice, "source": effective,
            "history": [dict(row) for row in history[:10]], "has_more": len(history) > 10, **extra}


def _check_draft_revision(conn, inspection, body, source):
    """Guard an explicit current-inspection draft, without changing the OCR.

    Saves call this while holding the inspection row lock used by corrections,
    so a concurrent human correction cannot silently change the draft's basis.
    Ordinary edits of the approved standard do not need this optional guard.
    """
    if "draft_manual_revision" not in body:
        return
    if source.get("source_kind") not in {"manual","catalog","desktop","photo"}:
        abort(400, description="此來源不支援帶入本次辨識。")
    wanted = _integer(body["draft_manual_revision"], "辨識訂正版本", 0, 2**31-2)
    import corrections
    from standard_draft_quality import eligibility
    correction = corrections.latest(conn, inspection["id"])
    if wanted != (correction["revision"] if correction else 0):
        abort(409, description="本次辨識訂正已更新，請重新載入最新辨識草稿後確認。")
    quality = eligibility(inspection.get("ocr"), (correction or {}).get("patches"), inspection.get("result"))
    if not quality["eligible"]:
        abort(409, description=quality["reason"])


def _use_inspection_photo(body, source):
    value = body.get("use_inspection_photo", False)
    if not isinstance(value, bool):
        abort(400, description="更新標準照片須為明確的勾選設定。")
    if value and source.get("source_kind") not in {"manual","catalog","desktop","photo"}:
        abort(400, description="此來源不支援設定目前標準照片。")
    return value


def preview_changes(engine, inspection, body):
    """Validate the exact replacement/delta without writing a standard version."""
    if (not isinstance(body,dict) or not {"base_revision","source_revision","changes"} <= set(body)
            or set(body)-{"base_revision","source_revision","changes","draft_manual_revision","use_inspection_photo"}):
        abort(400,description="請提供目前版本與待預覽的修改內容。")
    base,unsupported=_context(engine,inspection)
    if unsupported:
        if inspection.get("template_id"):
            import photo_standard_authoring
            return photo_standard_authoring.preview_changes(engine,inspection,body)
        abort(409,description=unsupported["notice"])
    current=_current(engine,str(base["code"]))
    revision=current["revision"] if current else 0
    if (_integer(body.get("base_revision"),"版本",0,2**31-2)!=revision
            or body.get("source_revision")!=str(base["revision"])):
        abort(409,description="標準或來源已更新，請重新載入後預覽。")
    effective=apply_current(engine,base,current or {})
    use_photo = _use_inspection_photo(body,effective)
    with engine.connect() as conn:
        _check_draft_revision(conn,inspection,body,effective)
        if use_photo:
            from reference_photos import require_inspection_image
            require_inspection_image(conn,inspection)
    source=changed_snapshot(base,effective,body["changes"])
    if use_photo:
        source["reference_image_id"]=inspection["image_id"]
        source["reference_inspection_id"]=inspection["id"]
    if source.get("source_kind")=="manual":
        from manual_reference import validate_date_rules
        validate_date_rules(source)
    from nutrition_checks import checks_for
    return {"base_revision":revision,"source_revision":str(base["revision"]),"source":source,
            "use_inspection_photo":use_photo,
            "nutrition_checks":checks_for({"lines":source["lines"],"context":"standard_draft"})}


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
    from nutrition_checks import checks_for
    result["nutrition_checks"]=checks_for({"lines":result["source"]["lines"],"context":"standard_draft"})
    return result


def save(engine, inspection, body):
    if not isinstance(body, dict) or body.get("confirmed") is not True:
        abort(400, description="請明確確認此標準將用於後續同款標籤。")
    if set(body) - {"base_revision", "source_revision", "changes", "reviewer", "note", "confirmed", "operation", "target_revision", "draft_manual_revision", "use_inspection_photo"}:
        abort(400, description="不支援的標準修改欄位。")
    base_revision = _integer(body.get("base_revision"), "版本", 0, 2**31-2)
    reviewer, note = _text(body.get("reviewer"), "確認人", 100), _text(body.get("note"), "修改原因", 2000)
    operation = body.get("operation", "update")
    if not isinstance(operation, str) or operation not in {"update", "reset", "restore"}:
        abort(400, description="不支援的版本操作。")
    if operation != "update" and "draft_manual_revision" in body:
        abort(400, description="還原版本時不可同時帶入本次辨識。")
    if operation != "update" and body.get("use_inspection_photo"):
        abort(400, description="還原版本時不可同時更新標準照片。")
    base, unsupported = _context(engine, inspection)
    if unsupported:
        if inspection.get("template_id"):
            import photo_standard_authoring
            return photo_standard_authoring.save(engine,inspection,body)
        abort(409, description=unsupported["notice"])
    if body.get("source_revision") != str(base["revision"]):
        abort(409, description="原始來源已變更，請重新載入後確認；未套用舊文字列修改。")
    code = str(base["code"])
    try:
        with engine.begin() as conn:
            _lock_active_inspection(conn, inspection["id"])
            from standard_library import ensure_selectable
            ensure_selectable(conn,code=code)
            fresh,unavailable=_context(engine,inspection)
            if unavailable or fresh is None or str(fresh["revision"])!=body.get("source_revision"):
                abort(409,description="原始來源已變更，請重新載入後確認。")
            base=fresh
            if conn.dialect.name == "postgresql":
                from sqlalchemy.dialects.postgresql import insert as upsert
            else:
                from sqlalchemy.dialects.sqlite import insert as upsert
            conn.execute(upsert(heads).values(code=code,revision=0).on_conflict_do_nothing(index_elements=["code"]))
            head = conn.execute(select(heads).where(heads.c.code == code).with_for_update()).mappings().first()
            current_revision = head["revision"] if head else 0
            if current_revision != base_revision:
                abort(409, description="另一位使用者已建立新版，請重新載入後修改。")
            prior = conn.execute(select(versions).where((versions.c.code == code) &
                (versions.c.revision == current_revision))).mappings().first() if current_revision else None
            effective = apply_current(engine, base, dict(prior) if prior else {})
            _check_draft_revision(conn,inspection,body,effective)
            use_photo = _use_inspection_photo(body,effective)
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
            if use_photo:
                from reference_photos import require_inspection_image
                snapshot["reference_image_id"] = require_inspection_image(conn,inspection)
                snapshot["reference_inspection_id"] = inspection["id"]
            new_revision = current_revision + 1
            stored_changes = deepcopy(body.get("changes", {}))
            if "draft_manual_revision" in body:
                stored_changes["draft_origin"] = {"inspection_id": inspection["id"],
                    "manual_revision": body["draft_manual_revision"]}
            if use_photo:
                stored_changes["reference_photo"] = {"image_id": inspection["image_id"], "inspection_id": inspection["id"]}
            version = dict(id=db.uid(), code=code, revision=new_revision,
                source_revision=str(base["revision"]), operation=operation, snapshot=snapshot,
                changes=stored_changes, inspection_id=inspection["id"], reviewer=reviewer, note=note, created_at=db.now())
            conn.execute(insert(versions).values(**version))
            if head:
                changed = conn.execute(update(heads).where((heads.c.code == code) & (heads.c.revision == current_revision)).values(revision=new_revision))
                if changed.rowcount != 1:
                    abort(409, description="標準版本已變更，請重新載入。")
            else:
                conn.execute(insert(heads).values(code=code, revision=new_revision))
            if use_photo:
                from reference_photos import attach_locked
                attach_locked(conn,inspection,apply_current(engine,base,version),new_revision,reviewer,note)
    except IntegrityError:
        abort(409, description="另一位使用者已建立新版，請重新載入後修改。")
    return payload(engine, inspection)


def register_routes(app, engine):
    from manual_reference import register_routes as register_manual_routes
    register_manual_routes(app, engine)
    @app.get("/api/inspections/<identifier>/standard")
    def get_comparison_standard(identifier):
        return jsonify(payload(engine, _inspection(engine, identifier)))

    @app.route("/api/inspections/<identifier>/standard/preview",methods=["GET","POST"])
    def preview_comparison_standard(identifier):
        if request.method=="POST":
            return jsonify(preview_changes(engine,_inspection(engine,identifier),request.get_json(silent=True)))
        return jsonify(preview(engine, _inspection(engine, identifier), request.args.get("operation"),
                               request.args.get("target_revision")))

    @app.post("/api/inspections/<identifier>/standard")
    def update_comparison_standard(identifier):
        return jsonify(save(engine, _inspection(engine, identifier), request.get_json(silent=True))), 201
