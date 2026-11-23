"""Approve this inspection's text in a new version of its existing photo family.

Original OCR, inspection snapshots and prior photo versions are never rewritten.
This module performs no recognition and therefore cannot incur an API request.
"""
from copy import deepcopy

from flask import abort, current_app
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError, OperationalError

import database as db
import standard_library as library
import standard_reference as standards
from validation import FIELD_NAMES, TEXT_FIELDS


def source_for(template):
    """Adapt approved fields only; never populate a standard from a scan here."""
    rules = template.get("rules") or {}
    approved = rules.get("approved_text_source")
    if approved:
        source = deepcopy(approved)
    else:
        legacy_source = rules.get("source") or {}
        fields = deepcopy(template.get("fields") or {})
        rows = [{"id": "photo_" + key, "text": FIELD_NAMES[key] + "：" + fields[key],
                 "score": 1., "box": []} for key in TEXT_FIELDS if fields.get(key)]
        source = {"name": template["name"], "fields": fields, "lines": rows,
            "keep_days": rules.get("keep_days"), "keep_days_source": "photo_standard",
            "date_settings": deepcopy(legacy_source.get("date_settings", rules.get("date_settings", []))),
            "barcode_config": deepcopy(legacy_source.get("barcode_config", rules.get("barcode_config", {}))),
            "barcode_values": deepcopy(legacy_source.get("barcode_values", rules.get("barcode_values", []))),
            "rules": {"dates": bool(rules.get("dates")), "arrival": bool(rules.get("arrival"))},
            "known_fields": [key for key, value in fields.items() if value],
            "comparison_scope": "configured_fields", "limitations": ["目前只包含已核准的照片欄位；全文尚待人工確認。"]}
    source.update(code="photo:" + template["family_id"], source_kind="photo", revision=template["id"],
                  reference_image_id=template["image_id"])
    return source


def _context(conn, inspection, lock=False):
    identifier = inspection.get("template_id")
    origin = conn.execute(select(db.templates).where(db.templates.c.id == identifier)).mappings().first()
    if origin is None:
        abort(409, description="找不到原照片標準，無法建立同款新版；原檢查紀錄仍保留。")
    template = library._photo_family(conn, origin["family_id"], lock=lock)
    state = library._state(conn, "photo", origin["family_id"], lock=lock)
    return template, state


def _guard(template, state, body):
    if state["removed"] or not template["active"]:
        abort(409, description="這份照片標準已移除，請先從標準庫還原後再編輯。")
    if (standards._integer(body.get("base_revision"), "版本", 1, 2**31-2) != template["version"]
            or body.get("source_revision") != template["id"]):
        abort(409, description="照片標準已有新版，請重新載入最新文字與照片後確認。")


def _image(identifier):
    callback = current_app.extensions.get("label_reference_image_payload")
    return library._safe_image(callback, identifier) if callback and identifier else None


def payload(engine, inspection):
    with engine.connect() as conn:
        template, state = _context(conn, inspection)
        history = conn.execute(select(db.templates).where(db.templates.c.family_id == template["family_id"])
            .order_by(db.templates.c.version.desc()).limit(11)).mappings().all()
    source = source_for(template)
    removed = state["removed"] or not template["active"]
    result = {"editable": not removed, "removed": removed, "kind": "photo_template", "code": source["code"],
        "name": source["name"], "base_revision": template["version"], "source_revision": template["id"],
        "photo_template_id": template["id"], "source": source, "stale": False,
        "supports_line_replacement": True, "supports_history_restore": False,
        "focus_ids_stale": inspection.get("template_id") != template["id"],
        "current_reference_image": _image(template["image_id"]),
        "history": [{"revision": row["version"], "operation": "photo_version", "reviewer": row["approved_by"],
            "note": (row.get("rules") or {}).get("web_text_update", {}).get("note", "照片標準版本"),
            "created_at": row["created_at"], "source_revision": row["id"], "name": row["name"]} for row in history[:10]],
        "has_more": len(history) > 10,
        "notice": "此標準已移除，請先從標準庫還原後再編輯。" if removed else
            "確認後會建立同款照片標準新版；舊文字、照片及檢查紀錄都會保留，不會重新辨識。"}
    if not removed:
        result.update(standards.inspection_draft_fields(engine, inspection, source))
    return result


def _changed(conn, inspection, template, body):
    source = source_for(template)
    standards._check_draft_revision(conn, inspection, body, source)
    use_photo = standards._use_inspection_photo(body, source)
    changes = body.get("changes", {})
    changed = standards.changed_snapshot(source, source, changes)
    from manual_reference import validate_date_rules
    validate_date_rules(changed)
    result = deepcopy(template)
    if use_photo:
        from reference_photos import require_inspection_image
        result["image_id"] = require_inspection_image(conn, inspection)
        changed.update(reference_image_id=result["image_id"], reference_inspection_id=inspection["id"])
    result.update(name=changed["name"], fields={**result["fields"], **changed.get("fields", {})})
    result["rules"]["keep_days"] = changed.get("keep_days")
    # Preserve legacy mode for a photo-only operation. Full text becomes an
    # approved comparison source only after explicit full-text replacement.
    if "replace_lines" in changes or template["rules"].get("approved_text_source"):
        result["rules"]["approved_text_source"] = changed
    elif any(key in changes for key in ("lines", "date_settings")):
        abort(400, description="第一次核准照片全文時請提供完整文字；原日期規則會一併保留。")
    return result, changed, use_photo


def preview_changes(engine, inspection, body):
    if (not isinstance(body, dict) or not {"base_revision", "source_revision", "changes"} <= set(body)
            or set(body) - {"base_revision", "source_revision", "changes", "draft_manual_revision", "use_inspection_photo"}):
        abort(400, description="請提供目前照片標準版本與待預覽內容。")
    with engine.connect() as conn:
        template, state = _context(conn, inspection)
        _guard(template, state, body)
        _, source, use_photo = _changed(conn, inspection, template, body)
    return {"base_revision": template["version"], "source_revision": template["id"], "source": source,
        "use_inspection_photo": use_photo,
        "nutrition_checks": []}


def save(engine, inspection, body):
    allowed = {"base_revision", "source_revision", "changes", "reviewer", "note", "confirmed", "operation",
               "target_revision", "draft_manual_revision", "use_inspection_photo"}
    if not isinstance(body, dict) or body.get("confirmed") is not True or set(body) - allowed:
        abort(400, description="請明確確認此照片標準將用於後續同款標籤。")
    if body.get("operation", "update") != "update" or "target_revision" in body:
        abort(409, description="照片標準請預覽完整文字後建立新版，目前不支援直接還原歷史版本。")
    reviewer = standards._text(body.get("reviewer"), "確認人", 100)
    note = standards._text(body.get("note"), "修改原因", 2000)
    try:
        with engine.begin() as conn:
            standards._lock_active_inspection(conn, inspection["id"])
            template, state = _context(conn, inspection, lock=True)
            _guard(template, state, body)
            changed, source, use_photo = _changed(conn, inspection, template, body)
            identifier = db.uid()
            changed.update(id=identifier, version=template["version"] + 1, active=True,
                           approved_by=reviewer, created_at=db.now())
            approved = changed["rules"].get("approved_text_source")
            if approved:
                approved["revision"] = identifier
            evidence = {"inspection_id": inspection["id"], "note": note, "use_inspection_photo": use_photo}
            if "draft_manual_revision" in body:
                evidence["draft_manual_revision"] = body["draft_manual_revision"]
            changed["rules"]["web_text_update"] = evidence
            updated = conn.execute(update(db.templates).where(db.templates.c.id == template["id"],
                db.templates.c.active.is_(True), db.templates.c.version == template["version"]).values(active=False))
            if updated.rowcount != 1:
                abort(409, description="另一位使用者已更新照片標準，請重新載入。")
            conn.execute(insert(db.templates).values(**changed))
            item_revision = library._write_state(conn, state)
            library._audit(conn, "photo", template["family_id"], "save", reviewer, note,
                {"item_revision": item_revision, "base_revision": changed["version"],
                 "reviewer": reviewer, **evidence})
    except IntegrityError:
        abort(409, description="另一位使用者已建立照片標準新版，請重新載入。")
    except OperationalError as error:
        if getattr(error.orig, "sqlite_errorcode", None) in {5, 6, 517}:
            abort(409, description="照片標準正在更新，請重新載入後再確認。")
        raise
    return payload(engine, inspection)
