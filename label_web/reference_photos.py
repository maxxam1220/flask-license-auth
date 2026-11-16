"""Explicit photo associations with existing comparison sources, never new OCR truth."""
from flask import abort, current_app, jsonify, request
from sqlalchemy import Column, Integer, String, Table, Text, UniqueConstraint, select, insert, func
from sqlalchemy.exc import IntegrityError

import database as db
import history_cleanup
import standard_reference as standards


photos = Table("labelcheck_reference_photos", db.metadata,
    Column("id", String(32), primary_key=True),
    Column("image_id", String(32), nullable=False, index=True),
    Column("inspection_id", String(32), nullable=False, index=True),
    Column("source_code", String(80), nullable=False, index=True),
    Column("source_revision", String(128), nullable=False),
    Column("standard_revision", Integer, nullable=False),
    Column("reviewer", String(100), nullable=False), Column("note", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint("image_id", "source_code", name="uq_labelcheck_reference_photo_source"))


def _code(value):
    value = standards._text(value, "標準代碼", 80)
    if any(ord(char) < 32 for char in value):
        abort(400, description="標準代碼格式不正確。")
    return value


def _source(engine, code, version=None):
    from label_source import raw_draft
    base = raw_draft(engine, code)
    if base is None:
        abort(404, description="找不到這份比對標準，請重新選擇。")
    effective = standards.apply_current(engine, base, version)
    if effective.get("standard_reference", {}).get("state") == "stale":
        abort(409, description="來源已變更，請先重新確認比對標準後再關聯照片。")
    return effective


def source_info(source):
    return {"code": str(source["code"]), "name": source["name"],
            "source_kind": source.get("source_kind", "desktop"),
            "source_revision": str(source["revision"]),
            "base_revision": source.get("standard_reference", {}).get("revision", 0)}


def require_inspection_image(conn, inspection):
    """Validate a current-inspection photo for an atomic standard update."""
    identifier = inspection["image_id"]
    available = current_app.extensions.get("label_reference_image_available")
    if (available is None or not available(identifier) or
            conn.execute(select(db.images.c.id).where(db.images.c.id == identifier)).first() is None):
        abort(409, description="這筆紀錄的原照片已不存在，無法設為目前標準照片；標準尚未儲存。")
    return identifier


def current_image(engine, source):
    """The approved current photo, falling back to the creation photograph."""
    identifier = source.get("reference_image_id")
    if not identifier:
        with engine.connect() as conn:
            identifier = conn.execute(select(db.inspections.c.image_id).join(db.manual_sources,
                db.manual_sources.c.inspection_id == db.inspections.c.id)
                .where(db.manual_sources.c.code == str(source["code"]))).scalar_one_or_none()
    image_payload = current_app.extensions.get("label_reference_image_payload")
    if not identifier or image_payload is None:
        return None
    from werkzeug.exceptions import HTTPException
    try:
        return image_payload(identifier)
    except HTTPException as error:
        if error.code == 404:
            return None
        raise


def attach_locked(conn, inspection, source, revision, reviewer, note):
    """Caller holds inspection + source/head locks and owns the transaction.

    Existing associations retain their original audit metadata. The standard
    snapshot separately records which retained photograph is current.
    """
    identifier = require_inspection_image(conn, inspection)
    existing = conn.execute(select(photos.c.id).where(photos.c.image_id == identifier,
        photos.c.source_code == str(source["code"]))).scalar_one_or_none()
    if existing:
        return existing
    identifier_row = db.uid()
    conn.execute(insert(photos).values(id=identifier_row, image_id=identifier, inspection_id=inspection["id"],
        source_code=str(source["code"]), source_revision=str(source["revision"]), standard_revision=revision,
        reviewer=reviewer, note=note, created_at=db.now()))
    return identifier_row


def _public(row, image_payload, current_revision=None):
    return dict(row, image=image_payload(row["image_id"]),
                stale=current_revision is not None and row["source_revision"] != current_revision)


def listing(engine, code, image_payload, image_available, page=1, limit=24):
    code = _code(code)
    page = standards._integer(page, "頁碼", 1, 1_000_000)
    limit = standards._integer(limit, "每頁筆數", 1, 50)
    source = _source(engine, code)
    clauses = [photos.c.source_code == code, history_cleanup.active_filter()]
    joined = photos.join(db.inspections, photos.c.inspection_id == db.inspections.c.id)
    with engine.connect() as conn:
        total = conn.execute(select(func.count()).select_from(joined).where(*clauses)).scalar_one()
        rows = conn.execute(select(photos).select_from(joined).where(*clauses)
            .order_by(photos.c.created_at.desc(), photos.c.id).offset((page-1)*limit).limit(limit+1)).mappings().all()
    available = [row for row in rows[:limit] if image_available(row["image_id"])]
    return {"items": [_public(dict(row), image_payload, str(source["revision"])) for row in available],
            "page": page, "has_more": len(rows) > limit, "total": total,
            "unavailable_on_page": len(rows[:limit])-len(available), "source": source_info(source)}


def payload(engine, inspection, image_payload, image_available, code=""):
    with engine.connect() as conn:
        history_cleanup.ensure_active(conn, inspection["id"])
        own = conn.execute(select(photos).join(db.inspections, photos.c.inspection_id == db.inspections.c.id)
                           .where(photos.c.image_id == inspection["image_id"], history_cleanup.active_filter())
                           .order_by(photos.c.created_at.desc()).limit(51)).mappings().all()
    if not image_available(inspection["image_id"]):
        abort(409, description="這筆紀錄的原照片已不存在，無法關聯為參考照片。")
    # A suggestion is explicit provenance, never an image-similarity decision.
    suggested = (inspection.get("template_snapshot") or {}).get("source")
    if not suggested or not suggested.get("code"):
        with engine.connect() as conn:
            prior = conn.execute(select(db.manual_sources.c.code).where(
                db.manual_sources.c.inspection_id == inspection["id"], db.manual_sources.c.active.is_(True))).first()
        suggested = {"code": prior.code} if prior else None
    if code:
        source = _source(engine, _code(code))
    elif suggested:
        source = _source(engine, str(suggested["code"]))
    else:
        source = None
    return {"inspection_id": inspection["id"], "image": image_payload(inspection["image_id"]),
            "source": source, "source_code": source["code"] if source else "",
            "source_revision": str(source["revision"]) if source else "",
            "base_revision": source_info(source)["base_revision"] if source else 0,
            "suggested_source": source_info(source) if source else None,
            "associations": [_public(dict(row), image_payload) for row in own[:50]],
            "associations_has_more": len(own) > 50,
            "linked_photos": listing(engine, str(source["code"]), image_payload, image_available) if source else
                {"items": [], "page": 1, "has_more": False, "total": 0, "unavailable_on_page": 0},
            "notice": "請確認這張照片與所選標準為同款內容；照片只加入參考，不會改寫標準或原始辨識。"}


def save(engine, inspection, body, image_payload, image_available):
    keys = {"source_code", "source_revision", "base_revision", "reviewer", "note", "confirmed"}
    if not isinstance(body, dict) or set(body)-keys or body.get("confirmed") is not True:
        abort(400, description="請明確確認照片與所選標準內容一致，再儲存關聯。")
    code = _code(body.get("source_code"))
    wanted = standards._text(body.get("source_revision"), "標準來源版本", 128)
    revision = standards._integer(body.get("base_revision"), "標準版本", 0, 2**31-2)
    reviewer = standards._text(body.get("reviewer"), "確認人員", 100)
    note = standards._text(body.get("note"), "確認原因", 2000)
    # Read the current base first; the version row is locked below before an
    # association is committed. External desktop edits remain separate sources.
    from label_source import raw_draft
    base = raw_draft(engine, code)
    if base is None:
        abort(404, description="找不到這份比對標準，請重新選擇。")
    created = False
    try:
        with engine.begin() as conn:
            from standard_library import ensure_selectable
            standards._lock_active_inspection(conn, inspection["id"])
            ensure_selectable(conn,code=code)
            image_id = conn.execute(select(db.inspections.c.image_id).where(
                db.inspections.c.id == inspection["id"])).scalar_one()
            if not image_available(image_id) or conn.execute(select(db.images.c.id).where(db.images.c.id == image_id)).first() is None:
                abort(409, description="這筆紀錄的原照片已不存在，無法關聯為參考照片。")
            # Seed only a lockable revision counter, not a standard version.
            # First standard edits then share the same lock even for a raw
            # desktop/catalog source which has no approved web revisions yet.
            if conn.dialect.name == "postgresql":
                from sqlalchemy.dialects.postgresql import insert as upsert
            elif conn.dialect.name == "sqlite":
                from sqlalchemy.dialects.sqlite import insert as upsert
            else:
                abort(503, description="目前資料庫不支援安全的標準照片關聯。")
            conn.execute(upsert(standards.heads).values(code=code, revision=0).on_conflict_do_nothing(index_elements=["code"]))
            head = conn.execute(select(standards.heads.c.revision).where(standards.heads.c.code == code).with_for_update()).scalar_one()
            prior = conn.execute(select(standards.versions).where(standards.versions.c.code == code,
                standards.versions.c.revision == head)).mappings().first() if head else None
            # Re-read the external source after waiting on the version lock.
            # A concurrent master edit must not quietly use the earlier read.
            base = raw_draft(engine, code)
            if base is None:
                abort(409, description="原始來源已移除，請重新選擇比對標準。")
            source = standards.apply_current(engine, base, dict(prior) if prior else {})
            if head != revision or str(source["revision"]) != wanted or source.get("standard_reference", {}).get("state") == "stale":
                abort(409, description="比對標準已變更，請重新載入並確認後再關聯照片。")
            existing = conn.execute(select(photos).where(photos.c.image_id == image_id, photos.c.source_code == code)).mappings().first()
            if existing:
                history_cleanup.ensure_active(conn, existing["inspection_id"])
                row = dict(existing)
            else:
                row = {"id": db.uid(), "image_id": image_id, "inspection_id": inspection["id"],
                       "source_code": code, "source_revision": wanted, "standard_revision": head,
                       "reviewer": reviewer, "note": note, "created_at": db.now()}
                conn.execute(insert(photos).values(**row))
                created = True
    except IntegrityError:
        abort(409, description="照片關聯或標準已更新，請重新載入後確認。")
    return {"association": _public(row, image_payload, wanted), "created": created, "source_code": code}


def register_routes(app, engine, require_admin, get_inspection, image_payload, image_available):
    app.extensions["label_reference_image_available"] = image_available
    app.extensions["label_reference_image_payload"] = image_payload
    @app.get("/api/inspections/<identifier>/reference-photo")
    def get_reference_photo(identifier):
        require_admin()
        return jsonify(payload(engine, get_inspection(identifier), image_payload, image_available, request.args.get("source_code", "")))

    @app.post("/api/inspections/<identifier>/reference-photo")
    def attach_reference_photo(identifier):
        require_admin()
        result = save(engine, get_inspection(identifier), request.get_json(silent=True), image_payload, image_available)
        return jsonify(result), 201 if result["created"] else 200

    @app.get("/api/reference-photos")
    def list_reference_photos():
        require_admin()
        try:
            page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 24))
        except ValueError:
            abort(400, description="頁碼與每頁筆數須為整數。")
        return jsonify(listing(engine, request.args.get("source_code"), image_payload, image_available, page, limit))
