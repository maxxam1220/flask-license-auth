"""Administrator-only, reversible history archiving. Never delete inspection data."""
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import re
import secrets

from flask import abort, jsonify, request, session
from sqlalchemy import Table, Column, String, Integer, Boolean, JSON, Text, select, insert, update, delete, func
from sqlalchemy.exc import IntegrityError, OperationalError

import database as db


MAX_RECORDS = 500
PREVIEW_SECONDS = 600
TAIWAN = timezone(timedelta(hours=8))
previews = Table("labelcheck_history_previews", db.metadata,
    Column("id", String(32), primary_key=True), Column("owner_hash", String(64), nullable=False),
    Column("preview_hash", String(64), nullable=False), Column("filters", JSON, nullable=False),
    Column("entries", JSON, nullable=False), Column("state", String(20), nullable=False),
    Column("created_at", String(40), nullable=False), Column("expires_at", String(40), nullable=False, index=True))
batches = Table("labelcheck_history_batches", db.metadata,
    Column("id", String(32), primary_key=True), Column("preview_id", String(32), nullable=False, unique=True),
    Column("status", String(20), nullable=False), Column("revision", Integer, nullable=False),
    Column("count", Integer, nullable=False), Column("members", JSON, nullable=False),
    Column("filters", JSON, nullable=False), Column("actor", String(100), nullable=False),
    Column("reviewer", String(100), nullable=False), Column("note", Text, nullable=False),
    Column("created_at", String(40), nullable=False), Column("restored_at", String(40)))
tombstones = Table("labelcheck_history_tombstones", db.metadata,
    Column("inspection_id", String(32), primary_key=True), Column("batch_id", String(32), nullable=False, index=True),
    Column("archived", Boolean, nullable=False, index=True), Column("revision", Integer, nullable=False),
    Column("updated_at", String(40), nullable=False))
audit = Table("labelcheck_history_audit", db.metadata,
    Column("id", String(32), primary_key=True), Column("batch_id", String(32), nullable=False, index=True),
    Column("operation", String(20), nullable=False), Column("actor", String(100), nullable=False),
    Column("reviewer", String(100), nullable=False), Column("note", Text, nullable=False),
    Column("inspection_ids", JSON, nullable=False), Column("created_at", String(40), nullable=False))


def active_filter(table=db.inspections):
    return ~select(tombstones.c.inspection_id).where(
        tombstones.c.inspection_id == table.c.id, tombstones.c.archived.is_(True)).correlate(table).exists()


def archive_batch_id(conn, identifier):
    return conn.execute(select(tombstones.c.batch_id).where(
        tombstones.c.inspection_id == identifier, tombstones.c.archived.is_(True))).scalar_one_or_none()


def ensure_active(conn, identifier):
    if archive_batch_id(conn, identifier):
        abort(404, description="這筆檢查紀錄已移至回收區；請由管理員還原後查看。")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _body(keys):
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or set(body) - set(keys):
        abort(400, description="清理資料格式不正確。")
    return body


def _text(value, label, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 and c not in "\r\n\t" for c in value):
        abort(400, description=f"請填寫{label}，最多 {maximum} 字。")
    return value.strip()


def _confirm(body):
    if body.get("confirmed") is not True:
        abort(400, description="請先核對預覽並勾選確認。")
    return _text(body.get("reviewer"), "確認人", 100), _text(body.get("note"), "原因", 2000)


def _filters(value):
    if not isinstance(value, dict) or not value or set(value) - {"date_from", "date_to", "status", "ids"}:
        abort(400, description="請指定日期、原始判定或選取的紀錄。")
    result = {}
    if "ids" in value:
        ids = value["ids"]
        if len(value) != 1 or not isinstance(ids, list) or not 1 <= len(ids) <= MAX_RECORDS or any(
                not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", item) for item in ids) or len(set(ids)) != len(ids):
            abort(400, description="請單獨選取 1 至 500 筆不同紀錄；不可同時套用其他條件。")
        return {"ids": sorted(ids)}
    for key in ("date_from", "date_to"):
        raw = value.get(key)
        if raw in (None, ""):
            continue
        try:
            if not isinstance(raw, str) or date.fromisoformat(raw).isoformat() != raw:
                raise ValueError()
        except (ValueError, TypeError):
            abort(400, description="日期請使用 YYYY-MM-DD 格式。")
        result[key] = raw
    if result.get("date_from", "") > result.get("date_to", "9999-12-31"):
        abort(400, description="開始日期不可晚於結束日期。")
    status = value.get("status")
    if status not in (None, ""):
        if not isinstance(status, str) or status not in {"pass", "fail", "review"}:
            abort(400, description="原始判定篩選不正確。")
        result["status"] = status
    if not result:
        abort(400, description="請至少指定一個篩選條件。")
    return result


def _projection():
    def scalar(table, expression, *extra):
        return select(expression).where(table.c.inspection_id == db.inspections.c.id, *extra).correlate(db.inspections).scalar_subquery()
    revision = scalar(db.corrections, func.max(db.corrections.c.revision))
    manual_status = select(db.corrections.c.status).where(db.corrections.c.inspection_id == db.inspections.c.id).order_by(
        db.corrections.c.revision.desc()).limit(1).correlate(db.inspections).scalar_subquery()
    return select(db.inspections.c.id, db.inspections.c.image_id, db.inspections.c.status, db.inspections.c.created_at,
        db.inspections.c.template_snapshot["name"].as_string().label("name"),
        func.coalesce(revision, 0).label("manual_revision"), manual_status.label("manual_status"),
        scalar(db.reviews, func.count()).label("review_count"), scalar(db.reviews, func.max(db.reviews.c.created_at)).label("last_review_at"),
        func.coalesce(scalar(tombstones, tombstones.c.revision), 0).label("tombstone_revision"))


def _entries(conn, query):
    entries = []
    for row in conn.execute(query).mappings():
        item = dict(row)
        item["name"] = item.get("name") or "未命名檢查"
        entries.append({**item, "stamp": _digest(item)})
    return entries


def _public_items(entries):
    keys = ("id", "name", "status", "created_at", "manual_status", "manual_revision")
    return [{key: item.get(key) for key in keys} for item in entries]


def _owner(actor):
    token = session.get("csrf")
    if not isinstance(token, str) or not token:
        abort(403, description="請重新整理頁面後再操作。")
    return _digest({"actor": actor, "session": token})


def _batch_payload(row):
    return {"batch_id": row["id"], **{key: row[key] for key in (
        "count", "reviewer", "note", "created_at", "status", "revision", "restored_at", "actor", "filters")}}


def _conflict():
    abort(409, description="紀錄或清理批次已變更，請重新預覽後再操作。")


def _lock_records(conn, ids):
    rows = conn.execute(select(db.inspections.c.id).where(db.inspections.c.id.in_(ids)).order_by(db.inspections.c.id).with_for_update()).scalars().all()
    if rows != sorted(ids):
        _conflict()


def register_routes(app, engine, require_admin):
    """Import this module before open_database so its tables join metadata.create_all."""
    def guard(write=False):
        identity = require_admin()
        if write:
            token, expected = request.headers.get("X-CSRF-Token", ""), session.get("csrf", "")
            if request.headers.get("Sec-Fetch-Site") == "cross-site" or not isinstance(expected, str) or not expected or not secrets.compare_digest(token.encode(), expected.encode()):
                abort(403, description="請從本站重新整理後操作。")
        actor = identity if isinstance(identity, str) else session.get("username") or session.get("admin_username") or "管理員共用帳號"
        return str(actor)[:100]

    @app.before_request
    def protect_archived_inspection():
        match = re.match(r"^/api/inspections/([^/]+)(?:/|$)", request.path)
        if match:
            with engine.connect() as conn:
                ensure_active(conn, match[1])

    @app.post("/api/admin/history/preview")
    def preview():
        actor = guard(True)
        filters = _filters(_body({"filters"}).get("filters"))
        query = _projection().where(active_filter())
        if "ids" in filters:
            query = query.where(db.inspections.c.id.in_(filters["ids"]))
        if filters.get("status"):
            query = query.where(db.inspections.c.status == filters["status"])
        for key, next_day in (("date_from", False), ("date_to", True)):
            if key in filters:
                try:
                    boundary = datetime.combine(date.fromisoformat(filters[key]), datetime.min.time(), TAIWAN)
                    boundary += timedelta(days=int(next_day))
                    boundary = boundary.astimezone(timezone.utc).isoformat()
                except (ValueError, OverflowError):
                    abort(400, description="日期範圍超出可處理範圍。")
                query = query.where(db.inspections.c.created_at < boundary if next_day else db.inspections.c.created_at >= boundary)
        now = datetime.now(timezone.utc)
        identifier, expires = db.uid(), (now + timedelta(seconds=PREVIEW_SECONDS)).isoformat()
        with engine.begin() as conn:
            # Only this feature's expired ten-minute preview cache is discarded.
            # Completed batches retain their own member snapshot and audit trail.
            conn.execute(delete(previews).where(previews.c.expires_at <= now.isoformat()))
            entries = _entries(conn, query.order_by(db.inspections.c.id).limit(MAX_RECORDS + 1))
            if len(entries) > MAX_RECORDS:
                abort(400, description="符合條件超過 500 筆，請縮小日期範圍或改用選取紀錄。")
            if "ids" in filters and len(entries) != len(filters["ids"]):
                _conflict()
            digest = _digest({"id": identifier, "entries": entries, "filters": filters, "expires_at": expires})
            conn.execute(insert(previews).values(id=identifier, owner_hash=_owner(actor), preview_hash=digest, filters=filters,
                entries=entries, state="ready", created_at=now.isoformat(), expires_at=expires))
        return jsonify(preview_id=identifier, preview_hash=digest, expires_at=expires, count=len(entries),
                       items=_public_items(entries), max_records=MAX_RECORDS, status_basis="original")

    @app.post("/api/admin/history/archive")
    def archive():
        actor = guard(True)
        body = _body({"preview_id", "preview_hash", "confirmed", "reviewer", "note"})
        reviewer, note = _confirm(body)
        identifier = _text(body.get("preview_id"), "預覽識別", 32)
        supplied_hash = _text(body.get("preview_hash"), "預覽驗證", 64)
        if not re.fullmatch(r"[a-f0-9]{64}", supplied_hash):
            abort(400, description="預覽驗證格式不正確，請重新預覽。")
        try:
            with engine.begin() as conn:
                preview_row = conn.execute(select(previews).where(previews.c.id == identifier).with_for_update()).mappings().first()
                if not preview_row or preview_row["owner_hash"] != _owner(actor):
                    abort(404, description="找不到本次預覽，請重新預覽。")
                if preview_row["state"] != "ready" or not secrets.compare_digest(preview_row["preview_hash"], supplied_hash):
                    _conflict()
                if datetime.fromisoformat(preview_row["expires_at"]) <= datetime.now(timezone.utc):
                    abort(409, description="預覽已超過 10 分鐘，請重新預覽。")
                members = preview_row["entries"]
                if not members:
                    abort(400, description="沒有可移入回收區的紀錄。")
                ids = sorted(item["id"] for item in members)
                claimed = conn.execute(update(previews).where(previews.c.id == identifier, previews.c.state == "ready").values(state="used", entries=[]))
                if claimed.rowcount != 1:
                    _conflict()
                _lock_records(conn, ids)
                fresh = _entries(conn, _projection().where(db.inspections.c.id.in_(ids), active_filter()).order_by(db.inspections.c.id))
                if [(x["id"],x["stamp"]) for x in fresh] != [(x["id"],x["stamp"]) for x in members]:
                    _conflict()
                batch_id, now = db.uid(), db.now()
                for item in members:
                    values = dict(batch_id=batch_id, archived=True, revision=item["tombstone_revision"]+1, updated_at=now)
                    if item["tombstone_revision"]:
                        changed = conn.execute(update(tombstones).where(tombstones.c.inspection_id == item["id"],
                            tombstones.c.revision == item["tombstone_revision"], tombstones.c.archived.is_(False)).values(**values))
                        if changed.rowcount != 1:
                            _conflict()
                    else:
                        conn.execute(insert(tombstones).values(inspection_id=item["id"], **values))
                conn.execute(insert(batches).values(id=batch_id, preview_id=identifier, status="archived", revision=1,
                    count=len(members), members=members, filters=preview_row["filters"], actor=actor, reviewer=reviewer, note=note, created_at=now))
                conn.execute(insert(audit).values(id=db.uid(),batch_id=batch_id,operation="archive",actor=actor,
                    reviewer=reviewer,note=note,inspection_ids=ids,created_at=now))
        except IntegrityError:
            _conflict()
        except OperationalError as error:
            if getattr(error.orig,"sqlite_errorcode",None) in {5,6,517}:
                _conflict()
            raise
        return jsonify(batch_id=batch_id,count=len(members),status="archived",revision=1),201

    @app.get("/api/admin/history/batches")
    def list_batches():
        guard()
        try:
            page = int(request.args.get("page", "1"))
            if not 1 <= page <= 10000:
                raise ValueError()
        except ValueError:
            abort(400, description="頁碼不正確。")
        with engine.connect() as conn:
            rows = conn.execute(select(batches).order_by(batches.c.created_at.desc(),batches.c.id).offset((page-1)*20).limit(21)).mappings().all()
        return jsonify(items=[_batch_payload(row) for row in rows[:20]],page=page,has_more=len(rows)>20)

    @app.get("/api/admin/history/batches/<identifier>")
    def batch_detail(identifier):
        guard()
        with engine.connect() as conn:
            batch = conn.execute(select(batches).where(batches.c.id == identifier)).mappings().first()
            if not batch:
                abort(404, description="找不到清理批次。")
            events = conn.execute(select(audit.c.operation,audit.c.actor,audit.c.reviewer,audit.c.note,audit.c.created_at)
                .where(audit.c.batch_id==identifier).order_by(audit.c.created_at,audit.c.id)).mappings().all()
        return jsonify(batch=_batch_payload(batch),items=_public_items(batch["members"]),audit=[dict(row) for row in events])

    @app.post("/api/admin/history/batches/<identifier>/restore")
    def restore(identifier):
        actor = guard(True)
        body = _body({"base_revision","confirmed","reviewer","note"})
        reviewer,note = _confirm(body)
        revision = body.get("base_revision")
        if isinstance(revision,bool) or not isinstance(revision,int) or revision < 1:
            abort(400, description="清理批次版本不正確。")
        try:
            with engine.begin() as conn:
                batch = conn.execute(select(batches).where(batches.c.id == identifier).with_for_update()).mappings().first()
                if not batch:
                    abort(404, description="找不到清理批次。")
                if batch["status"] != "archived" or batch["revision"] != revision:
                    _conflict()
                now = db.now()
                changed = conn.execute(update(batches).where(batches.c.id==identifier,batches.c.status=="archived",batches.c.revision==revision)
                    .values(status="restored",revision=revision+1,restored_at=now))
                if changed.rowcount != 1:
                    _conflict()
                ids = sorted(item["id"] for item in batch["members"])
                _lock_records(conn,ids)
                for item in batch["members"]:
                    version = item["tombstone_revision"]+1
                    changed = conn.execute(update(tombstones).where(tombstones.c.inspection_id==item["id"],
                        tombstones.c.batch_id==identifier,tombstones.c.archived.is_(True),tombstones.c.revision==version)
                        .values(archived=False,revision=version+1,updated_at=now))
                    if changed.rowcount != 1:
                        _conflict()
                conn.execute(insert(audit).values(id=db.uid(),batch_id=identifier,operation="restore",actor=actor,
                    reviewer=reviewer,note=note,inspection_ids=ids,created_at=now))
        except IntegrityError:
            _conflict()
        except OperationalError as error:
            if getattr(error.orig,"sqlite_errorcode",None) in {5,6,517}:
                _conflict()
            raise
        return jsonify(batch_id=identifier,count=batch["count"],status="restored",revision=revision+1)
