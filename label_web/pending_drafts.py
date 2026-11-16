"""Reversible, image-scoped pending-draft decisions; no inspection/photo deletion."""
import secrets

from flask import abort, jsonify, request, session
from sqlalchemy import Table, Column, String, Integer, Boolean, Text, select, insert, func, and_
from sqlalchemy.exc import IntegrityError, OperationalError

import database as db


events = Table("labelcheck_pending_draft_events", db.metadata,
    Column("image_id", String(32), primary_key=True), Column("revision", Integer, primary_key=True),
    Column("removed", Boolean, nullable=False), Column("inspection_id", String(32), nullable=False),
    Column("actor", String(100), nullable=False), Column("note", Text, nullable=False),
    Column("created_at", String(40), nullable=False))
MAX_BATCH = 24


def current_states():
    latest=select(events.c.image_id,func.max(events.c.revision).label("revision")).group_by(events.c.image_id).subquery()
    return select(events).join(latest,and_(events.c.image_id==latest.c.image_id,
        events.c.revision==latest.c.revision)).subquery("pending_draft_states")


def _conflict():
    abort(409,description="待建草稿狀態已變更，請重新載入清單後再選取。")


def _request_body(body):
    if not isinstance(body,dict) or set(body)-{"operation","items","note"}:
        abort(400,description="待建草稿操作格式不正確。")
    operation=body.get("operation")
    if not isinstance(operation,str) or operation not in {"remove","restore"}:
        abort(400,description="請選擇移除或還原待建草稿。")
    items=body.get("items")
    if not isinstance(items,list) or not 1<=len(items)<=MAX_BATCH:
        abort(400,description=f"每次請選取 1 至 {MAX_BATCH} 張照片。")
    seen=set()
    for item in items:
        if not isinstance(item,dict) or set(item)!={"inspection_id","image_id","base_revision"}:
            abort(400,description="每筆須包含檢查、照片識別及待建版本。")
        for key in ("inspection_id","image_id"):
            value=item[key]
            if not isinstance(value,str) or not value or len(value)>32 or any(ord(c)<32 for c in value):
                abort(400,description="照片或檢查識別不正確。")
        revision=item["base_revision"]
        if type(revision) is not int or not 0<=revision<2_147_483_647:
            abort(400,description="待建草稿版本不正確。")
        if item["image_id"] in seen:
            abort(400,description="同一張照片不可重複選取。")
        seen.add(item["image_id"])
    note=body.get("note","")
    if not isinstance(note,str) or len(note)>500 or any(ord(c)<32 and c not in "\r\n\t" for c in note):
        abort(400,description="操作備註最多 500 字，請勿包含控制字元。")
    return operation,items,note.strip() or ("移除重複或不需建立的待建草稿。" if operation=="remove" else "還原待建草稿。")


def change_state(engine, body, actor):
    import history_cleanup
    import manual_reference
    from standard_draft_quality import eligibility
    operation,items,note=_request_body(body)
    image_ids=sorted(item["image_id"] for item in items)
    state="active" if operation=="remove" else "removed"
    try:
        with engine.begin() as conn:
            # Existing image rows serialize even the first decision (revision 0)
            # on PostgreSQL. Unique event revisions also fail closed on SQLite.
            locked=conn.execute(select(db.images.c.id).where(db.images.c.id.in_(image_ids))
                .order_by(db.images.c.id).with_for_update()).scalars().all()
            if locked!=image_ids:
                abort(404,description="找不到選取的照片。")
            originals=conn.execute(select(db.inspections.c.id,db.inspections.c.image_id)
                .where(db.inspections.c.id.in_([item["inspection_id"] for item in items]))
                .order_by(db.inspections.c.id).with_for_update()).mappings().all()
            original_map={row["id"]:row["image_id"] for row in originals}
            for item in items:
                if original_map.get(item["inspection_id"])!=item["image_id"]:
                    abort(404,description="檢查紀錄與選取照片不相符。")
                history_cleanup.ensure_active(conn,item["inspection_id"])
            query=manual_reference._pending_query("all",state).where(db.inspections.c.image_id.in_(image_ids))
            candidates={row["image_id"]:row for row in conn.execute(query).mappings()}
            now,changes=db.now(),[]
            for item in items:
                row=candidates.get(item["image_id"])
                if row is None or row["pending_revision"]!=item["base_revision"]:
                    _conflict()
                if operation=="remove" and not eligibility(manual_reference._pending_ocr(row),row["patches"],
                        manual_reference._pending_result(row))["eligible"]:
                    _conflict()
                changes.append(dict(image_id=item["image_id"],revision=item["base_revision"]+1,
                    removed=operation=="remove",inspection_id=row["id"],actor=str(actor)[:100],note=note,created_at=now))
            conn.execute(insert(events),changes)
    except IntegrityError:
        _conflict()
    except OperationalError as error:
        if getattr(error.orig,"sqlite_errorcode",None) in {5,6,517}:
            _conflict()
        raise
    return {"operation":operation,"count":len(changes),
            "items":[{key:row[key] for key in ("image_id","revision","removed")} for row in changes]}


def register_routes(app,engine,require_admin):
    @app.post("/api/manual-standards/pending/state")
    def change_pending_draft_state():
        identity=require_admin()
        token,expected=request.headers.get("X-CSRF-Token",""),session.get("csrf","")
        if (request.headers.get("Sec-Fetch-Site")=="cross-site" or not isinstance(expected,str) or not expected or
                not secrets.compare_digest(token.encode(),expected.encode())):
            abort(403,description="請從本站重新整理後操作。")
        actor=identity if isinstance(identity,str) else session.get("username") or session.get("admin_username") or "管理員共用帳號"
        return jsonify(change_state(engine,request.get_json(silent=True),actor))
