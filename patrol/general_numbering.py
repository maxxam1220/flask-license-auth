"""Stable general-point numbering, applied inside the caller's transaction.

Point IDs own all permissions and history. Codes are only display labels. The
latest numbering audit preserves the original numeric order, so disabling and
reenabling a point never gradually rearranges the other points on its floor.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
import secrets

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from domain import FLOOR_LABELS, FLOOR_ORDER
from models import AuditLog, Point, PointSchedule, TAIPEI, db


NUMBERING_ACTION = "general_numbering_applied"
NUMBERING_LOCK_ID = 714032611102
_SYSTEM_CODE = re.compile(r"^(?:B2|B1|1F|1M|2F|3F|4F|4M|5F|5M)-G([0-9]+)$")


class GeneralNumberingError(ValueError):
    """A numbering preview cannot safely be applied."""


def _instant(value):
    value = value or datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise GeneralNumberingError("編號整理時間必須是有效日期時間。")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _iso(value):
    return value.isoformat() if value is not None else None


def _origin_mapping(value):
    if not isinstance(value, dict):
        raise GeneralNumberingError("總務編號排序紀錄不完整，請先確認稽核紀錄。")
    result = {}
    for key, ordinal in value.items():
        if (not isinstance(key, str) or not key.isascii() or not key.isdecimal()
                or str(int(key)) != key or int(key) < 1 or type(ordinal) is not int or ordinal < 0):
            raise GeneralNumberingError("總務編號排序紀錄格式錯誤，未重新編號。")
        result[key] = ordinal
    return result


def _latest_marker():
    return db.session.scalar(select(AuditLog).where(AuditLog.action == NUMBERING_ACTION)
                             .order_by(AuditLog.id.desc()).limit(1))


def numbering_enabled():
    """Whether an administrator has enabled automatic numbering."""
    return db.session.scalar(select(AuditLog.id).where(AuditLog.action == NUMBERING_ACTION).limit(1)) is not None


def lock_general_numbering():
    """Take the shared transaction lock BEFORE a caller locks or edits any Point.

    Do not commit or roll back here: the point edit and its resulting numbering
    must succeed together. Repeated calls in the same transaction are safe.
    """
    with db.session.no_autoflush:
        dialect = db.engine.dialect.name
        if dialect == "postgresql":
            db.session.execute(db.text("SELECT pg_advisory_xact_lock(:key)"), {"key": NUMBERING_LOCK_ID})
        elif dialect == "sqlite":
            # Reserve SQLite's writer slot even when no marker exists yet.
            db.session.execute(db.update(AuditLog).where(db.false()).values(action=NUMBERING_ACTION))
        else:
            raise GeneralNumberingError("目前資料庫不支援安全的總務自動編號鎖。")


def _marker_order(marker):
    if marker is None:
        return {}
    try:
        payload = json.loads(marker.detail)
    except (TypeError, ValueError) as exc:
        raise GeneralNumberingError("總務編號排序紀錄無法讀取，未重新編號。") from exc
    if not isinstance(payload, dict) or "origin_order" not in payload:
        raise GeneralNumberingError("總務編號排序紀錄不完整，請先確認稽核紀錄。")
    return _origin_mapping(payload["origin_order"])


def _point_state(point):
    fields = ("id", "code", "name", "floor", "category", "inspection_team", "frequency",
              "workflow_mode", "active", "qr_token", "pending_frequency")
    state = {field: getattr(point, field) for field in fields}
    state.update({field: _iso(getattr(point, field)) for field in
                  ("deleted_at", "created_at", "schedule_start", "frequency_effective_date")})
    state["schedules"] = [
        {**{field: getattr(s, field) for field in
            ("id", "frequency", "category", "workflow_mode", "active", "legacy_unscheduled",
             "floor", "point_code", "point_name")},
         **{field: _iso(getattr(s, field)) for field in ("effective_date", "workflow_changed_at", "retired_at")}}
        for s in sorted(point.schedules, key=lambda s: (s.effective_date, s.id or 0))]
    return state


def plan_general_numbering(points, instant, *, origin_order=None, enabled=False, marker_id=None):
    """Pure, JSON-safe plan; never mutate points or their schedule snapshots.

    Active system G codes are globally numbered 001..099 in floor order;
    inactive/deleted system G codes are globally numbered 100..999. Non-G and
    non-general points retain their codes, but still participate in collisions.
    """
    instant = _instant(instant)
    day = instant.astimezone(TAIPEI).date()
    points = sorted(points, key=lambda p: p.id)
    origins = _origin_mapping(origin_order if origin_order is not None else {})
    candidates = []
    for point in points:
        match = _SYSTEM_CODE.fullmatch(point.code) if point.category == "general" else None
        if not match:
            continue
        if point.floor not in FLOOR_ORDER:
            raise GeneralNumberingError(f"點位 {point.code} 的樓層無法安全編號。")
        if point.id is None:
            raise GeneralNumberingError("請先儲存新點位身分再整理編號。")
        origins.setdefault(str(point.id), int(match.group(1)))
        candidates.append(point)
    candidates.sort(key=lambda p: (FLOOR_ORDER[p.floor], origins[str(p.id)], p.id))
    active = [p for p in candidates if p.active and p.deleted_at is None]
    inactive = [p for p in candidates if not p.active or p.deleted_at is not None]
    blockers = []
    if len(active) > 99:
        blockers.append({"reason": "active_capacity", "message": "啟用的總務 G 編號已超過 99 點，請先調整編號規則。"})
    if len(inactive) > 900:
        blockers.append({"reason": "inactive_capacity", "message": "停用的總務 G 編號已超過 900 點，請先調整編號規則。"})
    targets = {}
    for group, start in ((active, 1), (inactive, 100)):
        for number, point in enumerate(group, start):
            targets[point.id] = f"{FLOOR_LABELS[point.floor]}-G{number:03d}"
    changes = []
    for point in candidates:
        new_code = targets[point.id]
        if new_code == point.code:
            continue
        changes.append({"id": point.id, "code": point.code, "new_code": new_code, "name": point.name,
                        "floor": point.floor, "active": bool(point.active), "deleted": point.deleted_at is not None})
        if (point.pending_frequency is not None or point.frequency_effective_date is not None
                or any(s.effective_date > day for s in point.schedules) or point.schedule_start > day):
            blockers.append({"id": point.id, "code": point.code, "reason": "future_schedule",
                             "message": "已有預約排程，請先完成或取消預約再整理編號。"})
    owners = {}
    for point in points:
        code = targets.get(point.id, point.code)
        if code in owners:
            blockers.append({"id": point.id, "code": code, "other_id": owners[code], "reason": "code_conflict",
                             "message": f"目標編號 {code} 已被其他點位使用，未重新編號。"})
        owners[code] = point.id
    state = {"day": day.isoformat(), "marker_id": marker_id, "enabled": bool(enabled), "origin_order": origins,
             "points": [_point_state(p) for p in points]}
    return {"day": day.isoformat(), "effective_date": day.isoformat(), "enabled": bool(enabled),
            "changed": len(changes), "changes": changes, "origin_order": origins, "blockers": blockers,
            "active_count": len(active), "inactive_count": len(inactive),
            "state_digest": hashlib.sha256(_json(state).encode("utf-8")).hexdigest()}


def preview_general_numbering(instant):
    """Read a preview without committing, rolling back, or autoflushing edits."""
    with db.session.no_autoflush:
        marker = _latest_marker()
        points = db.session.scalars(select(Point).options(selectinload(Point.schedules)).order_by(Point.id)).all()
        return plan_general_numbering(points, instant, origin_order=_marker_order(marker),
                                      enabled=marker is not None, marker_id=marker.id if marker else None)


def _preserve_schedule(point, day):
    # Fill legacy NULL display snapshots before the live code changes.
    for schedule in point.schedules:
        if schedule.category == point.category:
            for field, source in (("floor", "floor"), ("point_code", "code"), ("point_name", "name")):
                if getattr(schedule, field) is None:
                    setattr(schedule, field, getattr(point, source))
    if not point.schedules and point.schedule_start <= day:
        point.schedules.append(PointSchedule(effective_date=point.schedule_start,
            frequency=point.frequency, category=point.category, workflow_mode=point.workflow_mode,
            active=bool(point.active and point.deleted_at is None), floor=point.floor,
            point_code=point.code, point_name=point.name, retired_at=point.deleted_at))
    schedules = [s for s in point.schedules if s.effective_date <= day]
    return max(schedules, key=lambda s: (s.effective_date, s.id or 0)) if schedules else None


def apply_general_numbering(instant, actor_id, expected_plan=None):
    """Apply atomically with caller changes; the caller must commit or roll back.

    expected_plan may be the preview dictionary or its state_digest. The digest
    binds the Taipei day, all current point identities/codes/schedules and saved
    origin ordering; a stale preview never partially applies.
    """
    instant = _instant(instant)
    day = instant.astimezone(TAIPEI).date()
    lock_general_numbering()
    db.session.flush()  # Include the caller's new point, edit, delete or restore.
    marker = _latest_marker()
    origins = _marker_order(marker)
    points = db.session.scalars(select(Point).options(selectinload(Point.schedules)).order_by(Point.id)
                               .with_for_update().execution_options(populate_existing=True)).all()
    plan = plan_general_numbering(points, instant, origin_order=origins,
                                  enabled=marker is not None, marker_id=marker.id if marker else None)
    if expected_plan is not None:
        expected = expected_plan.get("state_digest") if isinstance(expected_plan, dict) else expected_plan
        if (not isinstance(expected, str) or len(expected) != 64 or not expected.isascii()
                or not hmac.compare_digest(expected, plan["state_digest"])):
            raise GeneralNumberingError("頁面資料或日期已變更，請重新整理編號預覽後再確認。")
    if plan["blockers"]:
        raise GeneralNumberingError("；".join(b["message"] for b in plan["blockers"]))
    by_id = {p.id: p for p in points}
    occupied = {p.code for p in points}
    snapshots = {}
    for change in plan["changes"]:
        point = by_id[change["id"]]
        schedule = _preserve_schedule(point, day)
        snapshots[point.id] = {
            "workflow_changed_at": schedule.workflow_changed_at if schedule else None,
            "legacy_unscheduled": bool(schedule.legacy_unscheduled) if schedule else False,
            "retired_at": point.deleted_at or (schedule.retired_at if schedule else None),
        }
        # Stage *every* changed code before assigning final values, so SQLite
        # and PostgreSQL's immediate UNIQUE constraints both permit swaps.
        temporary = "~GN-" + secrets.token_hex(12)
        while temporary in occupied:
            temporary = "~GN-" + secrets.token_hex(12)
        occupied.add(temporary)
        point.code = temporary
    if plan["changes"]:
        db.session.flush()
    for change in plan["changes"]:
        point = by_id[change["id"]]
        point.code = change["new_code"]
        point.schedules.append(PointSchedule(effective_date=day, frequency=point.frequency,
            category=point.category, workflow_mode=point.workflow_mode,
            active=bool(point.active and point.deleted_at is None), floor=point.floor,
            point_code=point.code, point_name=point.name, **snapshots[point.id]))
    if marker is None or plan["changed"] or plan["origin_order"] != origins:
        db.session.add(AuditLog(actor_id=actor_id, action=NUMBERING_ACTION, target="general point numbering",
            detail=_json(plan), created_at=instant.replace(tzinfo=None)))
    db.session.flush()
    return plan
