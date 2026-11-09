"""Explicit, replay-safe point responsibility/frequency revision authorized on 2026-11-09.

This is separate from schema migration and the original private catalogue import.
It never rotates QR tokens or rewrites completed inspection/execution snapshots.
"""
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import hmac
import json

from sqlalchemy import select

from general_workflow import execution_deadline
from models import AuditLog, Inspection, PatrolExecution, Point, PointSchedule, TAIPEI, db


REVISION_ACTION = "point_assignment_revision_20261109"
REVISION_LOCK_ID = 714032611091
ACTIVATION_ACTION = "scheduled_point_frequency_activated"
# code: (expected name, floor, original frequency, workflow mode, target frequency)
ENGINEERING_POINTS = {
    "B2-G003": ("消防泵浦室", -2, "monthly", "spot", "monthly"),
    "B1-G008": ("發電機室", -1, "daily", "spot", "daily"),
    "B1-G009": ("空調機房", -1, "daily", "spot", "daily"),
    "4F-G051": ("IQF機房", 4, "daily", "spot", "daily"),
    "5F-G066": ("抽風機/冷卻水塔/桶槽區", 5, "daily", "two_stage", "daily"),
    "5F-G067": ("1、2號客梯機房", 5, "daily", "spot", "weekly"),
    "5F-G068": ("3、4號客梯機房", 5, "daily", "spot", "weekly"),
    "5F-G069": ("5、6號貨梯機房", 5, "daily", "spot", "weekly"),
    "5F-G070": ("7、8號貨梯機房", 5, "daily", "spot", "weekly"),
    "5F-G071": ("7、9號貨梯機房", 5, "daily", "spot", "weekly"),
    "5F-G072": ("7、10號貨梯機房", 5, "daily", "spot", "weekly"),
}


def _instant(value):
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _snapshot(point):
    return {"frequency": point.frequency, "inspection_team": point.inspection_team,
            "workflow_mode": point.workflow_mode, "active": point.active}


def revision_plan_digest(plan):
    """Bind an admin confirmation to the exact, JSON-safe preview it displayed."""
    payload = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _blockers(point, instant):
    day = instant.astimezone(TAIPEI).date()
    start = datetime.combine(day, time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
    end = datetime.combine(day + timedelta(days=1), time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
    result = []
    inspected = db.session.scalar(select(Inspection.id).where(Inspection.point_id == point.id,
        db.or_(Inspection.personal_day == day,
               db.and_(Inspection.created_at >= start, Inspection.created_at < end))).limit(1))
    executed = db.session.scalar(select(PatrolExecution.id).where(PatrolExecution.point_id == point.id,
        PatrolExecution.created_at >= start, PatrolExecution.created_at < end).limit(1))
    if inspected is not None or executed is not None:
        result.append({"point_id": point.id, "code": point.code, "reason": "today_started",
                       "message": "今日已有簽到或巡檢紀錄，請隔日再調整頻率。"})
    pending = db.session.scalars(select(PatrolExecution).where(PatrolExecution.point_id == point.id,
        ~select(Inspection.id).where(Inspection.execution_id == PatrolExecution.id).exists())).all()
    for first in pending:
        deadline = execution_deadline(first.frequency, first.period_key, first.slot)
        if deadline is None or instant < deadline:
            result.append({"point_id": point.id, "code": point.code, "reason": "pending_execution",
                           "execution_id": first.id,
                           "message": "本期已有執行尚未巡檢，請先完成巡檢或待本期結束。"})
            break
    return result


def _preserve_schedule(point, day):
    for schedule in point.schedules:
        if schedule.category != point.category:
            continue
        for field, source in (("floor", "floor"), ("point_code", "code"), ("point_name", "name")):
            if getattr(schedule, field) is None:
                setattr(schedule, field, getattr(point, source))
    if not point.schedules and point.schedule_start <= day:
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=point.frequency,
            category=point.category, workflow_mode=point.workflow_mode, active=point.active,
            floor=point.floor, point_code=point.code, point_name=point.name))


def revise_point_assignments(apply=False, instant=None, effective_date=None, expected_plan=None):
    """Return a JSON-safe preview, or atomically apply it; own the session transaction.

    Responsibility changes now. Frequency changes may be scheduled durably for a
    later Taipei date; pending state and its historical schedule commit together.
    An immediate apply with blockers leaves all points and the marker intact.
"""
    instant = _instant(instant)
    day = instant.astimezone(TAIPEI).date()
    effective_date = effective_date or day + timedelta(days=1)
    if isinstance(effective_date, str):
        effective_date = date.fromisoformat(effective_date)
    if not isinstance(effective_date, date) or isinstance(effective_date, datetime):
        raise ValueError("頻率生效日期必須為有效日期。")
    try:
        if apply:
            if db.engine.dialect.name == "postgresql":
                db.session.execute(db.text("SELECT pg_advisory_xact_lock(:key)"), {"key": REVISION_LOCK_ID})
            elif db.engine.dialect.name == "sqlite":
                db.session.execute(db.update(AuditLog).where(db.false()).values(action=REVISION_ACTION))
        marker = db.session.scalar(select(AuditLog.id).where(AuditLog.action == REVISION_ACTION).limit(1))
        if marker is not None:
            db.session.rollback()
            return {"already_applied": True, "effective_date": None, "changed": 0, "changes": [], "blockers": []}
        if effective_date < day:
            raise ValueError("頻率生效日期必須為今日或未來日期，不可改寫過去排程。")
        query = select(Point).where(db.or_(Point.code.in_(ENGINEERING_POINTS),
            db.and_(Point.category == "general", Point.frequency == "daily2", Point.deleted_at.is_(None)))).order_by(Point.id)
        if apply:
            query = query.with_for_update().execution_options(populate_existing=True)
        points = db.session.scalars(query).all()
        by_code = {p.code: p for p in points}
        missing = sorted(set(ENGINEERING_POINTS) - by_code.keys())
        if missing:
            raise ValueError("指定工務點位不完整，未套用任何修改：" + "、".join(missing))
        for code, (name, floor, old_frequency, mode, new_frequency) in ENGINEERING_POINTS.items():
            point = by_code[code]
            if (point.category != "general" or point.name != name or point.floor != floor
                    or point.workflow_mode != mode or point.frequency not in {old_frequency, new_frequency}
                    or point.deleted_at is not None or point.schedule_start > day):
                raise ValueError(f"點位 {code} 與授權清單設定不符，未套用任何修改。")
        changes, blockers = [], []
        for point in points:
            before = _snapshot(point)
            after = dict(before)
            if point.code in ENGINEERING_POINTS:
                after.update(inspection_team="engineering", frequency=ENGINEERING_POINTS[point.code][4])
            elif point.category == "general" and point.frequency == "daily2":
                after["frequency"] = "daily"
            if before == after:
                continue
            changes.append({"point_id": point.id, "code": point.code, "name": point.name, "floor": point.floor,
                            "before": before, "after": after})
            if point.pending_frequency is not None or point.frequency_effective_date is not None:
                blockers.append({"point_id": point.id, "code": point.code, "reason": "scheduled_change_exists",
                    "message": "已有預約頻率變更，請先確認既有排程，避免覆寫。"})
            if before["frequency"] != after["frequency"] and effective_date == day:
                blockers.extend(_blockers(point, instant))
        result = {"already_applied": False, "effective_date": effective_date.isoformat(),
                  "team_effective_date": day.isoformat(), "changed": len(changes),
                  "frequency_changed": sum(c["before"]["frequency"] != c["after"]["frequency"] for c in changes),
                  "team_changed": sum(c["before"]["inspection_team"] != c["after"]["inspection_team"] for c in changes),
                  "changes": changes, "blockers": blockers}
        if not apply:
            db.session.rollback()
            return result
        if expected_plan is not None and (not isinstance(expected_plan, str)
                or len(expected_plan) != 64 or not expected_plan.isascii()
                or not hmac.compare_digest(expected_plan, revision_plan_digest(result))):
            raise ValueError("頁面資料已變更，未套用任何修改。請重新整理預覽後再確認。")
        if blockers:
            raise ValueError("頻率修改尚有進行中的作業，未套用任何修改：" +
                             "；".join(f"{b['code']}：{b['message']}" for b in blockers))
        for change in changes:
            point = by_code[change["code"]]
            _preserve_schedule(point, day)
            frequency_changed = point.frequency != change["after"]["frequency"]
            scheduled = frequency_changed and effective_date > day
            schedule_day = effective_date if frequency_changed else day
            cutoff = (datetime.combine(schedule_day, time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
                      if scheduled else instant.replace(tzinfo=None))
            point.schedules.append(PointSchedule(effective_date=schedule_day, frequency=change["after"]["frequency"],
                category=point.category, workflow_mode=point.workflow_mode, active=point.active,
                workflow_changed_at=cutoff if frequency_changed else None,
                floor=point.floor, point_code=point.code, point_name=point.name))
            if scheduled:
                point.pending_frequency = change["after"]["frequency"]
                point.frequency_effective_date = effective_date
            else:
                point.frequency = change["after"]["frequency"]
            point.inspection_team = change["after"]["inspection_team"]
        db.session.add(AuditLog(action=REVISION_ACTION, target="general/engineering point assignment",
            detail=json.dumps(result, ensure_ascii=False, sort_keys=True), created_at=instant.replace(tzinfo=None)))
        db.session.commit()
        return result
    except Exception:
        db.session.rollback()
        raise


def activate_due_point_frequencies(instant=None):
    """Activate due live frequencies atomically without changing old schedules.

    Call before request work starts, not midway through another mutation. The
    admin editor must prevent changes while a point has a pending frequency.
    A mismatched scheduled snapshot fails closed instead of reviving stale work.
    """
    instant = _instant(instant)
    day = instant.astimezone(TAIPEI).date()
    try:
        candidates = select(Point.id).where(Point.pending_frequency.is_not(None),
                                            Point.frequency_effective_date <= day)
        if db.session.scalar(candidates.limit(1)) is None:
            db.session.rollback()
            return {"activated": 0, "points": []}
        if db.engine.dialect.name == "sqlite":
            db.session.execute(db.update(AuditLog).where(db.false()).values(action=ACTIVATION_ACTION))
        points = db.session.scalars(select(Point).where(Point.pending_frequency.is_not(None),
            Point.frequency_effective_date <= day).order_by(Point.id).with_for_update()
            .execution_options(populate_existing=True)).all()
        changes = []
        for point in points:
            schedules = [s for s in point.schedules if s.effective_date <= point.frequency_effective_date]
            schedule = max(schedules, key=lambda s: (s.effective_date, s.id or 0)) if schedules else None
            if (schedule is None or schedule.effective_date != point.frequency_effective_date
                    or schedule.frequency != point.pending_frequency or point.deleted_at is not None
                    or any(getattr(schedule, field) != getattr(point, current) for field, current in
                        (("category", "category"), ("workflow_mode", "workflow_mode"), ("active", "active"),
                         ("floor", "floor"), ("point_code", "code"), ("point_name", "name")))):
                raise ValueError(f"點位 {point.code} 的預約頻率設定不一致，請由系統管理員確認後再打卡。")
            changes.append({"point_id": point.id, "code": point.code, "before": point.frequency,
                            "after": point.pending_frequency, "effective_date": point.frequency_effective_date.isoformat()})
        for point in points:
            point.frequency = point.pending_frequency
            point.pending_frequency = None
            point.frequency_effective_date = None
        if changes:
            db.session.add(AuditLog(action=ACTIVATION_ACTION, target="scheduled point frequencies",
                detail=json.dumps(changes, ensure_ascii=False, sort_keys=True), created_at=instant.replace(tzinfo=None)))
        db.session.commit()
        return {"activated": len(changes), "points": changes}
    except Exception:
        db.session.rollback()
        raise
