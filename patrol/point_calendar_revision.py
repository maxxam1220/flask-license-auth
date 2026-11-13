"""Explicit, atomic application of the marked 2026-11-10 general patrol sheet.

Current point IDs and QR links own attendance history. This revision never runs
at startup and never treats a same-name safety point as a general point.
"""
from datetime import datetime, time, timedelta, timezone
import hashlib
import hmac
import json
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from domain import floor_label
from general_numbering import (apply_general_numbering, lock_general_numbering,
                               plan_general_numbering, preview_general_numbering)
from general_workflow import execution_deadline
from missed import period_bounds
from models import AuditLog, Inspection, PatrolExecution, Point, PointSchedule, TAIPEI, User, db


REVISION_ACTION = "point_calendar_revision_20261113"
# id: (code, name, floor, old frequency, old mode, target frequency, target mode, sheet row)
POINT_CHANGES = {
    47: ("AB2-M01", "b2男廁所-甲", -2, "three_day", "spot", "weekly_wed", "spot", 5),
    49: ("BB2-W02", "b2女廁所-乙", -2, "three_day", "spot", "weekly_wed", "spot", 6),
    48: ("BB2-M02", "b2男廁所-乙", -2, "three_day", "spot", "weekly_wed", "spot", 7),
    53: ("AB1m-W01", "b1女廁所", -1, "three_day", "spot", "weekly_wed", "spot", 14),
    117: ("AB1-M01", "b1男廁所-甲", -1, "three_day", "spot", "weekly_wed", "spot", 15),
    118: ("BB1-M02", "b1男廁所-乙", -1, "three_day", "spot", "weekly_wed", "spot", 16),
    54: ("1F-G005", "1.2客梯梯廳", 1, "three_day", "spot", "daily", "two_stage", 18),
    55: ("1F-G006", "吸菸區", 1, "three_day", "spot", "daily", "spot", 19),
    59: ("1F-G009", "人行道", 1, "three_day", "spot", "daily", "spot", 22),
    68: ("1M-G014", "201會議室", 11, "weekly", "two_stage", "weekly_fri", "two_stage", 31),
    69: ("1M-G015", "202會議室", 11, "weekly", "two_stage", "weekly_fri", "two_stage", 32),
    70: ("1M-G016", "203會議室", 11, "weekly", "two_stage", "weekly_fri", "two_stage", 33),
    71: ("1M-G017", "204會議室", 11, "weekly", "two_stage", "weekly_fri", "two_stage", 34),
    72: ("1M-G018", "205會議室", 11, "weekly", "two_stage", "weekly_fri", "two_stage", 35),
    88: ("3F-G024", "參觀步道", 3, "weekly", "two_stage", "weekly_wed", "two_stage", 52),
}
EXISTING_LOBBIES = {79: ("2F-G019", 2), 87: ("3F-G023", 3), 93: ("4F-G025", 4)}
NEW_LOBBIES = ((-2, 10), (-1, 17), (11, 42), (14, 72), (5, 74))
LOBBY_NAME = "1.2客梯梯廳"


def calendar_revision_digest(plan):
    return hashlib.sha256(json.dumps(plan, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def _instant(value):
    value = value or datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise ValueError("請使用有效的調整時間。")
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).astimezone(timezone.utc)


def _state(point):
    return {"frequency": point.frequency, "workflow_mode": point.workflow_mode,
            "inspection_team": point.inspection_team, "active": point.active}


def _pending_blockers(point, instant, effective_date):
    blockers = []
    day = instant.astimezone(TAIPEI).date()
    if (point.pending_frequency is not None or point.frequency_effective_date is not None
            or any(s.effective_date > day for s in point.schedules)):
        blockers.append({"point_id": point.id, "code": point.code, "reason": "future_schedule",
                         "message": "已有預約排程，請先完成或確認既有變更。"})
    pending = db.session.scalars(select(PatrolExecution).where(PatrolExecution.point_id == point.id,
        ~select(Inspection.id).where(Inspection.execution_id == PatrolExecution.id).exists())).all()
    cutover = datetime.combine(effective_date, time.min, TAIPEI)
    for execution in pending:
        deadline = execution_deadline(execution.frequency, execution.period_key, execution.slot)
        # Current-period work remains usable until its existing deadline. Only
        # an unknown period or one extending beyond the planned cutover blocks.
        if deadline is None or cutover < deadline:
            blockers.append({"point_id": point.id, "code": point.code, "reason": "pending_execution",
                             "execution_id": execution.id,
                             "message": "尚未巡檢的執行紀錄超過切換日，或期間不明，請先完成或確認原紀錄。"})
            break
    return blockers


def _initial_schedule(point):
    if not point.schedules:
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=point.frequency,
            workflow_mode=point.workflow_mode, category=point.category, active=point.active,
            floor=point.floor, point_code=point.code, point_name=point.name))


def revise_calendar_points(apply=False, instant=None, actor_id=None, expected_plan=None):
    """Preview or commit the exact authorized changes; own the session transaction."""
    instant = _instant(instant)
    day = instant.astimezone(TAIPEI).date()
    try:
        if apply:
            if actor_id is None:
                raise ValueError("套用點位調整須由系統管理員執行。")
            actor = db.session.scalar(select(User).where(User.id == actor_id).with_for_update(key_share=True)
                                      .execution_options(populate_existing=True))
            if actor is None or not actor.active or actor.role != "admin":
                raise ValueError("套用點位調整須由系統管理員執行。")
            lock_general_numbering()
        marker = db.session.scalar(select(AuditLog).where(AuditLog.action == REVISION_ACTION).limit(1))
        if marker is not None:
            saved = json.loads(marker.detail)
            saved["already_applied"] = True
            db.session.rollback()
            return saved
        query = select(Point).options(selectinload(Point.schedules)).order_by(Point.id)
        if apply:
            query = query.with_for_update().execution_options(populate_existing=True)
        points = db.session.scalars(query).all()
        by_id = {p.id: p for p in points}
        # Do not split today's three-day/weekly work into a new obligation.
        # Every existing point changes together after the longest old period.
        effective_date = max(period_bounds(day, spec[3])[1] for spec in POINT_CHANGES.values()) + timedelta(days=1)
        changes, blockers = [], []
        for pid, (code, name, floor, frequency, mode, target_frequency, target_mode, row) in POINT_CHANGES.items():
            point = by_id.get(pid)
            if (point is None or (point.code, point.name, point.floor, point.frequency, point.workflow_mode,
                                  point.category, point.inspection_team, point.active, point.deleted_at)
                    != (code, name, floor, frequency, mode, "general", "general", True, None)
                    or point.schedule_start > day):
                raise ValueError(f"點位 {code}（ID {pid}）與本次清單不一致，未套用任何修改。")
            before = _state(point)
            changes.append({"point_id": pid, "code": code, "name": name, "floor": floor, "source_row": row,
                            "before": before, "after": {**before, "frequency": target_frequency,
                                                        "workflow_mode": target_mode}})
            blockers.extend(_pending_blockers(point, instant, effective_date))
        for pid, (code, floor) in EXISTING_LOBBIES.items():
            point = by_id.get(pid)
            if (point is None or (point.code, point.name, point.floor, point.category, point.inspection_team,
                                  point.frequency, point.workflow_mode, point.active, point.deleted_at)
                    != (code, LOBBY_NAME, floor, "general", "general", "daily", "two_stage", True, None)):
                raise ValueError(f"既有梯廳 {code} 與清單不一致，未套用任何修改。")
        numbering = preview_general_numbering(instant)
        occupied = {p.code.casefold() for p in points}
        new_points, projected = [], list(points)
        next_id = max(by_id, default=0) + 1
        for offset, (floor, row) in enumerate(NEW_LOBBIES):
            if any(p.category == "general" and p.floor == floor and p.name == LOBBY_NAME for p in points):
                raise ValueError(f"{floor_label(floor)} 已有同名梯廳點位（含停用或刪除），未重複建立。")
            ordinal = 900 + offset if numbering["enabled"] else 1
            while f"{floor_label(floor)}-G{ordinal:03d}".casefold() in occupied:
                ordinal += 1
            provisional = f"{floor_label(floor)}-G{ordinal:03d}"
            occupied.add(provisional.casefold())
            candidate = SimpleNamespace(id=next_id + offset, code=provisional, name=LOBBY_NAME,
                floor=floor, category="general", inspection_team="general", frequency="daily",
                workflow_mode="two_stage", active=True, deleted_at=None, qr_token="new-point-qr",
                pending_frequency=None, frequency_effective_date=None, created_at=instant.replace(tzinfo=None),
                schedule_start=day, schedules=[])
            projected.append(candidate)
            new_points.append({"point_id": None, "code": provisional, "provisional_code": provisional,
                               "name": LOBBY_NAME, "floor": floor, "source_row": row,
                               "frequency": "daily", "workflow_mode": "two_stage"})
        projected_numbering = None
        if numbering["enabled"]:
            projected_numbering = plan_general_numbering(projected, instant,
                origin_order=numbering["origin_order"], enabled=True)
            targets = {row["id"]: row["new_code"] for row in projected_numbering["changes"]}
            for offset, item in enumerate(new_points):
                item["code"] = targets.get(next_id + offset, item["code"])
            blockers.extend(projected_numbering["blockers"])
        code_changes = ([row for row in projected_numbering["changes"] if row["id"] in by_id]
                        if projected_numbering else [])
        result = {"already_applied": False, "effective_date": effective_date.isoformat(),
                  "new_points_effective_date": day.isoformat(), "changed": len(changes),
                  "created": len(new_points), "changes": changes, "new_points": new_points,
                  "unchanged_lobbies": len(EXISTING_LOBBIES), "blockers": blockers,
                  "numbering_enabled": numbering["enabled"], "point_state_digest": numbering["state_digest"],
                  "code_changes": code_changes, "reprint_ids": sorted(set(POINT_CHANGES) | {r["id"] for r in code_changes})}
        if not apply:
            db.session.rollback()
            return result
        if (not isinstance(expected_plan, str) or not re_full_digest(expected_plan)
                or not hmac.compare_digest(expected_plan, calendar_revision_digest(result))):
            raise ValueError("預覽資料或日期已變更，未套用任何修改。請重新整理後再確認。")
        if blockers:
            raise ValueError("目前尚有待處理項目，未套用任何修改：" +
                             "；".join(f"{b.get('code', '')}：{b['message']}" for b in blockers))
        created = []
        for item in new_points:
            point = Point(code=item["provisional_code"], name=item["name"], floor=item["floor"],
                category="general", inspection_team="general", frequency="daily", workflow_mode="two_stage",
                active=True, schedule_start=day, created_at=instant.replace(tzinfo=None))
            # Assign the QR once through the model default, before final numbering.
            db.session.add(point)
            _initial_schedule(point)
            created.append(point)
        db.session.flush()
        applied_numbering = apply_general_numbering(instant, actor_id) if numbering["enabled"] else None
        # Number first, then schedule: the normal numbering guard correctly
        # refuses unrelated future plans, but must not reject our own new plan.
        # The future snapshot stores final labels and never rewrites old rows.
        cutover = datetime.combine(effective_date, time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
        for change in changes:
            point = by_id[change["point_id"]]
            _initial_schedule(point)
            point.pending_frequency = change["after"]["frequency"]
            point.frequency_effective_date = effective_date
            change["activation_identity"] = {key: getattr(point, key) for key in
                ("code", "name", "floor", "category", "inspection_team", "active")}
            point.schedules.append(PointSchedule(effective_date=effective_date,
                frequency=change["after"]["frequency"], category=point.category,
                workflow_mode=change["after"]["workflow_mode"], active=point.active,
                workflow_changed_at=cutover, floor=point.floor, point_code=point.code, point_name=point.name))
        for item, point in zip(new_points, created):
            item.update(point_id=point.id, code=point.code)
            item.pop("provisional_code", None)
        if applied_numbering:
            result["code_changes"] = [row for row in applied_numbering["changes"] if row["id"] in by_id]
        result["reprint_ids"] = sorted(set(POINT_CHANGES) | {p.id for p in created}
                                        | {r["id"] for r in result["code_changes"]})
        db.session.add(AuditLog(actor_id=actor_id, action=REVISION_ACTION, target="general patrol calendar",
            detail=json.dumps(result, ensure_ascii=False, sort_keys=True), created_at=instant.replace(tzinfo=None)))
        db.session.commit()
        return result
    except Exception:
        db.session.rollback()
        raise


def re_full_digest(value):
    return len(value) == 64 and value.isascii() and all(c in "0123456789abcdef" for c in value)
