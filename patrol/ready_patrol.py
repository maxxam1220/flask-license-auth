"""Today's outstanding, actionable patrol stops in the current Taipei time slot."""
from datetime import timezone

from sqlalchemy import select

from missed import period_bounds, schedule_timeline, slot_plans
from models import Inspection, PatrolExecution, db
from patrol_access import can_access_category


def ready_patrol_points(points, user, local_now, floor_filter, category_filter):
    """Use current names and schedules; submitted snapshots identify fulfilled obligations."""
    today = local_now.date()
    executor = user.role == "executor"
    current_half = "am" if local_now.hour < 12 else "pm"
    candidates = {}
    for point in points:
        # historical_points() can include a former team's redacted point.
        if not can_access_category(user, point.category) or (category_filter and point.category != category_filter):
            continue
        if not point.active or point.deleted_at is not None or point.schedule_start > today:
            continue
        if floor_filter and point.floor != int(floor_filter):
            continue
        if point.frequency == "irregular" or (executor and point.workflow_mode != "two_stage"):
            continue
        view = point.frequency if point.frequency in ("monthly", "weekly") else "daily"
        current_slot = current_half if point.frequency == "daily2" else "any"
        for plan, slot, deadline in slot_plans(point, today, schedule_timeline(point), view=view):
            if slot != current_slot or (plan["frequency"], plan["workflow_mode"], plan["category"]) != (
                    point.frequency, point.workflow_mode, point.category):
                continue
            created_at = point.created_at
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if created_at and created_at >= deadline:
                continue
            period_key = period_bounds(today, point.frequency)[0].isoformat()
            candidates[point.id, point.frequency, period_key, slot] = point
            break
    if not candidates:
        return []

    point_ids = {key[0] for key in candidates}
    periods = {key[2] for key in candidates}
    shared = select(Inspection.point_id, Inspection.frequency, Inspection.period_key, Inspection.slot).where(
        Inspection.point_id.in_(point_ids), Inspection.period_key.in_(periods),
        Inspection.legacy_unscheduled.is_(False), Inspection.executor_visit.is_(False)).distinct()
    completed = set(db.session.execute(shared))

    # A schedule change can leave an individual receipt from another frequency
    # or an all-day slot. Match the personal duplication gate on the QR form.
    personal_slots = {}
    if user.role == "inspector" and any(p.workflow_mode != "standard" for p in candidates.values()):
        personal = select(Inspection.point_id, Inspection.slot).where(
            Inspection.user_id == user.id, Inspection.personal_day == today, Inspection.point_id.in_(point_ids))
        for point_id, slot in db.session.execute(personal):
            personal_slots.setdefault(point_id, set()).add(slot)

    executions = {}
    paired_ids = {p.id for p in candidates.values() if p.workflow_mode == "two_stage"}
    if paired_ids:
        stages = select(PatrolExecution.point_id, PatrolExecution.frequency, PatrolExecution.period_key,
                        PatrolExecution.slot, PatrolExecution.user_id).where(
            PatrolExecution.point_id.in_(paired_ids), PatrolExecution.period_key.in_(periods))
        executions = {tuple(row[:4]): row.user_id for row in db.session.execute(stages)}

    result = []
    for key, point in candidates.items():
        if key in completed:
            continue
        slots = personal_slots.get(point.id)
        if point.workflow_mode != "standard" and slots and (key[3] == "any" or "any" in slots or key[3] in slots):
            continue
        if point.workflow_mode == "two_stage":
            first_user = executions.get(key)
            if executor:
                if first_user is not None:
                    continue
                status, label = "execute", "待簽到"
            else:
                if first_user is None or (user.role == "inspector" and first_user == user.id):
                    continue
                status, label = "review", "已簽到待巡檢"
        else:
            status, label = "inspect", "待巡檢"
        result.append(dict(floor=point.floor, code=point.code, name=point.name, status_key=status, status_label=label))
    return result
