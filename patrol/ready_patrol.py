"""Today's outstanding, actionable patrol stops and each actor's next round."""
from datetime import timezone

from sqlalchemy import select

from daily_rounds import daily2_anytime, next_daily2_slot
from missed import period_bounds, schedule_timeline, slot_plans
from models import Inspection, PatrolExecution, db
from patrol_access import can_access_point


def ready_patrol_points(points, user, local_now, floor_filter, category_filter):
    """Use current names and schedules; submitted snapshots identify fulfilled obligations."""
    today = local_now.date()
    executor = user.role == "executor"
    current_half = "am" if local_now.hour < 12 else "pm"
    period_ranges = {frequency: period_bounds(today, frequency) for frequency in ("daily", "daily2", "weekly", "monthly")}
    candidates = {}
    for point in points:
        # historical_points() can include a former team's redacted point.
        if not can_access_point(user, point) or (category_filter and point.category != category_filter):
            continue
        if not point.active or point.deleted_at is not None or point.schedule_start > today:
            continue
        if floor_filter and point.floor != int(floor_filter):
            continue
        if point.frequency == "irregular" or (executor and point.workflow_mode != "two_stage"):
            continue
        view = point.frequency if point.frequency in ("monthly", "weekly") else "daily"
        anytime = point.frequency == "daily2" and daily2_anytime(today)
        current_slot = current_half if point.frequency == "daily2" else "any"
        for plan, slot, deadline in slot_plans(point, today, schedule_timeline(point), view=view):
            if (not anytime and slot != current_slot) or (plan["frequency"], plan["workflow_mode"], plan["category"]) != (
                    point.frequency, point.workflow_mode, point.category):
                continue
            created_at = point.created_at
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if created_at and created_at >= deadline:
                continue
            period_key = period_ranges[point.frequency][0].isoformat()
            candidates[point.id, point.frequency, period_key, slot] = point
            if not anytime:
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
    selected_rounds = {}
    completed_rounds, executed_rounds, reviewable_rounds = {}, {}, {}
    for point_id, frequency, period_key, slot in completed:
        completed_rounds.setdefault((point_id, frequency, period_key), set()).add(slot)
    for (point_id, frequency, period_key, slot), executor_id in executions.items():
        executed_rounds.setdefault((point_id, frequency, period_key), set()).add(slot)
        if executor_id != user.id:
            reviewable_rounds.setdefault((point_id, frequency, period_key), set()).add(slot)
    for key, point in candidates.items():
        if point.frequency != "daily2" or not daily2_anytime(today) or point.id in selected_rounds:
            continue
        prefix = key[:3]
        if executor:
            selected_rounds[point.id] = next_daily2_slot(executed_rounds.get(prefix, ()))
        elif user.role == "inspector" and point.workflow_mode != "standard":
            used = personal_slots.get(point.id, ())
            available = reviewable_rounds.get(prefix, ()) if point.workflow_mode == "two_stage" else ("am", "pm")
            selected_rounds[point.id] = next_daily2_slot(used, available) or next_daily2_slot(used)
        else:
            used = completed_rounds.get(prefix, ())
            available = executed_rounds.get(prefix, ()) if point.workflow_mode == "two_stage" else ("am", "pm")
            selected_rounds[point.id] = next_daily2_slot(used, available) or next_daily2_slot(used)
    for key, point in candidates.items():
        anytime = point.id in selected_rounds
        if anytime:
            if key[3] != selected_rounds[point.id] or {"am", "pm"} <= completed_rounds.get(key[:3], set()):
                continue
        elif key in completed:
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
        if anytime:
            label = ("第 1 次" if key[3] == "am" else "第 2 次") + " · " + label
        result.append(dict(id=point.id, floor=point.floor, code=point.code, name=point.name,
                           frequency=point.frequency, period_end=period_ranges[point.frequency][1],
                           status_key=status, status_label=label))
    return result
