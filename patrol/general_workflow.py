"""Two-stage attendance and the status of its original execution period."""
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import select

from daily_rounds import daily2_anytime
from models import Inspection, PatrolExecution, db
from missed import TAIPEI, period_bounds


EXECUTION_STATUS_LABELS = {"done": "已巡檢", "pending": "待巡檢", "expired": "已到期、未巡檢",
                           "unknown": "未巡檢（期間未明）"}


def execution_deadline(frequency, period_key, slot):
    """Return the original Taipei slot's exclusive deadline, or None for an invalid snapshot."""
    if frequency not in ("daily", "daily2", "weekly", "monthly", "irregular"):
        return None
    if slot not in (("am", "pm") if frequency == "daily2" else ("any",)):
        return None
    try:
        day = date.fromisoformat(period_key)
        start, end = period_bounds(day, frequency)
        if start != day or day.isoformat() != period_key:
            return None
        if slot == "am" and not daily2_anytime(day):
            return datetime.combine(day, time(12), TAIPEI)
        return datetime.combine(end + timedelta(days=1), time.min, TAIPEI)
    except (TypeError, ValueError, OverflowError):
        return None


def execution_review_status(frequency, period_key, slot, reviewed, instant):
    if reviewed:
        return "done"
    deadline = execution_deadline(frequency, period_key, slot)
    if deadline is None:
        return "unknown"
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return "expired" if instant >= deadline else "pending"


def execution_in_slot(point, key, slot):
    return db.session.scalar(select(PatrolExecution).where(
        PatrolExecution.point_id == point.id, PatrolExecution.frequency == point.frequency,
        PatrolExecution.period_key == key, PatrolExecution.slot == slot))


def personal_inspection_in_slot(point, user, personal_day, slot):
    query = select(Inspection).where(Inspection.point_id == point.id, Inspection.user_id == user.id,
                                     Inspection.personal_day == personal_day)
    if slot != "any":
        query = query.where(Inspection.slot.in_(("any", slot)))
    # Includes v7 entries, even duplicate spot history preserved during upgrade.
    return db.session.scalar(query.order_by(Inspection.created_at, Inspection.id).limit(1))


def new_execution(point, user, binding, key, slot, created_at):
    """Build an unsaved first stage with the confirmed point, person and timestamp snapshots."""
    if point.category != "general" or point.workflow_mode != "two_stage":
        raise ValueError("此點位不接受執行登記。")
    if not user.active or user.role != "executor" or user.patrol_category != "general":
        raise ValueError("僅限總務執行人員登記。")
    if not binding or binding.user_id != user.id or binding.status != "approved":
        raise ValueError("此瀏覽器尚未核准。")
    if created_at.tzinfo:
        created_at = created_at.astimezone(timezone.utc).replace(tzinfo=None)
    return PatrolExecution(user_id=user.id, point_id=point.id, binding_id=binding.id, created_at=created_at,
                           period_key=key, frequency=point.frequency, slot=slot, category=point.category,
                           point_code=point.code, point_name=point.name, point_floor=point.floor,
                           user_name=user.display_name)
