"""First-stage storage. Callers lock and revalidate the actor, binding and point before writing."""
from datetime import timezone

from sqlalchemy import select

from models import Inspection, PatrolExecution, db


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
