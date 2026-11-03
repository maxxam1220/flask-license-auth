"""Persistent inspection issues, with immutable inspection snapshots and events."""
import re

from sqlalchemy import and_, or_, select

from models import Inspection, InspectionIssue, IssueEvent, Point, db


class IssueActionError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def open_issue_condition():
    # The previous worker can submit during a zero-downtime schema rollout.
    # Read that abnormal record as open, without mutating on a GET request.
    return or_(InspectionIssue.status == "open", and_(InspectionIssue.inspection_id.is_(None), Inspection.is_abnormal.is_(True)))


def issue_state(record):
    return record.issue.status if record.issue else ("open" if record.is_abnormal else "")


def open_issue_counts(point_ids=None):
    """Return counts only; never expose another inspector's record or note."""
    query = (select(Inspection.point_id, db.func.count(Inspection.id))
             .outerjoin(InspectionIssue, InspectionIssue.inspection_id == Inspection.id)
             .where(open_issue_condition()).group_by(Inspection.point_id))
    if point_ids is not None:
        if not point_ids:
            return {}
        query = query.where(Inspection.point_id.in_(point_ids))
    return dict(db.session.execute(query).all())


def open_issue_for(record):
    """Attach to the same unit of work as the abnormal inspection and photos."""
    if record.is_abnormal:
        record.issue = InspectionIssue(status="open", opened_at=record.created_at)


def issue_version(issue):
    return max((event.id for event in issue.events), default=0) if issue else 0


def transition_issue(inspection_id, target_status, actor, expected_event_id, note, instant):
    """Caller locks/revalidates actor first; then lock point and its issue.

    This follows the check-in lock order. No commit here: issue, event and the
    caller's audit entry either all commit together or all roll back.
    """
    if target_status not in ("open", "resolved"):
        raise ValueError("Unsupported issue state")
    note = note.strip()
    if not note or len(note) > 2000 or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in note):
        raise IssueActionError("請填寫 1 至 2,000 字的處理說明，且不可包含無效控制字元。")
    if not re.fullmatch(r"[0-9]{1,10}", expected_event_id or "") or int(expected_event_id) > 2147483647:
        raise IssueActionError("案件表單已過期，請重新載入後再試。")
    point_id = db.session.scalar(select(Inspection.point_id).where(Inspection.id == inspection_id))
    if point_id is None:
        raise IssueActionError("找不到指定的巡檢紀錄。", 404)
    # Do not use the QR lookup: a disabled point still needs issue resolution.
    db.session.scalar(select(Point).where(Point.id == point_id).with_for_update())
    record = db.session.scalar(select(Inspection).where(Inspection.id == inspection_id).with_for_update()
                               .execution_options(populate_existing=True))
    issue = db.session.scalar(select(InspectionIssue).where(InspectionIssue.inspection_id == inspection_id)
                              .with_for_update().execution_options(populate_existing=True))
    if issue is None:
        if not record.is_abnormal:
            raise IssueActionError("這筆巡檢紀錄沒有異常案件。", 404)
        issue = InspectionIssue(inspection_id=inspection_id, status="open", opened_at=record.created_at)
        db.session.add(issue)
        db.session.flush()
    if issue.status == target_status:
        return False
    latest_event_id = db.session.scalar(select(db.func.coalesce(db.func.max(IssueEvent.id), 0))
                                       .where(IssueEvent.inspection_id == inspection_id))
    if int(expected_event_id) != latest_event_id:
        raise IssueActionError("案件已由其他操作更新，請確認最新處理紀錄後再送出。", 409)
    issue.status = target_status
    if target_status == "resolved":
        issue.resolved_at = instant
        issue.resolved_by_id = actor.id
        issue.resolved_by_name = actor.display_name
        issue.resolution_note = note
    else:
        issue.resolved_at = None
        issue.resolved_by_id = None
        issue.resolved_by_name = ""
        issue.resolution_note = ""
    db.session.add(IssueEvent(inspection_id=inspection_id, actor_id=actor.id, actor_name=actor.display_name,
                             action="resolved" if target_status == "resolved" else "reopened", note=note, created_at=instant))
    return True
