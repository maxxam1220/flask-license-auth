"""Persistent inspection issues, with immutable inspection snapshots and events."""
import re

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import object_session

from models import Inspection, InspectionIssue, IssueEvent, IssueEventPhoto, Point, db
from patrol_access import apply_point_scope, can_access_category, can_access_point_team, patrol_scope


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


def open_issue_counts(point_ids=None, user_id=None, category=None, *, actor=None, inspection_team=""):
    """Return counts only; never expose another inspector's record or note."""
    query = (select(Inspection.point_id, db.func.count(Inspection.id))
             .outerjoin(InspectionIssue, InspectionIssue.inspection_id == Inspection.id)
             .where(open_issue_condition()).group_by(Inspection.point_id))
    if actor is not None:
        query = apply_point_scope(query, actor, Inspection, inspection_team)
    if point_ids is not None:
        if not point_ids:
            return {}
        query = query.where(Inspection.point_id.in_(point_ids))
    if user_id is not None:
        query = query.where(Inspection.user_id == user_id)
    if category is not None:
        if not category:
            return {}
        query = query.where(Inspection.category == category)
    return dict(db.session.execute(query).all())


def open_issue_for(record):
    """Attach to the same unit of work as the abnormal inspection and photos."""
    if record.is_abnormal:
        record.issue = InspectionIssue(status="open", opened_at=record.created_at)


def issue_version(issue):
    return max((event.id for event in issue.events), default=0) if issue else 0


def can_resolve_issue(actor, record, *, point=None):
    """Resolution permission; it never grants reopen or point administration."""
    if (actor is None or record is None or not actor.active or actor.must_change_password
            or actor.role not in ("admin", "inspector") or not can_access_category(actor, record.category)):
        return False
    if record.category == "general" and not can_access_point_team(actor, point if point is not None else record.point):
        return False
    if actor.role == "admin":
        return True
    manager = (patrol_scope(actor) == "general" and bool(getattr(actor, "general_manager_title", False))
               and not bool(getattr(actor, "engineering_inspector_title", False)))
    return bool(actor.id == record.user_id or (manager and record.category == "general"))


def transition_issue(inspection_id, target_status, actor, expected_event_id, note, instant):
    """Compatibility API; use the event API when attaching resolution photos."""
    return transition_issue_event(inspection_id, target_status, actor, expected_event_id, note, instant) is not None


def transition_issue_event(inspection_id, target_status, actor, expected_event_id, note, instant):
    """Caller locks/revalidates actor first; then lock point and its issue.

    This follows the check-in lock order. No commit here: issue, event and the
    caller's audit entry either all commit together or all roll back.
    """
    if target_status not in ("open", "resolved"):
        raise ValueError("Unsupported issue state")
    if (not actor.active or actor.must_change_password or actor.role not in ("admin", "inspector")
            or (actor.role == "inspector" and (target_status != "resolved" or not patrol_scope(actor)))):
        raise IssueActionError("你沒有處理此異常案件的權限。", 403)
    owner = db.session.execute(select(Inspection.point_id, Inspection.user_id, Inspection.category).where(Inspection.id == inspection_id)).one_or_none()
    if owner is None:
        raise IssueActionError("找不到指定的巡檢紀錄。", 404)
    point_id, owner_id, category = owner
    if not can_access_category(actor, category):
        raise IssueActionError("找不到指定的巡檢紀錄。", 404)
    # Do not use the QR lookup: a disabled point still needs issue resolution.
    point = db.session.scalar(select(Point).where(Point.id == point_id).with_for_update()
                              .execution_options(populate_existing=True))
    if category == "general" and not can_access_point_team(actor, point):
        raise IssueActionError("找不到指定的巡檢紀錄。", 404)
    record = db.session.scalar(select(Inspection).where(Inspection.id == inspection_id).with_for_update()
                               .execution_options(populate_existing=True))
    if record is None:
        raise IssueActionError("找不到指定的巡檢紀錄。", 404)
    if not can_access_category(actor, record.category):
        raise IssueActionError("找不到指定的巡檢紀錄。", 404)
    if record.point_id != point_id:
        raise IssueActionError("案件已由其他操作更新，請重新載入後再試。", 409)
    if not can_resolve_issue(actor, record, point=point):
        raise IssueActionError("只能結案自己回報的異常案件。", 403)
    # Authorize using the locked inspection before parsing form details or
    # materializing a legacy issue. An unauthorized POST must never reveal the
    # private record through an input-error form or leave a newly created case.
    # A browser submits CRLF for each single LF shown in the textarea.
    note = note.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not note or len(note) > 2000 or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in note):
        raise IssueActionError("請填寫 1 至 2,000 字的處理說明，且不可包含無效控制字元。")
    if not re.fullmatch(r"[0-9]{1,10}", expected_event_id or "") or int(expected_event_id) > 2147483647:
        raise IssueActionError("案件表單已過期，請重新載入後再試。")
    issue = db.session.scalar(select(InspectionIssue).where(InspectionIssue.inspection_id == inspection_id)
                              .with_for_update().execution_options(populate_existing=True))
    if issue is None:
        if not record.is_abnormal:
            raise IssueActionError("這筆巡檢紀錄沒有異常案件。", 404)
        issue = InspectionIssue(inspection_id=inspection_id, status="open", opened_at=record.created_at)
        db.session.add(issue)
        db.session.flush()
    if issue.status == target_status:
        return None
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
    event = IssueEvent(inspection_id=inspection_id, actor_id=actor.id, actor_name=actor.display_name,
                      action="resolved" if target_status == "resolved" else "reopened", note=note, created_at=instant)
    db.session.add(event)
    # A capability valid only for this transaction. Queries used for image quota
    # may autoflush the event, so checking session.new alone would be too strict.
    if target_status == "resolved":
        event._resolution_transaction = db.session().get_transaction()
    return event


def append_resolution_photos(event, prepared, instant):
    """Attach processed JPEGs to this transaction's new resolution only.

    The caller authorizes/version-checks via transition_issue_event before
    processing uploads, then commits evidence, status and audit atomically.
    No files are parsed and no transaction is committed here.
    """
    session = db.session()
    transaction = session.get_transaction()
    if (not isinstance(event, IssueEvent) or event.action != "resolved" or object_session(event) is not session
            or transaction is None or not transaction.is_active
            or getattr(event, "_resolution_transaction", None) is not transaction
            or getattr(event, "_resolution_photos_attached", False)):
        raise IssueActionError("照片只能附加到本次新建立的結案紀錄。", 409)
    prepared = list(prepared)
    if len(prepared) > 3:
        raise IssueActionError("每次結案最多上傳 3 張照片。")
    photos = []
    fields = {"data", "mime_type", "size_bytes", "width", "height"}
    for item in prepared:
        if (not isinstance(item, dict) or set(item) != fields or not isinstance(item["data"], bytes)
                or not item["data"] or item["mime_type"] != "image/jpeg"
                or any(type(item[name]) is not int or item[name] <= 0 for name in ("size_bytes", "width", "height"))
                or item["size_bytes"] != len(item["data"])):
            raise IssueActionError("結案照片資料無效，請重新選擇照片。")
        photos.append(IssueEventPhoto(**item, created_at=instant))
    # Validate the complete batch first so an invalid later item cannot leave
    # a partially attached evidence list even before the caller rolls back.
    event.photos.extend(photos)
    event._resolution_photos_attached = True
    return len(photos)
