"""The first ordinary request activates the approved workflow before processing scans."""
from datetime import date, datetime, timezone
import json

from sqlalchemy import select

from models import AuditLog, Inspection, PatrolExecution, Point, PointSchedule, db
from point_assignment_revision import CALENDAR_REVISION_ACTION
from test_engineering_point_scope import application, teams, rendered
from test_offline_api import entry, prepare, sync
from test_workflow_checkin import payload


def test_first_request_cuts_over_before_scan_and_rejects_stale_online_offline_drafts(teams):
    t = teams
    point = t.points["general"]
    point.frequency = point.schedules[0].frequency = "three_day"
    point.pending_frequency, point.frequency_effective_date = "daily", date(2026, 11, 16)
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 16), frequency="daily",
        category=point.category, workflow_mode="two_stage", active=True, floor=point.floor,
        point_code=point.code, point_name=point.name, workflow_changed_at=datetime(2026, 11, 15, 16)))
    before = dict(frequency="three_day", workflow_mode="spot", inspection_team="general", active=True)
    db.session.add(AuditLog(action=CALENDAR_REVISION_ACTION, detail=json.dumps({
        "effective_date": "2026-11-16", "changes": [{"point_id": point.id, "before": before,
            "after": {**before, "frequency": "daily", "workflow_mode": "two_stage"},
            "activation_identity": {field: getattr(point, field) for field in
                ("code", "name", "floor", "category", "inspection_team", "active")}}]})))
    db.session.commit()
    t.clock[0] = datetime(2026, 11, 13, 2, tzinfo=timezone.utc)
    url = "/c/" + point.qr_token
    inspector, executor = t.clients["general"], t.clients["executor"]
    old_form = payload(inspector, url)
    prepared = prepare(inspector)
    delayed = entry(prepared, url, t.clock[0], note="Old plan draft")
    original = tuple(getattr(t.records["general"], c.name) for c in Inspection.__table__.columns)
    assert old_form["workflow_mode"] == "spot" and old_form["frequency"] == "three_day"

    t.clock[0] = datetime(2026, 11, 15, 16, tzinfo=timezone.utc)
    # This is the first request after midnight; there is no timer or worker call.
    context, _ = rendered(t.app, inspector, url)
    assert context["waiting_for_execution"] and not context["can_confirm"]
    db.session.refresh(point)
    assert (point.frequency, point.workflow_mode, point.pending_frequency) == ("daily", "two_stage", None)
    assert inspector.post(url + "/confirm", data=old_form).status_code == 409
    assert sync(inspector, prepared, delayed).status_code == 409

    assert executor.post(url + "/confirm", data=payload(executor, url)).status_code == 302
    assert inspector.post(url + "/confirm", data=payload(inspector, url)).status_code == 302
    first = db.session.scalar(select(PatrolExecution).where(PatrolExecution.point_id == point.id))
    latest = db.session.scalar(select(Inspection).where(Inspection.execution_id == first.id))
    assert (first.frequency, first.period_key, latest.workflow_mode, latest.period_key) == (
        "daily", "2026-11-16", "two_stage", "2026-11-16")
    assert tuple(getattr(t.records["general"], c.name) for c in Inspection.__table__.columns) == original
    assert db.session.get(Point, point.id).qr_token == url[3:]
