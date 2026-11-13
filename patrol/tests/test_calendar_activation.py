"""Scheduled calendar workflows require their exact committed, immutable approval."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
import json
from threading import Barrier
from types import SimpleNamespace

import pytest
from sqlalchemy import false, select, text, update
from sqlalchemy.orm import scoped_session, sessionmaker

from migrations import upgrade_schema
from models import AuditLog, DeviceBinding, Inspection, Point, PointSchedule, User
import point_assignment_revision as revision
from test_offline_migrations import engine, postgres_store, sqlite_store


CUTOFF = datetime(2026, 11, 15, 16, tzinfo=timezone.utc)


@pytest.fixture
def planned(engine, monkeypatch):
    upgrade_schema(engine)
    session = scoped_session(sessionmaker(bind=engine))
    monkeypatch.setattr(revision, "db", SimpleNamespace(session=session, engine=engine,
        false=false, text=text, update=update))
    changes = []
    for pid, old, mode, target, new_mode in ((54, "three_day", "spot", "daily", "two_stage"),
                                           (68, "weekly", "two_stage", "weekly_fri", "two_stage")):
        point = Point(id=pid, code=f"1F-G{pid:03d}", name=f"Point {pid}", floor=1,
            category="general", inspection_team="general", active=True,
            frequency=old, workflow_mode=mode, qr_token=f"unchanged-{pid}",
            schedule_start=date(2026, 11, 1), created_at=datetime(2026, 11, 1),
            pending_frequency=target, frequency_effective_date=date(2026, 11, 16))
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=old,
            category="general", workflow_mode=mode, active=True, floor=1,
            point_code=point.code, point_name=point.name))
        point.schedules.append(PointSchedule(effective_date=date(2026, 11, 16), frequency=target,
            category="general", workflow_mode=new_mode, active=True, floor=1,
            point_code=point.code, point_name=point.name, workflow_changed_at=CUTOFF.replace(tzinfo=None)))
        session.add(point)
        before = dict(frequency=old, workflow_mode=mode, inspection_team="general", active=True)
        changes.append({"point_id": pid, "code": "old-code-before-renumbering",
            "before": before, "after": {**before, "frequency": target, "workflow_mode": new_mode},
            "activation_identity": {field: getattr(point, field) for field in
                ("code", "name", "floor", "category", "inspection_team", "active")}})
    session.add(User(id=1, username="inspector", display_name="Inspector", password_hash="fixture",
                     role="inspector", patrol_category="general", active=True))
    session.add(DeviceBinding(id=1, user_id=1, token_hash="x" * 64, status="approved"))
    session.flush()
    session.add(Inspection(id=1, point_id=54, user_id=1, binding_id=1,
        frequency="three_day", workflow_mode="spot", personal_day=date(2026, 11, 13),
        period_key="2026-11-13", slot="any", category="general", created_at=datetime(2026, 11, 13, 1),
        point_code="before-renumbering", point_name="Original name", point_floor=1,
        user_name="Inspector", note="Preserve original evidence", spot_request_id="unchanged-original-spot-request"))
    marker = AuditLog(action=revision.CALENDAR_REVISION_ACTION,
        detail=json.dumps({"effective_date": "2026-11-16", "changes": changes}),
        created_at=datetime(2026, 11, 13, 2))
    session.add(marker)
    session.commit()
    yield SimpleNamespace(session=session, marker_id=marker.id, engine=engine)
    session.remove()


def test_exact_calendar_plan_activates_frequency_and_workflow_at_midnight(planned):
    store = planned.session
    point = store.get(Point, 54)
    assert revision.approved_calendar_workflow_schedule(point, point.schedules[-1])
    assert revision.activate_due_point_frequencies(datetime(2026, 11, 15, 15, 59, 59, tzinfo=timezone.utc))["activated"] == 0
    assert (point.frequency, point.workflow_mode) == ("three_day", "spot")
    history = tuple(getattr(store.get(Inspection, 1), c.name) for c in Inspection.__table__.columns)
    schedules = [tuple(row) for row in store.execute(select(*PointSchedule.__table__.columns).order_by(PointSchedule.id))]
    result = revision.activate_due_point_frequencies(CUTOFF)
    assert result["activated"] == 2
    assert (point.frequency, point.workflow_mode, point.qr_token) == ("daily", "two_stage", "unchanged-54")
    assert point.pending_frequency is point.frequency_effective_date is None
    assert store.get(Point, 68).frequency == "weekly_fri"
    assert tuple(getattr(store.get(Inspection, 1), c.name) for c in Inspection.__table__.columns) == history
    assert [tuple(row) for row in store.execute(select(*PointSchedule.__table__.columns).order_by(PointSchedule.id))] == schedules
    changed = next(item for item in result["points"] if item["point_id"] == 54)
    assert (changed["workflow_before"], changed["workflow_after"], changed["source_audit_id"]) == (
        "spot", "two_stage", planned.marker_id)
    assert json.loads(store.scalar(select(AuditLog.detail).where(AuditLog.action == revision.ACTIVATION_ACTION))) == result["points"]
    assert revision.activate_due_point_frequencies(CUTOFF)["activated"] == 0


@pytest.mark.parametrize("tamper", ["missing", "wrong_action", "bad_json", "wrong_day", "wrong_point", "duplicate_point",
    "old_frequency", "old_workflow", "new_frequency", "new_workflow", "identity", "no_identity", "duplicate_marker"])
def test_missing_or_inexact_calendar_approval_fails_closed_for_entire_batch(planned, tamper):
    store = planned.session
    marker = store.get(AuditLog, planned.marker_id)
    plan = json.loads(marker.detail)
    if tamper == "missing":
        store.delete(marker)
    elif tamper == "wrong_action":
        marker.action = revision.REVISION_ACTION
    elif tamper == "bad_json":
        marker.detail = "not json"
    elif tamper == "duplicate_marker":
        store.add(AuditLog(action=marker.action, detail=marker.detail))
    else:
        change = plan["changes"][0]
        if tamper == "wrong_day": plan["effective_date"] = "2026-11-17"
        elif tamper == "wrong_point": change["point_id"] = 55
        elif tamper == "duplicate_point": plan["changes"].append(dict(change))
        elif tamper == "old_frequency": change["before"]["frequency"] = "weekly"
        elif tamper == "old_workflow": change["before"]["workflow_mode"] = "two_stage"
        elif tamper == "new_frequency": change["after"]["frequency"] = "weekly_fri"
        elif tamper == "new_workflow": change["after"]["workflow_mode"] = "spot"
        elif tamper == "identity": change["activation_identity"]["code"] = "old-code-before-renumbering"
        elif tamper == "no_identity": del change["activation_identity"]
        marker.detail = json.dumps(plan)
    store.commit()
    point = store.get(Point, 54)
    assert not revision.approved_calendar_workflow_schedule(point, point.schedules[-1])
    with pytest.raises(ValueError, match="預約頻率設定不一致"):
        revision.activate_due_point_frequencies(CUTOFF)
    assert (store.get(Point, 54).frequency, store.get(Point, 54).workflow_mode) == ("three_day", "spot")
    assert store.get(Point, 68).frequency == "weekly"
    assert store.query(Point).filter(Point.pending_frequency.is_not(None)).count() == 2
    assert store.query(AuditLog).filter_by(action=revision.ACTIVATION_ACTION).count() == 0


@pytest.mark.parametrize("field,value", [("name", "Changed name"), ("code", "1F-X999"), ("floor", 2),
                                         ("active", False), ("inspection_team", "engineering")])
def test_changed_live_identity_cannot_reuse_calendar_approval(planned, field, value):
    point = planned.session.get(Point, 54)
    setattr(point, field, value)
    planned.session.commit()
    assert not revision.approved_calendar_workflow_schedule(point, point.schedules[-1])
    with pytest.raises(ValueError, match="預約頻率設定不一致"):
        revision.activate_due_point_frequencies(CUTOFF)
    assert planned.session.get(Point, 68).frequency == "weekly"


def test_later_point_mismatch_and_commit_failure_rollback_every_activation(planned, monkeypatch):
    store = planned.session
    later = store.get(Point, 68)
    later.name = "Changed later point"
    store.commit()
    with pytest.raises(ValueError): revision.activate_due_point_frequencies(CUTOFF)
    assert (store.get(Point, 54).frequency, store.get(Point, 54).workflow_mode) == ("three_day", "spot")
    later.name = "Point 68"
    store.commit()
    def fail_commit():
        store.flush()
        raise RuntimeError("Injected activation commit failure")
    monkeypatch.setattr(store, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="Injected activation"):
        revision.activate_due_point_frequencies(CUTOFF)
    assert (store.get(Point, 54).frequency, store.get(Point, 54).workflow_mode) == ("three_day", "spot")
    assert store.query(AuditLog).filter_by(action=revision.ACTIVATION_ACTION).count() == 0


def test_parallel_calendar_activation_occurs_once_on_postgres(planned):
    if planned.engine.dialect.name != "postgresql":
        pytest.skip("Cross-worker row locking is tested on PostgreSQL.")
    planned.session.remove()
    start = Barrier(2)
    def activate():
        start.wait()
        try: return revision.activate_due_point_frequencies(CUTOFF)
        finally: planned.session.remove()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: activate(), range(2)))
    assert sorted(item["activated"] for item in results) == [0, 2]
    assert planned.session.query(AuditLog).filter_by(action=revision.ACTIVATION_ACTION).count() == 1
    assert planned.session.get(Point, 54).workflow_mode == "two_stage"
