"""Frequency cutovers retain signed scan-day identity and reject incompatible grants."""
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import event

import offline
from migrations import B2_STAIR_FREQUENCIES, _schedule_b2_stairs
from models import Inspection, InspectionPhoto, OfflineSubmission, PatrolExecution, Point, PointSchedule, db
from test_daily2_anytime import anytime
from test_engineering_point_scope import application, teams  # noqa: F401
from test_offline_api import assert_error, entry, prepare, sync
from test_scheduled_frequency_routes import schedule


MIDNIGHT = datetime(2026, 11, 9, 16, tzinfo=timezone.utc)


def receipt_and_attendance_counts():
    return {model.__tablename__: db.session.query(model).count()
        for model in (Inspection, PatrolExecution, OfflineSubmission, InspectionPhoto)}


def test_offline_sync_rechecks_cutover_after_waiting_for_point_lock(teams):
    t = teams
    point, url = schedule(t, "general", "daily2", "daily")
    client = t.clients["general"]
    prepared = prepare(client)
    delayed = entry(prepared, url, t.clock[0])
    baseline = receipt_and_attendance_counts()
    crossed = []
    def cross_after_point_lock(_conn, _cursor, statement, _parameters, _context, _many):
        if (not crossed and statement.lstrip().upper().startswith("SELECT")
                and "FROM patrol_points" in statement and "WHERE patrol_points.id =" in statement):
            crossed.append(True)
            t.clock[0] = MIDNIGHT
    event.listen(db.engine, "after_cursor_execute", cross_after_point_lock)
    try:
        response = sync(client, prepared, delayed)
    finally:
        event.remove(db.engine, "after_cursor_execute", cross_after_point_lock)
    assert crossed
    assert_error(response, "point_changed", status=409)
    assert receipt_and_attendance_counts() == baseline
    # A following request activates the schedule and still rejects the old grant.
    assert_error(sync(client, prepared, delayed), "point_changed", status=409)
    db.session.refresh(point)
    assert point.frequency == "daily" and point.pending_frequency is None
    assert receipt_and_attendance_counts() == baseline


def test_offline_sync_rechecks_cutover_after_processing_before_persistence(teams, monkeypatch):
    t = teams
    point, url = schedule(t, "general", "daily2", "daily")
    client = t.clients["general"]
    prepared = prepare(client)
    delayed = entry(prepared, url, t.clock[0], note="Do not partly store this note")
    baseline = receipt_and_attendance_counts()
    processed = []
    def process_then_cross(_uploads):
        processed.append(True)
        t.clock[0] = MIDNIGHT
        return []
    monkeypatch.setattr(offline, "process_uploads", process_then_cross)
    response = sync(client, prepared, delayed)
    assert processed
    assert_error(response, "point_changed", status=409)
    assert receipt_and_attendance_counts() == baseline
    db.session.refresh(point)
    assert point.pending_frequency == "daily"  # Rejected upload did not activate or rewrite the point.


def test_normal_offline_prior_day_capture_without_scheduled_cutover_still_uploads(teams):
    t = teams
    client = t.clients["general"]
    point = t.points["general"]
    t.clock[0] = datetime(2026, 11, 9, 15, 59, tzinfo=timezone.utc)
    prepared = prepare(client)
    delayed = entry(prepared, "/c/" + point.qr_token, t.clock[0])
    t.clock[0] = MIDNIGHT
    response = sync(client, prepared, delayed)
    assert response.status_code == 200 and response.json["status"] == "saved"
    record = db.session.get(Inspection, response.json["record_id"])
    assert record.period_key == "2026-11-09"
    assert db.session.query(OfflineSubmission).count() == 1


def test_b2_migration_keeps_signed_yesterday_stair_drafts_and_two_separate_day_slots(anytime):
    env = anytime
    env.clock[0] = datetime(2026, 11, 26, 15, 58, tzinfo=timezone.utc)
    urls = {}
    for point_id, (code, name, _) in B2_STAIR_FREQUENCIES.items():
        point = Point(id=point_id, code=code, name=name, floor=-2, category="general", active=True,
                      frequency="daily", workflow_mode="two_stage", schedule_start=date(2026, 11, 1))
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, category=point.category,
            frequency=point.frequency, workflow_mode=point.workflow_mode, active=True,
            floor=point.floor, point_code=code, point_name=name))
        db.session.add(point)
        db.session.flush()
        urls[point_id] = "/c/" + point.qr_token
    db.session.commit()

    executor, inspector, peer = prepare(env.executor), prepare(env.inspector), prepare(env.peer)
    old_drafts = {key: (entry(executor, url, env.clock[0]),
                        entry(inspector, url, env.clock[0] + timedelta(minutes=1))) for key, url in urls.items()}
    peer_drafts = {key: entry(peer, url, env.clock[0] + timedelta(minutes=1)) for key, url in urls.items()}
    _schedule_b2_stairs(db.session.connection(), env.clock[0])
    db.session.commit()
    env.clock[0] += timedelta(minutes=3)
    fresh = prepare(env.executor)
    for key, (_, _, frequency) in B2_STAIR_FREQUENCIES.items():
        present = next(item for item in fresh["points"] if item["id"] == key)
        assert (present["frequency"], present["period_key"], present["used_slots"]) == (frequency, "2026-11-27", [])
        old_execution, old_review = old_drafts[key]
        assert_error(sync(env.inspector, inspector, old_review), "waiting_execution", retryable=True)
        assert sync(env.executor, fresh, entry(fresh, urls[key], env.clock[0])).status_code == 200
        assert sync(env.executor, executor, old_execution).status_code == 200
        saved = sync(env.inspector, inspector, old_review)
        assert saved.status_code == 200, saved.text
        receipt = db.session.get(Inspection, saved.json["record_id"])
        first_stage = db.session.get(PatrolExecution, receipt.execution_id)
        assert (receipt.period_key, receipt.frequency) == (first_stage.period_key, first_stage.frequency) == ("2026-11-26", "daily")
        assert sync(env.inspector, inspector, old_review).json["status"] == "already_synced"
        assert env.inspector.get(saved.json["receipt_url"]).status_code == 200
        point = db.session.get(Point, key)
        point.name = "另一個位置"
        db.session.commit()
        assert_error(sync(env.peer, peer, peer_drafts[key]), "point_changed")
