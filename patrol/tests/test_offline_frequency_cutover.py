"""A sync spanning midnight cannot commit a retired point-frequency grant."""
from datetime import datetime, timezone

from sqlalchemy import event

import offline
from models import Inspection, InspectionPhoto, OfflineSubmission, PatrolExecution, db
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
