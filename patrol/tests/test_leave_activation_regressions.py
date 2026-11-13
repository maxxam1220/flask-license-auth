"""Leave/report consistency and atomic calendar activation in isolated databases."""
from datetime import date, datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import event, select

import app as patrol
import point_calendar_revision as revision
from models import AuditLog, DeviceBinding, Inspection, PatrolExecution, Point, PointSchedule, db
from point_assignment_revision import activate_due_point_frequencies
from safety_leave import SafetyLeaveExclusion, get_safety_leave_dates
from test_app import application, rendered_contexts  # noqa: F401
from test_go_live_routes import go_live, local, missed, page, snapshot  # noqa: F401
from test_point_calendar_revision import NOW, apply, calendar_points, catalogue_app  # noqa: F401
from test_postgres_features import postgres_app  # noqa: F401
from test_workflow_checkin import payload


def leave_rows():
    return list(db.session.scalars(select(SafetyLeaveExclusion).order_by(SafetyLeaveExclusion.id)))


def approve_browser(env, actor):
    token = "isolated-leave-browser-" + actor
    db.session.add(DeviceBinding(user_id=env.users[actor].id,
                                token_hash=patrol.hash_device_token(token), status="approved"))
    db.session.commit()
    env.clients[actor].set_cookie("patrol_device", token)


def save_scan(env, actor, point_name):
    url = "/c/" + env.points[point_name].qr_token
    response = env.clients[actor].post(url + "/confirm", data=payload(env.clients[actor], url))
    assert response.status_code == 302, response.text
    assert response.location.startswith(("/checkins/", "/executions/"))
    return response


def test_leave_add_cancel_updates_ready_overview_missed_and_csv_only_for_safety(go_live):
    env = go_live
    env.clock[0] = local("2026-11-18", 10)
    ready_before, _ = page(env, "/ready", actor="safety")
    assert {row["id"] for row in ready_before["ready_points"]} == {
        env.points["safety"].id, env.points["safety_twice"].id}
    other_before = {actor: page(env, "/dashboard", actor=actor, view="daily", date="2026-11-18")[0]["totals"]
                    for actor in ("general", "engineering", "manager", "executor")}
    response = env.clients["safety"].post("/safety-leave/add", data={
        "date_from": "2026-11-16", "date_to": "2026-11-18", "note": "inspection scheduling exception"})
    assert response.status_code == 302
    entry, = leave_rows()
    ready_after, _ = page(env, "/ready", actor="safety")
    assert ready_after["ready_points"] == [] and ready_after["ready_excluded"]
    safety, _ = page(env, "/dashboard", actor="safety", view="daily", date="2026-11-18")
    assert safety["totals"] == {"total": 0, "done": 0, "pending": 0}
    assert safety["missed_count"] == 0
    for actor, before in other_before.items():
        overview, _ = page(env, "/dashboard", actor=actor, view="daily", date="2026-11-18")
        assert overview["totals"] == before
    env.clock[0] = local("2026-11-19")
    excluded, _, _ = missed(env, "2026-11-01", "2026-11-18", actor="safety", frequency="daily_all")
    assert excluded["totals"]["missed"] == 0
    other_missing = {actor: missed(env, "2026-11-16", "2026-11-18", actor=actor,
                                  frequency="daily_all")[0]["totals"]
                     for actor in ("general", "engineering", "manager", "executor")}
    assert env.clients["safety"].post(f"/safety-leave/{entry.id}/cancel").status_code == 302
    restored, _, _ = missed(env, "2026-11-01", "2026-11-18", actor="safety", frequency="daily_all")
    assert restored["totals"] == {"missed": 9, "points": 2}
    overview, _ = page(env, "/dashboard", actor="safety", view="daily", date="2026-11-18")
    assert overview["totals"] == {"total": 3, "done": 0, "pending": 3} and overview["missed_count"] == 3
    for actor, before in other_missing.items():
        assert missed(env, "2026-11-16", "2026-11-18", actor=actor,
                      frequency="daily_all")[0]["totals"] == before
    assert env.clients["safety"].post(f"/safety-leave/{entry.id}/cancel").status_code == 409
    assert len(leave_rows()) == 1 and entry.cancelled_by == env.users["safety"].id


@pytest.mark.parametrize("actor", ["general", "engineering", "manager", "executor"])
def test_other_roles_cannot_change_or_cancel_safety_exclusion(go_live, actor):
    env = go_live
    assert env.clients["safety"].post("/safety-leave/add", data={"date_from": "2026-11-16"}).status_code == 302
    entry, = leave_rows()
    before = snapshot(SafetyLeaveExclusion)
    assert env.clients[actor].get("/safety-leave").status_code == 403
    assert env.clients[actor].post("/safety-leave/add", data={"date_from": "2026-11-17"}).status_code == 403
    assert env.clients[actor].post(f"/safety-leave/{entry.id}/cancel").status_code == 403
    assert snapshot(SafetyLeaveExclusion) == before
    result, _, _ = missed(env, "2026-11-16", "2026-11-16", actor="safety", frequency="daily_all")
    assert result["totals"]["missed"] == 0


def test_inclusive_leave_date_bounds_and_overlap_failure_preserve_original(go_live):
    env = go_live
    env.clock[0] = local("2026-11-17", 23, 59, 59)
    today = env.clock[0].date()
    for offset in (-366, 366):
        assert env.clients["safety"].post("/safety-leave/add", data={
            "date_from": (today + timedelta(days=offset)).isoformat()}).status_code == 302
    before = snapshot(SafetyLeaveExclusion)
    for offset in (-367, 367):
        assert env.clients["safety"].post("/safety-leave/add", data={
            "date_from": (today + timedelta(days=offset)).isoformat()}).status_code == 400
    assert snapshot(SafetyLeaveExclusion) == before
    assert env.clients["safety"].post("/safety-leave/add", data={
        "date_from": "2026-11-16", "date_to": "2026-11-18"}).status_code == 302
    before = snapshot(SafetyLeaveExclusion)
    assert env.clients["admin"].post("/safety-leave/add", data={
        "date_from": "2026-11-18", "date_to": "2026-11-20"}).status_code == 409
    assert snapshot(SafetyLeaveExclusion) == before
    assert get_safety_leave_dates(date(2026, 11, 17), date(2026, 11, 19)) == {
        date(2026, 11, 17), date(2026, 11, 18)}


def test_leave_does_not_block_voluntary_safety_checkin_or_destroy_receipt(go_live):
    env = go_live
    env.clock[0] = local("2026-11-16", 10)
    approve_browser(env, "safety")
    assert env.clients["safety"].post("/safety-leave/add", data={"date_from": "2026-11-16"}).status_code == 302
    save_scan(env, "safety", "safety")
    record = db.session.scalar(select(Inspection).where(Inspection.period_key == "2026-11-16"))
    original = tuple(getattr(record, c.name) for c in Inspection.__table__.columns)
    overview, _ = page(env, "/dashboard", actor="safety", view="daily", date="2026-11-16")
    assert overview["totals"] == {"total": 0, "done": 0, "pending": 0}
    card, = overview["cards"]
    assert card["status"] == "done" and not card["slots"][0]["counted"]
    env.clock[0] = local("2026-11-17")
    result, _, _ = missed(env, "2026-11-16", "2026-11-16", actor="safety", frequency="daily_all")
    assert result["totals"]["missed"] == 0
    entry, = leave_rows()
    assert env.clients["admin"].post(f"/safety-leave/{entry.id}/cancel").status_code == 302
    restored, _, _ = missed(env, "2026-11-16", "2026-11-16", actor="safety", frequency="daily_all")
    assert restored["totals"]["missed"] == 2  # Only the untouched daily-two point.
    assert tuple(getattr(record, c.name) for c in Inspection.__table__.columns) == original


def test_holiday_voluntary_checkins_work_for_all_units_and_both_stages(go_live):
    env = go_live
    env.clock[0] = local("2026-12-25", 10)
    for actor in ("safety", "general", "engineering", "executor"):
        approve_browser(env, actor)
    for actor in ("safety", "general", "engineering"):
        save_scan(env, actor, actor)
    save_scan(env, "executor", "general_pair")
    save_scan(env, "general", "general_pair")
    assert db.session.query(PatrolExecution).count() == 1
    assert db.session.query(Inspection).filter_by(period_key="2026-12-25").count() == 4
    overview, _ = page(env, "/dashboard", view="daily", date="2026-12-25")
    assert overview["totals"] == {"total": 0, "done": 0, "pending": 0}
    assert len(overview["cards"]) == 4 and all(card["status"] == "done" for card in overview["cards"])
    env.clock[0] = local("2026-12-26")
    result, _, _ = missed(env, "2026-12-25", "2026-12-25")
    assert result["totals"]["missed"] == 0


def test_late_batch_commit_failure_rolls_back_new_points_renumbering_and_all_future_snapshots(calendar_points, monkeypatch):
    before = {model: snapshot(model) for model in (Point, PointSchedule, AuditLog)}
    def fail_commit():
        db.session.flush()
        raise RuntimeError("injected late calendar commit failure")
    monkeypatch.setattr(db.session, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="late calendar"):
        apply()
    assert {model: snapshot(model) for model in before} == before
    assert not db.session.scalar(select(AuditLog.id).where(AuditLog.action == revision.REVISION_ACTION))


def test_invalid_last_scheduled_point_cannot_partially_activate_earlier_points(calendar_points):
    apply()
    invalid = db.session.get(Point, 118).schedules[-1]
    invalid.frequency = "daily"
    db.session.commit()
    before = {model: snapshot(model) for model in (Point, PointSchedule, AuditLog)}
    with pytest.raises(ValueError, match="預約頻率設定不一致"):
        activate_due_point_frequencies(datetime(2026, 11, 15, 16, tzinfo=timezone.utc))
    assert {model: snapshot(model) for model in before} == before
    assert all(db.session.get(Point, pid).pending_frequency for pid in revision.POINT_CHANGES)


def test_failed_database_activation_update_is_atomic_and_retry_keeps_codes_qr_and_history(calendar_points):
    apply()
    before = {model: snapshot(model) for model in (Point, PointSchedule, AuditLog)}
    identity = {p.id: (p.code, p.qr_token) for p in db.session.scalars(select(Point))}
    def fail_after_update(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE PATROL_POINTS"):
            raise RuntimeError("injected activation write failure")
    event.listen(db.engine, "after_cursor_execute", fail_after_update)
    try:
        with pytest.raises(RuntimeError, match="activation write"):
            activate_due_point_frequencies(datetime(2026, 11, 15, 16, tzinfo=timezone.utc))
    finally:
        event.remove(db.engine, "after_cursor_execute", fail_after_update)
    assert {model: snapshot(model) for model in before} == before
    assert activate_due_point_frequencies(datetime(2026, 11, 15, 16, tzinfo=timezone.utc))["activated"] == 15
    assert {p.id: (p.code, p.qr_token) for p in db.session.scalars(select(Point))} == identity
    assert snapshot(PointSchedule) == before[PointSchedule]


def test_qr_preprinting_does_not_activate_and_after_activation_labels_match(calendar_points, catalogue_app, monkeypatch):
    clock = [NOW]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    apply()
    client = catalogue_app.test_client()
    with client.session_transaction() as signed:
        signed.update(user_id=1, auth_version=1, sid="leave-activation-qr", csrf_token="fixture")
    before = {model: snapshot(model) for model in (Point, PointSchedule, AuditLog)}
    with rendered_contexts(catalogue_app) as rendered:
        preview = client.get("/admin/points/print?ids=54,47,68")
    assert preview.status_code == 200
    assert rendered[-1][1]["qr_workflows"][54] == "two_stage"
    assert "兩階段 · 每日一次" in preview.text and "單段 · 每週三" in preview.text and "兩階段 · 每週五" in preview.text
    assert {model: snapshot(model) for model in before} == before
    clock[0] = datetime(2026, 11, 15, 16, tzinfo=timezone.utc)
    live = client.get("/admin/points/print?ids=54,47,68")
    assert live.status_code == 200
    for label in ("兩階段 · 每日一次", "單段 · 每週三", "兩階段 · 每週五"):
        assert label in live.text
    assert db.session.get(Point, 54).workflow_mode == "two_stage"
    assert db.session.get(Point, 54).qr_token == "preserved-54"


@pytest.mark.parametrize("scenario", [test_leave_add_cancel_updates_ready_overview_missed_and_csv_only_for_safety,
    test_holiday_voluntary_checkins_work_for_all_units_and_both_stages], ids=["leave-reports", "holiday-attendance"])
def test_postgres_leave_and_holiday_route_consistency(postgres_app, monkeypatch, scenario):
    # The shared opt-in fixture rejects every host except local :55432/patrol_test
    # and gives this test its own disposable schema.
    with postgres_app.app_context():
        env = go_live.__wrapped__(postgres_app, monkeypatch)
        scenario(env)


def test_postgres_concurrent_overlapping_leave_adds_commit_exactly_one_range(postgres_app, monkeypatch):
    with postgres_app.app_context():
        env = go_live.__wrapped__(postgres_app, monkeypatch)
        clients = [env.clients["safety"], env.clients["admin"]]
        db.session.remove()
    barrier = Barrier(2)
    def add(client):
        barrier.wait(timeout=10)
        return client.post("/safety-leave/add", data={
            "date_from": "2026-11-16", "date_to": "2026-11-18"}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(add, client) for client in clients]
        outcomes = [future.result(timeout=30) for future in futures]
    assert sorted(outcomes) == [302, 409]
    with postgres_app.app_context():
        entries = leave_rows()
        assert len(entries) == 1 and entries[0].cancelled_at is None
        assert db.session.query(AuditLog).filter_by(action="safety_leave_added").count() == 1


@pytest.mark.parametrize("scenario", [test_invalid_last_scheduled_point_cannot_partially_activate_earlier_points,
    test_failed_database_activation_update_is_atomic_and_retry_keeps_codes_qr_and_history],
    ids=["invalid-last-point", "database-write-rollback"])
def test_postgres_calendar_activation_atomicity(postgres_app, scenario):
    with postgres_app.app_context():
        calendar_points.__wrapped__(postgres_app)
        # This historical-identity fixture inserts explicit IDs; PostgreSQL
        # sequences need alignment before exercising real auto-ID creation.
        db.session.execute(db.text("SELECT setval(pg_get_serial_sequence('patrol_points','id'), "
                                   "(SELECT max(id) FROM patrol_points), true)"))
        db.session.commit()
        scenario(None)
