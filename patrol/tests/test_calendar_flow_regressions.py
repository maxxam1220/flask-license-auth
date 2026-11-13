"""Calendar behavior agrees across ready lists, live scans and delayed receipts."""
from datetime import date, datetime, timedelta

import pytest

import app as patrol
from models import Inspection, PatrolExecution, PointSchedule, db
from safety_leave import SafetyLeaveExclusion
from test_app import application, approve_browser, login, seeded  # noqa: F401
from test_calendar_routes import calendar, context, instant, ready, scan  # noqa: F401
from test_offline_api import assert_error, entry, prepare, sync
from test_workflow_checkin import payload


@pytest.mark.parametrize("frequency,due", [("weekly_wed", "2026-11-18"), ("weekly_fri", "2026-11-20")])
def test_offline_execution_unlocks_only_its_day_and_delayed_review_closes_that_obligation(calendar, frequency, due):
    env = calendar
    point = env.wed
    point.frequency = point.schedules[0].frequency = frequency
    db.session.commit()
    env.clock[0] = instant(due)
    executor, inspector = prepare(env.executor), prepare(env.inspector)
    first = entry(executor, env.wed_url, env.clock[0])
    review = entry(inspector, env.wed_url, env.clock[0] + timedelta(minutes=1))
    env.clock[0] += timedelta(minutes=2)

    # A queued review remains retryable until its execution reaches the server.
    assert_error(sync(env.inspector, inspector, review), "waiting_execution", retryable=True)
    assert point.id not in ready(env)
    assert sync(env.executor, executor, first).status_code == 200
    assert ready(env)[point.id] == "review"
    assert point.id not in ready(env, env.executor)

    # Uploading tomorrow must finish yesterday, without creating today's execution.
    env.clock[0] = instant(due) + timedelta(days=1)
    assert point.id not in ready(env)
    live, _ = context(env.app, env.inspector, env.wed_url)
    assert live["waiting_for_execution"] and not live["can_confirm"]
    saved = sync(env.inspector, inspector, review)
    assert saved.status_code == 200, saved.text
    record = db.session.get(Inspection, saved.json["record_id"])
    execution = db.session.get(PatrolExecution, record.execution_id)
    assert record.period_key == execution.period_key == due
    assert record.created_at >= execution.created_at
    assert env.inspector.get(saved.json["receipt_url"]).status_code == 200
    missed, _ = context(env.app, env.inspector,
        f"/missed?frequency={frequency}&date_from={due}&date_to={due}")
    assert not [row for row in missed["occurrences"] if row["point_id"] == point.id]


def test_holiday_two_stage_offline_attendance_is_voluntary_and_not_a_ready_obligation(calendar):
    env = calendar
    point = env.wed
    point.frequency = point.schedules[0].frequency = "weekly_fri"
    db.session.commit()
    env.clock[0] = instant("2026-12-25")
    assert not ready(env) and not ready(env, env.executor)
    prepared = prepare(env.executor)
    first = sync(env.executor, prepared, entry(prepared, env.wed_url, env.clock[0]))
    assert first.status_code == 200
    assert not ready(env)  # Signing in on a holiday does not create a required task.
    live, _ = context(env.app, env.inspector, env.wed_url)
    assert live["can_confirm"] and not live["waiting_for_execution"]
    prepared = prepare(env.inspector)
    assert sync(env.inspector, prepared, entry(prepared, env.wed_url, env.clock[0])).status_code == 200
    overview, _ = context(env.app, env.inspector, "/dashboard?view=weekly_fri&date=2026-12-25")
    assert overview["totals"] == {"total": 0, "done": 0, "pending": 0}
    env.clock[0] += timedelta(days=1)
    missed, _ = context(env.app, env.inspector,
        "/missed?frequency=weekly_fri&date_from=2026-12-25&date_to=2026-12-25")
    assert missed["totals"]["missed"] == 0


def test_safety_leave_excludes_ready_and_missed_but_keeps_offline_attendance(application, seeded, monkeypatch):
    point = seeded["weekly"]
    point.frequency = point.schedules[0].frequency = "weekly_wed"
    day = date(2026, 11, 18)
    db.session.add(SafetyLeaveExclusion(date_from=day, date_to=day, created_by=seeded["inspector"].id))
    db.session.commit()
    clock = [instant(day.isoformat())]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    pending, _ = context(application, client, "/ready")
    assert not pending["ready_points"]
    url = "/c/" + point.qr_token
    prepared = prepare(client)
    delayed = entry(prepared, url, clock[0])
    clock[0] += timedelta(days=1)
    accepted = sync(client, prepared, delayed)
    assert accepted.status_code == 200, accepted.text
    assert db.session.get(Inspection, accepted.json["record_id"]).period_key == day.isoformat()
    missing, _ = context(application, client,
        "/missed?frequency=weekly_wed&date_from=2026-11-18&date_to=2026-11-18")
    assert missing["totals"]["missed"] == 0
    next_day, _ = context(application, client, "/ready")
    assert point.id not in {row["id"] for row in next_day["ready_points"]}


def test_november16_activation_reissues_fixed_day_grants_without_borrowing_offday_execution(calendar):
    env = calendar
    point = env.wed
    point.frequency = point.schedules[0].frequency = "three_day"
    point.pending_frequency, point.frequency_effective_date = "weekly_wed", date(2026, 11, 16)
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 16), frequency="weekly_wed",
        category=point.category, workflow_mode=point.workflow_mode, active=True, floor=point.floor,
        point_code=point.code, point_name=point.name, workflow_changed_at=datetime(2026, 11, 15, 16)))
    db.session.commit()
    original_token = point.qr_token
    env.clock[0] = instant("2026-11-15", 23)
    old = prepare(env.executor)
    draft = entry(old, env.wed_url, env.clock[0])
    assert next(row for row in old["points"] if row["id"] == point.id)["frequency"] == "three_day"

    env.clock[0] = instant("2026-11-16", 0)
    current = prepare(env.executor)  # The first request activates the pending rules.
    row = next(row for row in current["points"] if row["id"] == point.id)
    assert (row["frequency"], row["period_key"], row["stage"]) == ("weekly_wed", "2026-11-16", "execute")
    assert point.qr_token == original_token and point.pending_frequency is None
    assert_error(sync(env.executor, old, draft), "point_changed")
    assert point.id not in ready(env, env.executor)
    scan(env.executor, env.wed_url)  # Monday remains a permissible voluntary visit.
    scan(env.inspector, env.wed_url)
    env.clock[0] = instant("2026-11-18")
    assert ready(env, env.executor)[point.id] == "execute"
    assert point.id not in ready(env)
    fresh = payload(env.executor, env.wed_url)
    assert fresh["period_key"] == "2026-11-18" and fresh["frequency"] == "weekly_wed"
