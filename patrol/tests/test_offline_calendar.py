"""Fixed weekday offline receipts retain scan-day identity and actor permissions."""
from datetime import date, datetime, timedelta
from uuid import uuid4

import pytest

from missed import TAIPEI, calculate_missed
from models import Inspection, OfflineSubmission, PatrolExecution, db
from test_app import application  # noqa: F401
from test_daily2_anytime import anytime, rows  # noqa: F401
from test_executor_visits import second_executor
from test_offline_api import assert_error, entry, prepare, sync
from test_three_day_routes import stops, synthetic_register  # noqa: F401


def fixed_point(env, frequency, day, *, paired=False):
    point = env.pair_point if paired else env.direct_point
    point.frequency = frequency
    for schedule in point.schedules:
        schedule.frequency = frequency
    env.clock[0] = datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(hour=10)
    db.session.commit()
    return point, env.paired if paired else env.direct


@pytest.mark.parametrize("frequency, due", [("weekly_wed", "2026-11-18"), ("weekly_fri", "2026-11-20")])
def test_offday_receipt_cannot_complete_next_fixed_weekday(application, anytime, frequency, due):
    env = anytime
    point, url = fixed_point(env, frequency, due)
    due_day = env.clock[0].date()
    env.clock[0] -= timedelta(days=1)
    prepared = prepare(env.inspector)
    row = next(item for item in prepared["points"] if item["id"] == point.id)
    assert row["period_key"] == env.clock[0].date().isoformat()
    assert row["frequency"] == frequency and row["slots"] == ["any"]
    response = sync(env.inspector, prepared, entry(prepared, url, env.clock[0]))
    assert response.status_code == 200, response.text
    env.clock[0] += timedelta(days=2)
    missing = calculate_missed([point], rows(point), due_day, due_day, env.clock[0])
    assert len(missing) == 1 and missing[0]["period_key"] == due


@pytest.mark.parametrize("frequency, due", [("weekly_wed", "2026-11-18"), ("weekly_fri", "2026-11-20")])
def test_due_day_offline_upload_next_day_keeps_due_day_and_is_idempotent(application, anytime, frequency, due):
    env = anytime
    point, url = fixed_point(env, frequency, due)
    prepared = prepare(env.inspector)
    delayed = entry(prepared, url, env.clock[0])
    env.clock[0] += timedelta(days=1)
    result = sync(env.inspector, prepared, delayed)
    assert result.status_code == 200, result.text
    record, = rows(point)
    assert record.period_key == due and record.personal_day == date.fromisoformat(due)
    assert record.slot == "any" and record.frequency == frequency
    assert not calculate_missed([point], [record], date.fromisoformat(due), date.fromisoformat(due), env.clock[0])
    replay = sync(env.inspector, prepared, delayed)
    assert replay.status_code == 200 and replay.json["status"] == "already_synced"
    assert_error(sync(env.inspector, prepared, delayed | {"client_id": str(uuid4())}), "duplicate")
    assert len(rows(point)) == 1


def test_fixed_friday_public_holiday_can_still_save_a_voluntary_visit(application, anytime):
    env = anytime
    point, url = fixed_point(env, "weekly_fri", "2026-12-25")
    prepared = prepare(env.inspector)
    result = sync(env.inspector, prepared, entry(prepared, url, env.clock[0]))
    assert result.status_code == 200, result.text
    assert rows(point)[0].period_key == "2026-12-25"


def test_fixed_weekday_two_stage_cannot_reuse_yesterdays_execution(application, anytime):
    env = anytime
    point, url = fixed_point(env, "weekly_wed", "2026-11-18", paired=True)
    executor = prepare(env.executor)
    result = sync(env.executor, executor, entry(executor, url, env.clock[0]))
    assert result.status_code == 200, result.text
    env.clock[0] += timedelta(days=1)
    inspector = prepare(env.inspector)
    observation = entry(inspector, url, env.clock[0])
    assert_error(sync(env.inspector, inspector, observation), "waiting_execution", retryable=True)
    current = prepare(env.executor)
    assert sync(env.executor, current, entry(current, url, env.clock[0])).status_code == 200
    assert sync(env.inspector, inspector, observation).status_code == 200
    execution_days = {r.period_key for r in rows(point, PatrolExecution)}
    assert execution_days == {"2026-11-18", "2026-11-19"}
    record, = rows(point)
    assert record.period_key == "2026-11-19"
    assert db.session.get(PatrolExecution, record.execution_id).period_key == record.period_key


def test_frequency_change_rejects_old_grant_without_deleting_local_receipt_identity(application, anytime):
    env = anytime
    prepared = prepare(env.inspector)
    delayed = entry(prepared, env.direct, env.clock[0])
    env.direct_point.frequency = "weekly_wed"
    db.session.commit()
    assert_error(sync(env.inspector, prepared, delayed), "point_changed")
    assert not rows(env.direct_point) and db.session.query(OfflineSubmission).count() == 0


@pytest.mark.parametrize("frequency", ["weekly_wed", "weekly_fri", "daily"])
def test_original_visit_points_remain_authorized_but_new_points_do_not(stops, frequency):
    env = stops
    env.point.frequency = frequency
    env.point.schedules[-1].frequency = frequency
    env.clock[0] = datetime(2026, 11, 18, 10, tzinfo=TAIPEI)
    db.session.commit()
    other = env.create(code="1F-NEW090", frequency=frequency)
    prepared = prepare(env.executor)
    visits = {point["id"]: point for point in prepared["points"] if point["stage"] == "visit"}
    assert env.point.id in visits and other.id not in visits
    result = sync(env.executor, prepared, entry(prepared, env.url, env.clock[0]))
    assert result.status_code == 200, result.text
    record = db.session.get(Inspection, result.json["record_id"])
    assert record.executor_visit and record.point_id == env.point.id and record.frequency == frequency
    assert env.executor.get(result.json["receipt_url"]).status_code == 200
    assert second_executor(env.app).get(result.json["receipt_url"]).status_code == 403
