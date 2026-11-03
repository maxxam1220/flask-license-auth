"""Pure missed-patrol checks: no Flask, DB connection, employee data or clock IO."""
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from missed import calculate_missed

TAIPEI = ZoneInfo("Asia/Taipei")


def local(day="2026-11-03", hour=12, minute=0, second=0):
    return datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(hour=hour, minute=minute, second=second)


def schedule(day, frequency="daily", active=True, id=1, **snapshots):
    return SimpleNamespace(effective_date=date.fromisoformat(day), frequency=frequency, active=active, id=id,
                           category=snapshots.get("category", "safety"), floor=snapshots.get("floor", 1),
                           point_code=snapshots.get("point_code", "1F-OLD"), point_name=snapshots.get("point_name", "歷史名稱"))


def point(frequency="daily", id=1, **fields):
    values = dict(id=id, frequency=frequency, active=True, category="safety", floor=1, code="1F-CURRENT", name="目前名稱",
                  schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1),
                  schedules=[schedule("2026-01-01", frequency)])
    values.update(fields)
    return SimpleNamespace(**values)


def missed(points, completions=(), begin="2026-11-03", end=None, now=None, **filters):
    return calculate_missed(points, completions, date.fromisoformat(begin), date.fromisoformat(end or begin), now or local(), **filters)


@pytest.mark.parametrize("now,slots", [
    (local(hour=11, minute=59, second=59), []),
    (local(), ["am"]),
    (local(hour=23, minute=59, second=59), ["am"]),
    (local("2026-11-04", 0), ["pm", "am"]),
])
def test_daily2_expires_exactly_at_noon_and_following_midnight(now, slots):
    rows = missed([point("daily2")], now=now)
    assert [row["slot"] for row in rows] == slots
    assert all(row["due_date"] == date(2026, 11, 3) and row["period_key"] == "2026-11-03" for row in rows)
    assert all(row["deadline"].tzinfo == timezone.utc for row in rows)


def test_daily_expires_at_next_midnight_and_uses_original_due_date():
    assert missed([point()], now=local(hour=23, minute=59, second=59)) == []
    row, = missed([point()], now=local("2026-11-04", 0))
    assert row["due_date"] == date(2026, 11, 3) and row["slot"] == "any"
    assert row["deadline"] == datetime(2026, 11, 3, 16, tzinfo=timezone.utc)


def test_weekly_due_date_is_sunday_and_deadline_is_next_monday():
    weekly = point("weekly")
    assert missed([weekly], begin="2026-11-03", end="2026-11-07", now=local("2026-11-10")) == []
    assert missed([weekly], begin="2026-11-03", end="2026-11-08", now=local("2026-11-08", 23, 59, 59)) == []
    row, = missed([weekly], begin="2026-11-03", end="2026-11-08", now=local("2026-11-09", 0))
    assert row["due_date"] == date(2026, 11, 8) and row["period_key"] == "2026-11-02"
    assert row["period_label"] == "2026-11-02 – 2026-11-08"
    assert row["deadline"] == datetime(2026, 11, 8, 16, tzinfo=timezone.utc)


def test_weekly_not_duplicated_when_adjacent_date_ranges_are_combined():
    points = [point("weekly")]
    now = local("2026-11-16", 0)
    full = missed(points, begin="2026-11-02", end="2026-11-15", now=now)
    days = sum(len(missed(points, begin=(date(2026, 11, 2) + timedelta(days=offset)).isoformat(), now=now)) for offset in range(14))
    assert len(full) == days == 2
    assert [row["period_key"] for row in full] == ["2026-11-09", "2026-11-02"]


def test_any_employee_completion_satisfies_key_even_after_relocation():
    moved = point("daily2", floor=2, category="general", schedules=[schedule("2026-01-01", "daily2", floor=2, category="general")])
    completed = SimpleNamespace(point_id=1, frequency="daily2", period_key="2026-11-03", slot="am",
                                user_id=999, point_floor=1, category="safety", note="must not be inspected")
    rows = missed([moved], [completed], now=local("2026-11-04", 0), floor=2, category="general")
    assert [row["slot"] for row in rows] == ["pm"]
    assert "user_id" not in rows[0] and "note" not in rows[0]
    assert missed([moved], [(1, "daily2", "2026-11-03", "am"), (1, "daily2", "2026-11-03", "pm")], now=local("2026-11-04", 0)) == []


def test_completion_of_wrong_point_frequency_period_or_slot_does_not_hide_missed():
    completions = [(2, "daily2", "2026-11-03", "am"), (1, "daily", "2026-11-03", "any"),
                   (1, "daily2", "2026-11-02", "am"), (1, "daily2", "2026-11-03", "pm")]
    rows = missed([point("daily2")], completions)
    assert [row["slot"] for row in rows] == ["am"]


def test_historical_snapshot_filters_do_not_use_current_point_fields():
    moved = point(floor=2, code="2F-NEW", name="新名稱", category="general", schedules=[
        schedule("2026-01-01", floor=1, point_code="1F-OLD", point_name="舊名稱"),
        schedule("2026-11-04", id=2, floor=2, category="general", point_code="2F-NEW", point_name="新名稱"),
    ])
    row, = missed([moved], begin="2026-11-03", end="2026-11-04", now=local("2026-11-05", 0), floor=1, category="safety")
    assert (row["floor"], row["code"], row["name"], row["due_date"]) == (1, "1F-OLD", "舊名稱", date(2026, 11, 3))
    row, = missed([moved], begin="2026-11-03", end="2026-11-04", now=local("2026-11-05", 0), floor=2, category="general")
    assert (row["floor"], row["code"], row["name"]) == (2, "2F-NEW", "新名稱")


def test_null_legacy_snapshot_fields_fall_back_to_current_without_mutation():
    old = schedule("2026-01-01", floor=None, category=None, point_code=None, point_name=None)
    current = point(floor=11, code="1M-A01", name="目前名稱", category="general", schedules=[old])
    row, = missed([current], now=local("2026-11-04", 0))
    assert (row["floor"], row["category"], row["code"], row["name"]) == (11, "general", "1M-A01", "目前名稱")
    assert old.floor is old.category is old.point_code is old.point_name is None


def test_same_day_history_uses_highest_id_and_whole_day_effective_date():
    current = point(schedules=[schedule("2026-11-03", "daily2", id=3, floor=3),
                               schedule("2026-01-01", "daily", id=1),
                               schedule("2026-11-03", "daily2", id=2, floor=2)])
    rows = missed([current], now=local("2026-11-04", 0))
    assert len(rows) == 2 and {row["floor"] for row in rows} == {3}


def test_disable_and_reenable_preserve_only_active_days():
    current = point(schedules=[schedule("2026-01-01"), schedule("2026-11-03", active=False, id=2),
                               schedule("2026-11-05", active=True, id=3)])
    rows = missed([current], begin="2026-11-02", end="2026-11-05", now=local("2026-11-06", 0))
    assert {row["due_date"] for row in rows} == {date(2026, 11, 2), date(2026, 11, 5)}


def test_frequency_changes_generate_only_each_days_historical_obligation():
    current = point("daily2", schedules=[schedule("2026-01-01"), schedule("2026-11-03", "daily2", id=2),
                                         schedule("2026-11-04", "weekly", id=3)])
    rows = missed([current], begin="2026-11-02", end="2026-11-08", now=local("2026-11-09", 0))
    assert [(row["frequency"], row["due_date"], row["slot"]) for row in rows] == [
        ("weekly", date(2026, 11, 8), "any"), ("daily2", date(2026, 11, 3), "pm"),
        ("daily2", date(2026, 11, 3), "am"), ("daily", date(2026, 11, 2), "any")]
    assert len(missed([current], begin="2026-11-02", end="2026-11-08", now=local("2026-11-09", 0), frequency="weekly")) == 1


def test_weekly_uses_sunday_schedule_and_respects_start_and_disable():
    assert missed([point("weekly", schedule_start=date(2026, 11, 9))], begin="2026-11-08", now=local("2026-11-09", 0)) == []
    started_midweek = point("weekly", schedule_start=date(2026, 11, 6), created_at=local("2026-11-06"))
    assert len(missed([started_midweek], begin="2026-11-08", now=local("2026-11-09", 0))) == 1
    disabled = point("weekly", schedules=[schedule("2026-01-01", "weekly"), schedule("2026-11-06", "weekly", active=False, id=2)])
    assert missed([disabled], begin="2026-11-08", now=local("2026-11-09", 0)) == []


@pytest.mark.parametrize("created_at", [local(hour=12), local(hour=15), datetime(2026, 11, 3, 7)])
def test_new_afternoon_point_does_not_fabricate_missed_morning(created_at):
    current = point("daily2", schedule_start=date(2026, 11, 3), created_at=created_at)
    rows = missed([current], now=local("2026-11-04", 0))
    assert [row["slot"] for row in rows] == ["pm"]


def test_creation_exactly_on_deadline_excludes_prior_daily_and_weekly_obligations():
    current = point(created_at=local("2026-11-04", 0))
    assert missed([current], now=local("2026-11-04", 0)) == []
    weekly = point("weekly", created_at=local("2026-11-09", 0))
    assert missed([weekly], begin="2026-11-08", now=local("2026-11-09", 0)) == []


def test_future_range_and_future_slots_are_never_reported():
    assert missed([point("daily2")], begin="2026-11-04", end="2026-11-20") == []
    assert missed([point()], now=local()) == []
    assert missed([point("weekly")], begin="2026-11-08", now=local("2026-11-08", 23)) == []


def test_naive_utc_and_aware_clocks_agree_at_boundary():
    assert missed([point("daily2")], now=datetime(2026, 11, 3, 4)) == missed([point("daily2")], now=local())


def test_mapping_inputs_and_tuple_completions_produce_same_result():
    current = point("daily2")
    mapped = vars(current) | {"schedules": [vars(item) for item in current.schedules]}
    completion = {"point_id": 1, "frequency": "daily2", "period_key": date(2026, 11, 3), "slot": "am"}
    assert missed([mapped], [completion], now=local("2026-11-04", 0)) == missed([current], [(1, "daily2", "2026-11-03", "am")], now=local("2026-11-04", 0))


@pytest.mark.parametrize("filters", [{"floor": "0"}, {"category": "unknown"}, {"frequency": "monthly"}])
def test_invalid_filters_fail_explicitly(filters):
    with pytest.raises(ValueError):
        missed([point()], **filters)


def test_invalid_date_order_fails_explicitly():
    with pytest.raises(ValueError):
        missed([point()], begin="2026-11-04", end="2026-11-03")
