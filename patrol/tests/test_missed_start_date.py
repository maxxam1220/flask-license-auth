"""Formal launch limits missed obligations, never saved attendance or period identity."""
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from missed import (TAIPEI, calculate_missed, missed_period_required, period_bounds,
                    schedule_timeline, slot_plans)


LAUNCH = date(2026, 11, 16)


def local(day, hour=0, minute=0, second=0):
    return datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(
        hour=hour, minute=minute, second=second)


def point(frequency="daily", category="general", mode="spot"):
    snap = SimpleNamespace(id=1, effective_date=date(2026, 1, 1), frequency=frequency,
        category=category, workflow_mode=mode, active=True, floor=1, point_code="1F-G001", point_name="Fixture")
    return SimpleNamespace(id=1, category=category, workflow_mode=mode, frequency=frequency,
        active=True, floor=1, code="1F-G001", name="Fixture", schedule_start=date(2026, 1, 1),
        created_at=datetime(2026, 1, 1), schedules=[snap])


def missing(item, begin="2026-11-01", end="2026-11-30", now=None, *, completions=(), **options):
    options.setdefault("count_from", LAUNCH)
    return calculate_missed([item], completions, date.fromisoformat(begin), date.fromisoformat(end),
        now or local((date.fromisoformat(end) + timedelta(days=1)).isoformat()), **options)


@pytest.mark.parametrize("frequency,count", [("daily", 1), ("daily2", 2)])
@pytest.mark.parametrize("category,mode", [("safety", "standard"), ("general", "spot"), ("general", "two_stage")])
def test_launch_day_only_becomes_missed_at_next_midnight(frequency, count, category, mode):
    item = point(frequency, category, mode)
    assert missing(item, now=local("2026-11-16")) == []
    assert missing(item, now=local("2026-11-16", 23, 59, 59)) == []
    rows = missing(item, now=local("2026-11-17"))
    assert len(rows) == count
    assert {row["due_date"] for row in rows} == {LAUNCH}
    assert {row["period_key"] for row in rows} == {"2026-11-16"}
    assert all(row["deadline"] == datetime(2026, 11, 16, 16, tzinfo=timezone.utc) for row in rows)


@pytest.mark.parametrize("frequency", ["daily", "daily2", "weekly_wed", "weekly_fri", "weekly", "monthly", "three_day"])
def test_entirely_prelaunch_query_is_empty_and_none_keeps_historical_api(frequency):
    item = point(frequency)
    assert missing(item, end="2026-11-15", now=local("2026-12-01")) == []
    old = missing(item, end="2026-11-15", now=local("2026-12-01"), count_from=None)
    original = calculate_missed([item], (), date(2026, 11, 1), date(2026, 11, 15), local("2026-12-01"))
    assert old == original
    if frequency != "monthly": assert old


@pytest.mark.parametrize("frequency,expected,key", [
    ("weekly_wed", "2026-11-18", "2026-11-18"),
    ("weekly_fri", "2026-11-20", "2026-11-20"),
    ("weekly", "2026-11-22", "2026-11-16"),
    ("monthly", "2026-11-30", "2026-11-01"),
    ("three_day", "2026-11-18", "2026-11-16"),
])
def test_first_due_period_after_launch_uses_original_deadline_and_key(frequency, expected, key):
    item = point(frequency)
    assert missing(item, end=expected, now=local(expected, 23, 59, 59), frequency=frequency) == []
    row, = missing(item, end=expected, frequency=frequency)
    assert (row["due_date"].isoformat(), row["period_key"]) == (expected, key)
    assert missed_period_required(date.fromisoformat(expected), frequency, "general", count_from=LAUNCH)
    assert period_bounds(date.fromisoformat(expected), frequency)[0].isoformat() == key


@pytest.mark.parametrize("frequency", ["daily", "daily2", "weekly_wed", "weekly_fri", "weekly", "monthly", "three_day"])
def test_cross_launch_range_matches_clipped_and_disjoint_queries(frequency):
    item = point(frequency)
    full = missing(item, frequency=frequency)
    clipped = missing(item, begin="2026-11-16", frequency=frequency)
    assert full == clipped
    disjoint = sum((missing(item, begin=f"2026-11-{day:02}", end=f"2026-11-{day:02}",
                    now=local("2026-12-01"), frequency=frequency) for day in range(1, 31)), [])
    assert sorted((row["due_date"], row["slot"]) for row in full) == sorted(
        (row["due_date"], row["slot"]) for row in disjoint)
    assert all(row["due_date"] >= LAUNCH for row in full)


@pytest.mark.parametrize("frequency,cutoff,end", [
    ("weekly", date(2026, 11, 21), "2026-11-22"),
    ("three_day", date(2026, 11, 14), "2026-11-15"),
    ("monthly", date(2026, 10, 31), "2026-10-31"),
])
def test_prelaunch_workdays_cannot_make_an_all_exempt_remaining_period_missed(frequency, cutoff, end):
    item = point(frequency)
    begin = period_bounds(date.fromisoformat(end), frequency)[0].isoformat()
    options = dict(begin=begin, end=end, frequency=frequency, calendar_policy_start=None)
    assert len(missing(item, count_from=None, **options)) == 1
    assert missing(item, count_from=cutoff, **options) == []
    assert not missed_period_required(date.fromisoformat(end), frequency, "general", count_from=cutoff,
                                      calendar_policy_start=None)
    assert len(missing(item, count_from=cutoff, respect_calendar=False, **options)) == 1
    assert missed_period_required(date.fromisoformat(end), frequency, "general", count_from=cutoff,
                                  respect_calendar=False, calendar_policy_start=None)


def test_monthly_safety_leave_after_launch_does_not_count_prior_workdays():
    leave = {date(2026, 11, day) for day in range(16, 31)}
    safety = point("monthly", "safety", "standard")
    assert len(missing(safety, count_from=None, safety_leave_dates=leave)) == 1
    assert missing(safety, safety_leave_dates=leave) == []
    assert not missed_period_required(date(2026, 11, 30), "monthly", "safety", count_from=LAUNCH,
                                      safety_leave_dates=leave)
    assert len(missing(point("monthly"), safety_leave_dates=leave)) == 1


@pytest.mark.parametrize("frequency,day", [("daily", "2026-12-25"), ("daily2", "2026-12-25"),
    ("weekly_fri", "2026-12-25"), ("weekly_wed", "2027-06-09")])
def test_public_holidays_remain_exempt_after_launch(frequency, day):
    assert missing(point(frequency), begin=day, end=day) == []
    assert not missed_period_required(date.fromisoformat(day), frequency, "general", count_from=LAUNCH)


@pytest.mark.parametrize("frequency,cutoff,day,key", [
    ("monthly", LAUNCH, "2026-11-30", "2026-11-01"),
    ("weekly", date(2026, 11, 18), "2026-11-22", "2026-11-16"),
    ("three_day", date(2026, 11, 17), "2026-11-18", "2026-11-16"),
])
def test_same_period_completion_before_launch_remains_valid_without_rewriting_evidence(frequency, cutoff, day, key):
    item = point(frequency, mode="two_stage")
    completion = {"point_id": 1, "frequency": frequency, "period_key": key, "slot": "any",
        "workflow_mode": "two_stage", "personal_day": date.fromisoformat(key), "note": "Existing evidence"}
    before_item, before_record = deepcopy(item), deepcopy(completion)
    assert missing(item, end=day, count_from=cutoff, completions=[completion]) == []
    assert item == before_item and completion == before_record
    row, = missing(item, end=day, count_from=cutoff)
    assert row["period_key"] == key


def test_executor_visits_do_not_complete_required_inspection_and_stage_is_preserved():
    item = point("daily", mode="two_stage")
    visit = dict(point_id=1, frequency="daily", period_key="2026-11-16", slot="any",
                 workflow_mode="spot", executor_visit=True)
    row, = missing(item, end="2026-11-16", completions=[visit], two_stage_only=True)
    assert row["missing_stage_label"] == "未執行"
    first = (1, "daily", "2026-11-16", "any", "two_stage")
    row, = missing(item, end="2026-11-16", completions=[visit], executions=[first], two_stage_only=True)
    assert row["missing_stage_label"] == "已執行、未巡檢"
    assert missing(item, end="2026-11-16", completions=[visit, first], executions=[first]) == []


def test_slot_plan_obligation_start_excludes_prestart_workdays_without_reanchoring_period():
    item = point("weekly")
    day = date(2026, 11, 22)
    timeline = schedule_timeline(item)
    assert len(list(slot_plans(item, day, timeline, for_missed=True))) == 1
    assert list(slot_plans(item, day, timeline, for_missed=True, obligation_start=date(2026, 11, 21))) == []
    plan, = slot_plans(item, day, timeline, for_missed=True, obligation_start=date(2026, 11, 20))
    assert plan[0]["frequency"] == "weekly" and plan[2] == local("2026-11-23")
    assert period_bounds(day, "weekly")[0] == date(2026, 11, 16)


def test_helper_rejects_prelaunch_period_and_fixed_offday_even_without_calendar():
    assert not missed_period_required(date(2026, 11, 15), "weekly", "general", count_from=LAUNCH,
                                      respect_calendar=False)
    assert not missed_period_required(date(2026, 11, 17), "weekly_wed", "general", count_from=LAUNCH,
                                      respect_calendar=False)
    assert not missed_period_required(LAUNCH, "irregular", "general", count_from=LAUNCH)
    assert missed_period_required(LAUNCH, "daily", "general", count_from=LAUNCH)


@pytest.mark.parametrize("invalid", ["2026-11-16", datetime(2026, 11, 16), local("2026-11-16"), 20261116, True])
def test_start_dates_require_date_values_not_strings_datetimes_or_numbers(invalid):
    item = point()
    with pytest.raises(ValueError, match="count_from"):
        missing(item, end="2026-11-15", count_from=invalid)
    with pytest.raises(ValueError, match="count_from"):
        missed_period_required(LAUNCH, "daily", "general", count_from=invalid)
    with pytest.raises(ValueError, match="obligation_start"):
        list(slot_plans(item, LAUNCH, schedule_timeline(item), obligation_start=invalid))
