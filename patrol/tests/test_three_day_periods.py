"""Fixed calendar obligations for the three-day patrol frequency."""
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from general_workflow import execution_deadline, execution_review_status
from missed import TAIPEI, calculate_missed, period_bounds, schedule_timeline, slot_plans


def local(day, hour=0, minute=0, second=0):
    return datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(
        hour=hour, minute=minute, second=second)


def point(*, start="2026-11-10", history=True, mode="spot"):
    def snapshot(day, frequency, ident):
        return SimpleNamespace(id=ident, effective_date=date.fromisoformat(day), active=True,
                               frequency=frequency, workflow_mode=mode, category="general",
                               legacy_unscheduled=False)
    return SimpleNamespace(id=1, code="1F-G011", name="Fixture stop", floor=1,
                           category="general", active=True, frequency="three_day",
                           workflow_mode=mode, created_at=local("2026-01-01"),
                           schedule_start=date(2026, 1, 1) if history else date.fromisoformat(start),
                           schedules=([snapshot("2026-01-01", "irregular", 1)] if history else [])
                           + [snapshot(start, "three_day", 2)])


def missed(current, *, begin="2026-11-01", end="2026-11-30", now="2026-12-01", frequency="", completions=(), executions=()):
    return calculate_missed([current], completions, date.fromisoformat(begin), date.fromisoformat(end),
                            local(now), frequency=frequency, executions=executions)


@pytest.mark.parametrize("day,start,end", [
    ("2026-11-10", "2026-11-10", "2026-11-12"),
    ("2026-11-11", "2026-11-10", "2026-11-12"),
    ("2026-11-12", "2026-11-10", "2026-11-12"),
    ("2026-11-13", "2026-11-13", "2026-11-15"),
    ("2026-11-30", "2026-11-28", "2026-11-30"),
    ("2026-12-01", "2026-12-01", "2026-12-03"),
    ("2026-12-31", "2026-12-31", "2027-01-02"),
    ("2027-01-01", "2026-12-31", "2027-01-02"),
    ("2028-02-29", "2028-02-27", "2028-02-29"),
    ("2028-03-01", "2028-03-01", "2028-03-03"),
    ("0001-01-01", "0001-01-01", "0001-01-03"),
    ("9999-12-31", "9999-12-29", "9999-12-31"),
])
def test_fixed_periods_cross_month_year_leap_day_and_supported_date_limits(day, start, end):
    assert period_bounds(date.fromisoformat(day), "three_day") == (date.fromisoformat(start), date.fromisoformat(end))


@pytest.mark.parametrize("instant", [local("2026-11-10"), local("2026-11-11"), local("2026-11-12", 23, 59, 59)])
def test_no_missed_before_exclusive_third_day_deadline(instant):
    assert calculate_missed([point()], [], date(2026, 11, 1), date(2026, 11, 12), instant) == []


def test_first_overdue_cycle_begins_at_taipei_midnight_with_one_obligation():
    rows = missed(point(), end="2026-11-12", now="2026-11-13")
    assert len(rows) == 1
    row = rows[0]
    assert (row["period_key"], row["due_date"], row["period_label"], row["slot"]) == (
        "2026-11-10", date(2026, 11, 12), "2026-11-10 – 2026-11-12", "any")
    assert row["deadline"] == datetime(2026, 11, 12, 16, tzinfo=timezone.utc)


def test_filtered_and_unfiltered_queries_count_only_expired_cycles_not_prior_optional_days():
    all_rows = missed(point())
    filtered = missed(point(), frequency="three_day")
    assert all_rows == filtered
    assert [row["due_date"].day for row in all_rows] == [30, 27, 24, 21, 18, 15, 12]
    # Disjoint due-date ranges add up to the same result, even if selected range
    # begins inside a cycle rather than on its first day.
    separate = sum(len(missed(point(), begin=f"2026-11-{day:02}", end=f"2026-11-{day:02}", frequency="three_day"))
                   for day in range(1, 31))
    assert separate == len(all_rows)


def test_new_point_midcycle_never_acquires_an_obligation_before_creation_or_effective_date():
    current = point(start="2026-11-17", history=False)
    current.created_at = local("2026-11-17", 8)
    assert missed(current, end="2026-11-15") == []
    row, = missed(current, end="2026-11-18", frequency="three_day")
    assert row["period_key"] == "2026-11-16" and row["due_date"] == date(2026, 11, 18)


def test_one_inspector_completion_satisfies_cycle_but_old_frequency_and_executor_visit_do_not():
    original = dict(point_id=1, frequency="irregular", period_key="2026-11-10", slot="any", workflow_mode="spot")
    visit = original | {"frequency": "three_day", "executor_visit": True}
    assert len(missed(point(), end="2026-11-12", completions=[original, visit])) == 1
    completion = visit | {"executor_visit": False}
    assert missed(point(), end="2026-11-12", completions=[original, visit, completion, completion]) == []


def test_missing_first_stage_and_missing_inspection_remain_distinct():
    current = point(mode="two_stage")
    row, = missed(current, end="2026-11-12")
    assert row["missing_stage_label"] == "未執行"
    row, = missed(current, end="2026-11-12", executions=[(1, "three_day", "2026-11-10", "any", "two_stage")])
    assert row["missing_stage_label"] == "已執行、未巡檢"


def test_only_three_day_view_contains_three_day_plan():
    current = point()
    timeline = schedule_timeline(current)
    assert len(list(slot_plans(current, date(2026, 11, 11), timeline, view="three_day"))) == 1
    assert list(slot_plans(current, date(2026, 11, 11), timeline, view="daily")) == []
    assert list(slot_plans(current, date(2026, 11, 11), timeline, view="weekly")) == []


def test_execution_deadline_is_end_of_three_day_period_and_rejects_noncanonical_key():
    deadline = local("2026-11-13")
    assert execution_deadline("three_day", "2026-11-10", "any") == deadline
    assert execution_deadline("three_day", "2026-11-11", "any") is None
    assert execution_deadline("three_day", "2026-11-10", "am") is None
    assert execution_review_status("three_day", "2026-11-10", "any", False, deadline - timedelta(microseconds=1)) == "pending"
    assert execution_review_status("three_day", "2026-11-10", "any", False, deadline) == "expired"
