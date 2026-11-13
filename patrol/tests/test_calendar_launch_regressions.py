"""Adversarial calendar/launch cases with historical plans, cutovers and year boundaries."""
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


def snapshot(day, frequency, ident=1, *, category="general", mode="spot", active=True, **extra):
    return SimpleNamespace(id=ident, effective_date=date.fromisoformat(day), frequency=frequency,
        category=category, workflow_mode=mode, active=active, floor=1,
        point_code=f"HISTORY-{ident}", point_name=f"Historical location {ident}", **extra)


def point(frequency="weekly_fri", *, schedules=None, category="general", mode="spot", active=True):
    return SimpleNamespace(id=1, frequency=frequency, category=category, workflow_mode=mode, active=active,
        code="CURRENT-POINT", name="Current label", floor=1, created_at=datetime(2026, 1, 1),
        schedule_start=date(2026, 1, 1), schedules=schedules or [snapshot("2026-01-01", frequency, category=category, mode=mode)])


def missed(item, begin, end=None, *, now=None, **kwargs):
    end = end or begin
    return calculate_missed([item], kwargs.pop("completions", ()), date.fromisoformat(begin), date.fromisoformat(end),
        now or local((date.fromisoformat(end) + timedelta(days=1)).isoformat()), count_from=LAUNCH, **kwargs)


@pytest.mark.parametrize("frequency,day", [("daily", "2026-11-13"), ("daily2", "2026-11-13"),
    ("weekly_fri", "2026-11-13"), ("weekly", "2026-11-15"), ("three_day", "2026-11-15"),
    ("monthly", "2026-10-31")])
@pytest.mark.parametrize("calendar_enabled", [False, True])
def test_disabling_holiday_exclusions_never_disables_the_formal_launch_cutoff(frequency, day, calendar_enabled):
    item = point(frequency)
    due = date.fromisoformat(day)
    assert not missed_period_required(due, frequency, "general", count_from=LAUNCH,
                                      respect_calendar=calendar_enabled)
    assert list(slot_plans(item, due, schedule_timeline(item), for_missed=True,
        obligation_start=LAUNCH, respect_calendar=calendar_enabled)) == []
    assert missed(item, day, respect_calendar=calendar_enabled) == []


def test_consecutive_holiday_fridays_across_year_end_are_skipped_without_shift_or_offday_credit():
    item = point("weekly_fri", mode="two_stage")
    history = [
        (1, "weekly_fri", "2026-12-25", "any", "two_stage"),
        (1, "weekly_fri", "2027-01-01", "any", "two_stage"),
        (1, "weekly_fri", "2027-01-04", "any", "two_stage"),
    ]
    original = deepcopy(history)
    for frequency in ("", "weekly_all", "weekly_fri"):
        row, = missed(item, "2026-12-24", "2027-01-10", completions=history,
                       executions=history, frequency=frequency)
        assert (row["due_date"], row["period_key"], row["missing_stage_label"]) == (
            date(2027, 1, 8), "2027-01-08", "未執行")
        assert missed(item, "2026-12-24", "2027-01-07", frequency=frequency) == []
    assert missed(item, "2026-12-24", "2027-01-10", completions=history + [
        (1, "weekly_fri", "2027-01-08", "any", "two_stage")]) == []
    assert history == original


def test_observed_2027_year_end_holidays_do_not_reappear_as_shifted_friday_obligations():
    item = point("weekly_fri")
    rows = missed(item, "2027-12-17", "2027-12-31")
    assert [row["period_key"] for row in rows] == ["2027-12-17"]
    assert missed(item, "2027-12-18", "2027-12-31") == []


def test_historical_weekday_changes_and_daily_rounds_keep_their_own_due_dates_and_labels():
    history = [snapshot("2026-01-01", "weekly_wed"),
        snapshot("2026-11-19", "weekly_fri", 2, mode="two_stage"),
        snapshot("2026-11-23", "daily2", 3, mode="two_stage")]
    item = point("daily2", schedules=list(reversed(history)), mode="two_stage")
    before = deepcopy(item)
    rows = missed(item, "2026-11-01", "2026-11-23")
    assert [(row["frequency"], row["period_key"], row["slot"], row["code"]) for row in rows] == [
        ("daily2", "2026-11-23", "am", "HISTORY-3"),
        ("daily2", "2026-11-23", "pm", "HISTORY-3"),
        ("weekly_fri", "2026-11-20", "any", "HISTORY-2"),
        ("weekly_wed", "2026-11-18", "any", "HISTORY-1")]
    for frequency in ("weekly_wed", "weekly_fri", "daily2"):
        assert missed(item, "2026-11-01", "2026-11-23", frequency=frequency) == [
            row for row in rows if row["frequency"] == frequency]
    assert item == before


@pytest.mark.parametrize("new_day,expected", [("2026-11-18", ["2026-11-20"]),
                                              ("2026-11-19", ["2026-11-20", "2026-11-18"])])
def test_same_day_change_replaces_unexpired_plan_but_next_day_change_cannot_erase_old_due(new_day, expected):
    changed = local(new_day, 15).astimezone(timezone.utc).replace(tzinfo=None)
    history = [snapshot("2026-01-01", "weekly_wed"),
        snapshot(new_day, "weekly_fri", 2, workflow_changed_at=changed)]
    rows = missed(point("weekly_fri", schedules=history), "2026-11-16", "2026-11-22")
    assert [row["period_key"] for row in rows] == expected


@pytest.mark.parametrize("clock,expected", [
    (datetime(2026, 11, 20, 15, 59, 59), 0),
    (datetime(2026, 11, 20, 16), 1),
    (datetime(2026, 11, 20, 16, tzinfo=timezone.utc), 1),
    (local("2026-11-21"), 1),
])
def test_midnight_frequency_cutover_keeps_just_expired_friday_and_does_not_create_weekend_rounds(clock, expected):
    history = [snapshot("2026-01-01", "weekly_fri", mode="two_stage"),
        snapshot("2026-11-21", "daily2", 2, mode="two_stage", workflow_changed_at=datetime(2026, 11, 20, 16))]
    item = point("daily2", schedules=history, mode="two_stage")
    rows = missed(item, "2026-11-20", "2026-11-22", now=clock)
    assert len(rows) == expected
    assert all(row["period_key"] == "2026-11-20" and row["frequency"] == "weekly_fri" for row in rows)


def test_historical_safety_leave_does_not_exempt_a_later_general_weekday_plan():
    history = [snapshot("2026-01-01", "weekly_wed", category="safety", mode="standard"),
        snapshot("2026-11-19", "weekly_fri", 2)]
    item = point("weekly_fri", schedules=history)
    leave = {date(2026, 11, 18), date(2026, 11, 20)}
    row, = missed(item, "2026-11-16", "2026-11-22", safety_leave_dates=leave)
    assert (row["category"], row["frequency"], row["period_key"]) == ("general", "weekly_fri", "2026-11-20")
    assert missed(item, "2026-11-16", "2026-11-22", category="safety", safety_leave_dates=leave) == []
    assert len(missed(item, "2026-11-16", "2026-11-22")) == 2


@pytest.mark.parametrize("delete_day,expected", [("2026-11-18", 0), ("2026-11-19", 1)])
def test_retiring_before_or_at_midnight_does_not_erase_an_already_expired_fixed_day(delete_day, expected):
    retirement = local(delete_day).astimezone(timezone.utc).replace(tzinfo=None)
    history = [snapshot("2026-01-01", "weekly_wed", mode="two_stage"),
        snapshot(delete_day, "weekly_wed", 2, mode="two_stage", active=False, retired_at=retirement)]
    item = point("weekly_wed", schedules=history, mode="two_stage", active=False)
    rows = missed(item, "2026-11-16", "2026-11-25")
    assert len(rows) == expected
    assert all(row["period_key"] == "2026-11-18" for row in rows)


def test_same_month_completion_survives_launch_and_later_workflow_and_name_change():
    history = [snapshot("2026-01-01", "monthly"),
        snapshot("2026-11-20", "monthly", 2, mode="two_stage")]
    item = point("monthly", schedules=history, mode="two_stage")
    completion = dict(point_id=1, frequency="monthly", period_key="2026-11-01", slot="any",
                      workflow_mode="spot", personal_day=date(2026, 11, 4), point_name="Old name")
    original = deepcopy(completion)
    assert missed(item, "2026-11-01", "2026-11-30", completions=[completion]) == []
    row, = missed(item, "2026-11-01", "2026-11-30")
    assert row["period_key"] == "2026-11-01" and row["workflow_mode"] == "two_stage"
    assert completion == original


def test_same_day_rename_with_higher_id_cannot_shift_fixed_day_or_create_another_obligation():
    history = [snapshot("2026-01-01", "weekly_wed"),
        snapshot("2026-11-18", "weekly_wed", 3), snapshot("2026-11-18", "weekly_wed", 2)]
    item = point("weekly_wed", schedules=history)
    row, = missed(item, "2026-11-16", "2026-11-22")
    assert row["code"] == "HISTORY-3" and row["period_key"] == "2026-11-18"
    assert period_bounds(date(2026, 11, 17), "weekly_wed") == (date(2026, 11, 17),) * 2
    completion = (1, "weekly_wed", "2026-11-18", "any", "spot")
    assert missed(item, "2026-11-16", "2026-11-22", completions=[completion, completion]) == []
