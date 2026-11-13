"""Fixed weekday obligations, official holidays, and date-only safety leave."""
from datetime import date, datetime, timedelta
from types import SimpleNamespace

import pytest

from general_workflow import execution_deadline, execution_review_status
from missed import TAIPEI, calculate_missed, period_bounds, schedule_timeline, slot_plans
from patrol_calendar import (CALENDAR_COVERAGE_END, CALENDAR_YEARS, HOLIDAY_NAMES,
                             exclusion_reason, has_calendar_year, is_excluded_day,
                             is_fixed_schedule_day, obligation_required)


def local(day, hour=0):
    return datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(hour=hour)


def point(frequency="daily", category="general", mode="spot", start="2026-11-01", **extra):
    snap = SimpleNamespace(id=1, effective_date=date.fromisoformat(start), frequency=frequency,
                           category=category, workflow_mode=mode, active=True)
    result = dict(id=1, frequency=frequency, category=category, workflow_mode=mode, active=True,
                  code="B1-G001", name="Fixture", floor=-1, schedule_start=date.fromisoformat(start),
                  created_at=local(start), schedules=[snap])
    result.update(extra)
    return SimpleNamespace(**result)


def missed(item, begin, end=None, *, now=None, completions=(), **kwargs):
    end = end or begin
    return calculate_missed([item], completions, date.fromisoformat(begin), date.fromisoformat(end),
                            local(now or (date.fromisoformat(end) + timedelta(days=1)).isoformat()), **kwargs)


@pytest.mark.parametrize("frequency,day", [("weekly_wed", "2026-11-18"), ("weekly_fri", "2026-11-20")])
def test_fixed_days_expire_at_following_midnight_and_use_actual_date_key(frequency, day):
    item = point(frequency)
    assert missed(item, day, now=day) == []
    row, = missed(item, day)
    assert row["period_key"] == day and row["period_label"] == day
    assert row["deadline"] == execution_deadline(frequency, day, "any")
    assert execution_review_status(frequency, day, "any", False, row["deadline"]) == "expired"
    assert execution_review_status(frequency, day, "any", True, row["deadline"]) == "done"


@pytest.mark.parametrize("frequency", ["weekly_wed", "weekly_fri"])
def test_offday_visits_have_their_own_day_and_cannot_complete_fixed_day(frequency):
    item = point(frequency)
    day = "2026-11-18" if frequency == "weekly_wed" else "2026-11-20"
    offday = "2026-11-17"
    assert period_bounds(date.fromisoformat(offday), frequency) == (date.fromisoformat(offday),) * 2
    completion = (1, frequency, offday, "any", "spot")
    assert len(missed(item, day, completions=[completion])) == 1
    assert missed(item, day, completions=[(1, frequency, day, "any", "spot")]) == []
    assert missed(item, offday) == []
    assert execution_deadline(frequency, offday, "am") is None


@pytest.mark.parametrize("frequency,weekday", [("weekly_wed", 2), ("weekly_fri", 4)])
def test_fixed_filter_aligns_after_midweek_range_start_and_disjoint_ranges(frequency, weekday):
    item = point(frequency)
    begin, end = date(2026, 11, 19), date(2026, 12, 5)
    rows = missed(item, begin.isoformat(), end.isoformat(), frequency=frequency)
    assert all(begin <= row["due_date"] <= end and row["due_date"].weekday() == weekday for row in rows)
    assert rows == missed(item, begin.isoformat(), end.isoformat())
    parts = sum((missed(item, (begin + timedelta(days=i)).isoformat(), frequency=frequency)
                 for i in range((end - begin).days + 1)), [])
    assert len(parts) == len(rows)


def test_weekly_all_filter_includes_three_types_without_losing_wednesday_or_friday():
    points = [point("weekly", id=1), point("weekly_wed", id=2), point("weekly_fri", id=3)]
    args = (points, [], date(2026, 11, 16), date(2026, 11, 22), local("2026-11-23"))
    rows = calculate_missed(*args, frequency="weekly_all")
    assert [(r["frequency"], r["due_date"].day) for r in rows] == [("weekly", 22), ("weekly_fri", 20), ("weekly_wed", 18)]
    assert len(calculate_missed(*args, frequency="weekly")) == 1


@pytest.mark.parametrize("category", ["safety", "general"])
@pytest.mark.parametrize("frequency", ["daily", "daily2"])
def test_weekends_removed_for_all_scheduled_roles_after_policy(category, frequency):
    assert missed(point(frequency, category), "2026-11-14", "2026-11-15") == []
    rows = missed(point(frequency, category), "2026-11-13", "2026-11-16")
    assert {r["due_date"] for r in rows} == {date(2026, 11, 13), date(2026, 11, 16)}
    assert len(rows) == (4 if frequency == "daily2" else 2)


def test_policy_does_not_rewrite_previous_weekend_obligations():
    assert len(missed(point(), "2026-11-07", "2026-11-08")) == 2
    assert len(missed(point(), "2026-11-14", "2026-11-15", respect_calendar=False)) == 2
    assert not is_excluded_day(date(2026, 11, 14), "uncategorized")


def test_official_holiday_data_contains_complete_year_metadata_and_observed_dates():
    assert CALENDAR_YEARS == (2026, 2027)
    assert CALENDAR_COVERAGE_END == date(2027, 12, 31)
    assert HOLIDAY_NAMES[date(2026, 12, 25)] == "行憲紀念日"
    assert HOLIDAY_NAMES[date(2027, 6, 9)] == "端午節"
    assert HOLIDAY_NAMES[date(2027, 12, 24)] == "補假"
    assert HOLIDAY_NAMES[date(2027, 12, 31)] == "補假"
    assert has_calendar_year(date(2027, 12, 31))
    assert not has_calendar_year(date(2028, 1, 1))


@pytest.mark.parametrize("frequency,day", [("weekly_fri", "2026-12-25"), ("weekly_wed", "2027-06-09"),
                                           ("weekly_fri", "2027-12-24"), ("weekly_fri", "2027-12-31")])
def test_fixed_day_holiday_skips_that_week_without_rescheduling(frequency, day):
    item = point(frequency)
    assert missed(item, day, (date.fromisoformat(day) + timedelta(days=6)).isoformat()) == []
    assert list(slot_plans(item, date.fromisoformat(day), schedule_timeline(item), view="weekly")) == []


def test_flexible_weekly_sunday_deadline_is_not_automatically_exempt():
    row, = missed(point("weekly"), "2026-11-22")
    assert row["period_key"] == "2026-11-16"
    # Fri is a holiday and Sat/Sun are weekends, but Mon-Thu are still valid.
    assert len(missed(point("weekly"), "2026-12-27")) == 1


def test_rename_on_weekend_does_not_remove_flexible_weekly_obligation():
    item = point("weekly")
    item.schedules.append(SimpleNamespace(id=2, effective_date=date(2026, 11, 22), frequency="weekly",
                                         category="general", workflow_mode="spot", active=True,
                                         point_name="Renamed"))
    row, = missed(item, "2026-11-22")
    assert row["name"] == "Renamed"


def test_new_period_cannot_count_workdays_before_creation_or_frequency_change():
    item = point("three_day", start="2026-11-14")
    assert missed(item, "2026-11-15") == []  # only Sat and Sun were available
    changed = point("weekly")
    changed.schedules[0].frequency = "daily"
    changed.schedules.append(SimpleNamespace(id=2, effective_date=date(2026, 11, 21), frequency="weekly",
                                            category="general", workflow_mode="spot", active=True))
    assert missed(changed, "2026-11-22") == []


def test_flexible_period_exemption_requires_every_possible_day_to_be_exempt():
    days = frozenset(date(2026, 11, d) for d in range(16, 21))
    assert not obligation_required(date(2026, 11, 16), date(2026, 11, 22), "safety", days)
    assert obligation_required(date(2026, 11, 16), date(2026, 11, 22), "general", days)
    assert missed(point("weekly", "safety"), "2026-11-22", safety_leave_dates=days) == []
    assert len(missed(point("weekly", "safety"), "2026-11-22", safety_leave_dates={date(2026, 11, 20)})) == 1


def test_safety_leave_only_excludes_its_team_and_can_correct_an_earlier_date():
    day = date(2026, 11, 12)
    assert exclusion_reason(day, "safety", {day}) == "職安請休"
    assert missed(point("daily2", "safety"), day.isoformat(), safety_leave_dates={day}) == []
    assert len(missed(point("daily2", "general"), day.isoformat(), safety_leave_dates={day})) == 2
    assert exclusion_reason(day, "safety", {day.isoformat()}) == "職安請休"


def test_two_stage_fixed_day_missing_status_respects_same_date_execution():
    item = point("weekly_wed", mode="two_stage")
    row, = missed(item, "2026-11-18", executions=[(1, "weekly_wed", "2026-11-17", "any", "two_stage")])
    assert row["missing_stage_label"] == "未執行"
    row, = missed(item, "2026-11-18", executions=[(1, "weekly_wed", "2026-11-18", "any", "two_stage")])
    assert row["missing_stage_label"] == "已執行、未巡檢"


def test_fixed_schedule_plan_only_appears_on_its_weekday():
    item = point("weekly_wed")
    for day in range(16, 23):
        plans = list(slot_plans(item, date(2026, 11, day), schedule_timeline(item), view="weekly"))
        assert bool(plans) == (day == 18)
        assert is_fixed_schedule_day(date(2026, 11, day), "weekly_wed") == (day == 18)


@pytest.mark.parametrize("shown,visible", [("2026-11-03", True), ("2026-12-24", True),
                                         ("2026-12-25", False), ("2026-12-26", False)])
def test_future_start_retains_overview_placeholder_but_never_creates_missed(shown, visible):
    item = point("daily2", "safety", mode="standard")
    item.schedule_start = date(2026, 12, 28)
    day = date.fromisoformat(shown)
    timeline = schedule_timeline(item)
    assert bool(list(slot_plans(item, day, timeline, view="daily"))) is visible
    assert list(slot_plans(item, day, timeline, for_missed=True)) == []
    assert missed(item, shown) == []
