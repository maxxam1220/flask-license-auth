"""Taipei patrol obligations; these exclusions never prohibit voluntary attendance.

The holiday resource contains official DGPA data, not a calculated lunar calendar.
Future years outside its published coverage remain explicit to callers through
``has_calendar_year`` so report pages can request an updated calendar.
"""
from datetime import date, timedelta
import json
from pathlib import Path


CALENDAR_POLICY_START = date(2026, 11, 13)
FIXED_WEEKDAYS = {"weekly_wed": 2, "weekly_fri": 4}
FIXED_FREQUENCIES = frozenset(FIXED_WEEKDAYS)
_RESOURCE = json.loads((Path(__file__).parent / "data/taiwan_holidays.json").read_text(encoding="utf-8"))
CALENDAR_YEARS = tuple(sorted(int(year) for year in _RESOURCE["years"]))
CALENDAR_COVERAGE_END = date(max(CALENDAR_YEARS), 12, 31)
HOLIDAY_NAMES = {date.fromisoformat(day): name
                 for year in _RESOURCE["years"].values() for day, name in year["weekday_holidays"].items()}


def fixed_weekday(frequency):
    return FIXED_WEEKDAYS.get(frequency)


def is_fixed_schedule_day(day, frequency):
    weekday = fixed_weekday(frequency)
    return weekday is None or day.weekday() == weekday


def has_calendar_year(day):
    return day.year in CALENDAR_YEARS


def exclusion_reason(day, category, safety_leave_dates=(), *, policy_start=CALENDAR_POLICY_START):
    """Return an obligation exclusion; leave affects the safety team only.

    Explicit leave dates may precede policy_start, as users can correct a missed
    leave declaration. Automatic weekend/holiday changes never rewrite dates
    before the policy's effective day.
    """
    if category == "safety" and (day in safety_leave_dates or day.isoformat() in safety_leave_dates):
        return "職安請休"
    if category not in ("safety", "general") or (policy_start is not None and day < policy_start):
        return ""
    if day.weekday() >= 5:
        return "週末"
    return HOLIDAY_NAMES.get(day, "")


def is_excluded_day(day, category, safety_leave_dates=(), *, policy_start=CALENDAR_POLICY_START):
    return bool(exclusion_reason(day, category, safety_leave_dates, policy_start=policy_start))


def obligation_required(start, end, category, safety_leave_dates=(), *, policy_start=CALENDAR_POLICY_START):
    """A flexible multi-day period is exempt only when every possible day is exempt."""
    day = start
    while day <= end:
        if not is_excluded_day(day, category, safety_leave_dates, policy_start=policy_start):
            return True
        day += timedelta(days=1)
    return False
