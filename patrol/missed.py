"""Pure, historical calculation of expired, uncompleted patrol obligations.

The selected dates mean *due dates*: a daily slot is due on its patrol day,
a three-day slot on its third day, a weekly slot on Sunday, and a monthly
slot on the last Taipei calendar day.
At the exclusive deadline it becomes overdue. Both daily rounds now end at
midnight; dates before the policy change retain their original noon deadline.

Callers must preload point.schedules and supply completions for every user,
starting at the earliest overlapping three-day, week or month start. Ordinary schedule
changes apply to the whole effective date. A deletion records its precise
instant so obligations already overdue that day can still be reported.
"""
from bisect import bisect_right
from calendar import monthrange
from collections.abc import Mapping
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from domain import CATEGORY_OPTIONS, FLOOR_ORDER
from daily_rounds import daily2_anytime
from patrol_calendar import (CALENDAR_POLICY_START, FIXED_FREQUENCIES, fixed_weekday,
                             is_fixed_schedule_day, obligation_required)

TAIPEI = ZoneInfo("Asia/Taipei")
THREE_DAY_ANCHOR = date(2026, 11, 10)
VIEW_FREQUENCIES = {"daily": ("daily", "daily2"), "three_day": ("three_day",),
                    "weekly": ("weekly", "weekly_wed", "weekly_fri"), "monthly": ("monthly",),
                    "weekly_wed": ("weekly_wed",), "weekly_fri": ("weekly_fri",)}
FREQUENCIES = {"daily", "daily2", "three_day", "weekly", "monthly", "irregular", *FIXED_FREQUENCIES}


def period_bounds(day, view):
    # Fixed-weekday points use the actual attendance day. An optional visit on
    # another day cannot satisfy Wednesday/Friday or unlock a different day's
    # second stage, even though reports group them under the weekly tab.
    if view in FIXED_FREQUENCIES:
        return day, day
    if view == "three_day":
        # One shared calendar, not a rolling deadline from each person's visit.
        # This anchor also aligns with date.min, so the supported date range
        # never needs an out-of-range start date or a truncated first period.
        start = day - timedelta(days=(day - THREE_DAY_ANCHOR).days % 3)
        return start, start + timedelta(days=2)
    if view == "monthly":
        return day.replace(day=1), day.replace(day=monthrange(day.year, day.month)[1])
    if view == "weekly":
        monday = day - timedelta(days=day.weekday())
        return monday, monday + timedelta(days=6)
    return day, day


def _optional_date(value, name):
    if value is not None and (not isinstance(value, date) or isinstance(value, datetime)):
        raise ValueError(f"{name} must be a date or None")
    return value


def missed_period_required(day, frequency, category, *, count_from=None, safety_leave_dates=(),
                           respect_calendar=True, calendar_policy_start=CALENDAR_POLICY_START):
    """Whether this period has an obligation on/after the missed-count start.

    This does not determine whether its deadline has passed. Attendance retains
    its original period identity, including any completion before count_from.
    """
    _optional_date(count_from, "count_from")
    if frequency == "irregular" or not is_fixed_schedule_day(day, frequency):
        return False
    start, end = period_bounds(day, frequency)
    if count_from is not None:
        start = max(start, count_from)
    if start > end:
        return False
    return (not respect_calendar or obligation_required(start, end, category, safety_leave_dates,
                                                        policy_start=calendar_policy_start))


def _value(item, name, default=None):
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _utc(instant):
    # Database timestamps are UTC without tzinfo; aware inputs may use any zone.
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def _completion_keys(completions, default_mode="standard"):
    keys = set()
    for item in completions:
        if _value(item, "legacy_unscheduled", False) or _value(item, "executor_visit", False):
            continue
        if isinstance(item, (tuple, list)) and not hasattr(item, "point_id"):
            point_id, frequency, period_key, slot, *modes = item
            mode = modes[0] if modes else default_mode
        else:
            point_id = _value(item, "point_id")
            frequency = _value(item, "frequency")
            period_key = _value(item, "period_key")
            slot = _value(item, "slot", "any")
            mode = _value(item, "workflow_mode", default_mode)
        if isinstance(period_key, date):
            period_key = period_key.isoformat()
        keys.add((point_id, frequency, period_key, slot or "any", mode or default_mode))
    return keys


def schedule_timeline(point):
    schedules = list(_value(point, "schedules", ()) or ())
    ordered = sorted(enumerate(schedules), key=lambda pair: (
        _value(pair[1], "effective_date"), _value(pair[1], "id") or 0, pair[0]))
    schedules = [schedule for _, schedule in ordered]
    return [_value(schedule, "effective_date") for schedule in schedules], schedules


def schedule_snapshot(point, schedule):
    def historical(field, fallback):
        value = _value(schedule, field) if schedule is not None else None
        return fallback if value is None else value

    point_id = _value(point, "id")
    current_category = _value(point, "category", "uncategorized")
    category = historical("category", current_category)
    same_category = category == current_category
    return {
        "point_id": point_id,
        "code": historical("point_code", _value(point, "code") if same_category else f"#{point_id}"),
        "name": historical("point_name", _value(point, "name") if same_category else "歷史巡檢點"),
        "floor": historical("floor", _value(point, "floor") if same_category else None),
        "category": category,
        "frequency": historical("frequency", _value(point, "frequency")),
        # Schedules from before workflows were introduced represent the original rules.
        "workflow_mode": _value(schedule if schedule is not None else point, "workflow_mode", "standard") or "standard",
        "legacy_unscheduled": bool(_value(schedule, "legacy_unscheduled", False)),
        "active": historical("active", _value(point, "active", True)),
    }


def slot_plans(point, day, timeline, *, for_missed=False, view="daily", respect_calendar=True,
               safety_leave_dates=(), calendar_policy_start=CALENDAR_POLICY_START, obligation_start=None):
    """Yield the schedule binding each slot immediately before its Taipei deadline."""
    _optional_date(obligation_start, "obligation_start")
    dates, schedules = timeline
    last = bisect_right(dates, day) - 1
    if schedules and last < 0:
        # A later snapshot cannot tell which team or plan owned an earlier gap.
        return
    next_midnight = datetime.combine(day + timedelta(days=1), time.min, TAIPEI)
    first_deadline = next_midnight if daily2_anytime(day) else datetime.combine(day, time(12), TAIPEI)
    for morning, deadline in ((True, first_deadline), (False, next_midnight)):
        index = last
        # Rewind any workflow change after (or exactly at) this expiry. Ordinary
        # renames made later the same day cannot override the pre-change snapshot.
        for j in range(last, -1, -1):
            if dates[j] != day:
                break
            changed = _value(schedules[j], "workflow_changed_at")
            if changed is not None and _utc(changed) >= deadline:
                index = j - 1
        if index < 0 <= last:
            continue
        schedule = schedules[index] if index >= 0 else None
        # Retirement preserves already-expired slots on both the report and the
        # dashboard, even after an inactive rename/restore later the same day.
        # An ordinary disable with no retirement still applies to the whole day.
        while index > 0 and dates[index] == day and not _value(schedules[index], "active", True):
            retired = _value(schedules[index], "retired_at")
            if retired is not None:
                if deadline > _utc(retired):
                    break
                schedule = schedules[index - 1]
            index -= 1
        snapshot = schedule_snapshot(point, schedule)
        frequency = snapshot["frequency"]
        if not snapshot["active"] or snapshot["legacy_unscheduled"] or frequency not in FREQUENCIES or frequency == "irregular":
            continue
        if morning and frequency != "daily2":
            continue
        if not is_fixed_schedule_day(day, frequency):
            continue
        if for_missed and day != period_bounds(day, frequency)[1]:
            continue
        if not for_missed and frequency not in VIEW_FREQUENCIES[view]:
            continue
        if respect_calendar:
            start, end = period_bounds(day, frequency)
            # Days before creation or this schedule's start cannot make an
            # otherwise fully exempt period acquire a new obligation.
            binding_start = None
            if schedule is not None:
                binding_index = next(i for i, item in enumerate(schedules) if item is schedule)
                plan_fields = ("frequency", "workflow_mode", "category", "active", "legacy_unscheduled")
                while binding_index > 0:
                    previous = schedule_snapshot(point, schedules[binding_index - 1])
                    if any(previous[field] != snapshot[field] for field in plan_fields):
                        break
                    binding_index -= 1
                binding_start = dates[binding_index]
            # A rename on Sunday must not discard the preceding working days
            # of an unchanged weekly obligation.
            starts = [start, _value(point, "schedule_start"), binding_start, obligation_start]
            created = _value(point, "created_at")
            if created is not None:
                starts.append(_utc(created).astimezone(TAIPEI).date())
            start = max(value for value in starts if value is not None)
            if not for_missed and start > end:
                # The overview retains a not-yet-due card for a point whose
                # start date is in a later period. Calendar exclusions still
                # apply to the displayed period, not to that future start.
                start = period_bounds(day, frequency)[0]
            if not obligation_required(start, end, snapshot["category"], safety_leave_dates,
                                       policy_start=calendar_policy_start):
                continue
        slot = ("am" if morning else "pm") if frequency == "daily2" else "any"
        yield snapshot, slot, deadline


def calculate_missed(points, completions, date_from, date_to, now, *, category="", floor=None, frequency="",
                     executions=(), two_stage_only=False, respect_calendar=True, safety_leave_dates=(),
                     calendar_policy_start=CALENDAR_POLICY_START, count_from=None):
    """Return expired missing occurrences as plain dicts, newest deadline first.

    The inputs may be preloaded ORM objects or attribute/mapping-based fixtures;
    completion entries may alternatively be (point_id, frequency, period_key,
    slot) tuples. Completion identity deliberately ignores employee and location
    snapshots: any person's completion satisfies that point's obligation.

    Filtering happens after historical schedule selection. Never prefilter
    points or completion rows by their current category/floor or by employee.
    A deadline at or before Point.created_at is excluded, so a newly created
    afternoon point does not acquire a fabricated missed morning obligation.
    count_from limits obligation due dates; it never alters saved period keys
    or discards an earlier completion belonging to the same period.
    """
    if not isinstance(date_from, date) or isinstance(date_from, datetime) or not isinstance(date_to, date) or isinstance(date_to, datetime):
        raise ValueError("date_from and date_to must be dates")
    if date_from > date_to:
        raise ValueError("date_from must not be after date_to")
    if not isinstance(now, datetime):
        raise ValueError("now must be a datetime")
    if category not in ("", None) and category not in dict(CATEGORY_OPTIONS):
        raise ValueError("Unknown category filter")
    if frequency not in ("", None, "daily_all", "weekly_all") and frequency not in FREQUENCIES:
        raise ValueError("Unknown frequency filter")
    if floor not in (None, ""):
        if str(floor) not in {str(value) for value in FLOOR_ORDER}:
            raise ValueError("Unknown floor filter")
        floor = int(floor)
    else:
        floor = None

    _optional_date(count_from, "count_from")
    if count_from is not None:
        date_from = max(date_from, count_from)
    instant = _utc(now)
    last_due_day = min(date_to, instant.astimezone(TAIPEI).date())
    if date_from > last_due_day or frequency == "irregular":
        return []
    # A scheduled completion survives same-period plan edits. Several qualifying
    # inspections by one or more people still satisfy just one team obligation.
    completed = {key[:4] for key in _completion_keys(completions)}
    executed = _completion_keys(executions, "two_stage")
    occurrences = []
    seen_points = set()
    day_step = timedelta(days=7 if frequency == "weekly" or frequency in FIXED_FREQUENCIES else 3 if frequency == "three_day" else 1)
    for point in points:
        point_id = _value(point, "id")
        if point_id in seen_points:
            continue
        seen_points.add(point_id)
        schedule_start = _value(point, "schedule_start")
        first_due_day = max(date_from, schedule_start) if schedule_start else date_from
        created_at = _value(point, "created_at")
        created_at = _utc(created_at) if created_at is not None else None
        timeline = schedule_timeline(point)
        # A period filter can only match its last day. Choose
        # those dates before reading historical schedules for each point.
        due_day = period_bounds(first_due_day, frequency)[1]
        if frequency in FIXED_FREQUENCIES:
            due_day += timedelta(days=(fixed_weekday(frequency) - due_day.weekday()) % 7)
        while due_day <= last_due_day:
            for snapshot, slot, local_deadline in slot_plans(point, due_day, timeline, for_missed=True,
                    respect_calendar=respect_calendar, safety_leave_dates=safety_leave_dates,
                    calendar_policy_start=calendar_policy_start, obligation_start=count_from):
                period_frequency, mode = snapshot["frequency"], snapshot["workflow_mode"]
                if ((two_stage_only and mode != "two_stage")
                        or (category and snapshot["category"] != category)
                        or (floor is not None and snapshot["floor"] != floor)
                        or (frequency and period_frequency != frequency
                            and not (frequency == "daily_all" and period_frequency in ("daily", "daily2"))
                            and not (frequency == "weekly_all" and period_frequency in VIEW_FREQUENCIES["weekly"]))):
                    continue
                period_start, _ = period_bounds(due_day, period_frequency)
                if period_frequency in ("three_day", "weekly", "monthly"):
                    period_label = f"{period_start.isoformat()} – {due_day.isoformat()}"
                else:
                    period_label = due_day.isoformat()
                period_key = period_start.isoformat()
                deadline = local_deadline.astimezone(timezone.utc)
                if deadline > instant or (created_at is not None and deadline <= created_at):
                    continue
                key = (point_id, period_frequency, period_key, slot, mode)
                if key[:4] in completed:
                    continue
                missing_stage = ""
                if mode == "two_stage":
                    missing_stage = "已執行、未巡檢" if key in executed else "未執行"
                occurrences.append({key: value for key, value in snapshot.items() if key != "active"} | {
                    "period_key": period_key, "period_label": period_label, "slot": slot,
                    "due_date": due_day, "deadline": deadline, "missing_stage_label": missing_stage,
                })
            due_day += day_step
            if frequency == "monthly":
                due_day = period_bounds(due_day, frequency)[1]
    occurrences.sort(key=lambda row: (-row["deadline"].timestamp(), FLOOR_ORDER.get(row["floor"], len(FLOOR_ORDER)),
                                      row["code"], row["point_id"], row["slot"]))
    return occurrences
