"""Pure, historical calculation of expired, uncompleted patrol obligations.

The selected dates mean *due dates*: a daily slot is due on its patrol day,
a weekly slot on Sunday, and a monthly slot on the last Taipei calendar day.
At the exclusive deadline (noon or the following midnight) it becomes overdue.

Callers must preload point.schedules and supply completions for every user,
starting at the earliest overlapping week or month start. Ordinary schedule
changes apply to the whole effective date. A deletion records its precise
instant so obligations already overdue that day can still be reported.
"""
from bisect import bisect_right
from calendar import monthrange
from collections.abc import Mapping
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from domain import CATEGORY_OPTIONS, FLOOR_ORDER

TAIPEI = ZoneInfo("Asia/Taipei")
VIEW_FREQUENCIES = {"daily": ("daily", "daily2"), "weekly": ("weekly",), "monthly": ("monthly",)}
FREQUENCIES = {"daily", "daily2", "weekly", "monthly", "irregular"}


def period_bounds(day, view):
    if view == "monthly":
        return day.replace(day=1), day.replace(day=monthrange(day.year, day.month)[1])
    if view == "weekly":
        monday = day - timedelta(days=day.weekday())
        return monday, monday + timedelta(days=6)
    return day, day


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
        if _value(item, "legacy_unscheduled", False):
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


def _snapshot(point, schedule):
    def historical(field, fallback):
        value = _value(schedule, field) if schedule is not None else None
        return fallback if value is None else value

    return {
        "point_id": _value(point, "id"),
        "code": historical("point_code", _value(point, "code")),
        "name": historical("point_name", _value(point, "name")),
        "floor": historical("floor", _value(point, "floor")),
        "category": historical("category", _value(point, "category", "uncategorized")),
        "frequency": historical("frequency", _value(point, "frequency")),
        # Schedules from before workflows were introduced represent the original rules.
        "workflow_mode": _value(schedule if schedule is not None else point, "workflow_mode", "standard") or "standard",
        "legacy_unscheduled": bool(_value(schedule, "legacy_unscheduled", False)),
        "active": historical("active", _value(point, "active", True)),
    }


def slot_plans(point, day, timeline, *, for_missed=False, view="daily"):
    """Yield the schedule binding each slot immediately before its Taipei deadline."""
    dates, schedules = timeline
    last = bisect_right(dates, day) - 1
    next_midnight = datetime.combine(day + timedelta(days=1), time.min, TAIPEI)
    for morning, deadline in ((True, datetime.combine(day, time(12), TAIPEI)), (False, next_midnight)):
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
        if for_missed:
            # An ordinary disable applies the whole day. A retirement instead
            # preserves obligations that expired before the point was retired,
            # also after a subsequent inactive rename/restore on the same day.
            while index > 0 and dates[index] == day and not _value(schedules[index], "active", True):
                retired = _value(schedules[index], "retired_at")
                if retired is not None:
                    if deadline > _utc(retired):
                        break
                    schedule = schedules[index - 1]
                index -= 1
        snapshot = _snapshot(point, schedule)
        frequency = snapshot["frequency"]
        if not snapshot["active"] or snapshot["legacy_unscheduled"] or frequency not in FREQUENCIES or frequency == "irregular":
            continue
        if morning and frequency != "daily2":
            continue
        if for_missed and day != period_bounds(day, frequency)[1]:
            continue
        if not for_missed and frequency not in VIEW_FREQUENCIES[view]:
            continue
        slot = ("am" if morning else "pm") if frequency == "daily2" else "any"
        yield snapshot, slot, deadline


def calculate_missed(points, completions, date_from, date_to, now, *, category="", floor=None, frequency="",
                     executions=(), two_stage_only=False):
    """Return expired missing occurrences as plain dicts, newest deadline first.

    The inputs may be preloaded ORM objects or attribute/mapping-based fixtures;
    completion entries may alternatively be (point_id, frequency, period_key,
    slot) tuples. Completion identity deliberately ignores employee and location
    snapshots: any person's completion satisfies that point's obligation.

    Filtering happens after historical schedule selection. Never prefilter
    points or completion rows by their current category/floor or by employee.
    A deadline at or before Point.created_at is excluded, so a newly created
    afternoon point does not acquire a fabricated missed morning obligation.
    """
    if not isinstance(date_from, date) or isinstance(date_from, datetime) or not isinstance(date_to, date) or isinstance(date_to, datetime):
        raise ValueError("date_from and date_to must be dates")
    if date_from > date_to:
        raise ValueError("date_from must not be after date_to")
    if not isinstance(now, datetime):
        raise ValueError("now must be a datetime")
    if category not in ("", None) and category not in dict(CATEGORY_OPTIONS):
        raise ValueError("Unknown category filter")
    if frequency not in ("", None, "daily_all") and frequency not in FREQUENCIES:
        raise ValueError("Unknown frequency filter")
    if floor not in (None, ""):
        if str(floor) not in {str(value) for value in FLOOR_ORDER}:
            raise ValueError("Unknown floor filter")
        floor = int(floor)
    else:
        floor = None

    instant = _utc(now)
    last_due_day = min(date_to, instant.astimezone(TAIPEI).date())
    # A scheduled completion survives same-period plan edits. Several qualifying
    # inspections by one or more people still satisfy just one team obligation.
    completed = {key[:4] for key in _completion_keys(completions)}
    executed = _completion_keys(executions, "two_stage")
    occurrences = []
    seen_points = set()
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
        due_day = first_due_day
        while due_day <= last_due_day:
            for snapshot, slot, local_deadline in slot_plans(point, due_day, timeline, for_missed=True):
                period_frequency, mode = snapshot["frequency"], snapshot["workflow_mode"]
                if ((two_stage_only and mode != "two_stage")
                        or (category and snapshot["category"] != category)
                        or (floor is not None and snapshot["floor"] != floor)
                        or (frequency and period_frequency != frequency
                            and not (frequency == "daily_all" and period_frequency in ("daily", "daily2")))):
                    continue
                period_start, _ = period_bounds(due_day, period_frequency)
                if period_frequency in ("weekly", "monthly"):
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
            due_day += timedelta(days=1)
    occurrences.sort(key=lambda row: (-row["deadline"].timestamp(), FLOOR_ORDER.get(row["floor"], len(FLOOR_ORDER)),
                                      row["code"], row["point_id"], row["slot"]))
    return occurrences
