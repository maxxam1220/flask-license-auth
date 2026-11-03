"""Pure, historical calculation of expired, uncompleted patrol obligations.

The selected dates mean *due dates*: a daily slot is due on its patrol day,
and a weekly slot is due on Sunday. The actual exclusive deadline is noon,
the following midnight, or the following Monday. At the deadline a missing
slot becomes overdue. A week is therefore counted once across adjacent ranges.

Callers must preload point.schedules and supply completions for every user,
starting at the Monday containing date_from through date_to. Schedule changes
have date-only precision and apply to the whole effective date, as in the
dashboard. No change time or employee assignment is inferred here.
"""
from bisect import bisect_right
from collections.abc import Mapping
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from domain import CATEGORY_OPTIONS, FLOOR_ORDER

TAIPEI = ZoneInfo("Asia/Taipei")
FREQUENCIES = {"daily", "daily2", "weekly"}


def _value(item, name, default=None):
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _utc(instant):
    # Database timestamps are UTC without tzinfo; aware inputs may use any zone.
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    return instant.astimezone(timezone.utc)


def _completion_keys(completions):
    keys = set()
    for item in completions:
        if isinstance(item, (tuple, list)) and not hasattr(item, "point_id"):
            point_id, frequency, period_key, slot = item
        else:
            point_id = _value(item, "point_id")
            frequency = _value(item, "frequency")
            period_key = _value(item, "period_key")
            slot = _value(item, "slot", "any")
        if isinstance(period_key, date):
            period_key = period_key.isoformat()
        keys.add((point_id, frequency, period_key, slot or "any"))
    return keys


def _timeline(point):
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
        "active": historical("active", _value(point, "active", True)),
    }


def calculate_missed(points, completions, date_from, date_to, now, *, category="", floor=None, frequency=""):
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
    if frequency not in ("", None) and frequency not in FREQUENCIES:
        raise ValueError("Unknown frequency filter")
    if floor not in (None, ""):
        if str(floor) not in {str(value) for value in FLOOR_ORDER}:
            raise ValueError("Unknown floor filter")
        floor = int(floor)
    else:
        floor = None

    instant = _utc(now)
    last_due_day = min(date_to, instant.astimezone(TAIPEI).date())
    completed = _completion_keys(completions)
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
        effective_dates, schedules = _timeline(point)
        due_day = first_due_day
        while due_day <= last_due_day:
            index = bisect_right(effective_dates, due_day) - 1
            schedule = schedules[index] if index >= 0 else None
            snapshot = _snapshot(point, schedule)
            period_frequency = snapshot["frequency"]
            if (snapshot["active"] and period_frequency in FREQUENCIES
                    and (not category or snapshot["category"] == category)
                    and (floor is None or snapshot["floor"] == floor)
                    and (not frequency or period_frequency == frequency)):
                next_midnight = datetime.combine(due_day + timedelta(days=1), time.min, TAIPEI)
                if period_frequency == "weekly":
                    slots = (("any", next_midnight),) if due_day.weekday() == 6 else ()
                    period_start = due_day - timedelta(days=6)
                    period_label = f"{period_start.isoformat()} – {due_day.isoformat()}"
                else:
                    slots = (("am", datetime.combine(due_day, time(12), TAIPEI)), ("pm", next_midnight)) if period_frequency == "daily2" else (("any", next_midnight),)
                    period_start = due_day
                    period_label = due_day.isoformat()
                period_key = period_start.isoformat()
                for slot, local_deadline in slots:
                    deadline = local_deadline.astimezone(timezone.utc)
                    if deadline > instant or (created_at is not None and deadline <= created_at):
                        continue
                    if (point_id, period_frequency, period_key, slot) in completed:
                        continue
                    occurrences.append({key: value for key, value in snapshot.items() if key != "active"} | {
                        "period_key": period_key, "period_label": period_label, "slot": slot,
                        "due_date": due_day, "deadline": deadline,
                    })
            due_day += timedelta(days=1)
    occurrences.sort(key=lambda row: (-row["deadline"].timestamp(), FLOOR_ORDER.get(row["floor"], len(FLOOR_ORDER)),
                                      row["code"], row["point_id"], row["slot"]))
    return occurrences
