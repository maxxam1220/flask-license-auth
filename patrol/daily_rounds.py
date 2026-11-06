"""Daily two-round policy, retaining the original database slot identities.

The persisted ``am`` and ``pm`` keys are the first and second occurrence after
the policy start date. Keeping them avoids rewriting historical execution links
or the unique constraints which protect per-person and shared completion.
"""
from datetime import date, datetime


DAILY2_ANYTIME_START = date(2026, 11, 6)
DAILY2_SLOTS = ("am", "pm")


def daily2_anytime(day):
    """Whether a Taipei calendar date (or ISO period key) uses anytime rounds."""
    if isinstance(day, str):
        try:
            day = date.fromisoformat(day)
        except ValueError:
            return False
    elif isinstance(day, datetime):
        day = day.date()
    return isinstance(day, date) and day >= DAILY2_ANYTIME_START


def next_daily2_slot(used_slots, available_slots=DAILY2_SLOTS):
    """Return the first unused available occurrence, or None when exhausted.

    A prior all-day record still consumes both occurrences when a point changes
    frequency on the same day. Availability lets a review select an existing
    first stage, including a second-slot execution saved before the release.
    """
    used, available = set(used_slots), set(available_slots)
    if "any" in used:
        return None
    return next((slot for slot in DAILY2_SLOTS if slot not in used and slot in available), None)
