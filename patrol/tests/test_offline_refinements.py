"""Bounded preparation and defensive input handling for offline patrols."""
from datetime import timedelta
import json

import pytest
from sqlalchemy import event

from models import Inspection, OfflineSubmission, Point, User, db
from test_app import application
from test_daily2_anytime import anytime, form
from test_offline_api import assert_error, entry, prepare, sync
from test_workflow_checkin import payload


def test_preparation_query_count_does_not_grow_with_route_size(application, anytime):
    actor = anytime.inspector
    counts = []
    def count_selects(_conn, _cursor, statement, *_):
        if statement.lstrip().upper().startswith("SELECT"):
            counts.append(statement)
    event.listen(db.engine, "before_cursor_execute", count_selects)
    try:
        initial = prepare(actor)
        initial_count = len(counts)
        for i in range(80):
            db.session.add(Point(code=f"1F-LOAD{i:03}", name=f"route {i}", floor=1, category="general",
                workflow_mode="two_stage" if i % 2 else "spot", frequency="daily2",
                schedule_start=anytime.clock[0].date()))
        db.session.commit()
        counts.clear()
        expanded = prepare(actor)
        assert len(expanded["points"]) == len(initial["points"]) + 80
        assert len(counts) <= initial_count + 1 and len(counts) <= 8
    finally:
        event.remove(db.engine, "before_cursor_execute", count_selects)


@pytest.mark.parametrize("frequency", ["daily2", "weekly", "monthly"])
def test_preparation_keeps_shared_execution_and_personal_review_quotas(application, anytime, frequency):
    a = anytime
    p = a.pair_point
    p.frequency = p.schedules[0].frequency = frequency
    db.session.commit()
    assert a.executor.post(a.paired + "/confirm", data=payload(a.executor, a.paired)).status_code == 302
    a.clock[0] += timedelta(seconds=1)
    assert a.inspector.post(a.paired + "/confirm", data=payload(a.inspector, a.paired)).status_code == 302
    slot = "am" if frequency == "daily2" else "any"
    for client, own in ((a.executor, True), (a.inspector, True), (a.peer, False)):
        item = next(row for row in prepare(client)["points"] if row["id"] == p.id)
        assert item["executed_slots"] == [slot]
        assert item["used_slots"] == ([slot] if own else [])
    if frequency != "daily2":
        a.clock[0] += timedelta(days=1)
        first = next(row for row in prepare(a.executor)["points"] if row["id"] == p.id)
        second = next(row for row in prepare(a.inspector)["points"] if row["id"] == p.id)
        assert first["used_slots"] == ["any"] and second["used_slots"] == []
        assert second["executed_slots"] == ["any"]


@pytest.mark.parametrize("old_frequency,new_frequency", [("daily", "daily2"), ("daily2", "daily")])
def test_preparation_counts_older_personal_slot_when_schedule_changes(application, anytime, old_frequency, new_frequency):
    a = anytime
    p = a.direct_point
    p.frequency = p.schedules[0].frequency = old_frequency
    db.session.commit()
    assert a.inspector.post(a.direct + "/confirm", data=payload(a.inspector, a.direct)).status_code == 302
    # Model a preserved historical receipt; current management guards separately
    # reject unsafe edits once a two-round schedule has started.
    p.frequency = new_frequency
    db.session.commit()
    item = next(row for row in prepare(a.inspector)["points"] if row["id"] == p.id)
    assert item["used_slots"] == (["am", "pm"] if new_frequency == "daily2" else ["any"])


def test_deeply_nested_invalid_json_returns_actionable_error_without_writes(application, anytime):
    prepared = prepare(anytime.inspector)
    response = anytime.inspector.post("/api/offline/sync", data={"entry": "[" * 1500 + "0" + "]" * 1500},
        headers={"X-CSRF-Token": prepared["csrf_token"]})
    assert_error(response, "invalid_entry", status=400)
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"])
def test_extreme_phone_dates_fail_without_conversion_overflow(application, anytime, stamp):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0], observed_at=stamp)
    assert_error(sync(anytime.inspector, prepared, item), "invalid_time", status=409)
    assert db.session.query(Inspection).count() == 0
