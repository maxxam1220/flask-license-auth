"""Cross-day/period checklist checks with isolated SQLite and synthetic staff."""
from datetime import datetime, timedelta

import pytest

import app as patrol
from checklist_records import checklist_snapshot
from models import PatrolExecution, User, db
from test_app import application
from test_checklist_routes import toilet
from test_daily2_anytime import anytime, rows
from test_offline_api import assert_error, entry, prepare, sync


def checklist_point(a, frequency, *, direct=False):
    point = toilet(a, direct=direct)
    point.frequency = point.schedules[0].frequency = frequency
    db.session.commit()
    return point


@pytest.mark.parametrize("frequency", ["weekly", "monthly"])
def test_cross_day_review_keeps_own_checks_and_original_execution_snapshot(application, anytime, frequency):
    a = anytime
    point = checklist_point(a, frequency)
    # Stay in one week/month while capture authorizations remain day-scoped.
    a.clock[0] = datetime(2026, 11, 9, 9, tzinfo=patrol.TAIPEI)
    worker = prepare(a.executor)
    signed = entry(worker, a.paired, a.clock[0], checklist=["toilet.soap"])
    assert sync(a.executor, worker, signed).get_json()["status"] == "saved"
    execution = rows(point, PatrolExecution)[0]
    original = execution.checklist_data

    a.clock[0] += timedelta(days=1)
    reviewer = prepare(a.inspector)
    reviewed = entry(reviewer, a.paired, a.clock[0], checklist=["toilet.floor"])
    assert sync(a.inspector, reviewer, reviewed).get_json()["status"] == "saved"
    first = rows(point)[0]
    assert first.execution_id == execution.id
    assert checklist_snapshot(first)["selected"] == ["toilet.floor"]
    assert checklist_snapshot(first.execution)["selected"] == ["toilet.soap"]
    assert first.personal_day == a.clock[0].date()

    a.clock[0] += timedelta(days=1)
    refreshed = prepare(a.inspector)
    again = entry(refreshed, a.paired, a.clock[0], checklist=["toilet.mirror"])
    assert sync(a.inspector, refreshed, again).get_json()["status"] == "saved"
    saved = rows(point)
    assert len(saved) == 2 and saved[1].execution_id == execution.id
    assert checklist_snapshot(saved[1])["selected"] == ["toilet.mirror"]
    assert execution.checklist_data == original
    # An accepted original UUID resolves after its upload deadline and does
    # not turn the weekly/monthly execution into another attendance row.
    assert sync(a.executor, worker, signed).get_json()["status"] == "already_synced"
    assert len(rows(point, PatrolExecution)) == 1


@pytest.mark.parametrize("frequency,last_day", [("weekly", "2026-11-08"), ("monthly", "2026-11-30")])
def test_period_boundary_cannot_pair_checklists_with_a_new_period_execution(application, anytime, frequency, last_day):
    a = anytime
    point = checklist_point(a, frequency)
    a.clock[0] = datetime.fromisoformat(last_day).replace(hour=23, minute=55, tzinfo=patrol.TAIPEI)
    old_worker, old_reviewer = prepare(a.executor), prepare(a.inspector)
    old_signed = entry(old_worker, a.paired, a.clock[0] + timedelta(minutes=1), checklist=["toilet.soap"])
    old_reviewed = entry(old_reviewer, a.paired, a.clock[0] + timedelta(minutes=2), checklist=["toilet.floor"])
    a.clock[0] += timedelta(minutes=10)
    new_worker = prepare(a.executor)
    new_signed = entry(new_worker, a.paired, a.clock[0], checklist=["toilet.mirror"])
    assert sync(a.executor, new_worker, new_signed).get_json()["status"] == "saved"
    assert_error(sync(a.inspector, old_reviewer, old_reviewed), "waiting_execution", retryable=True)
    assert not rows(point)
    assert sync(a.executor, old_worker, old_signed).get_json()["status"] == "saved"
    assert sync(a.inspector, old_reviewer, old_reviewed).get_json()["status"] == "saved"
    saved = rows(point)[0]
    assert saved.period_key == saved.execution.period_key
    assert checklist_snapshot(saved.execution)["selected"] == ["toilet.soap"]
    assert checklist_snapshot(saved)["selected"] == ["toilet.floor"]
    assert len(rows(point, PatrolExecution)) == 2


def test_next_day_upload_keeps_original_checklist_and_day_after_new_day_is_complete(application, anytime):
    a = anytime
    point = checklist_point(a, "daily", direct=True)
    old = prepare(a.inspector)
    old_day = a.clock[0].date()
    old_item = entry(old, a.direct, a.clock[0], checklist=["toilet.soap"])
    a.clock[0] += timedelta(days=1)
    current = prepare(a.inspector)
    current_item = entry(current, a.direct, a.clock[0], checklist=["toilet.floor"])
    assert sync(a.inspector, current, current_item).get_json()["status"] == "saved"
    assert sync(a.inspector, old, old_item).get_json()["status"] == "saved"
    saved = rows(point)
    assert len(saved) == 2
    assert saved[0].personal_day == a.clock[0].date()
    assert saved[1].personal_day == old_day
    assert checklist_snapshot(saved[0])["selected"] == ["toilet.floor"]
    assert checklist_snapshot(saved[1])["selected"] == ["toilet.soap"]
    assert saved[1].offline_submission.observed_at == saved[1].created_at
    assert saved[1].offline_submission.received_at > saved[1].created_at


@pytest.mark.parametrize("locale", ["id", "vi"])
def test_language_change_does_not_reinterpret_saved_ids_or_original_grant(application, anytime, locale):
    a = anytime
    point = checklist_point(a, "daily", direct=True)
    original = prepare(a.inspector)
    pending = entry(original, a.direct, a.clock[0], checklist=["toilet.soap"])
    user = db.session.scalar(db.select(User).where(User.username == "inspect"))
    user.ui_language = locale
    db.session.commit()
    refreshed = prepare(a.inspector)
    assert refreshed["identity"]["ui_language"] == locale
    assert refreshed["owner"] == original["owner"]
    assert sync(a.inspector, original, pending).get_json()["status"] == "saved"
    snapshot = checklist_snapshot(rows(point)[0])
    assert snapshot["selected"] == ["toilet.soap"]
    assert all(set(item["label"]) == {"zh-Hant", "id", "vi"} for item in snapshot["items"])
    assert sync(a.inspector, original, pending).get_json()["status"] == "already_synced"
    assert len(rows(point)) == 1
