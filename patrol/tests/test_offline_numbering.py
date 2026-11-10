"""Offline grants retain point identity through audited automatic renumbering."""
from datetime import timedelta
from uuid import uuid4

import pytest

import app as patrol
from general_numbering import apply_general_numbering
from models import AuditLog, Inspection, OfflineSubmission, PatrolExecution, Point, User, db
from test_app import application
from test_general_numbering_routes import NOW, numbered_team
from test_offline_api import assert_error, entry, prepare, sync
from test_postgres_features import postgres_app
from test_workflow_checkin import payload, team


def renumber(actors, instant=NOW):
    admin = db.session.scalar(db.select(User).where(User.username == "admin"))
    result = apply_general_numbering(instant, admin.id)
    db.session.commit()
    db.session.expire_all()
    return result


def point(actors, index=1):
    return db.session.get(Point, actors["active_ids"][index])


@pytest.mark.parametrize("stage", ["execute", "inspect", "direct"])
def test_pending_offline_entry_survives_pure_numbering_and_keeps_original_point(application, numbered_team, stage):
    a = numbered_team
    index = 1 if stage == "direct" else 0
    client = a["executor" if stage == "execute" else "inspector"]
    url = a["urls"][index]
    if stage == "inspect":
        assert a["executor"].post(url + "/confirm", data=payload(a["executor"], url)).status_code == 302
    prepared = prepare(client)
    item = entry(prepared, url, NOW)
    old = next(p for p in prepared["points"] if p["token"] == url[3:])
    renumber(a)
    assert old["code"] != point(a, index).code
    response = sync(client, prepared, item)
    assert response.status_code == 200 and response.json["status"] == "saved", response.text
    record = db.session.scalar(db.select(PatrolExecution if stage == "execute" else Inspection))
    assert record.point_id == old["id"] and record.point_code == point(a, index).code
    assert record.point.qr_token == old["token"]
    retry = sync(client, prepared, item)
    assert retry.status_code == 200 and retry.json["status"] == "already_synced"
    assert_error(sync(client, prepared, item | {"client_id": str(uuid4())}), "duplicate")
    assert db.session.query(OfflineSubmission).count() == 1


def test_prepared_before_renumber_then_captured_after_renumber_works(application, numbered_team, monkeypatch):
    a = numbered_team
    prepared = prepare(a["inspector"])
    renumber(a, NOW + timedelta(minutes=1))
    monkeypatch.setattr(patrol, "now_utc", lambda: NOW + timedelta(minutes=2))
    response = sync(a["inspector"], prepared, entry(prepared, a["urls"][1], NOW + timedelta(minutes=2)))
    assert response.status_code == 200, response.text
    current = prepare(a["inspector"])
    row = next(p for p in current["points"] if p["id"] == point(a).id)
    assert row["code"] == point(a).code and row["used_slots"] == ["any"]


def test_current_online_completion_blocks_old_offline_entry_as_duplicate(application, numbered_team):
    a = numbered_team
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], NOW)
    renumber(a)
    assert a["inspector"].post(a["urls"][1] + "/confirm", data=payload(a["inspector"], a["urls"][1])).status_code == 302
    assert_error(sync(a["inspector"], prepared, item), "duplicate")
    assert db.session.query(Inspection).count() == 1 and db.session.query(OfflineSubmission).count() == 0


@pytest.mark.parametrize("field,value", [
    ("name", "relocated"), ("floor", 2), ("inspection_team", "engineering"),
    ("workflow_mode", "two_stage"), ("frequency", "weekly"),
    ("qr_token", "new-token-after-numbering"), ("active", False), ("deleted_at", NOW.replace(tzinfo=None)),
    ("code", "1F-G088"),
])
def test_renumbering_does_not_authorize_real_point_changes(application, numbered_team, field, value):
    a = numbered_team
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], NOW)
    renumber(a)
    setattr(point(a), field, value)
    db.session.commit()
    assert_error(sync(a["inspector"], prepared, item), "point_changed")
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0


def test_code_reuse_never_moves_old_grant_to_the_new_code_owner(application, numbered_team):
    a = numbered_team
    renumber(a)
    # Put both points on the same floor before the signed preparations.
    first, second = point(a, 0), point(a, 1)
    first.floor = 1
    first.workflow_mode = first.schedules[-1].workflow_mode = "spot"
    renumber(a)
    prepared = prepare(a["inspector"])
    first_entry = entry(prepared, a["urls"][0], NOW)
    second_entry = entry(prepared, a["urls"][1], NOW)
    original_code = first.code
    first.active = False
    renumber(a)
    assert point(a, 1).code == original_code
    assert_error(sync(a["inspector"], prepared, first_entry), "point_changed")
    assert sync(a["inspector"], prepared, second_entry).status_code == 200
    saved = db.session.scalar(db.select(Inspection))
    assert saved.point_id == a["active_ids"][1]


def test_multiple_automatic_number_changes_remain_compatible(application, numbered_team):
    a = numbered_team
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], NOW)
    renumber(a)
    point(a, 0).active = False
    renumber(a)
    assert point(a, 1).code == "1F-G001"
    response = sync(a["inspector"], prepared, item)
    assert response.status_code == 200, response.text
    assert db.session.scalar(db.select(Inspection)).point_id == a["active_ids"][1]


def test_manual_code_change_between_automatic_changes_breaks_compatibility(application, numbered_team):
    a = numbered_team
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], NOW)
    renumber(a)
    point(a).code = "1F-G080"
    renumber(a)
    assert_error(sync(a["inspector"], prepared, item), "point_changed")
    assert db.session.query(Inspection).count() == 0


def test_weekly_execution_before_numbering_links_delayed_offline_inspection(application, numbered_team, monkeypatch):
    a = numbered_team
    p = point(a, 0)
    p.frequency = p.schedules[0].frequency = "weekly"
    db.session.commit()
    url = a["urls"][0]
    assert a["executor"].post(url + "/confirm", data=payload(a["executor"], url)).status_code == 302
    execution = db.session.scalar(db.select(PatrolExecution))
    monkeypatch.setattr(patrol, "now_utc", lambda: NOW + timedelta(days=1))
    prepared = prepare(a["inspector"])
    item = entry(prepared, url, NOW + timedelta(days=1))
    renumber(a, NOW + timedelta(days=1))
    response = sync(a["inspector"], prepared, item)
    assert response.status_code == 200, response.text
    saved = db.session.scalar(db.select(Inspection))
    assert saved.execution_id == execution.id and saved.point_id == execution.point_id


@pytest.mark.parametrize("detail", ["not json", "[]", '{"changes":null}', '{"changes":[null]}'])
def test_unreadable_numbering_audit_fails_closed_without_server_error(application, numbered_team, detail):
    a = numbered_team
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], NOW)
    renumber(a)
    db.session.scalar(db.select(AuditLog).where(AuditLog.action == "general_numbering_applied")).detail = detail
    db.session.commit()
    assert_error(sync(a["inspector"], prepared, item), "point_changed")
    assert db.session.query(Inspection).count() == 0


@pytest.mark.parametrize("delay", [timedelta(minutes=5), timedelta(hours=3)])
def test_preparation_during_pending_renumber_accepts_audit_started_before_grant(application, numbered_team, delay):
    # 10:00 Taipei minus 3 hours is same-day; a longer preceding operation is
    # represented separately below so no arbitrary minute limit is assumed.
    a = numbered_team
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], NOW)
    renumber(a, NOW - delay)
    assert sync(a["inspector"], prepared, item).status_code == 200


def test_renumber_started_previous_day_can_commit_after_new_day_preparation(application, numbered_team, monkeypatch):
    a = numbered_team
    midnight = NOW.replace(hour=16) - timedelta(days=1)  # 00:00 Taipei Nov 10.
    monkeypatch.setattr(patrol, "now_utc", lambda: midnight + timedelta(minutes=1))
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], midnight + timedelta(minutes=1))
    renumber(a, midnight - timedelta(minutes=1))
    assert sync(a["inspector"], prepared, item).status_code == 200


def test_each_inspector_keeps_own_quota_after_renumber(application, numbered_team):
    a = numbered_team
    pending = [(client, prepare(client)) for client in (a["inspector"], a["peer"])]
    renumber(a)
    for client, prepared in pending:
        item = entry(prepared, a["urls"][1], NOW)
        assert sync(client, prepared, item).status_code == 200
        assert_error(sync(client, prepared, item | {"client_id": str(uuid4())}), "duplicate")
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 2


def test_executor_direct_visit_follows_original_point_after_renumber(application, numbered_team):
    a = numbered_team
    application.config["EXECUTOR_VISIT_CODES"] = {"1F-G011"}
    p = point(a)
    p.code = p.schedules[0].point_code = "1F-G011"
    p.frequency = p.schedules[0].frequency = "three_day"
    db.session.commit()
    prepared = prepare(a["executor"])
    item = entry(prepared, a["urls"][1], NOW)
    renumber(a)
    response = sync(a["executor"], prepared, item)
    assert response.status_code == 200, response.text
    saved = db.session.scalar(db.select(Inspection))
    assert saved.point_id == p.id and saved.executor_visit


@pytest.mark.parametrize("change_definition", [False, True])
def test_checklist_selection_is_validated_after_renumber(application, numbered_team, change_definition):
    a = numbered_team
    p = point(a)
    p.name = p.schedules[0].point_name = "測試廁所"
    db.session.commit()
    prepared = prepare(a["inspector"])
    item = entry(prepared, a["urls"][1], NOW, checklist=["toilet.floor"])
    renumber(a)
    if change_definition:
        p = point(a)
        p.name, p.floor = "員工餐廳", 14
        db.session.commit()
        assert_error(sync(a["inspector"], prepared, item), "point_changed")
    else:
        assert_error(sync(a["inspector"], prepared, item | {"checklist": []}), "invalid_checklist")
        response = sync(a["inspector"], prepared, item)
        assert response.status_code == 200, response.text
        assert '"toilet.floor"' in db.session.scalar(db.select(Inspection)).checklist_data


@pytest.mark.parametrize("stage", ["execute", "inspect"])
def test_postgres_old_offline_grant_survives_committed_renumber(postgres_app, monkeypatch, stage):
    monkeypatch.setattr(patrol, "now_utc", lambda: NOW)
    with postgres_app.app_context():
        executor, inspector, _, _, paired, direct, _ = team(postgres_app)
        url, client = (paired, executor) if stage == "execute" else (direct, inspector)
        p = db.session.scalar(db.select(Point).where(Point.qr_token == url[3:]))
        p.code = "1F-G030"
        original_id, original_token = p.id, p.qr_token
        db.session.commit()
    prepared = prepare(client)
    item = entry(prepared, url, NOW)
    with postgres_app.app_context():
        renumber({}, NOW - timedelta(minutes=5))
    response = sync(client, prepared, item)
    assert response.status_code == 200 and response.json["status"] == "saved", response.text
    with postgres_app.app_context():
        record = db.session.scalar(db.select(PatrolExecution if stage == "execute" else Inspection))
        assert record.point_id == original_id and record.point.qr_token == original_token
        assert record.point_code == record.point.code and record.point_code != "1F-G030"
    assert_error(sync(client, prepared, item | {"client_id": str(uuid4())}), "duplicate")
