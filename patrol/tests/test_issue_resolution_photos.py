"""Resolution evidence is atomic, event-specific, and scoped by current authority."""
from datetime import date, datetime, timedelta
from contextlib import nullcontext
import os
import sys
from types import SimpleNamespace

import pytest
from flask import Flask
from sqlalchemy import event, inspect, select
from sqlalchemy.orm import scoped_session, sessionmaker

import issues
from issues import (IssueActionError, append_resolution_photos, can_resolve_issue,
                    transition_issue, transition_issue_event)
from models import Inspection, InspectionIssue, InspectionPhoto, IssueEvent, IssueEventPhoto, Point, User, db
from test_postgres import engine as postgres_store


NOW = datetime(2026, 11, 9, 5)


@pytest.fixture(params=["sqlite", "postgres"])
def domain(request, monkeypatch):
    if request.param == "postgres":
        if not os.environ.get("PATROL_TEST_POSTGRES_URL"):
            pytest.skip("Set PATROL_TEST_POSTGRES_URL for isolated local PostgreSQL tests.")
        engine = request.getfixturevalue("postgres_store")
        db.metadata.create_all(engine)
        session = scoped_session(sessionmaker(bind=engine))
        store = SimpleNamespace(session=session, engine=engine, func=db.func)
        monkeypatch.setattr(issues, "db", store)
        monkeypatch.setattr(sys.modules[__name__], "db", store)
        context = nullcontext()
    else:
        app = Flask(__name__)
        app.config.update(SQLALCHEMY_DATABASE_URI="sqlite://", TESTING=True)
        db.init_app(app)
        context = app.app_context()
    with context:
        if request.param == "sqlite":
            db.create_all()
        users = {}
        for username, role, category, manager, engineer in (
            ("owner", "inspector", "general", False, False),
            ("other", "inspector", "general", False, False),
            ("general-manager", "inspector", "general", True, False),
            ("engineering", "inspector", "general", False, True),
            ("safety", "inspector", "safety", False, False),
            ("executor", "executor", "general", False, False),
            ("admin", "admin", None, False, False),
        ):
            user = User(username=username, display_name=username, password_hash="fixture",
                        role=role, patrol_category=category, general_manager_title=manager,
                        engineering_inspector_title=engineer, active=True, must_change_password=False)
            db.session.add(user)
            users[username] = user
        db.session.flush()
        records = {}
        for code, category, team, owner in (
            ("GENERAL", "general", "general", users["owner"]),
            ("ENGINEERING", "general", "engineering", users["engineering"]),
            ("SAFETY", "safety", "general", users["safety"]),
        ):
            point = Point(code=code, name=code, floor=1, frequency="daily", category=category,
                          inspection_team=team, workflow_mode="standard", schedule_start=date(2026, 1, 1))
            db.session.add(point)
            db.session.flush()
            record = Inspection(user_id=owner.id, point_id=point.id, created_at=NOW, period_key="2026-11-09",
                frequency="daily", category=category, point_code=code, point_name=code, point_floor=1,
                user_name=owner.display_name, is_abnormal=True, note="Original anomaly")
            record.issue = InspectionIssue(status="open", opened_at=NOW)
            record.photos.append(InspectionPhoto(data=b"original", size_bytes=8, width=1, height=1))
            db.session.add(record)
            records[code] = record
        db.session.commit()
        yield SimpleNamespace(users=users, records=records)
        db.session.remove()
        if request.param == "sqlite":
            db.drop_all()


def prepared(value=b"processed-jpeg"):
    return {"data": value, "mime_type": "image/jpeg", "size_bytes": len(value), "width": 20, "height": 10}


def resolve(record, actor, version="0"):
    return transition_issue_event(record.id, "resolved", actor, version, "Repaired", NOW)


def test_resolution_photos_survive_reopen_and_second_resolution_without_replacing_original(domain):
    record, actor = domain.records["GENERAL"], domain.users["owner"]
    original = (record.note, record.is_abnormal, record.photos[0].data, record.photos[0].id)
    first = resolve(record, actor)
    # Quota queries may autoflush before image processing completes.
    assert db.session.scalar(select(db.func.count(IssueEvent.id))) == 1
    assert append_resolution_photos(first, [prepared(b"first"), prepared(b"second")], NOW) == 2
    db.session.commit()
    first_id = first.id
    assert transition_issue(record.id, "open", domain.users["admin"], str(first_id), "Again", NOW + timedelta(hours=1)) is True
    db.session.commit()
    reopened = db.session.scalar(select(IssueEvent).where(IssueEvent.action == "reopened"))
    second = resolve(record, actor, str(reopened.id))
    append_resolution_photos(second, [prepared(b"third")], NOW + timedelta(hours=2))
    db.session.commit()
    db.session.expire_all()
    assert [photo.data for photo in db.session.get(IssueEvent, first_id).photos] == [b"first", b"second"]
    assert reopened.photos == []
    assert [photo.data for photo in second.photos] == [b"third"]
    assert (record.note, record.is_abnormal, record.photos[0].data, record.photos[0].id) == original
    assert [item.id for item in first.photos] == sorted(item.id for item in first.photos)


def test_duplicate_and_stale_actions_never_get_event_capability_or_attach_evidence(domain):
    record, actor = domain.records["GENERAL"], domain.users["owner"]
    first = resolve(record, actor)
    append_resolution_photos(first, [prepared()], NOW)
    db.session.commit()
    assert resolve(record, actor) is None
    with pytest.raises(IssueActionError) as blocked:
        append_resolution_photos(first, [prepared(b"injected")], NOW)
    assert blocked.value.status == 409
    db.session.rollback()
    transition_issue(record.id, "open", domain.users["admin"], str(first.id), "Reopened", NOW)
    db.session.commit()
    with pytest.raises(IssueActionError) as stale:
        resolve(record, actor, "0")
    assert stale.value.status == 409
    db.session.rollback()
    assert db.session.query(IssueEventPhoto).count() == 1
    assert db.session.query(IssueEvent).count() == 2
    assert record.issue.status == "open"


def test_photo_insert_failure_rolls_back_status_and_event_with_original_photos_untouched(domain):
    record = domain.records["GENERAL"]
    resolved = resolve(record, domain.users["owner"])
    append_resolution_photos(resolved, [prepared()], NOW)
    def fail_photo(_connection, _cursor, statement, _params, _context, _many):
        if statement.startswith("INSERT INTO patrol_issue_event_photos"):
            raise RuntimeError("Injected resolution evidence failure")
    event.listen(db.engine, "before_cursor_execute", fail_photo)
    try:
        with pytest.raises(RuntimeError, match="Injected resolution"):
            db.session.commit()
    finally:
        event.remove(db.engine, "before_cursor_execute", fail_photo)
        db.session.rollback()
    assert record.issue.status == "open"
    assert db.session.query(IssueEvent).count() == db.session.query(IssueEventPhoto).count() == 0
    assert db.session.query(InspectionPhoto).count() == 3
    with pytest.raises(IssueActionError):
        append_resolution_photos(resolved, [prepared()], NOW)


@pytest.mark.parametrize("bad", [
    [prepared()] * 4, [prepared(), prepared() | {"size_bytes": 999}],
    [prepared() | {"width": 0}], [prepared() | {"mime_type": "image/svg+xml"}],
    [prepared() | {"data": "not-bytes"}], [prepared() | {"event_id": 5}],
])
def test_invalid_batch_never_partially_attaches(domain, bad):
    resolved = resolve(domain.records["GENERAL"], domain.users["owner"])
    with pytest.raises(IssueActionError):
        append_resolution_photos(resolved, bad, NOW)
    assert resolved.photos == []
    assert append_resolution_photos(resolved, [prepared()], NOW) == 1
    with pytest.raises(IssueActionError):
        append_resolution_photos(resolved, [prepared()], NOW)


def test_reopened_or_manually_created_event_cannot_receive_resolution_photos(domain):
    record = domain.records["GENERAL"]
    resolved = resolve(record, domain.users["owner"])
    db.session.commit()
    reopened = transition_issue_event(record.id, "open", domain.users["admin"], str(resolved.id), "Again", NOW)
    with pytest.raises(IssueActionError):
        append_resolution_photos(reopened, [prepared()], NOW)
    forged = IssueEvent(inspection_id=record.id, actor_id=domain.users["admin"].id,
                       actor_name="admin", action="resolved", note="forged", created_at=NOW)
    db.session.add(forged)
    with pytest.raises(IssueActionError):
        append_resolution_photos(forged, [prepared()], NOW)


def test_photo_binary_is_deferred_until_explicitly_read(domain):
    resolved = resolve(domain.records["GENERAL"], domain.users["owner"])
    append_resolution_photos(resolved, [prepared()], NOW)
    db.session.commit()
    db.session.expire_all()
    photo = db.session.scalar(select(IssueEventPhoto))
    assert "data" in inspect(photo).unloaded
    assert photo.data == b"processed-jpeg"


@pytest.mark.parametrize("code", ["GENERAL", "ENGINEERING"])
def test_general_manager_can_resolve_other_reporters_in_both_teams_but_never_reopen(domain, code):
    record, actor = domain.records[code], domain.users["general-manager"]
    assert can_resolve_issue(actor, record)
    resolved = resolve(record, actor)
    append_resolution_photos(resolved, [prepared()], NOW)
    db.session.commit()
    assert record.issue.resolved_by_id == actor.id
    assert record.user_id != actor.id
    with pytest.raises(IssueActionError) as blocked:
        transition_issue(record.id, "open", actor, str(resolved.id), "Not authorized", NOW)
    assert blocked.value.status == 403


@pytest.mark.parametrize("actor_key,code,status", [
    ("general-manager", "SAFETY", 404), ("other", "GENERAL", 403),
    ("owner", "ENGINEERING", 404), ("engineering", "GENERAL", 404),
    ("executor", "GENERAL", 403),
])
def test_unrelated_actor_cannot_resolve_or_parse_upload_form(domain, actor_key, code, status):
    class MustNotParse:
        def replace(self, *_args):
            raise AssertionError("Unauthorized form parsed")
    record, actor = domain.records[code], domain.users[actor_key]
    assert not can_resolve_issue(actor, record)
    with pytest.raises(IssueActionError) as blocked:
        transition_issue_event(record.id, "resolved", actor, "", MustNotParse(), NOW)
    assert blocked.value.status == status
    assert db.session.query(IssueEvent).count() == 0


@pytest.mark.parametrize("changes", [
    {"role": "executor"}, {"patrol_category": "safety"}, {"patrol_category": None},
    {"engineering_inspector_title": True}, {"active": False}, {"must_change_password": True},
])
def test_forged_or_revoked_manager_title_never_broadens_scope(domain, changes):
    original = domain.users["general-manager"]
    actor = SimpleNamespace(**{name: getattr(original, name) for name in (
        "id", "role", "patrol_category", "general_manager_title", "engineering_inspector_title",
        "active", "must_change_password", "display_name")})
    actor.__dict__.update(changes)
    record = domain.records["GENERAL"]
    assert not can_resolve_issue(actor, record)
    with pytest.raises(IssueActionError):
        resolve(record, actor)
    assert db.session.query(IssueEvent).count() == 0


def test_owner_loses_resolution_permission_after_point_moves_to_other_team(domain):
    record, actor = domain.records["GENERAL"], domain.users["owner"]
    assert can_resolve_issue(actor, record)
    record.point.inspection_team = "engineering"
    db.session.commit()
    assert not can_resolve_issue(actor, record)
    with pytest.raises(IssueActionError) as blocked:
        resolve(record, actor)
    assert blocked.value.status == 404
    assert can_resolve_issue(domain.users["general-manager"], record)
