"""Safety-only date exclusions, authorization, history and invalid requests."""
from datetime import date, datetime, timezone
import re

import pytest
from flask import g, request
from sqlalchemy import select

from models import AuditLog, RevokedSession, User, db
from safety_leave import SafetyLeaveExclusion, get_safety_leave_dates, register_routes
from test_app import PASSWORD, app_module, application, seeded, login


@pytest.fixture
def leave_app(application):
    if "safety_leave" not in application.view_functions:
        register_routes(application, now_utc=lambda: datetime(2026, 11, 13, 0, 0, tzinfo=timezone.utc))
    return application


def new_leave(client, first="2026-11-13", last="", **extra):
    return client.post("/safety-leave/add", data={"date_from": first, "date_to": last, **extra})


def test_safety_staff_can_add_department_date_and_cancel_without_losing_audit(leave_app, seeded):
    client = leave_app.test_client()
    login(client)
    assert client.get("/safety-leave").status_code == 200
    response = new_leave(client, note="請休")
    assert response.status_code == 302 and response.location == "/safety-leave"
    entry = db.session.scalar(select(SafetyLeaveExclusion))
    assert (entry.date_from, entry.date_to, entry.created_by, entry.note) == (
        date(2026, 11, 13), date(2026, 11, 13), seeded["inspector"].id, "請休")
    assert get_safety_leave_dates(date(2026, 11, 1), date(2026, 11, 30)) == {date(2026, 11, 13)}
    page = client.get("/safety-leave").get_data(as_text=True)
    assert "取消排除" in page and "Inspector Alpha" in page
    assert client.post(f"/safety-leave/{entry.id}/cancel").status_code == 302
    assert entry.cancelled_by == seeded["inspector"].id and entry.cancelled_at is not None
    assert get_safety_leave_dates(date(2026, 11, 1), date(2026, 11, 30)) == set()
    assert "請休" in client.get("/safety-leave?status=cancelled").get_data(as_text=True)
    assert client.post(f"/safety-leave/{entry.id}/cancel").status_code == 409
    actions = list(db.session.scalars(select(AuditLog.action).where(AuditLog.action.like("safety_leave_%"))))
    assert actions == ["safety_leave_added", "safety_leave_cancelled"]
    assert new_leave(client).status_code == 302
    assert db.session.scalar(select(db.func.count()).select_from(SafetyLeaveExclusion)) == 2


def test_range_query_is_inclusive_clipped_and_overlap_is_all_or_nothing(leave_app, seeded):
    client = leave_app.test_client()
    login(client)
    assert new_leave(client, "2026-11-16", "2026-11-18").status_code == 302
    assert get_safety_leave_dates(date(2026, 11, 17), date(2026, 11, 20)) == {
        date(2026, 11, 17), date(2026, 11, 18)}
    for first, last in [("2026-11-16", ""), ("2026-11-15", "2026-11-16"),
                        ("2026-11-18", "2026-11-20"), ("2026-11-15", "2026-11-20")]:
        assert new_leave(client, first, last).status_code == 409
    assert db.session.scalar(select(db.func.count()).select_from(SafetyLeaveExclusion)) == 1
    assert new_leave(client, "2026-11-19").status_code == 302


@pytest.mark.parametrize("role,category,manager,engineering", [
    ("inspector", "general", False, False), ("inspector", "general", True, False),
    ("inspector", "general", False, True), ("executor", "general", False, False),
    ("inspector", None, False, False),
])
def test_other_department_accounts_cannot_read_or_write(leave_app, seeded, role, category, manager, engineering):
    client = leave_app.test_client()
    user = User(username="denied", display_name="Denied", role=role, patrol_category=category,
                general_manager_title=manager, engineering_inspector_title=engineering,
                active=True, must_change_password=False)
    user.set_password(PASSWORD)
    db.session.add(user)
    db.session.commit()
    login(client, "denied")
    assert client.get("/safety-leave").status_code == 403
    assert new_leave(client, category="safety", created_by=seeded["inspector"].id).status_code == 403
    assert client.post("/safety-leave/1/cancel").status_code == 403
    assert get_safety_leave_dates(date(2026, 11, 1), date(2026, 11, 30)) == set()


def test_peer_cannot_cancel_others_but_admin_can(leave_app, seeded):
    owner, peer, admin = (leave_app.test_client() for _ in range(3))
    login(owner)
    login(peer, "colleague")
    login(admin, "manager")
    assert new_leave(owner).status_code == 302
    entry = db.session.scalar(select(SafetyLeaveExclusion))
    assert "2026-11-13" in peer.get("/safety-leave").get_data(as_text=True)
    assert "取消排除</button>" not in peer.get("/safety-leave").get_data(as_text=True)
    assert peer.post(f"/safety-leave/{entry.id}/cancel").status_code == 403
    assert entry.cancelled_at is None
    assert admin.post(f"/safety-leave/{entry.id}/cancel").status_code == 302
    assert entry.cancelled_by == seeded["manager"].id


@pytest.mark.parametrize("first,last,note", [
    ("", "", ""), ("2026-2-01", "", ""), ("2026-02-30", "", ""),
    ("2026-11-20", "2026-11-19", ""), ("2026-11-01", "2027-02-01", ""),
    ("2000-01-01", "", ""), ("2099-01-01", "", ""),
    ("2026-11-13", "", "x" * 101), ("2026-11-13", "", "bad\ntext"),
])
def test_invalid_dates_and_notes_make_no_changes(leave_app, seeded, first, last, note):
    client = leave_app.test_client()
    login(client)
    assert new_leave(client, first, last, note=note).status_code == 400
    assert db.session.scalar(select(db.func.count()).select_from(SafetyLeaveExclusion)) == 0


def test_note_is_escaped_and_past_dates_are_supported(leave_app, seeded):
    client = leave_app.test_client()
    login(client)
    assert new_leave(client, "2026-11-01", note='<script>alert("x")</script>').status_code == 302
    page = client.get("/safety-leave").get_data(as_text=True)
    assert "&lt;script&gt;" in page and '<script>alert("x")</script>' not in page
    assert get_safety_leave_dates(date(2026, 11, 1), date(2026, 11, 1)) == {date(2026, 11, 1)}


def test_login_csrf_and_missing_ids(leave_app, seeded):
    anonymous = leave_app.test_client()
    assert "/login" in anonymous.get("/safety-leave").location
    assert "/login" in new_leave(anonymous).location
    client = leave_app.test_client()
    login(client)
    assert client.post("/safety-leave/999/cancel").status_code == 404
    leave_app.config["CSRF_ENABLED"] = True
    page = client.get("/safety-leave").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page)[1]
    assert new_leave(client).status_code == 400
    assert new_leave(client, csrf_token=token).status_code == 302


@pytest.mark.parametrize("start,end", [(date(2026, 11, 2), date(2026, 11, 1)),
                                      ("2026-11-01", date(2026, 11, 1)),
                                      (datetime(2026, 11, 1), date(2026, 11, 1))])
def test_date_helper_rejects_invalid_ranges(leave_app, start, end):
    with pytest.raises(ValueError):
        get_safety_leave_dates(start, end)


def test_leave_clock_tracks_app_clock_after_factory(leave_app, seeded, monkeypatch):
    # The same request clock drives dashboard, date bounds and audit timestamps.
    # Changing it after create_app must not leave this module on the old clock.
    current = datetime(2026, 11, 13, 17, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(app_module, "now_utc", lambda: current)
    client = leave_app.test_client()
    login(client)
    page = client.get("/safety-leave").get_data(as_text=True)
    assert 'value="2026-11-14"' in page
    assert new_leave(client, "2026-11-14").status_code == 302
    entry = db.session.scalar(select(SafetyLeaveExclusion))
    assert entry.created_at == current.replace(tzinfo=None)


@pytest.mark.parametrize("change", ["revoked", "password", "category", "inactive"])
def test_write_rechecks_account_after_request_authentication(leave_app, seeded, change):
    @leave_app.before_request
    def change_after_authentication():
        if request.endpoint != "add_safety_leave":
            return
        if change == "revoked":
            db.session.add(RevokedSession(token_hash=g.patrol_session_hash, user_id=g.user.id,
                                         auth_version=g.user.auth_version))
        else:
            values = {"password": {"must_change_password": True}, "category": {"patrol_category": "general"},
                      "inactive": {"active": False}}[change]
            db.session.execute(db.update(User).where(User.id == g.user.id).values(**values))
        db.session.commit()

    client = leave_app.test_client()
    login(client)
    assert new_leave(client).status_code == 403
    assert db.session.scalar(select(db.func.count()).select_from(SafetyLeaveExclusion)) == 0
