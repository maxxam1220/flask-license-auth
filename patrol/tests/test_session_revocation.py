"""A logout revokes one signed login, including its in-flight responses."""
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
import re
import secrets
import threading

import pytest
from flask import has_request_context, request
from sqlalchemy import event
from sqlalchemy.orm import Session

from models import DeviceBinding, RevokedSession, User, db
from test_app import PASSWORD, application, approve_browser, seeded  # noqa: F401
from test_postgres_features import postgres_app  # noqa: F401


def sign_in(client, user, legacy=False):
    if legacy:
        # Exact v5 signed payload, including Flask's permanent-session flag.
        with client.session_transaction() as session:
            session["user_id"] = user.id
            session["auth_version"] = user.auth_version
            session.permanent = True
            session["csrf_token"] = secrets.token_urlsafe(32)
    else:
        login_page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token"[^>]+value="([^"]+)"', login_page).group(1)
        assert client.post("/login", data={"username": user.username, "password": PASSWORD, "csrf_token": token}).status_code == 302
    with client.session_transaction() as session:
        return session["csrf_token"]


@pytest.mark.parametrize("legacy", [True, False])
def test_logout_revokes_only_this_cookie_and_preserves_other_browser_and_approved_phone(application, seeded, legacy):
    application.config["CSRF_ENABLED"] = True
    manager = seeded["manager"]
    phone, office, copy = [application.test_client() for _ in range(3)]
    csrf = sign_in(phone, manager, legacy)
    sign_in(office, manager, not legacy)
    binding = approve_browser(phone, manager)
    old_cookie = phone.get_cookie("patrol_session").value
    copy.set_cookie("patrol_session", old_cookie)
    assert copy.get("/admin/users").status_code == 200
    assert phone.post("/logout", data={"csrf_token": "invalid"}).status_code == 400
    assert db.session.query(RevokedSession).count() == 0
    assert phone.post("/logout", data={"csrf_token": csrf}).status_code == 302
    assert phone.get_cookie("patrol_session") is None
    assert office.get("/admin/users").status_code == 200
    assert copy.get("/admin/users").location.startswith("/login")
    copy.set_cookie("patrol_session", old_cookie)
    response = copy.post("/admin/users/create", data={"username": "forged_user", "display_name": "test",
                         "role": "safety", "password": PASSWORD, "csrf_token": csrf})
    assert response.location.startswith("/login")
    assert db.session.scalar(db.select(User.id).where(User.username == "forged_user")) is None
    row = db.session.scalars(db.select(RevokedSession)).one()
    assert row.user_id == manager.id and row.auth_version == manager.auth_version
    assert len(row.token_hash) == 64 and row.token_hash not in (csrf, old_cookie)
    assert binding.status == "approved" and phone.get_cookie("patrol_device") is not None
    sign_in(phone, manager)
    assert phone.get("/admin/users").status_code == 200


def test_legacy_password_change_preserves_login_identifier_while_rotating_csrf(application, seeded):
    application.config["CSRF_ENABLED"] = True
    client = application.test_client()
    user = seeded["inspector"]
    previous_nonce = sign_in(client, user, legacy=True)
    response = client.post("/change-password", data={"csrf_token": previous_nonce, "current_password": PASSWORD,
        "new_password": "Fresh-password-for-test-123", "confirm_password": "Fresh-password-for-test-123"})
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["sid"] == previous_nonce and session["csrf_token"] != previous_nonce
        updated_token = session["csrf_token"]
        assert session["auth_version"] == user.auth_version == 2
    saved_cookie = client.get_cookie("patrol_session").value
    assert client.post("/logout", data={"csrf_token": updated_token}).status_code == 302
    client.set_cookie("patrol_session", saved_cookie)
    assert client.get("/dashboard").location.startswith("/login")


def pg_browsers(application, *, legacy=False):
    application.config["CSRF_ENABLED"] = True
    first, second = application.test_client(), application.test_client()
    with application.app_context():
        user = User(username="session-admin", display_name="Test", role="admin", active=True, must_change_password=False)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        csrf = sign_in(first, user, legacy)
    second.set_cookie("patrol_session", first.get_cookie("patrol_session").value)
    return first, second, csrf


def test_postgres_late_response_cookie_cannot_restore_admin_session(postgres_app):
    browser, in_flight, csrf = pg_browsers(postgres_app, legacy=True)
    ready, release = threading.Event(), threading.Event()

    @postgres_app.after_request
    def hold_response(response):
        if request.args.get("hold") == "1":
            ready.set()
            assert release.wait(10)
        return response

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(in_flight.get, "/admin/users?hold=1")
        try:
            assert ready.wait(10)
            assert browser.post("/logout", data={"csrf_token": csrf}).status_code == 302
        finally:
            release.set()
        delayed = pending.result(timeout=10)
    assert delayed.status_code == 200
    cookie = SimpleCookie()
    cookie.load(delayed.headers["Set-Cookie"])
    browser.set_cookie("patrol_session", cookie["patrol_session"].value)
    assert browser.get("/admin/users").location.startswith("/login")


def test_postgres_simultaneous_logouts_commit_one_revocation(postgres_app):
    from test_admin_races import simultaneously_after_authorization

    first, second, csrf = pg_browsers(postgres_app)
    actions = [lambda client=client: client.post("/logout", data={"csrf_token": csrf}) for client in (first, second)]
    assert simultaneously_after_authorization(actions) == [302, 302]
    with postgres_app.app_context():
        assert db.session.query(RevokedSession).count() == 1


@pytest.mark.parametrize("route", ["/devices/request", "/admin/users/create"])
def test_postgres_logout_wins_before_inflight_authenticated_write_locks(postgres_app, route):
    browser, in_flight, csrf = pg_browsers(postgres_app)
    ready, release = threading.Event(), threading.Event()

    def hold_write_before_lock(state):
        if (has_request_context() and request.path == route and state.is_select
                and getattr(state.statement, "_for_update_arg", None) is not None and not ready.is_set()):
            ready.set()
            assert release.wait(10)

    event.listen(Session, "do_orm_execute", hold_write_before_lock)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(in_flight.post, route, data={"label": "new", "role": "safety", "username": "unexpected",
                "display_name": "test", "password": PASSWORD, "csrf_token": csrf})
            try:
                assert ready.wait(10)
                assert browser.post("/logout", data={"csrf_token": csrf}).status_code == 302
            finally:
                release.set()
            assert pending.result(timeout=10).status_code == 403
    finally:
        event.remove(Session, "do_orm_execute", hold_write_before_lock)
    with postgres_app.app_context():
        assert db.session.query(DeviceBinding).count() == 0 and db.session.query(User).count() == 1
