"""Rendered actions must keep their meaning across another tab's update."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from urllib.parse import urlsplit

from flask import has_request_context, request
from sqlalchemy import event
from sqlalchemy.orm import Session

from models import AuditLog, DeviceBinding, User, db
from test_app import PASSWORD, application, login, seeded
from test_device_review_rounds import ReviewForms
from test_postgres_features import postgres_app
from test_session_revocation import pg_browsers


def test_pending_withdrawal_after_approval_never_disconnects_phone(application, seeded):
    phone, admin = application.test_client(), application.test_client()
    login(phone)
    login(admin, "manager")
    qr = "/c/" + seeded["daily"].qr_token
    phone.post("/devices/request", data={"label": "QA phone", "next": qr})
    binding = db.session.scalars(db.select(DeviceBinding)).one()
    path = f"/devices/{binding.id}/revoke"
    form = ReviewForms(phone.get("/devices", query_string={"next": qr}).text).fields[path]
    assert admin.post(f"/admin/devices/{binding.id}/approve").status_code == 302
    for old in (form, {"next": qr}):  # Including an open tab from the previous release.
        response = phone.post(path, data=old)
        assert response.status_code == 409 and "最新綁定" in response.text and qr in response.text
        assert binding.status == "approved" and 'id="inspection-form"' in phone.get(qr).text
    assert db.session.query(AuditLog).filter_by(action="device_self_revoked").count() == 0
    # The refreshed form explicitly offers to disconnect the approved browser.
    renewed = ReviewForms(phone.get("/devices", query_string={"next": qr}).text).fields[path]
    assert phone.post(path, data=renewed).status_code == 302 and binding.status == "revoked"


def test_admin_own_password_change_cannot_skip_current_password(application, seeded):
    manager = seeded["manager"]
    browser = application.test_client()
    login(browser, "manager")
    initial = manager.auth_version
    assert browser.post(f"/admin/users/{manager.id}/reset-password", data={"password": "different-admin-password"}).status_code == 403
    assert manager.auth_version == initial and manager.check_password(PASSWORD)
    assert db.session.query(AuditLog).filter_by(action="password_reset").count() == 0


def test_concurrent_reset_invalidates_password_change_response(postgres_app):
    browser, _, csrf = pg_browsers(postgres_app)
    saved, release = Event(), Event()

    def hold_after_save(session):
        if has_request_context() and request.path == "/change-password":
            saved.set()
            assert release.wait(12)

    event.listen(Session, "after_commit", hold_after_save)
    try:
        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(browser.post, "/change-password", data={
                "current_password": PASSWORD, "new_password": "my-fresh-password",
                "confirm_password": "my-fresh-password", "csrf_token": csrf})
            try:
                assert saved.wait(12)
                with postgres_app.app_context():
                    worker = db.session.scalars(db.select(User)).one()
                    worker.set_password("subsequent-admin-reset")
                    worker.auth_version += 1
                    worker.must_change_password = True
                    db.session.commit()
            finally:
                release.set()
            assert result.result(timeout=15).status_code == 302
    finally:
        event.remove(Session, "after_commit", hold_after_save)
    assert urlsplit(browser.get("/dashboard").location).path == "/login"
