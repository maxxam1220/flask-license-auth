"""Recovery when a mobile patrol form outlives its login or displayed data."""
from urllib.parse import parse_qs, urlsplit

import pytest

from models import AuditLog, DeviceBinding, Inspection
from test_app import PASSWORD, application, approve_browser, db, login, rendered_contexts, seeded  # noqa: F401


@pytest.mark.parametrize("operation", ["request", "revoke"])
def test_expired_binding_form_returns_to_scanned_point_without_replaying_action(application, seeded, operation):
    client = application.test_client()
    login(client)
    qr_path = f"/c/{seeded['weekly'].qr_token}"
    assert client.get("/devices", query_string={"next": qr_path}).status_code == 200
    endpoint = "/devices/request"
    if operation == "revoke":
        endpoint = f"/devices/{approve_browser(client, seeded['inspector']).id}/revoke"
    with client.session_transaction() as session:
        session.clear()
    response = client.post(endpoint, data={"next": qr_path, "label": "Work phone"})
    location = urlsplit(response.location)
    assert location.path == "/login"
    return_url = parse_qs(location.query)["next"][0]
    response = login(client, next=return_url)
    with rendered_contexts(application) as contexts:
        assert client.get(response.location).status_code == 200
    assert contexts[-1][1]["next_url"] == qr_path
    assert {b.status for b in db.session.scalars(db.select(DeviceBinding))} == ({"approved"} if operation == "revoke" else set())


def test_expired_binding_form_discards_unsafe_return_url(application, seeded):
    client = application.test_client()
    response = client.post("/devices/request", data={"label": "Work phone", "next": "//untrusted.example/path"})
    assert parse_qs(urlsplit(response.location).query)["next"] == ["/devices"]


def test_first_password_change_that_expires_returns_to_qr_after_one_new_confirmation(application, seeded):
    user = seeded["inspector"]
    user.must_change_password = True
    db.session.commit()
    client = application.test_client()
    qr_path = f"/c/{seeded['daily'].qr_token}"
    first_login = login(client, next=qr_path)
    with rendered_contexts(application) as contexts:
        assert client.get(first_login.location).status_code == 200
    assert contexts[-1][1]["next_url"] == qr_path
    password_fields = {"current_password": PASSWORD, "new_password": "Patrol-recovery-password-12!",
                       "confirm_password": "Patrol-recovery-password-12!", "next": qr_path}
    with client.session_transaction() as session:
        session.clear()
    expired = client.post("/change-password", data=password_fields)
    assert user.check_password(PASSWORD) and user.must_change_password
    login_next = parse_qs(urlsplit(expired.location).query)["next"][0]
    signed_in = login(client, next=login_next)
    with rendered_contexts(application) as contexts:
        assert client.get(signed_in.location).status_code == 200
    assert contexts[-1][0] == "change_password.html"
    assert contexts[-1][1]["next_url"] == qr_path
    assert client.post("/change-password", data=password_fields).location == qr_path
    assert user.check_password(password_fields["new_password"]) and not user.must_change_password


def test_stale_self_revoke_preserves_admin_rejection_and_does_not_create_audit(application, seeded):
    inspector = application.test_client()
    login(inspector)
    assert inspector.post("/devices/request", data={"label": "Old phone"}).status_code == 302
    binding = db.session.scalar(db.select(DeviceBinding))
    assert inspector.get("/devices").status_code == 200
    admin = application.test_client()
    login(admin, "manager")
    assert admin.post(f"/admin/devices/{binding.id}/reject").status_code == 302
    assert inspector.post(f"/devices/{binding.id}/revoke").status_code == 302
    db.session.refresh(binding)
    assert binding.status == "rejected"
    assert db.session.query(AuditLog).filter_by(action="device_self_revoked").count() == 0


def test_repeated_self_revoke_only_audits_real_transition(application, seeded):
    client = application.test_client()
    login(client)
    binding = approve_browser(client, seeded["inspector"])
    for _ in range(2):
        assert client.post(f"/devices/{binding.id}/revoke").status_code == 302
    db.session.refresh(binding)
    assert binding.status == "revoked"
    assert db.session.query(AuditLog).filter_by(action="device_self_revoked").count() == 1


def test_confirm_requires_new_confirmation_after_same_qr_moves_to_another_floor(application, seeded):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    point = seeded["daily"]
    path = f"/c/{point.qr_token}"
    with rendered_contexts(application) as contexts:
        initial = client.get(path)
    assert initial.status_code == 200
    displayed = contexts[-1][1]
    assert f'name="point_revision" value="{displayed["point_revision"]}"' in initial.get_data(as_text=True)
    submitted = {"frequency": "daily", "period_key": displayed["current_period_key"], "slot": displayed["current_slot"],
                 "point_revision": displayed["point_revision"], "note": "現場消防箱已檢查"}
    admin = application.test_client()
    login(admin, "manager")
    assert admin.post(f"/admin/points/{point.id}/update", data={"floor": "5", "code": "5F-MOVED", "name": "五樓消防箱",
                       "frequency": point.frequency, "category": point.category, "active": "on"}).status_code == 302
    with rendered_contexts(application) as contexts:
        response = client.post(path + "/confirm", data=submitted)
    assert response.status_code == 409
    latest = contexts[-1][1]
    assert latest["point"].floor == 5 and latest["note"] == submitted["note"]
    assert "五樓消防箱" in response.get_data(as_text=True)
    assert latest["point_revision"] != submitted["point_revision"]
    assert db.session.query(Inspection).count() == 0
    submitted["point_revision"] = latest["point_revision"]
    assert client.post(path + "/confirm", data=submitted).status_code == 302
    record = db.session.scalar(db.select(Inspection))
    assert (record.point_floor, record.point_code, record.point_name) == (5, "5F-MOVED", "五樓消防箱")


@pytest.mark.parametrize("reporter", ["inspector", "colleague"])
def test_duplicate_submission_with_an_abnormal_report_explains_it_was_not_added(application, seeded, reporter):
    point = seeded["daily"]
    path = f"/c/{point.qr_token}"
    first = application.test_client()
    login(first)
    approve_browser(first, seeded["inspector"])
    second = first
    if reporter == "colleague":
        second = application.test_client()
        login(second, reporter)
        approve_browser(second, seeded[reporter])
    assert second.get(path).status_code == 200
    assert first.post(path + "/confirm", data={"frequency": "daily", "note": "FIRST-PRIVATE-NOTE"}).status_code == 302
    response = second.post(path + "/confirm", data={"frequency": "daily", "is_abnormal": "on", "note": "新增異常"})
    assert response.status_code == 302 and urlsplit(response.location).path == path
    message = second.get(response.location).get_data(as_text=True)
    assert "本次填寫的回報內容未追加" in message
    assert "FIRST-PRIVATE-NOTE" not in message
    record = db.session.scalars(db.select(Inspection)).one()
    assert not record.is_abnormal and record.issue is None and record.note == "FIRST-PRIVATE-NOTE"
