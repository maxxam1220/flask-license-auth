"""Admin transitions must preserve history, invalidate stale access and QR labels."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from models import AuditLog, InspectionIssue, InspectionPhoto, User, db
from test_app import (FIXED_NOW, PASSWORD, application, approve_browser, login,
                      record, seeded)


def test_role_change_revokes_old_session_but_keeps_phone_and_password(application, seeded):
    worker, admin = application.test_client(), application.test_client()
    login(worker)
    login(admin, "manager")
    user = seeded["inspector"]
    device = approve_browser(worker, user)
    password, version = user.password_hash, user.auth_version
    target = f"/admin/users/{user.id}/update"
    form = {"display_name": user.display_name, "active": "on"}
    for invalid in ("inspector", "uncategorized", "", "ADMIN"):
        assert admin.post(target, data={**form, "role": invalid}).status_code == 400
    assert admin.post(target, data={**form, "role": "general"}).status_code == 302
    assert (user.role, user.patrol_category, user.active, user.auth_version) == ("inspector", "general", True, version + 1)
    assert user.password_hash == password and device.status == "approved"
    assert "/login" in worker.get("/dashboard").location
    login(worker)
    assert seeded["daily"].code not in worker.get("/dashboard").get_data(as_text=True)
    assert admin.post(target, data={**form, "role": "general"}).status_code == 302
    assert user.auth_version == version + 1 and worker.get("/dashboard").status_code == 200


@pytest.mark.parametrize("choice,expected", [("general", ("inspector", "general")), ("safety", ("inspector", "safety")),
                                            ("admin", ("admin", None))])
def test_new_account_roles(application, seeded, choice, expected):
    manager = application.test_client()
    login(manager, "manager")
    form = dict(username="test.new", display_name="New staff", password=PASSWORD)
    assert manager.post("/admin/users/create", data=form).status_code == 400
    assert manager.post("/admin/users/create", data={**form, "role": choice}).status_code == 302
    user = db.session.scalar(select(User).where(User.username == "test.new"))
    assert (user.role, user.patrol_category) == expected and user.must_change_password


def test_archive_restore_preserves_history_and_permanently_retires_printed_token(application, seeded):
    admin, worker = application.test_client(), application.test_client()
    login(admin, "manager")
    login(worker)
    approve_browser(worker, seeded["inspector"])
    p = seeded["daily"]
    original_token, pid = p.qr_token, p.id
    saved = record(seeded["inspector"], p, FIXED_NOW - timedelta(days=2))
    saved.is_abnormal = True
    saved.issue = InspectionIssue(status="open", opened_at=saved.created_at)
    saved.photos.append(InspectionPhoto(data=b"test picture", size_bytes=12, width=1, height=1))
    db.session.commit()
    path = f"/admin/points/{pid}"
    form = {"code": p.code, "name": p.name, "frequency": p.frequency, "floor": str(p.floor), "category": p.category, "active": "on"}
    missed = "/missed/export?date_from=2026-11-01&date_to=2026-11-02&floor=1"
    before = worker.get(missed).data
    assert p.code.encode() in before
    assert worker.post(path + "/delete").status_code == 403
    assert admin.post(path + "/delete?floor=oops").status_code == 400 and p.active
    response = admin.post(path + "/delete?floor=1&category=safety")
    assert response.status_code == 302 and "floor=1" in response.location and "category=safety" in response.location
    assert p.deleted_at and not p.active and p.qr_token != original_token and not p.schedules[-1].active
    assert p.code not in admin.get("/admin/points").get_data(as_text=True)
    assert p.code in admin.get("/admin/points?list=deleted").get_data(as_text=True)
    for suffix in ("/delete", "/rotate-qr", "/update"):
        assert admin.post(path + suffix, data=form).status_code == 404
    assert admin.get(path + "/qr.svg").status_code == 404
    assert p.code not in admin.get(f"/admin/points/print?ids={pid}").get_data(as_text=True)
    for token in (original_token, p.qr_token):
        assert worker.get("/c/" + token).status_code == 404
        assert worker.post("/c/" + token + "/confirm", data={"frequency": p.frequency}).status_code == 404
    assert admin.post("/admin/points/create", data=form).status_code == 400
    assert worker.get(missed).data == before
    assert worker.get(f"/records/{saved.id}").status_code == 200
    assert worker.get(f"/photos/{saved.photos[0].id}").data == b"test picture"
    assert p.code in worker.get(f"/issues?point_id={pid}").get_data(as_text=True)
    assert worker.post(path + "/restore").status_code == 403
    result = admin.post(path + "/restore?floor=1")
    assert result.status_code == 302 and "list=deleted" in result.location
    assert not p.active and p.deleted_at is None
    assert admin.post(path + "/restore").status_code == 404
    assert worker.get("/c/" + p.qr_token).status_code == 403
    assert admin.post(path + "/update", data=form).status_code == 302
    assert worker.get("/c/" + original_token).status_code == 404
    assert worker.get("/c/" + p.qr_token).status_code == 200
    logs = db.session.scalars(select(AuditLog.action).where(AuditLog.target == p.code).order_by(AuditLog.id)).all()
    assert logs == ["point_deleted", "point_restored", "point_updated"]


def test_new_points_need_a_department(application, seeded):
    admin = application.test_client()
    login(admin, "manager")
    form = dict(code="1F-RR09", name="test post", floor="1", frequency="daily")
    for category in ("", "uncategorized", "all"):
        assert admin.post("/admin/points/create", data={**form, "category": category}).status_code == 400
    assert admin.post("/admin/points/create", data={**form, "category": "general"}).status_code == 302
