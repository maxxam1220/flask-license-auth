"""The general manager title uses the same patrol scope and attendance rules as a general inspector."""
import pytest

from models import AuditLog, Inspection, InspectionPhoto, IssueEvent, PatrolExecution, User, db
from test_app import PASSWORD, application, login, record, seeded  # noqa: F401
from test_classification_management import form_revision
from test_features import png
from test_workflow_checkin import payload, team


def assign(admin, user, choice, *, revision=None):
    path = f"/admin/users/{user.id}/update"
    if revision is None:
        revision = form_revision(admin, "/admin/users", path)
    return admin.post(path, data={"expected_state": revision, "display_name": user.display_name,
                                  "role": choice, "active": "on"})


def test_create_named_general_inspector_and_reject_admin_self_demotion(application, seeded):
    admin = application.test_client()
    login(admin, "manager")
    actor = seeded["manager"]
    assert assign(admin, actor, "general_manager").status_code == 400
    form = {"username": "general.lead", "display_name": "總務值班", "password": PASSWORD, "role": "general_manager"}
    assert admin.post("/admin/users/create", data=form).status_code == 302
    account = db.session.scalar(db.select(User).where(User.username == "general.lead"))
    assert (account.role, account.patrol_category, account.general_manager_title) == ("inspector", "general", True)
    assert account.must_change_password and actor.role == "admin" and not actor.general_manager_title
    staff = application.test_client()
    assert login(staff, account.username).location == "/change-password"
    fresh = PASSWORD + "-new"
    assert staff.post("/change-password", data={"current_password": PASSWORD, "new_password": fresh,
                                                "confirm_password": fresh}).status_code == 302
    assert "總務管理員" in staff.get("/dashboard").text
    assert staff.get("/admin/users").status_code == 403


def test_title_edits_keep_existing_login_and_attendance_but_invalidate_older_admin_forms(application):
    _, staff, _, admin, _, spot, _ = team(application)
    inspector = db.session.scalar(db.select(User).where(User.username == "inspect"))
    old_version = inspector.auth_version
    submitted = payload(staff, spot)
    first_receipt = staff.post(spot + "/confirm", data=submitted)
    assert first_receipt.status_code == 302
    old_revision = form_revision(admin, "/admin/users", f"/admin/users/{inspector.id}/update")
    assert assign(admin, inspector, "general_manager", revision=old_revision).status_code == 302
    assert assign(admin, inspector, "general", revision=old_revision).status_code == 409
    assert inspector.general_manager_title and inspector.auth_version == old_version
    assert "總務管理員" in staff.get("/dashboard").text
    assert staff.post(spot + "/confirm", data=submitted).location == first_receipt.location
    assert db.session.query(Inspection).count() == 1
    assert assign(admin, inspector, "general").status_code == 302
    assert not inspector.general_manager_title and inspector.auth_version == old_version
    assert "總務巡檢員" in staff.get("/dashboard").text
    edits = db.session.scalars(db.select(AuditLog.detail).where(AuditLog.action == "user_updated")
                               .order_by(AuditLog.id)).all()
    assert len(edits) == 2 and edits[0] != edits[1]
    assert assign(admin, inspector, "general_manager").status_code == 302
    assert assign(admin, inspector, "safety").status_code == 302
    assert (inspector.patrol_category, inspector.general_manager_title) == ("safety", False)
    assert inspector.auth_version > old_version and staff.get("/dashboard").location.startswith("/login")


@pytest.mark.parametrize("title", ["general_manager", "engineering"])
def test_both_titles_share_general_handoffs_and_report_access(application, seeded, title):
    executor, lead, inspector, admin, pair, _, _ = team(application)
    user = db.session.scalar(db.select(User).where(User.username == "inspect"))
    assert assign(admin, user, title).status_code == 302
    safety = seeded["daily"]
    foreign = record(seeded["inspector"], safety)
    foreign.photos.append(InspectionPhoto(data=b"safety-photo", size_bytes=12, width=1, height=1))
    db.session.commit()

    execution_form = payload(executor, pair)
    for client in (lead, inspector):
        for path in ("/admin/users", "/admin/devices", "/admin/points", "/admin/points/print"):
            assert client.get(path).status_code == 403
        assert client.post(f"/admin/users/{user.id}/update", data={"role": "admin"}).status_code == 403
        for path in (f"/c/{safety.qr_token}", f"/records/{foreign.id}", f"/photos/{foreign.photos[0].id}"):
            assert client.get(path).status_code == 404
        assert client.post(f"/c/{safety.qr_token}/confirm", data={"frequency": safety.frequency}).status_code == 404
        assert client.post(pair + "/confirm", data=execution_form).status_code == 409
        assert client.post(pair + "/confirm", data={**execution_form, "stage": "inspect"}).status_code == 409
    assert db.session.query(PatrolExecution).count() == 0 and db.session.query(Inspection).count() == 1

    execution = executor.post(pair + "/confirm", data=execution_form)
    assert execution.status_code == 302
    reports = []
    for client, note in ((lead, "檢查燈具"), (inspector, "設備檢查")):
        saved = client.post(pair + "/confirm", data={**payload(client, pair), "note": note,
                            "is_abnormal": "on", "photos": (png(), "check.png")})
        assert saved.status_code == 302 and saved.location.startswith("/checkins/")
        reports.append(db.session.get(Inspection, int(saved.location.rsplit("/", 1)[-1])))
    first, second = reports
    assert first.execution_id == second.execution_id and first.user_id != second.user_id
    close = {"expected_event_id": "0", "note": "完成修復"}
    for client, own, peer in ((lead, first, second), (inspector, second, first)):
        assert client.get(execution.location).status_code == 200
        assert peer.note in client.get(f"/records/{peer.id}").text
        assert peer.note in client.get("/records/export?category=safety").get_data(as_text=True)
        assert client.get(f"/photos/{peer.photos[0].id}").data == peer.photos[0].data
        assert client.post(f"/issues/{peer.id}/resolve", data=close).status_code == 403
        assert client.post(f"/issues/{own.id}/resolve", data=close).status_code == 302
        assert own.issue.status == "resolved" and own.issue.resolved_by_id == own.user_id
        assert client.post(f"/admin/issues/{own.id}/reopen", data=close).status_code == 403
    assert db.session.query(IssueEvent).count() == 2
