"""工務 is a display title on the existing general inspector permission scope."""
from account_roles import account_role_choice, role_label
from models import DeviceBinding, Inspection, OfflineSubmission, User, db
from test_app import PASSWORD, application, login, seeded
from test_classification_management import form_revision
from test_daily2_anytime import anytime
from test_general_manager_role import assign
from test_offline_api import entry, prepare, sync


def test_create_engineering_title_has_general_scope_without_management_access(application, seeded):
    admin = application.test_client()
    login(admin, "manager")
    response = admin.post("/admin/users/create", data={"username": "engineering.inspector", "display_name": "工務值班",
                                                     "password": PASSWORD, "role": "engineering"})
    assert response.status_code == 302
    user = db.session.scalar(db.select(User).where(User.username == "engineering.inspector"))
    assert (user.role, user.patrol_category, user.general_manager_title, user.engineering_inspector_title) == (
        "inspector", "general", False, True)
    assert account_role_choice(user) == "engineering" and role_label(user) == "工務巡檢員"
    assert user.must_change_password
    staff = application.test_client()
    assert login(staff, user.username).location == "/change-password"
    password = PASSWORD + "-changed"
    assert staff.post("/change-password", data={"current_password": PASSWORD, "new_password": password,
                                               "confirm_password": password}).status_code == 302
    assert "工務巡檢員" in staff.get("/dashboard").text
    for path in ("/admin/users", "/admin/login-records", "/admin/devices", "/admin/points"):
        assert staff.get(path).status_code == 403
    assert assign(admin, seeded["manager"], "engineering").status_code == 400


def test_title_switch_keeps_binding_session_and_prepared_offline_grant(application, anytime):
    a = anytime
    user = db.session.scalar(db.select(User).where(User.username == "inspect"))
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == user.id))
    before = (user.auth_version, binding.id, binding.token_hash, binding.status)
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0], note="Before title change")
    revision = form_revision(a.admin, "/admin/users", f"/admin/users/{user.id}/update")
    assert assign(a.admin, user, "engineering", revision=revision).status_code == 302
    assert assign(a.admin, user, "general", revision=revision).status_code == 409
    assert (user.auth_version, binding.id, binding.token_hash, binding.status) == before
    assert "工務巡檢員" in a.inspector.get("/dashboard").text
    renamed = prepare(a.inspector)
    assert renamed["owner"] == prepared["owner"] and renamed["identity"]["role_label"] == "工務巡檢員"
    saved = sync(a.inspector, prepared, item)
    assert saved.status_code == 200 and saved.json["status"] == "saved", saved.json
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 1
    assert assign(a.admin, user, "general_manager").status_code == 302
    assert user.general_manager_title and not user.engineering_inspector_title
    assert user.auth_version == before[0] and role_label(user) == "總務管理員"
    retry = sync(a.inspector, prepared, item)
    assert retry.status_code == 200 and retry.json["status"] == "already_synced"
    assert assign(a.admin, user, "engineering").status_code == 302
    assert user.engineering_inspector_title and not user.general_manager_title
    assert assign(a.admin, user, "general").status_code == 302
    assert not user.engineering_inspector_title and not user.general_manager_title
    assert user.auth_version == before[0] and role_label(user) == "總務巡檢員"


def test_real_category_change_clears_engineering_title_and_revokes_old_session(application, anytime):
    a = anytime
    user = db.session.scalar(db.select(User).where(User.username == "inspect"))
    original_version = user.auth_version
    assert assign(a.admin, user, "engineering").status_code == 302
    assert assign(a.admin, user, "safety").status_code == 302
    assert (user.role, user.patrol_category, user.engineering_inspector_title, user.general_manager_title) == (
        "inspector", "safety", False, False)
    assert user.auth_version == original_version + 1
    assert a.inspector.get("/dashboard").location.startswith("/login")
