"""Per-account presentation settings never change the underlying patrol authority."""
from datetime import date, timedelta

import pytest
from werkzeug.datastructures import MultiDict

import app as patrol
from models import DeviceBinding, Inspection, PatrolExecution, Point, User, db
from test_app import PASSWORD, application, login, rendered_contexts, seeded
from test_classification_management import form_revision
from test_daily2_anytime import anytime
from test_offline_api import entry, prepare, sync
from test_ready_patrol import ready
from test_workflow_checkin import payload, team


def preferences(admin, user, *, language="id", simple="1", role="general_executor", revision=None):
    path = f"/admin/users/{user.id}/update"
    return admin.post(path, data={"expected_state": revision or form_revision(admin, "/admin/users", path),
        "display_name": user.display_name, "role": role, "active": "on",
        "ui_language": language, "simple_executor_ui": simple})


def test_preferences_are_explicit_default_safe_and_admin_only(application, seeded):
    admin = application.test_client()
    login(admin, "manager")
    base = {"password": PASSWORD, "role": "general_executor"}
    for username, name in (("foreign-a", "怒西"), ("foreign-b", "裴氏惠")):
        assert admin.post("/admin/users/create", data=base | {"username": username, "display_name": name}).status_code == 302
    users = db.session.scalars(db.select(User).where(User.username.like("foreign-%"))).all()
    assert all(user.ui_language == "zh-Hant" and not user.simple_executor_ui for user in users)
    assert preferences(admin, users[0]).status_code == 302
    assert preferences(admin, users[1], language="vi").status_code == 302
    assert [(u.ui_language, u.simple_executor_ui) for u in users] == [("id", True), ("vi", True)]
    worker = application.test_client()
    login(worker, "inspector")
    assert preferences(worker, users[0], revision="irrelevant").status_code == 403
    assert worker.get("/admin/users").status_code == 403


@pytest.mark.parametrize("field,values", [("ui_language", ["en"]), ("ui_language", ["id", "vi"]),
                                         ("simple_executor_ui", ["on"]), ("simple_executor_ui", ["0", "1"])])
def test_invalid_or_duplicated_settings_never_update_account(application, seeded, field, values):
    admin = application.test_client()
    login(admin, "manager")
    user = seeded["inspector"]
    original = patrol.management_state(user)
    form = MultiDict({"display_name": user.display_name, "role": "safety", "active": "on"})
    form.setlist(field, values)
    assert admin.post(f"/admin/users/{user.id}/update", data=form).status_code == 400
    assert patrol.management_state(user) == original


def test_presentation_change_preserves_bound_session_and_existing_offline_grant(application, anytime):
    a = anytime
    user = db.session.scalar(db.select(User).where(User.username == "exec"))
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == user.id))
    original = (user.auth_version, binding.id, binding.token_hash, binding.status)
    prepared = prepare(a.executor)
    pending = entry(prepared, a.paired, a.clock[0])
    revision = form_revision(a.admin, "/admin/users", f"/admin/users/{user.id}/update")
    assert preferences(a.admin, user, revision=revision).status_code == 302
    assert preferences(a.admin, user, language="vi", revision=revision).status_code == 409
    assert (user.auth_version, binding.id, binding.token_hash, binding.status) == original
    assert a.executor.get("/dashboard").location == "/ready"
    assert prepare(a.executor)["owner"] == prepared["owner"]
    saved = sync(a.executor, prepared, pending)
    assert saved.status_code == 200 and saved.json["status"] == "saved"
    assert db.session.query(PatrolExecution).count() == 1
    assert sync(a.executor, prepared, pending).json["status"] == "already_synced"
    # An older form preserves preferences; an actual role change resets only the interface.
    old_form = {"display_name": user.display_name, "role": "general_executor", "active": "on"}
    assert a.admin.post(f"/admin/users/{user.id}/update", data=old_form).status_code == 302
    assert user.ui_language == "id" and user.simple_executor_ui
    assert a.admin.post(f"/admin/users/{user.id}/update", data=old_form | {"role": "general"}).status_code == 302
    assert user.ui_language == "id" and not user.simple_executor_ui and user.auth_version == original[0] + 1


def test_simple_login_logout_and_account_switch_preserve_authoritative_locale(application, seeded):
    worker = seeded["inspector"]
    worker.role, worker.patrol_category, worker.ui_language, worker.simple_executor_ui = "executor", "general", "id", True
    db.session.commit()
    client = application.test_client()
    assert login(client, worker.username).location == "/ready"
    with rendered_contexts(application) as rendered:
        assert client.get("/ready").status_code == 200
    context = rendered[-1][1]
    assert (context["ui_locale"], context["simple_executor_ui"], context["home_url"]) == ("id", True, "/ready")
    assert client.get("/").location == "/ready"
    assert client.get("/dashboard?floor=5").location == "/ready?floor=5"
    assert client.post("/logout").status_code == 302
    with client.session_transaction() as state:
        assert state["ui_language"] == "id" and "user_id" not in state
    assert login(client, "manager").location == "/dashboard"
    with rendered_contexts(application) as rendered:
        client.get("/admin/users")
    assert rendered[-1][1]["ui_locale"] == "zh-Hant" and not rendered[-1][1]["simple_executor_ui"]


def test_simple_password_and_device_workflows_keep_scanned_destination(application):
    executor, _, _, _, paired, *_ = team(application)
    user = db.session.scalar(db.select(User).where(User.username == "exec"))
    user.set_password(PASSWORD)
    user.ui_language, user.simple_executor_ui, user.must_change_password = "vi", True, True
    db.session.commit()
    client = application.test_client()
    assert client.post("/login", data={"username": "exec", "password": PASSWORD, "next": paired}).location == "/change-password"
    changed = client.post("/change-password", data={"current_password": PASSWORD,
        "new_password": PASSWORD + "new", "confirm_password": PASSWORD + "new"})
    assert changed.location == paired
    assert client.post(paired + "/confirm", data={}).status_code == 403
    with rendered_contexts(application) as rendered:
        page = client.get("/devices", query_string={"next": paired})
    assert page.status_code == 200 and rendered[-1][1]["ui_locale"] == "vi"
    assert paired in page.text


def test_expired_simple_session_keeps_language_without_preserving_authority(application, seeded):
    user = seeded["inspector"]
    user.role, user.patrol_category, user.ui_language, user.simple_executor_ui = "executor", "general", "vi", True
    db.session.commit()
    client = application.test_client()
    login(client, user.username)
    user.auth_version += 1
    db.session.commit()
    assert client.get("/ready").location.startswith("/login")
    with client.session_transaction() as state:
        assert state["ui_language"] == "vi" and "user_id" not in state


def test_simple_ready_adds_only_allowed_irregular_points_with_personal_daily_eligibility(application, monkeypatch):
    executor, inspector, peer, _, _, _, _ = team(application)
    user = db.session.scalar(db.select(User).where(User.username == "exec"))
    user.simple_executor_ui = True
    peer_user = db.session.scalar(db.select(User).where(User.username == "peer"))
    peer_user.role, peer_user.simple_executor_ui = "executor", True
    application.config["EXECUTOR_VISIT_CODES"] = frozenset({"1F-OPEN", "2F-OPEN"})
    urls = {}
    for code, frequency, category in (("1F-OPEN", "irregular", "general"), ("2F-OPEN", "irregular", "general"),
                                       ("1F-EXTRA", "irregular", "general"), ("1F-NO", "daily", "general"),
                                       ("1F-SAFE", "irregular", "safety")):
        point = Point(code=code, name=code, floor=2 if code.startswith("2") else 1, category=category,
                      workflow_mode="spot" if category == "general" else "standard", frequency=frequency,
                      schedule_start=date(2020, 1, 1), active=True)
        db.session.add(point)
        db.session.flush()
        urls[code] = "/c/" + point.qr_token
    db.session.commit()
    initial = ready(application, executor)
    assert {code for code, stage in initial.items() if stage == "visit"} == {"1F-OPEN", "2F-OPEN"}
    assert {code for code, stage in ready(application, executor, "/ready?floor=2").items() if stage == "visit"} == {"2F-OPEN"}
    assert "1F-OPEN" not in ready(application, inspector)
    assert executor.post(urls["1F-OPEN"] + "/confirm", data=payload(executor, urls["1F-OPEN"])).status_code == 302
    assert "1F-OPEN" not in ready(application, executor) and "1F-OPEN" in ready(application, peer)
    assert executor.get(urls["1F-NO"]).status_code == executor.get(urls["1F-SAFE"]).status_code == 404
    now = patrol.now_utc()
    monkeypatch.setattr(patrol, "now_utc", lambda: now + timedelta(days=1))
    assert ready(application, executor)["1F-OPEN"] == "visit"


def test_server_errors_and_flashes_use_translation_boundary(application, seeded, monkeypatch):
    client = application.test_client()
    login(client, "inspector")
    monkeypatch.setattr(patrol, "t", lambda source, **kwargs: "translated:" + str(source))
    assert "translated:此功能僅限系統管理員使用。" in client.get("/admin/users").text
    client.post("/change-password", data={"current_password": "wrong"})
    with client.session_transaction() as state:
        # Rendering consumes flashes, so the error page itself is the evidence.
        assert state["user_id"] == seeded["inspector"].id
    assert "translated:目前密碼不正確。" in client.post("/change-password", data={"current_password": "wrong"}).text
