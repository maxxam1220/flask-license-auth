"""A private language hint works without granting an unbound browser attendance access."""
import pytest

import app as patrol
from models import DeviceBinding, Inspection, OfflineSubmission, PatrolExecution, User, db
from test_app import PASSWORD, application, login, seeded
from test_daily2_anytime import anytime
from test_offline_api import entry, prepare, sync


@pytest.mark.parametrize("locale", ["id", "vi"])
@pytest.mark.parametrize("binding_state", ["absent", "pending", "revoked"])
def test_signed_in_unbound_hint_is_private_and_cannot_prepare_or_sync(application, anytime, locale, binding_state):
    a = anytime
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.ui_language, actor.simple_executor_ui = locale, True
    db.session.commit()
    original = prepare(a.executor)
    pending = entry(original, a.paired, a.clock[0])
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == actor.id))
    if binding_state == "absent":
        a.executor.delete_cookie("patrol_device")
    else:
        binding.status = binding_state
        db.session.commit()
    response = a.executor.get("/api/ui-preferences")
    assert response.status_code == 200
    assert response.json == {"ok": True, "ui_language": locale, "simple_executor_ui": True, "home_url": "/ready"}
    assert response.headers["Cache-Control"] == "private, no-store"
    assert "Access-Control-Allow-Origin" not in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Permissions-Policy"].startswith("camera=()")
    for path in ("/api/offline/status", "/api/offline/prepare"):
        denied = a.executor.get(path)
        assert denied.status_code == 403 and denied.json["code"] == "device_required"
    denied = sync(a.executor, original, pending)
    assert denied.status_code == 403 and denied.json["code"] == "device_required"
    assert a.executor.post(a.paired + "/confirm", data={}).status_code == 403
    assert db.session.query(PatrolExecution).count() == db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0
    public = application.test_client().get("/offline")
    assert a.executor.get("/offline").data == public.data


def test_password_setup_hint_does_not_replace_scanned_return_or_enable_other_routes(application, anytime):
    a = anytime
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.ui_language, actor.simple_executor_ui, actor.must_change_password = "vi", True, True
    db.session.commit()
    with a.executor.session_transaction() as state:
        state["after_password"] = a.paired
    response = a.executor.get("/api/ui-preferences")
    assert response.status_code == 200 and response.is_json and response.json["ui_language"] == "vi"
    with a.executor.session_transaction() as state:
        assert state["after_password"] == a.paired
    assert a.executor.get("/ready").location.startswith("/change-password")
    assert a.executor.get("/api/offline/prepare").json["code"] == "password_required"
    assert a.executor.post(a.paired + "/confirm", data={}).location.startswith("/change-password")


def test_preference_hint_tracks_account_switch_and_live_settings_without_inferred_authority(application, seeded):
    actor = seeded["inspector"]
    actor.role, actor.patrol_category, actor.ui_language, actor.simple_executor_ui = "executor", "general", "id", True
    db.session.commit()
    client = application.test_client()
    assert login(client, actor.username).status_code == 302
    assert client.get("/api/ui-preferences").json["home_url"] == "/ready"
    assert client.get("/admin/users").status_code == 403
    actor.ui_language = "vi"
    db.session.commit()
    assert client.get("/api/ui-preferences").json["ui_language"] == "vi"
    assert login(client, "manager").status_code == 302
    assert client.get("/api/ui-preferences").json == {"ok": True, "ui_language": "zh-Hant",
                                                    "simple_executor_ui": False, "home_url": "/dashboard"}
    assert client.post("/logout").status_code == 302
    assert client.get("/api/ui-preferences").status_code == 401


@pytest.mark.parametrize("change", ["anonymous", "stale-version", "disabled", "revoked-login"])
def test_unauthenticated_or_revoked_hint_has_no_private_preferences(application, seeded, change):
    actor = seeded["inspector"]
    actor.ui_language = "vi"
    db.session.commit()
    client = application.test_client()
    if change != "anonymous":
        login(client, actor.username)
        if change == "stale-version":
            actor.auth_version += 1
        elif change == "disabled":
            actor.active = False
        else:
            stale_cookie = client.get_cookie("patrol_session").value
            client.post("/logout")
            client.set_cookie("patrol_session", stale_cookie)
        db.session.commit()
    with client.session_transaction() as state:
        state["ui_language"] = "id"  # A remembered language is not authentication.
    response = client.get("/api/ui-preferences")
    assert response.status_code == 401 and response.json == {"ok": False, "code": "login_required"}
    assert response.headers["Cache-Control"] == "private, no-store"


def test_ui_hint_is_read_only_and_never_uses_requested_locale_or_home(application, seeded):
    client = application.test_client()
    login(client, "inspector")
    response = client.get("/api/ui-preferences?ui_language=vi&simple_executor_ui=1&home_url=https://example.test/")
    assert response.json == {"ok": True, "ui_language": "zh-Hant", "simple_executor_ui": False, "home_url": "/dashboard"}
    assert client.post("/api/ui-preferences", data={"ui_language": "vi"}).status_code == 405
    assert seeded["inspector"].ui_language == "zh-Hant" and not seeded["inspector"].simple_executor_ui
