import pytest

from models import db
from test_app import actors_only, application, login


@pytest.mark.parametrize("username,category,allowed", [
    ("inspector", "safety", True),
    ("inspector", "general", True),
    ("inspector", None, False),
    ("manager", None, True),
])
def test_scanner_ui_and_camera_permission_share_the_same_scope(application, actors_only, username, category, allowed):
    client = application.test_client()
    actors_only[username].patrol_category = category
    db.session.commit()
    anonymous = client.get("/dashboard")
    assert anonymous.status_code == 302
    assert "camera=()" in anonymous.headers["Permissions-Policy"]
    login(client, username)
    for path in ("/dashboard", "/devices", "/records"):
        response = client.get(path)
        assert response.status_code == 200
        assert (b"data-qr-start" in response.data) == allowed
        assert response.data.count(b"data-qr-dialog") == int(allowed)
        if allowed:
            assert 'data-qr-decoder="/static/vendor/jsqr-1.4.0.js"' in response.text
            assert 'role="dialog" aria-labelledby="patrol-scanner-title"' in response.text
        assert ("camera=(self)" in response.headers["Permissions-Policy"]) == allowed
        assert "microphone=()" in response.headers["Permissions-Policy"]
        assert "geolocation=()" in response.headers["Permissions-Policy"]
        assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    for path in ("/change-password", "/c/invalid-test-code", "/healthz", "/static/logo.ico", "/records/export"):
        response = client.get(path)
        assert "camera=()" in response.headers["Permissions-Policy"]
        assert b"data-qr-start" not in response.data


def test_offline_scanner_keeps_its_decoder_path_and_accessible_dialog_contract(application):
    page = application.test_client().get("/offline")
    assert page.status_code == 200
    assert page.data.count(b"data-qr-dialog") == 1
    assert 'data-qr-decoder="/static/vendor/jsqr-1.4.0.js"' in page.text
    assert 'role="dialog" aria-labelledby="patrol-scanner-title"' in page.text
    assert 'data-qr-close' in page.text and '手機內建相機' in page.text


def test_decoder_url_uses_template_url_generation_instead_of_current_script(application, actors_only):
    client = application.test_client()
    login(client, "inspector")
    page = client.get("/dashboard", environ_overrides={"SCRIPT_NAME": "/patrol"})
    assert page.status_code == 200
    assert 'data-qr-decoder="/patrol/static/vendor/jsqr-1.4.0.js"' in page.text
