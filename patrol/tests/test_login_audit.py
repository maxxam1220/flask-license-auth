"""Only a successful password sign-in generates a durable, coarse login event."""
import pytest

from login_client import classify_login_client
from models import LoginEvent, db
from test_app import FIXED_NOW, PASSWORD, actors_only, application  # noqa: F401

IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605 Version/18.1 Mobile/15E148 Safari/604"
EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537 Chrome/132.0 Safari/537.36 Edg/132.0"


def test_only_successful_password_logins_are_logged(application, actors_only):
    phone, pc = application.test_client(), application.test_client()
    worker = actors_only["inspector"]
    worker.must_change_password = True
    db.session.commit()
    def post(client, username, ua, password=PASSWORD):
        return client.post("/login", data=dict(username=username, password=password),
                           headers={"User-Agent": ua})
    assert post(phone, worker.username, IPHONE, "incorrect").status_code == 200
    assert post(phone, worker.username, IPHONE).location.endswith("/change-password")
    assert phone.get("/change-password").status_code == 200
    assert phone.post("/logout").status_code == 302
    assert post(pc, "manager", EDGE).location.endswith("/dashboard")
    assert pc.get("/dashboard").status_code == 200
    # Same browser switches to a different verified account.
    assert post(pc, worker.username, EDGE).location.endswith("/change-password")
    rows = db.session.scalars(db.select(LoginEvent).order_by(LoginEvent.id)).all()
    assert [(r.username, r.client_type, r.browser) for r in rows] == [
        ("inspector", "mobile", "Safari"), ("manager", "desktop", "Edge"), ("inspector", "desktop", "Edge")]
    assert rows[0].display_name == worker.display_name and rows[0].created_at == FIXED_NOW.replace(tzinfo=None)


@pytest.mark.parametrize(("ua", "hint", "expected"), [
    ("Mozilla/5.0 (iPad) Version/17.0 Mobile/15E148 Safari/604.1", None, ("tablet", "Safari")),
    ("Mozilla/5.0 (Linux; Android 14) Chrome/123.0 Mobile Safari/537", "?1", ("mobile", "Chrome")),
    ("Mozilla/5.0 (Linux; Android 14) Chrome/123.0 Safari/537", "?0", ("tablet", "Chrome")),
    (IPHONE + " Line/15.0", None, ("mobile", "LINE")),
    ("Mozilla/5.0 (iPhone) FxiOS/129.0 Mobile/15E148 Safari/605.1", None, ("mobile", "Firefox")),
    ("fixture-private-device-id", None, ("unknown", "無法辨識")),
    ("", None, ("unknown", "無法辨識")),
])
def test_device_and_browser_labels(ua, hint, expected):
    assert classify_login_client(ua, hint) == expected
