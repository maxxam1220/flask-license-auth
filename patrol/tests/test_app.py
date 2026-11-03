"""Integration checks for authorization, device approval and inspection periods.

All data uses an isolated in-memory SQLite database.  No production service or
account is contacted by these tests.
"""

from datetime import date, datetime, timedelta, timezone
from contextlib import contextmanager
import csv
import importlib
import io
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree

import pytest
from flask import template_rendered
from sqlalchemy.exc import IntegrityError


app_module = importlib.import_module("app")
from models import DeviceBinding, Inspection, Point, PointSchedule, User  # noqa: E402


db = app_module.db
PASSWORD = "Patrol-test-password-123!"
FIXED_NOW = datetime(2026, 11, 3, 4, 0, tzinfo=timezone.utc)


@pytest.fixture
def application(monkeypatch):
    monkeypatch.setattr(app_module, "now_utc", lambda: FIXED_NOW)
    application = app_module.create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "CSRF_ENABLED": False,
            "PUBLIC_BASE_URL": "https://patrol.example.test",
            "COOKIE_SECURE": False,
        }
    )
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def seeded(application):
    users = {}
    for username, display_name, role in (
        ("inspector", "Inspector Alpha", "inspector"),
        ("colleague", "Inspector Bravo", "inspector"),
        ("manager", "Manager Charlie", "admin"),
    ):
        user = User(
            username=username,
            display_name=display_name,
            role=role,
            active=True,
            must_change_password=False,
        )
        user.set_password(PASSWORD)
        db.session.add(user)
        users[username] = user
    daily = Point(
        code="1F-A01",
        name="Daily Test Point",
        floor=1,
        frequency="daily",
        active=True,
        qr_token="daily-test-token-0123456789abcdef",
        schedule_start=date(2026, 1, 1),
    )
    weekly = Point(
        code="5F-A01",
        name="Weekly Test Point",
        floor=5,
        frequency="weekly",
        active=True,
        qr_token="weekly-test-token-0123456789abcdef",
        schedule_start=date(2026, 1, 1),
    )
    for point in (daily, weekly):
        point.schedules.append(PointSchedule(
            effective_date=point.schedule_start, frequency=point.frequency, active=True
        ))
    db.session.add_all([daily, weekly])
    db.session.commit()
    return {**users, "daily": daily, "weekly": weekly}


def login(client, username="inspector", **extra):
    return client.post(
        "/login", data={"username": username, "password": PASSWORD, **extra}
    )


def approve_browser(client, user, token=None):
    token = token or ("browser-secret-" + user.username + "-" + "a" * 32)
    binding = DeviceBinding(
        user_id=user.id,
        token_hash=app_module.hash_device_token(token),
        label="Test mobile browser",
        status="approved",
    )
    db.session.add(binding)
    db.session.commit()
    client.set_cookie("patrol_device", token)
    return binding


def submit(client, point):
    return client.post(f"/c/{point.qr_token}/confirm")


def count_inspections():
    return db.session.query(Inspection).count()


def record(user, point, instant=FIXED_NOW):
    period_key, _, _ = app_module.period_for(point, instant)
    result = Inspection(
        user_id=user.id,
        point_id=point.id,
        created_at=instant.replace(tzinfo=None),
        period_key=period_key,
        frequency=point.frequency,
        point_code=point.code,
        point_name=point.name,
        point_floor=point.floor,
        user_name=user.display_name,
    )
    db.session.add(result)
    db.session.commit()
    return result


@contextmanager
def rendered_contexts(application):
    rendered = []

    def capture(sender, template, context, **extra):
        rendered.append((template.name, context))

    template_rendered.connect(capture, application)
    try:
        yield rendered
    finally:
        template_rendered.disconnect(capture, application)


def test_qr_get_never_records_inspection(application, seeded):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    for _ in range(2):
        response = client.get(f"/c/{seeded['daily'].qr_token}")
        assert response.status_code == 200
    assert count_inspections() == 0


def test_anonymous_submission_requires_login(application, seeded):
    client = application.test_client()
    response = submit(client, seeded["daily"])
    assert response.status_code in (302, 303, 401, 403)
    assert count_inspections() == 0
    if response.status_code in (302, 303):
        assert urlsplit(response.headers["Location"]).path == "/login"


@pytest.mark.parametrize("username", ["inspector", "manager"])
def test_even_admin_needs_approved_browser(application, seeded, username):
    client = application.test_client()
    login(client, username)
    response = submit(client, seeded["daily"])
    assert response.status_code == 403
    assert count_inspections() == 0


def test_cookie_approved_for_another_user_cannot_check_in(application, seeded):
    client = application.test_client()
    login(client, "inspector")
    approve_browser(client, seeded["colleague"])
    assert submit(client, seeded["daily"]).status_code == 403
    assert count_inspections() == 0


def test_valid_approved_browser_records_authenticated_user(application, seeded):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    response = submit(client, seeded["daily"])
    assert response.status_code in (302, 303)
    saved = db.session.query(Inspection).one()
    assert saved.user_id == seeded["inspector"].id
    assert saved.point_id == seeded["daily"].id
    assert saved.point_code == "1F-A01"
    assert saved.period_key == "2026-11-03"


@pytest.mark.parametrize("point_name", ["daily", "weekly"])
def test_period_is_completed_once_even_by_different_inspectors(
    application, seeded, point_name
):
    for username in ("inspector", "colleague"):
        client = application.test_client()
        login(client, username)
        approve_browser(client, seeded[username])
        response = submit(client, seeded[point_name])
        assert response.status_code in (302, 303)
    assert count_inspections() == 1


def test_database_rejects_duplicate_point_period(application, seeded):
    record(seeded["inspector"], seeded["daily"])
    with pytest.raises(IntegrityError):
        record(seeded["colleague"], seeded["daily"])
    db.session.rollback()
    assert count_inspections() == 1


@pytest.mark.parametrize(
    "point_name, instant, expected_key, expected_start, length_days",
    [
        (
            "daily",
            datetime(2026, 11, 2, 15, 59, 59, tzinfo=timezone.utc),
            "2026-11-02",
            datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc),
            1,
        ),
        (
            "daily",
            datetime(2026, 11, 2, 16, 0, tzinfo=timezone.utc),
            "2026-11-03",
            datetime(2026, 11, 2, 16, 0, tzinfo=timezone.utc),
            1,
        ),
        (
            "weekly",
            datetime(2026, 11, 1, 15, 59, 59, tzinfo=timezone.utc),
            "2026-10-26",
            datetime(2026, 10, 25, 16, 0, tzinfo=timezone.utc),
            7,
        ),
        (
            "weekly",
            datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc),
            "2026-11-02",
            datetime(2026, 11, 1, 16, 0, tzinfo=timezone.utc),
            7,
        ),
    ],
)
def test_period_uses_taipei_midnight_and_monday(
    application, seeded, point_name, instant, expected_key, expected_start, length_days
):
    key, start, end = app_module.period_for(seeded[point_name], instant)
    assert key == expected_key
    assert start.tzinfo is not None and end.tzinfo is not None
    assert start == expected_start
    assert end - start == timedelta(days=length_days)
    assert start <= instant < end


def test_next_taipei_day_can_be_recorded_again(application, seeded, monkeypatch):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    assert submit(client, seeded["daily"]).status_code in (302, 303)
    monkeypatch.setattr(
        app_module,
        "now_utc",
        lambda: datetime(2026, 11, 3, 16, 0, tzinfo=timezone.utc),
    )
    assert submit(client, seeded["daily"]).status_code in (302, 303)
    assert count_inspections() == 2


@pytest.mark.parametrize("status", ["pending", "rejected", "revoked"])
def test_unapproved_or_revoked_device_cannot_submit(application, seeded, status):
    client = application.test_client()
    login(client)
    binding = approve_browser(client, seeded["inspector"])
    binding.status = status
    db.session.commit()
    assert submit(client, seeded["daily"]).status_code == 403
    assert count_inspections() == 0


def test_approving_replacement_revokes_old_browser(application, seeded):
    old_client = application.test_client()
    login(old_client)
    old_binding = approve_browser(old_client, seeded["inspector"])
    new_client = application.test_client()
    login(new_client)
    response = new_client.post("/devices/request", data={"label": "Replacement phone"})
    assert response.status_code in (302, 303)
    pending = db.session.query(DeviceBinding).filter_by(
        user_id=seeded["inspector"].id, status="pending"
    ).one()
    admin_client = application.test_client()
    login(admin_client, "manager")
    response = admin_client.post(f"/admin/devices/{pending.id}/approve")
    assert response.status_code in (302, 303)
    db.session.refresh(old_binding)
    db.session.refresh(pending)
    assert old_binding.status == "revoked"
    assert pending.status == "approved"
    assert db.session.query(DeviceBinding).filter_by(
        user_id=seeded["inspector"].id, status="approved"
    ).count() == 1
    assert submit(old_client, seeded["daily"]).status_code == 403
    assert count_inspections() == 0
    assert submit(new_client, seeded["daily"]).status_code in (302, 303)
    assert count_inspections() == 1


def test_device_request_stores_hash_not_cookie_secret(application, seeded):
    client = application.test_client()
    login(client)
    response = client.post("/devices/request", data={"label": "My work phone"})
    assert response.status_code in (302, 303)
    cookie = client.get_cookie("patrol_device")
    assert cookie is not None and len(cookie.value) >= 32
    binding = db.session.query(DeviceBinding).filter_by(
        user_id=seeded["inspector"].id
    ).one()
    assert binding.status == "pending"
    assert binding.token_hash != cookie.value
    assert binding.token_hash == app_module.hash_device_token(cookie.value)
    assert cookie.http_only


def test_staff_cannot_approve_devices_or_create_points(application, seeded):
    client = application.test_client()
    login(client)
    binding = DeviceBinding(
        user_id=seeded["inspector"].id,
        token_hash=app_module.hash_device_token("unapproved-secret"),
        label="Unapproved",
        status="pending",
    )
    db.session.add(binding)
    db.session.commit()
    assert client.get("/admin/points").status_code == 403
    assert client.post(f"/admin/devices/{binding.id}/approve").status_code == 403
    assert client.post("/admin/points/create", data={
        "code": "2F-ATTACK", "name": "Forbidden point", "floor": "2", "frequency": "daily"
    }).status_code == 403
    db.session.refresh(binding)
    assert binding.status == "pending"
    assert db.session.query(Point).count() == 2


def test_staff_records_and_export_are_scoped_to_self(application, seeded):
    record(seeded["inspector"], seeded["daily"])
    record(seeded["colleague"], seeded["weekly"])
    client = application.test_client()
    login(client)
    for path in (
        "/records",
        "/records/export",
        f"/records?user_id={seeded['colleague'].id}",
        f"/records/export?user_id={seeded['colleague'].id}",
    ):
        response = client.get(path)
        assert response.status_code == 200
        text = response.get_data(as_text=True)
        assert "Inspector Bravo" not in text
        if "/export" in path:
            assert "Weekly Test Point" not in text
        if "?" not in path:
            assert "Inspector Alpha" in text


def test_inactive_user_existing_session_cannot_submit(application, seeded):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    seeded["inspector"].active = False
    db.session.commit()
    response = submit(client, seeded["daily"])
    assert response.status_code in (302, 303, 401, 403)
    assert count_inspections() == 0


def test_inactive_point_cannot_be_recorded(application, seeded):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    seeded["daily"].active = False
    db.session.commit()
    response = submit(client, seeded["daily"])
    assert response.status_code in (403, 404, 410)
    assert count_inspections() == 0


def test_rotating_qr_rejects_old_url(application, seeded):
    point = seeded["daily"]
    previous_token = point.qr_token
    admin_client = application.test_client()
    login(admin_client, "manager")
    response = admin_client.post(f"/admin/points/{point.id}/rotate-qr")
    assert response.status_code in (302, 303)
    db.session.refresh(point)
    assert point.qr_token != previous_token
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    assert client.get(f"/c/{previous_token}").status_code in (404, 410)
    assert client.post(f"/c/{previous_token}/confirm").status_code in (404, 410)
    assert count_inspections() == 0
    assert client.get(f"/c/{point.qr_token}").status_code == 200


def test_inspection_post_requires_csrf_when_enabled(application, seeded):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    application.config["CSRF_ENABLED"] = True
    response = submit(client, seeded["daily"])
    assert response.status_code in (400, 403)
    assert count_inspections() == 0


@pytest.mark.parametrize("destination", ["https://evil.example/", "//evil.example/"])
def test_login_refuses_external_next_redirect(application, seeded, destination):
    client = application.test_client()
    response = client.post(
        "/login",
        query_string={"next": destination},
        data={"username": "inspector", "password": PASSWORD, "next": destination},
    )
    assert response.status_code in (302, 303)
    location = response.headers.get("Location", "")
    assert location.startswith("/") and not location.startswith("//")
    assert "evil.example" not in location


def test_admin_password_reset_invalidates_existing_sessions(application, seeded):
    staff_client = application.test_client()
    login(staff_client)
    approve_browser(staff_client, seeded["inspector"])
    admin_client = application.test_client()
    login(admin_client, "manager")
    response = admin_client.post(
        f"/admin/users/{seeded['inspector'].id}/reset-password",
        data={"password": "Changed-test-password-456!"},
    )
    assert response.status_code in (302, 303)
    response = submit(staff_client, seeded["daily"])
    assert response.status_code in (302, 303, 401, 403)
    if response.status_code in (302, 303):
        assert urlsplit(response.headers["Location"]).path == "/login"
    assert count_inspections() == 0
    db.session.refresh(seeded["inspector"])
    assert seeded["inspector"].check_password("Changed-test-password-456!")
    assert seeded["inspector"].must_change_password


def test_first_login_rejects_reusing_initial_password(application, seeded):
    user = seeded["inspector"]
    user.must_change_password = True
    db.session.commit()
    original_version = user.auth_version
    original_hash = user.password_hash
    client = application.test_client()
    response = login(client)
    assert urlsplit(response.headers["Location"]).path == "/change-password"

    response = client.post("/change-password", data={
        "current_password": PASSWORD,
        "new_password": PASSWORD,
        "confirm_password": PASSWORD,
    })
    assert response.status_code == 200
    assert "新密碼不可與目前密碼相同" in response.get_data(as_text=True)
    db.session.refresh(user)
    assert user.must_change_password is True
    assert user.auth_version == original_version
    assert user.password_hash == original_hash
    assert user.check_password(PASSWORD)
    with client.session_transaction() as session:
        assert session["user_id"] == user.id
        assert session["auth_version"] == original_version
    response = client.get("/dashboard")
    assert urlsplit(response.headers["Location"]).path == "/change-password"


def test_completed_point_does_not_disclose_other_inspector(application, seeded):
    existing = record(seeded["colleague"], seeded["daily"])
    client = application.test_client()
    login(client)
    for path in (f"/c/{seeded['daily'].qr_token}", "/dashboard"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Inspector Bravo" not in response.get_data(as_text=True)
    assert client.get(f"/checkins/{existing.id}").status_code == 403
    assert count_inspections() == 1


def test_valid_csrf_form_allows_inspection(application, seeded):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    application.config["CSRF_ENABLED"] = True
    page = client.get(f"/c/{seeded['daily'].qr_token}")
    token = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"', page.get_data(as_text=True)
    )
    assert token, "The rendered confirmation form must contain a CSRF token"
    response = client.post(
        f"/c/{seeded['daily'].qr_token}/confirm", data={"csrf_token": token.group(1)}
    )
    assert response.status_code in (302, 303)
    assert count_inspections() == 1


def test_qr_svg_encodes_configured_origin_not_request_host(
    application, seeded, monkeypatch
):
    original_make = app_module.qrcode.make
    encoded = []

    def capture_data(data, *args, **kwargs):
        encoded.append(data)
        return original_make(data, *args, **kwargs)

    monkeypatch.setattr(app_module.qrcode, "make", capture_data)
    client = application.test_client()
    login(client, "manager")
    response = client.get(
        f"/admin/points/{seeded['daily'].id}/qr.svg",
        headers={"X-Forwarded-Host": "untrusted.example"},
    )
    assert response.status_code == 200
    assert response.mimetype == "image/svg+xml"
    assert encoded == [
        "https://patrol.example.test/c/" + seeded["daily"].qr_token
    ]
    assert ElementTree.fromstring(response.data).tag.endswith("}svg")


def test_new_week_accepts_another_completion(application, seeded, monkeypatch):
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    assert submit(client, seeded["weekly"]).status_code in (302, 303)
    monkeypatch.setattr(
        app_module,
        "now_utc",
        lambda: datetime(2026, 11, 8, 16, 0, tzinfo=timezone.utc),
    )
    assert submit(client, seeded["weekly"]).status_code in (302, 303)
    saved = db.session.query(Inspection).order_by(Inspection.id).all()
    assert [item.period_key for item in saved] == ["2026-11-02", "2026-11-09"]


def test_frequency_change_preserves_historical_daily_schedule(
    application, seeded, monkeypatch
):
    point = seeded["daily"]
    admin_client = application.test_client()
    login(admin_client, "manager")
    monkeypatch.setattr(
        app_module,
        "now_utc",
        lambda: datetime(2026, 11, 4, 4, 0, tzinfo=timezone.utc),
    )
    response = admin_client.post(f"/admin/points/{point.id}/update", data={
        "code": point.code,
        "name": point.name,
        "floor": str(point.floor),
        "frequency": "weekly",
        "active": "on",
    })
    assert response.status_code in (302, 303)
    with rendered_contexts(application) as contexts:
        assert admin_client.get("/dashboard?date=2026-11-03&view=daily").status_code == 200
    cards = contexts[-1][1]["cards"]
    assert any(card["point"].id == point.id for card in cards)


def test_weekly_completion_stays_visible_after_point_disabled(
    application, seeded, monkeypatch
):
    point = seeded["weekly"]
    record(seeded["inspector"], point)
    admin_client = application.test_client()
    login(admin_client, "manager")
    monkeypatch.setattr(
        app_module,
        "now_utc",
        lambda: datetime(2026, 11, 4, 4, 0, tzinfo=timezone.utc),
    )
    assert admin_client.post(f"/admin/points/{point.id}/update", data={
        "code": point.code,
        "name": point.name,
        "floor": str(point.floor),
        "frequency": "weekly",
    }).status_code in (302, 303)
    with rendered_contexts(application) as contexts:
        assert admin_client.get("/dashboard?date=2026-11-03&view=weekly").status_code == 200
    cards = contexts[-1][1]["cards"]
    assert any(card["point"].id == point.id and card["status"] == "done" for card in cards)


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t=", "\r="])
def test_csv_escapes_formula_values(application, seeded, prefix):
    seeded["inspector"].display_name = prefix + "TestPerson"
    seeded["daily"].name = prefix + "TestPoint"
    db.session.commit()
    record(seeded["inspector"], seeded["daily"])
    client = application.test_client()
    login(client)
    response = client.get("/records/export")
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True).lstrip("\ufeff"))))
    assert len(rows) == 2
    assert rows[1][0] == "'" + prefix + "TestPerson"
    assert rows[1][3] == "'" + prefix + "TestPoint"


def test_record_snapshots_survive_employee_and_point_changes(application, seeded):
    record(seeded["inspector"], seeded["daily"])
    seeded["inspector"].display_name = "Renamed Employee"
    seeded["daily"].name = "Renamed Point"
    seeded["daily"].code = "2F-A02"
    seeded["daily"].floor = 2
    db.session.commit()
    client = application.test_client()
    login(client)
    response = client.get("/records/export")
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True).lstrip("\ufeff"))))
    assert rows[1][0:4] == ["Inspector Alpha", "1F", "1F-A01", "Daily Test Point"]


def test_cannot_revoke_another_users_device(application, seeded):
    other_client = application.test_client()
    other_binding = approve_browser(other_client, seeded["colleague"])
    client = application.test_client()
    login(client)
    response = client.post(f"/devices/{other_binding.id}/revoke")
    assert response.status_code == 403
    db.session.refresh(other_binding)
    assert other_binding.status == "approved"


def test_future_point_cannot_be_recorded(application, seeded):
    seeded["daily"].schedule_start = date(2026, 11, 4)
    db.session.commit()
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    assert submit(client, seeded["daily"]).status_code == 403
    assert count_inspections() == 0

