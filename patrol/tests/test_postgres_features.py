"""Opt-in real PostgreSQL concurrency tests, restricted to a disposable local DB."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
import io
import os
import threading
import uuid

from PIL import Image
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from werkzeug.datastructures import FileStorage

import app as app_module
from images import process_uploads
from models import AuditLog, DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, IssueEvent, Point, PointSchedule, User, db


@pytest.fixture
def postgres_app(monkeypatch):
    configured = os.environ.get("PATROL_TEST_POSTGRES_URL")
    if not configured:
        pytest.skip("Set PATROL_TEST_POSTGRES_URL for the isolated local PostgreSQL checks")
    parsed = make_url(configured)
    if parsed.host not in ("127.0.0.1", "localhost") or parsed.port != 55432 or parsed.database != "patrol_test":
        pytest.fail("PostgreSQL concurrency tests only allow local port 55432 / patrol_test")
    schema = "patrol_backend_" + uuid.uuid4().hex
    admin = create_engine(configured)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    application = app_module.create_app({
        "TESTING": True, "SECRET_KEY": "test", "SQLALCHEMY_DATABASE_URI": configured,
        "SQLALCHEMY_ENGINE_OPTIONS": {"connect_args": {"options": f"-csearch_path={schema}"}},
        "CSRF_ENABLED": False, "COOKIE_SECURE": False, "PUBLIC_BASE_URL": "https://patrol.example.test",
    })
    monkeypatch.setattr(app_module, "now_utc", lambda: datetime(2026, 11, 3, 4, tzinfo=timezone.utc))
    try:
        with application.app_context():
            db.create_all()
        yield application
    finally:
        with application.app_context():
            db.session.remove()
            db.engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def image_bytes():
    buffer = io.BytesIO()
    Image.new("RGB", (20, 20), "blue").save(buffer, "PNG")
    return buffer.getvalue()


def seed_clients(application, separate_points=False):
    with application.app_context():
        points = []
        for number in range(2 if separate_points else 1):
            point = Point(code=f"1F-C{number:02}", name="Concurrent point", floor=1, frequency="daily2",
                          category="safety", schedule_start=date(2026, 1, 1))
            point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency="daily2", category="safety", active=True))
            db.session.add(point)
            points.append(point)
        db.session.flush()
        clients = []
        for number in range(2):
            user = User(username=f"concurrent{number}", display_name=f"Tester {number}", password_hash="unused-test-hash",
                        role="inspector", patrol_category="safety", active=True, must_change_password=False, auth_version=1)
            db.session.add(user)
            db.session.flush()
            secret = f"approved-local-test-browser-{number}"
            db.session.add(DeviceBinding(user_id=user.id, token_hash=app_module.hash_device_token(secret), status="approved"))
            client = application.test_client()
            with client.session_transaction() as session:
                session["user_id"], session["auth_version"] = user.id, 1
            client.set_cookie("patrol_device", secret)
            selected_point = points[number if separate_points else 0]
            clients.append((client, selected_point.qr_token, selected_point.frequency))
        db.session.commit()
        return clients


def concurrently_submit(clients):
    barrier = threading.Barrier(2)
    def submit(pair):
        client, token, frequency = pair
        barrier.wait(timeout=10)
        response = client.post(f"/c/{token}/confirm", data={"slot": "pm", "period_key": "2026-11-03", "frequency": frequency,
            "note": "Concurrency test", "photos": (io.BytesIO(image_bytes()), "test.png")})
        return response.status_code, response.location
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(submit, pair) for pair in clients]
        return [future.result(timeout=30) for future in futures]


def test_postgres_same_slot_concurrent_requests_store_one_record_and_one_photo(postgres_app):
    outcomes = concurrently_submit(seed_clients(postgres_app))
    assert [status for status, _ in outcomes] == [302, 302]
    assert sum("/checkins/" in location for _, location in outcomes) == 1
    with postgres_app.app_context():
        assert db.session.query(Inspection).count() == 1
        assert db.session.query(InspectionPhoto).count() == 1


def test_postgres_capacity_lock_prevents_two_points_exceeding_limit(postgres_app):
    processed = process_uploads([FileStorage(stream=io.BytesIO(image_bytes()), filename="test.png")])[0]
    postgres_app.config["PHOTO_STORAGE_LIMIT_BYTES"] = processed["size_bytes"]
    outcomes = concurrently_submit(seed_clients(postgres_app, separate_points=True))
    assert sorted(status for status, _ in outcomes) == [302, 409]
    with postgres_app.app_context():
        assert db.session.query(Inspection).count() == 1
        assert db.session.query(InspectionPhoto).count() == 1
        used = db.session.scalar(db.select(db.func.sum(InspectionPhoto.size_bytes)))
        assert used == postgres_app.config["PHOTO_STORAGE_LIMIT_BYTES"]


@pytest.mark.parametrize("legacy", [False, True])
def test_postgres_concurrent_resolve_reopen_is_idempotent_and_rejects_old_form(postgres_app, legacy):
    clients = seed_clients(postgres_app)
    author, token, frequency = clients[0]
    assert author.post(f"/c/{token}/confirm", data={"slot": "pm", "period_key": "2026-11-03", "frequency": frequency, "is_abnormal": "on", "note": "Original issue"}).status_code == 302
    with postgres_app.app_context():
        record = db.session.scalar(db.select(Inspection))
        record_id = record.id
        if legacy:
            db.session.delete(record.issue)
        db.session.execute(db.update(User).values(role="admin", patrol_category=None))
        db.session.commit()
    def both(action, version):
        barrier = threading.Barrier(2)
        def request_action(pair):
            client, _, _ = pair
            barrier.wait(timeout=10)
            return client.post(f"/admin/issues/{record_id}/{action}", data={"expected_event_id": str(version), "note": "Concurrent admin action"}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(request_action, pair) for pair in clients]
            return [future.result(timeout=30) for future in results]
    assert both("resolve", 0) == [302, 302]
    with postgres_app.app_context():
        assert db.session.query(InspectionIssue).count() == 1
        assert db.session.query(IssueEvent).count() == 1
        issue = db.session.get(InspectionIssue, record_id)
        assert issue.status == "resolved" and issue.resolved_by_id is not None
        resolved_event_id = db.session.scalar(db.select(IssueEvent.id))
    assert both("reopen", resolved_event_id) == [302, 302]
    assert author.post(f"/admin/issues/{record_id}/resolve", data={"expected_event_id": "0", "note": "Old tab"}).status_code == 409
    with postgres_app.app_context():
        issue = db.session.get(InspectionIssue, record_id)
        assert issue.status == "open" and issue.resolved_at is None and issue.resolved_by_id is None
        assert issue.resolved_by_name == issue.resolution_note == ""
        assert db.session.query(IssueEvent).count() == 2
        assert db.session.query(AuditLog).filter(AuditLog.action.in_(["issue_resolved", "issue_reopened"])).count() == 2
        assert db.session.get(Inspection, record_id).note == "Original issue"


def test_postgres_resolve_and_new_normal_checkin_same_point_do_not_deadlock(postgres_app):
    from issues import open_issue_counts
    clients = seed_clients(postgres_app)
    admin, token, frequency = clients[0]
    worker, _, _ = clients[1]
    with postgres_app.app_context():
        user = db.session.scalar(db.select(User).where(User.username == "concurrent0"))
        user.role = "admin"
        user.patrol_category = None
        point = db.session.scalar(db.select(Point))
        record = Inspection(user_id=user.id, point_id=point.id, period_key="2026-11-03", frequency="daily2", slot="am",
                            category="safety", point_code=point.code, point_name=point.name, point_floor=point.floor,
                            user_name=user.display_name, note="Morning issue", is_abnormal=True)
        record.issue = InspectionIssue(status="open", opened_at=datetime(2026, 11, 3, 2))
        db.session.add(record)
        db.session.commit()
        record_id = record.id
    barrier = threading.Barrier(2)
    def resolve():
        barrier.wait(timeout=10)
        return admin.post(f"/admin/issues/{record_id}/resolve", data={"expected_event_id": "0", "note": "Fixed"}).status_code
    def checkin():
        barrier.wait(timeout=10)
        return worker.post(f"/c/{token}/confirm", data={"slot": "pm", "period_key": "2026-11-03", "frequency": frequency, "note": "Normal afternoon"}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(resolve), pool.submit(checkin)]
        assert [future.result(timeout=30) for future in futures] == [302, 302]
    with postgres_app.app_context():
        assert db.session.query(Inspection).count() == 2
        assert db.session.query(InspectionIssue).count() == db.session.query(IssueEvent).count() == 1
        assert open_issue_counts() == {}
