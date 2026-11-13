"""Executor visits use synthetic catalog entries and isolated SQLite/local PostgreSQL only."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from io import BytesIO
from threading import Barrier

import pytest

from receipt_urls import without_voice_feedback

import app as patrol
from models import DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, PatrolExecution, Point, User, db
from test_app import FIXED_NOW, application
from test_postgres_features import postgres_app
from test_workflow_checkin import payload, team


@pytest.fixture(autouse=True)
def synthetic_register(monkeypatch):
    # The remaining 20 real NO entries are scheduled single-stage points. Names
    # and codes here are entirely synthetic, including a mixed-case code.
    frequencies = ["irregular"] * 7 + ["daily"] * 17 + ["daily2"] * 2 + ["monthly"]
    rows = [dict(code=f"Xq-T{index:03d}", name=f"測試點 {index}", category="general", floor=1,
                 frequency=frequency, workflow_mode="spot") for index, frequency in enumerate(frequencies)]
    monkeypatch.setattr(patrol, "general_catalogue_rows", lambda: rows)
    return rows


def register_point(row):
    point = Point(**row, active=True, schedule_start=date(2020, 1, 1))
    db.session.add(point)
    db.session.flush()
    return "/c/" + point.qr_token


def signed_browser(app, user, token):
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(user_id=user.id, auth_version=user.auth_version, csrf_token=f"test-browser-{user.id}")
    client.set_cookie("patrol_device", token)
    return client


def second_executor(app):
    user = User(username="visit-peer", display_name="第二位執行人員", role="executor", patrol_category="general",
                password_hash="unused-fixture-hash", active=True)
    db.session.add(user)
    db.session.flush()
    token = "visit-peer-device"
    db.session.add(DeviceBinding(user_id=user.id, token_hash=patrol.hash_device_token(token), status="approved"))
    db.session.commit()
    return signed_browser(app, user, token)


def test_only_the_seven_authorized_irregular_points_allow_executor_visits(application, synthetic_register):
    executor, inspector, _, _, first_url, _, _ = team(application)
    urls = [register_point(row) for row in synthetic_register]
    extra = register_point(synthetic_register[0] | {"code": "Xq-UNLISTED"})
    safety = register_point(synthetic_register[0] | {"code": "Xq-SAFETY", "category": "safety", "workflow_mode": "standard"})
    db.session.commit()

    for url in urls[:7]:
        fields = payload(executor, url)
        assert fields["stage"] == "visit" and fields["spot_ticket"]
        result = executor.post(url + "/confirm", data=fields)
        assert result.status_code == 302 and "/checkins/" in result.location
        assert executor.get(result.location).status_code == 200
    for url in [*urls[7:], extra, safety]:
        assert executor.get(url).status_code == 404
        assert executor.post(url + "/confirm", data=fields).status_code == 404
    saved = db.session.scalars(db.select(Inspection)).all()
    assert len(saved) == 7 and all(r.executor_visit and r.frequency == "irregular" and r.execution_id is None for r in saved)
    assert db.session.query(PatrolExecution).count() == 0

    # The existing two-stage first stage and the ordinary inspector's direct visit retain their distinct types.
    first = executor.post(first_url + "/confirm", data=payload(executor, first_url))
    assert first.status_code == 302 and "/executions/" in first.location
    assert db.session.query(PatrolExecution).count() == 1
    ordinary = inspector.post(urls[0] + "/confirm", data=payload(inspector, urls[0]) | {"executor_visit": "true"})
    assert ordinary.status_code == 302 and "/checkins/" in ordinary.location
    assert db.session.query(Inspection).filter_by(executor_visit=False).count() == 1


def test_reusing_a_registered_code_cannot_move_visit_access_to_another_point(application, synthetic_register):
    executor, _, _, admin, *_ = team(application)
    registered = synthetic_register[0]
    original_url = register_point(registered)
    other_url = register_point({**registered, "code": "1F-OTHER"})
    db.session.commit()
    def edit_path(url):
        point_id = db.session.scalar(db.select(Point.id).where(Point.qr_token == url.rsplit("/", 1)[1]))
        return f"/admin/points/{point_id}/update"
    form = {**registered, "active": "on"}
    assert admin.post(edit_path(original_url), data={**form, "code": "1F-RENAMED"}).status_code == 302
    assert payload(executor, original_url)["stage"] == "visit"
    assert admin.post(edit_path(other_url), data=form).status_code == 302
    assert executor.get(other_url).status_code == 404
    assert executor.post(other_url + "/confirm").status_code == 404
    # Even a later schedule using the old label cannot inherit its original ID.
    other = db.session.scalar(db.select(Point).where(Point.qr_token == other_url.rsplit("/", 1)[1]))
    other.code = "1F-OTHER"
    db.session.commit()
    assert admin.post(edit_path(original_url), data=form).status_code == 302
    assert payload(executor, original_url)["stage"] == "visit"


@pytest.mark.parametrize("change", [
    {"category": "safety", "workflow_mode": "standard"}, {"frequency": "monthly"}, {"code": "Xq-RENAMED"},
    {"code": "xq-t000"}, {"active": False},
])
def test_authorized_point_rechecks_current_classification_before_saving(application, synthetic_register, change):
    executor, *_ = team(application)
    url = register_point(synthetic_register[0])
    db.session.commit()
    fields = payload(executor, url)
    point = db.session.scalar(db.select(Point).where(Point.qr_token == url.split("/")[-1]))
    for field, value in change.items():
        setattr(point, field, value)
    db.session.commit()
    assert executor.post(url + "/confirm", data=fields).status_code in (403, 404)
    assert db.session.query(Inspection).count() == db.session.query(PatrolExecution).count() == 0


@pytest.mark.parametrize("frequency", ["daily", "weekly_wed", "weekly_fri"])
def test_allowed_frequency_change_still_rejects_old_visit_form_and_ticket(application, synthetic_register, frequency):
    executor, *_ = team(application)
    url = register_point(synthetic_register[0])
    db.session.commit()
    original = payload(executor, url)
    point = db.session.scalar(db.select(Point).where(Point.qr_token == url.split("/")[-1]))
    point.frequency = frequency
    db.session.commit()
    assert executor.post(url + "/confirm", data=original).status_code == 409
    current = payload(executor, url)
    assert current["stage"] == "visit" and current["frequency"] == frequency
    # Updating hidden fields cannot make the old signed ticket current.
    assert executor.post(url + "/confirm", data=current | {"spot_ticket": original["spot_ticket"]}).status_code == 409
    assert db.session.query(Inspection).count() == db.session.query(PatrolExecution).count() == 0
    saved = executor.post(url + "/confirm", data=current)
    assert saved.status_code == 302 and "/checkins/" in saved.location
    assert executor.get(saved.location).status_code == 200
    assert second_executor(application).get(saved.location).status_code == 403
    record = db.session.scalar(db.select(Inspection))
    assert record.frequency == frequency and record.executor_visit


def test_visit_requires_own_binding_ticket_and_cannot_submit_report_content(application, synthetic_register):
    executor, inspector, *_ = team(application)
    url = register_point(synthetic_register[0])
    db.session.commit()
    fields = payload(executor, url)
    other = payload(inspector, url)
    for changes in ({"stage": "inspect"}, {"spot_ticket": other["spot_ticket"]},
                    {"note": "未授權回報"}, {"is_abnormal": "on"}, {"photos": (BytesIO(b"test"), "photo.jpg")}):
        assert executor.post(url + "/confirm", data=fields | changes).status_code in (400, 403, 409)
    executor.set_cookie("patrol_device", "inspect-device")
    assert executor.post(url + "/confirm", data=fields).status_code == 403
    assert all(db.session.query(model).count() == 0 for model in (Inspection, InspectionIssue, InspectionPhoto, PatrolExecution))


def test_each_executor_once_per_taipei_day_across_tickets_and_midnight(application, synthetic_register, monkeypatch):
    now = FIXED_NOW.replace(hour=15, minute=59)
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    executor, *_ = team(application)
    peer = second_executor(application)
    url = register_point(synthetic_register[0])
    db.session.commit()
    post = url + "/confirm"
    first, second = payload(executor, url), payload(executor, url)
    assert first["spot_ticket"] != second["spot_ticket"]
    original = executor.post(post, data=first)
    assert original.status_code == 302
    assert without_voice_feedback(executor.post(post, data=first).location) == without_voice_feedback(original.location)
    assert without_voice_feedback(executor.post(post, data=second).location) == without_voice_feedback(original.location)
    other = peer.post(post, data=payload(peer, url))
    assert other.status_code == 302 and without_voice_feedback(other.location) != without_voice_feedback(original.location)
    assert db.session.query(Inspection).count() == 2
    now += timedelta(minutes=1)
    assert executor.post(post, data=first).status_code == 409
    assert executor.post(post, data=payload(executor, url)).status_code == 302
    rows = db.session.scalars(db.select(Inspection).order_by(Inspection.id)).all()
    assert [r.personal_day for r in rows] == [date(2026, 11, 3), date(2026, 11, 3), date(2026, 11, 4)]
    assert rows[0].user_id == rows[2].user_id != rows[1].user_id
    assert all(r.executor_visit and r.note == "" and not r.is_abnormal for r in rows)


def test_postgres_simultaneous_distinct_executor_and_same_account_tickets(postgres_app, synthetic_register):
    with postgres_app.app_context():
        executor, *_ = team(postgres_app)
        same_user = db.session.scalar(db.select(User).where(User.username == "exec"))
        same_account = signed_browser(postgres_app, same_user, "exec-device")
        peer = second_executor(postgres_app)
        url = register_point(synthetic_register[0])
        db.session.commit()
    clients = [executor, same_account, peer]
    requests = [(c, payload(c, url)) for c in clients]
    gate = Barrier(3)
    def submit(item):
        client, fields = item
        gate.wait(timeout=10)
        result = client.post(url + "/confirm", data=fields)
        return result.status_code, result.location
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(submit, requests))
    assert [code for code, _ in results] == [302, 302, 302]
    targets = [without_voice_feedback(location) for _, location in results]
    assert targets[0] == targets[1] != targets[2]
    # Both concurrent requests reach the same persisted receipt, while only
    # the request that created it may announce a newly saved visit.
    from test_voice_results import marker
    outcomes = [marker(client.get(location))["kind"] for client, (_, location) in zip(clients, results)]
    assert sorted(outcomes[:2]) == ["already_recorded", "saved_visit"]
    assert outcomes[2] == "saved_visit"
    with postgres_app.app_context():
        rows = db.session.scalars(db.select(Inspection)).all()
        assert len(rows) == 2 and len({r.user_id for r in rows}) == 2
        assert all(r.executor_visit for r in rows) and db.session.query(PatrolExecution).count() == 0
