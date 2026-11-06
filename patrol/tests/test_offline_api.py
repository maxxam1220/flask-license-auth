"""Offline sync uses local test clients and never contacts the deployed service."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
import csv
import json
from uuid import uuid4
from threading import Barrier

import pytest
from sqlalchemy import event

import app as patrol
from models import DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, OfflineSubmission, PatrolExecution, Point, User, db
from test_app import application
from test_daily2_anytime import anytime, context, form, rows
from test_features import png
from test_postgres_features import postgres_app, seed_clients
from test_workflow_checkin import payload, team


def utc_text(instant):
    return instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def prepare(client):
    response = client.get("/api/offline/prepare")
    assert response.status_code == 200 and response.is_json, response.text
    data = response.get_json()
    assert data["ok"] and data["version"] == 1
    return data


def entry(prepared, url, observed, **changes):
    point = next(item for item in prepared["points"] if item["token"] == url[3:])
    return dict(client_id=str(uuid4()), owner=prepared["owner"], token=point["token"], grant=point["grant"],
                slot=point["slots"][0], observed_at=utc_text(observed), note="", is_abnormal=False) | changes


def sync(client, prepared, item, photos=()):
    data = {"entry": json.dumps(item, ensure_ascii=False)}
    if photos:
        data["photos"] = list(photos)
    return client.post("/api/offline/sync", data=data, headers={"X-CSRF-Token": prepared["csrf_token"]})


def assert_error(response, code=None, *, status=None, retryable=False):
    assert response.is_json, response.text
    result = response.get_json()
    assert result["ok"] is False and result["retryable"] is retryable, result
    assert isinstance(result["message"], str) and result["message"]
    if code is not None:
        assert result["code"] == code, result
    if status is not None:
        assert response.status_code == status, result
    else:
        assert response.status_code >= 400, result
    return result


def test_prepare_status_require_login_and_never_cache_personal_data(application, anytime):
    for path in ("/api/offline/prepare", "/api/offline/status"):
        response = application.test_client().get(path)
        assert_error(response, status=401)
        assert "no-store" in response.headers.get("Cache-Control", "")
    prepared = prepare(anytime.inspector)
    assert prepared["identity"]["role"] == "inspector" and prepared["identity"]["category"] == "general"
    assert {item["id"] for item in prepared["points"]} == {p.id for p in db.session.scalars(db.select(Point))}
    assert all(item["stage"] == "inspect" for item in prepared["points"])
    assert all(item["slots"] == ["am", "pm"] and not item["used_slots"] for item in prepared["points"])
    assert prepared["day"] == "2026-11-06" and prepared["csrf_token"]
    for path in ("/api/offline/prepare", "/api/offline/status"):
        response = anytime.inspector.get(path)
        assert response.is_json and response.status_code == 200
        assert "no-store" in response.headers.get("Cache-Control", "")
        assert response.get_json()["owner"] == prepared["owner"]
    executable = prepare(anytime.executor)
    assert [item["id"] for item in executable["points"]] == [anytime.pair_point.id]
    assert executable["points"][0]["stage"] == "execute"


def test_offline_shell_is_identical_public_content_for_every_session_state(application, anytime):
    anonymous = application.test_client().get("/offline")
    logged_in = anytime.inspector.get("/offline")
    user = db.session.scalar(db.select(User).where(User.username == "inspect"))
    user.must_change_password = True
    db.session.commit()
    password_change = anytime.inspector.get("/offline")
    assert anonymous.status_code == logged_in.status_code == password_change.status_code == 200
    assert anonymous.data == logged_in.data == password_change.data
    for response in (anonymous, logged_in, password_change):
        assert "camera=(self)" in response.headers["Permissions-Policy"]
        assert "local-test-session" not in response.text and "inspect-device" not in response.text
        assert "existing-qr" not in response.text
    assert_error(anytime.inspector.get("/api/offline/prepare"), "password_required", status=403)


@pytest.mark.parametrize("change", ["disabled", "role", "category", "password-version", "binding"])
def test_prepared_grant_cannot_bypass_current_account_or_device_permissions(application, anytime, change):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0])
    actor = db.session.scalar(db.select(User).where(User.username == "inspect"))
    if change == "disabled":
        actor.active = False
    elif change == "role":
        actor.role = "executor"
    elif change == "category":
        actor.patrol_category = "safety"
    elif change == "password-version":
        actor.auth_version += 1
    else:
        db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == actor.id)).status = "revoked"
    db.session.commit()
    assert_error(sync(a.inspector, prepared, item))
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0


@pytest.mark.parametrize("change", ["owner", "grant", "point", "client-id", "slot"])
def test_tampered_offline_scope_is_rejected_without_creating_receipt(application, anytime, change):
    a = anytime
    prepared, peer = prepare(a.inspector), prepare(a.peer)
    item = entry(prepared, a.direct, a.clock[0])
    if change == "owner":
        item["owner"] = peer["owner"]
    elif change == "grant":
        item["grant"] += "tampered"
    elif change == "point":
        item["token"] = a.other[3:]
    elif change == "client-id":
        item["client_id"] = "not-a-uuid"
    else:
        item["slot"] = "any"
    assert_error(sync(a.inspector, prepared, item))
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0
    # A valid grant is also bound to its original employee.
    assert_error(sync(a.peer, peer, entry(prepared, a.direct, a.clock[0])))


@pytest.mark.parametrize("change", ["before-grant", "future", "different-day", "sync-expired", "naive-time"])
def test_observed_time_and_sync_deadline_are_server_bounded(application, anytime, change):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0])
    if change == "before-grant":
        item["observed_at"] = utc_text(a.clock[0] - timedelta(minutes=3))
    elif change == "future":
        item["observed_at"] = utc_text(a.clock[0] + timedelta(minutes=3))
    elif change == "different-day":
        a.clock[0] = (a.clock[0] + timedelta(days=1)).replace(hour=0, minute=0)
        item["observed_at"] = utc_text(a.clock[0])
    elif change == "sync-expired":
        a.clock[0] += timedelta(days=2)
    else:
        item["observed_at"] = "2026-11-06T09:00:00"
    assert_error(sync(a.inspector, prepared, item))
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0


def test_next_day_sync_preserves_capture_day_and_two_timestamps(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    observed = a.clock[0]
    item = entry(prepared, a.direct, observed, note="offline observation")
    a.clock[0] += timedelta(days=1)
    response = sync(a.inspector, prepared, item)
    assert response.status_code == 200 and response.get_json()["status"] == "saved", response.text
    saved = rows(a.direct_point)[0]
    assert saved.created_at == patrol.naive_utc(observed)
    assert saved.personal_day == observed.date() and saved.period_key == "2026-11-06" and saved.slot == "am"
    assert saved.offline_submission.received_at == patrol.naive_utc(a.clock[0])
    assert saved.offline_submission.observed_at == saved.created_at
    assert saved.note == "offline observation"


def test_successful_retry_is_immutable_even_after_grant_expiry_and_point_change(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0], note="only original")
    saved = sync(a.inspector, prepared, item)
    assert saved.status_code == 200 and saved.get_json()["status"] == "saved", saved.text
    a.clock[0] += timedelta(days=3)
    a.direct_point.name = "renamed after successful sync"
    a.direct_point.active = False
    db.session.commit()
    retried = sync(a.inspector, prepared, item)
    assert retried.status_code == 200 and retried.get_json()["status"] == "already_synced", retried.text
    assert retried.get_json()["receipt_url"] == saved.get_json()["receipt_url"]
    assert retried.get_json()["received_at"] == saved.get_json()["received_at"]
    assert db.session.query(OfflineSubmission).count() == len(rows(a.direct_point)) == 1
    assert_error(sync(a.inspector, prepared, item | {"note": "changed after ACK"}), "payload_conflict", status=409)
    assert rows(a.direct_point)[0].note == "only original"


def test_revoked_device_cannot_read_old_ack_via_sync(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0])
    assert sync(a.inspector, prepared, item).status_code == 200
    binding = db.session.get(DeviceBinding, prepared["identity"]["binding_id"])
    binding.status = "revoked"
    db.session.commit()
    assert_error(sync(a.inspector, prepared, item), status=403)
    assert db.session.query(OfflineSubmission).count() == 1


def test_daily2_offline_personal_rounds_never_auto_advance_duplicates(application, anytime):
    a = anytime
    for actor in (a.inspector, a.peer):
        prepared = prepare(actor)
        first = entry(prepared, a.direct, a.clock[0])
        assert sync(actor, prepared, first).status_code == 200
        assert_error(sync(actor, prepared, first | {"client_id": str(uuid4())}), status=409)
        assert sync(actor, prepared, first | {"client_id": str(uuid4()), "slot": "pm"}).status_code == 200
        assert_error(sync(actor, prepared, first | {"client_id": str(uuid4()), "slot": "pm"}), status=409)
    assert len(rows(a.direct_point)) == db.session.query(OfflineSubmission).count() == 4
    assert {item.slot for item in rows(a.direct_point)} == {"am", "pm"}


def test_two_stage_waiting_upload_is_retryable_then_links_earlier_execution(application, anytime):
    a = anytime
    reviewer, executor = prepare(a.inspector), prepare(a.executor)
    initial = a.clock[0]
    execution = entry(executor, a.paired, initial + timedelta(minutes=1))
    inspection = entry(reviewer, a.paired, initial + timedelta(minutes=2), note="after actual execution")
    a.clock[0] = initial + timedelta(minutes=3)
    assert_error(sync(a.inspector, reviewer, inspection), "waiting_execution", status=409, retryable=True)
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0
    first = sync(a.executor, executor, execution)
    assert first.status_code == 200, first.text
    final = sync(a.inspector, reviewer, inspection)
    assert final.status_code == 200, final.text
    saved, = rows(a.pair_point)
    executed, = rows(a.pair_point, PatrolExecution)
    assert saved.execution_id == executed.id and executed.created_at < saved.created_at
    assert db.session.query(OfflineSubmission).count() == 2


def test_two_stage_cannot_claim_review_before_its_execution(application, anytime):
    a = anytime
    reviewer, executor = prepare(a.inspector), prepare(a.executor)
    initial = a.clock[0]
    execution = entry(executor, a.paired, initial + timedelta(minutes=1))
    inspection = entry(reviewer, a.paired, initial)
    a.clock[0] += timedelta(minutes=2)
    assert sync(a.executor, executor, execution).status_code == 200
    assert_error(sync(a.inspector, reviewer, inspection), "execution_order", status=409)
    assert db.session.query(Inspection).count() == 0 and db.session.query(OfflineSubmission).count() == 1


def test_offline_photos_abnormal_report_and_mapping_commit_atomically(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0], note="offline leak", is_abnormal=True)
    rejected = sync(a.inspector, prepared, item, photos=[(BytesIO(b"not an image"), "invalid.jpg")])
    assert_error(rejected)
    assert all(db.session.query(model).count() == 0 for model in
               (Inspection, InspectionPhoto, InspectionIssue, OfflineSubmission))
    saved = sync(a.inspector, prepared, item, photos=[(png(), "leak.png")])
    assert saved.status_code == 200, saved.text
    assert all(db.session.query(model).count() == 1 for model in
               (Inspection, InspectionPhoto, InspectionIssue, OfflineSubmission))
    repeated = sync(a.inspector, prepared, item, photos=[(png(), "leak.png")])
    assert repeated.status_code == 200 and repeated.get_json()["status"] == "already_synced", repeated.text
    assert_error(sync(a.inspector, prepared, item), "payload_conflict", status=409)
    assert db.session.query(InspectionPhoto).count() == 1


@pytest.mark.parametrize("field,value", [("name", "changed name"), ("floor", 2), ("frequency", "weekly"),
                                          ("workflow_mode", "two_stage"), ("active", False)])
def test_point_changes_after_prepare_require_fresh_online_confirmation(application, anytime, field, value):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0])
    setattr(a.direct_point, field, value)
    db.session.commit()
    assert_error(sync(a.inspector, prepared, item), "point_changed", status=409)
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0


def test_sync_enforces_csrf_and_returns_json_for_bad_envelopes(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0])
    application.config["CSRF_ENABLED"] = True
    missing = a.inspector.post("/api/offline/sync", data={"entry": json.dumps(item)})
    assert_error(missing)
    malformed = a.inspector.post("/api/offline/sync", data={"entry": "{"},
        headers={"X-CSRF-Token": prepared["csrf_token"]})
    assert_error(malformed)
    assert db.session.query(OfflineSubmission).count() == 0


@pytest.mark.parametrize("frequency", ["weekly", "monthly"])
def test_long_period_shared_execution_and_daily_personal_limits_survive_delayed_sync(application, anytime, frequency):
    a = anytime
    a.pair_point.frequency = a.pair_point.schedules[0].frequency = frequency
    db.session.commit()
    executor = prepare(a.executor)
    assert sync(a.executor, executor, entry(executor, a.paired, a.clock[0])).status_code == 200
    reviewer = prepare(a.inspector)
    first_day = entry(reviewer, a.paired, a.clock[0])
    assert sync(a.inspector, reviewer, first_day).status_code == 200
    a.clock[0] += timedelta(days=1)
    next_reviewer, next_executor = prepare(a.inspector), prepare(a.executor)
    assert sync(a.inspector, next_reviewer, entry(next_reviewer, a.paired, a.clock[0])).status_code == 200
    assert_error(sync(a.executor, next_executor, entry(next_executor, a.paired, a.clock[0])), "duplicate", status=409)
    assert len(rows(a.pair_point)) == 2 and len(rows(a.pair_point, PatrolExecution)) == 1
    assert len({item.execution_id for item in rows(a.pair_point)}) == 1
    assert len({item.personal_day for item in rows(a.pair_point)}) == 2


def test_role_changed_executor_cannot_review_own_offline_execution(application, anytime):
    a = anytime
    executor = prepare(a.executor)
    assert sync(a.executor, executor, entry(executor, a.paired, a.clock[0])).status_code == 200
    user = db.session.scalar(db.select(User).where(User.username == "exec"))
    user.role = "inspector"
    db.session.commit()
    reviewer = prepare(a.executor)
    assert_error(sync(a.executor, reviewer, entry(reviewer, a.paired, a.clock[0])), "forbidden", status=403)
    assert db.session.query(Inspection).count() == 0


def test_upload_processing_cannot_extend_sync_deadline(application, anytime, monkeypatch):
    import offline
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0])
    a.clock[0] = (a.clock[0] + timedelta(days=1)).replace(hour=23, minute=59, second=59)
    original = offline.process_uploads
    def slow(files):
        result = original(files)
        a.clock[0] += timedelta(seconds=1)
        return result
    monkeypatch.setattr(offline, "process_uploads", slow)
    assert_error(sync(a.inspector, prepared, item, photos=[(png(), "late.png")]), "expired", status=409)
    assert all(db.session.query(model).count() == 0 for model in (Inspection, InspectionPhoto, OfflineSubmission))


def test_full_storage_keeps_entire_entry_retryable(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0], is_abnormal=True)
    application.config["PHOTO_STORAGE_LIMIT_BYTES"] = 1
    assert_error(sync(a.inspector, prepared, item, photos=[(png(), "large.png")]),
                 "storage_full", status=409, retryable=True)
    assert all(db.session.query(model).count() == 0 for model in
               (Inspection, InspectionPhoto, InspectionIssue, OfflineSubmission))


def test_database_failure_cannot_leave_receipt_photo_or_mapping_without_ack(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0], is_abnormal=True)
    def fail_mapping(_mapper, _connection, _row):
        raise RuntimeError("Injected offline mapping failure")
    event.listen(OfflineSubmission, "before_insert", fail_mapping)
    try:
        with pytest.raises(RuntimeError, match="Injected offline mapping"):
            sync(a.inspector, prepared, item, photos=[(png(), "atomic.png")])
    finally:
        event.remove(OfflineSubmission, "before_insert", fail_mapping)
        db.session.rollback()
    assert all(db.session.query(model).count() == 0 for model in
               (Inspection, InspectionPhoto, InspectionIssue, OfflineSubmission))


def test_invalid_unicode_note_is_a_json_validation_error(application, anytime):
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0], note="bad lone surrogate \ud800")
    # JSON accepts a Unicode escape that cannot be stored as UTF-8 text.
    raw = json.dumps(item, ensure_ascii=True)
    response = a.inspector.post("/api/offline/sync", data={"entry": raw},
        headers={"X-CSRF-Token": prepared["csrf_token"]})
    assert_error(response, "invalid_entry", status=400)
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0


@pytest.mark.parametrize("mode", ["standard", "spot", "execute"])
def test_postgres_concurrent_same_uuid_retries_create_one_offline_receipt(postgres_app, monkeypatch, mode):
    now = datetime(2026, 11, 6, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    if mode == "standard":
        (actor, token, _), _ = seed_clients(postgres_app)
        url = "/c/" + token
    else:
        with postgres_app.app_context():
            executor, inspector, _, _, paired, direct, _ = team(postgres_app)
        actor, url = (executor, paired) if mode == "execute" else (inspector, direct)
    prepared = prepare(actor)
    item = entry(prepared, url, now)
    gate = Barrier(3)
    def submit(_):
        gate.wait(timeout=10)
        response = sync(actor, prepared, item)
        return response.status_code, response.get_json()
    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(submit, range(3)))
    assert [status for status, _ in outcomes] == [200, 200, 200], outcomes
    assert sorted(data["status"] for _, data in outcomes) == ["already_synced", "already_synced", "saved"]
    assert len({data["receipt_url"] for _, data in outcomes}) == 1
    with postgres_app.app_context():
        model = PatrolExecution if mode == "execute" else Inspection
        assert db.session.query(model).count() == db.session.query(OfflineSubmission).count() == 1
        assert db.session.scalar(db.select(model.slot)) == "am"


def test_postgres_concurrent_standard_users_do_not_turn_two_first_rounds_into_two_visits(postgres_app, monkeypatch):
    now = datetime(2026, 11, 6, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    clients = seed_clients(postgres_app)
    pending = []
    for actor, token, _ in clients:
        prepared = prepare(actor)
        pending.append((actor, prepared, entry(prepared, "/c/" + token, now)))
    gate = Barrier(2)
    def submit(values):
        gate.wait(timeout=10)
        response = sync(*values)
        return response.status_code, response.get_json()
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, pending))
    assert sorted(code for code, _ in outcomes) == [200, 409], outcomes
    assert next(data for code, data in outcomes if code == 409)["code"] == "duplicate"
    with postgres_app.app_context():
        assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 1


def csv_rows(response):
    assert response.status_code == 200
    return list(csv.reader(response.get_data(as_text=True).lstrip("\ufeff").splitlines()))


def test_mixed_csv_appends_source_columns_without_changing_online_column_order(application, anytime):
    a = anytime
    assert a.inspector.post(a.direct + "/confirm", data=form(a.inspector, a.direct)).status_code == 302
    before = csv_rows(a.admin.get("/records/export?category=general"))
    assert "打卡時間來源" not in before[0]
    prepared = prepare(a.inspector)
    item = entry(prepared, a.other, a.clock[0], note="delayed report")
    a.clock[0] += timedelta(hours=1)
    saved = sync(a.inspector, prepared, item)
    assert saved.status_code == 200
    after = csv_rows(a.admin.get("/records/export?category=general"))
    assert after[0] == before[0] + ["打卡時間來源", "伺服器收件時間（台北）", "對應執行時間來源", "執行收件時間（台北）"]
    old_row = next(row for row in after[1:] if row[2] == a.direct_point.code)
    assert old_row[:-4] == before[1] and old_row[-4:] == ["伺服器時間", "", "", ""]
    offline_row = next(row for row in after[1:] if row[2] != a.direct_point.code)
    assert offline_row[4] == "2026-11-06 09:00:00"
    assert offline_row[-4:] == ["手機離線記錄時間", "2026-11-06 10:00:00", "", ""]
    record = db.session.get(Inspection, saved.get_json()["record_id"])
    for path in (saved.get_json()["receipt_url"], f"/records/{record.id}"):
        page = a.inspector.get(path)
        assert page.status_code == 200 and "手機記錄時間" in page.text and "離線補傳收件" in page.text
        assert "2026-11-06 09:00:00" in page.text and "2026-11-06 10:00:00" in page.text


def test_online_abnormal_review_exposes_its_linked_offline_execution_source(application, anytime):
    a = anytime
    prepared = prepare(a.executor)
    item = entry(prepared, a.paired, a.clock[0])
    a.clock[0] += timedelta(hours=1)
    first = sync(a.executor, prepared, item)
    assert first.status_code == 200
    a.clock[0] += timedelta(minutes=1)
    final = a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired) | {
        "note": "online abnormal review after offline execution", "is_abnormal": "on"})
    assert final.status_code == 302
    record, = rows(a.pair_point)
    assert record.offline_submission is None and record.execution.offline_submission is not None
    exported = csv_rows(a.admin.get("/records/export?category=general"))
    assert exported[1][-4:] == ["伺服器時間", "", "手機離線記錄時間", "2026-11-06 10:00:00"]
    executions = csv_rows(a.admin.get("/records/export?category=general&stage=execution"))
    assert executions[1][-4:] == ["手機離線記錄時間", "2026-11-06 10:00:00", "", ""]
    for path in (final.location, f"/records/{record.id}"):
        response = a.inspector.get(path)
        assert response.status_code == 200 and "手機記錄" in response.text and "補傳" in response.text
        assert "2026-11-06 09:00:00" in response.text and "2026-11-06 10:00:00" in response.text


def test_same_uuid_different_valid_photo_cannot_ack_or_replace_saved_photo(application, anytime):
    from PIL import Image
    a = anytime
    prepared = prepare(a.inspector)
    item = entry(prepared, a.direct, a.clock[0])
    assert sync(a.inspector, prepared, item, photos=[(png(), "same-name.png")]).status_code == 200
    original = db.session.scalar(db.select(InspectionPhoto)).data
    blue = BytesIO()
    Image.new("RGB", (20, 20), "blue").save(blue, "PNG")
    blue.seek(0)
    assert_error(sync(a.inspector, prepared, item, photos=[(blue, "same-name.png")]), "payload_conflict", status=409)
    assert db.session.query(OfflineSubmission).count() == db.session.query(InspectionPhoto).count() == 1
    assert db.session.scalar(db.select(InspectionPhoto)).data == original
