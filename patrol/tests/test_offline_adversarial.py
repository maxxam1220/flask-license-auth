"""Adversarial offline checks using isolated SQLite and allowlisted local PG only."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import event

import app as patrol
from models import DeviceBinding, Inspection, OfflineSubmission, PatrolExecution, RevokedSession, User, db
from test_app import application
from test_daily2_anytime import anytime, rows
from test_offline_api import assert_error, entry, prepare, sync
from test_postgres_features import postgres_app
from test_workflow_checkin import team


@pytest.mark.parametrize("frequency,last_day", [("weekly", "2026-11-08"), ("monthly", "2026-11-30")])
def test_out_of_order_period_sync_never_links_old_review_to_new_execution(application, anytime, frequency, last_day):
    a = anytime
    a.pair_point.frequency = a.pair_point.schedules[0].frequency = frequency
    db.session.commit()
    a.clock[0] = datetime.fromisoformat(last_day).replace(hour=23, minute=55, tzinfo=patrol.TAIPEI)
    old_worker, old_reviewer = prepare(a.executor), prepare(a.inspector)
    old_execution = entry(old_worker, a.paired, a.clock[0] + timedelta(minutes=1))
    old_review = entry(old_reviewer, a.paired, a.clock[0] + timedelta(minutes=2))

    a.clock[0] += timedelta(minutes=10)
    new_worker, new_reviewer = prepare(a.executor), prepare(a.inspector)
    new_execution = entry(new_worker, a.paired, a.clock[0])
    assert sync(a.executor, new_worker, new_execution).status_code == 200
    # An execution exists at this point, but it belongs to the next period.
    assert_error(sync(a.inspector, old_reviewer, old_review), "waiting_execution", status=409, retryable=True)
    assert db.session.query(Inspection).count() == 0
    assert sync(a.executor, old_worker, old_execution).status_code == 200
    assert sync(a.inspector, old_reviewer, old_review).status_code == 200
    a.clock[0] += timedelta(minutes=1)
    assert sync(a.inspector, new_reviewer, entry(new_reviewer, a.paired, a.clock[0])).status_code == 200
    saved = rows(a.pair_point)
    assert len(saved) == 2 and len(rows(a.pair_point, PatrolExecution)) == 2
    assert len({item.period_key for item in saved}) == len({item.personal_day for item in saved}) == 2
    assert all(item.execution.period_key == item.period_key and item.execution.created_at <= item.created_at for item in saved)
    assert len({item.execution_id for item in saved}) == 2


@pytest.mark.parametrize("frequency", ["daily2", "weekly", "monthly", "irregular"])
def test_reprepare_and_new_uuid_do_not_reset_personal_quota_or_change_peer_quota(application, anytime, frequency):
    a = anytime
    a.direct_point.frequency = a.direct_point.schedules[0].frequency = frequency
    db.session.commit()
    original = prepare(a.inspector)
    item = entry(original, a.direct, a.clock[0])
    accepted = sync(a.inspector, original, item)
    assert accepted.status_code == 200
    current = prepare(a.inspector)
    assert_error(sync(a.inspector, original, dict(item, client_id=str(uuid4()))), "duplicate", status=409)
    assert_error(sync(a.inspector, current, entry(current, a.direct, a.clock[0])), "duplicate", status=409)
    repeated = sync(a.inspector, original, item)
    assert repeated.status_code == 200 and repeated.get_json()["status"] == "already_synced"
    peer = prepare(a.peer)
    peer_item = entry(peer, a.direct, a.clock[0], client_id=item["client_id"])
    # UUID identity is per user; another authorized worker retains their own quota.
    assert sync(a.peer, peer, peer_item).status_code == 200
    assert len(rows(a.direct_point)) == db.session.query(OfflineSubmission).count() == 2
    if frequency == "daily2":
        second = entry(current, a.direct, a.clock[0], slot="pm")
        assert sync(a.inspector, current, second).status_code == 200
        assert_error(sync(a.inspector, current, dict(second, client_id=str(uuid4()))), "duplicate", status=409)
        assert len(rows(a.direct_point)) == 3


@pytest.mark.parametrize("frequency", ["daily2", "weekly", "monthly"])
def test_execution_quota_is_shared_by_all_executors_after_reprepare(application, anytime, frequency):
    a = anytime
    a.pair_point.frequency = a.pair_point.schedules[0].frequency = frequency
    other = db.session.scalar(db.select(User).where(User.username == "peer"))
    other.role = "executor"
    db.session.commit()
    first, peer = prepare(a.executor), prepare(a.peer)
    item = entry(first, a.paired, a.clock[0])
    assert sync(a.executor, first, item).status_code == 200
    assert_error(sync(a.peer, peer, entry(peer, a.paired, a.clock[0])), "duplicate", status=409)
    refreshed = prepare(a.executor)
    assert_error(sync(a.executor, refreshed, entry(refreshed, a.paired, a.clock[0])), "duplicate", status=409)
    assert len(rows(a.pair_point, PatrolExecution)) == 1
    if frequency == "daily2":
        assert sync(a.peer, peer, entry(peer, a.paired, a.clock[0], slot="pm")).status_code == 200
        assert len(rows(a.pair_point, PatrolExecution)) == 2


@pytest.mark.parametrize("attempt", ["raw-peer", "rewritten-owner", "rewritten-grant"])
def test_valid_peer_grant_and_receipt_cannot_be_transplanted_to_another_identity(application, anytime, attempt):
    a = anytime
    mine, peer = prepare(a.inspector), prepare(a.peer)
    item = entry(peer, a.direct, a.clock[0], note="Private peer note")
    assert sync(a.peer, peer, item).status_code == 200
    forged = dict(item)
    if attempt == "rewritten-owner":
        forged["owner"] = mine["owner"]
    elif attempt == "rewritten-grant":
        forged["grant"] = entry(mine, a.direct, a.clock[0])["grant"]
    rejected = sync(a.inspector, mine, forged)
    assert_error(rejected, status=400 if attempt == "rewritten-owner" else 403)
    assert "Private peer note" not in rejected.text
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 1


@pytest.mark.parametrize("mutation", ["role", "category", "password", "binding", "logout", "title-only"])
def test_postgres_sync_rechecks_identity_after_waiting_for_account_lock(postgres_app, monkeypatch, mutation):
    instant = datetime(2026, 11, 6, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(patrol, "now_utc", lambda: instant)
    with postgres_app.app_context():
        _, reviewer, _, _, _, direct, _ = team(postgres_app)
        user = db.session.scalar(db.select(User).where(User.username == "inspect"))
        user_id, version = user.id, user.auth_version
        binding_id = db.session.scalar(db.select(DeviceBinding.id).where(DeviceBinding.user_id == user_id))
        engine = db.engine
    prepared = prepare(reviewer)
    item = entry(prepared, direct, instant)
    reached_lock = Event()
    def observe_lock(_connection, _cursor, statement, _parameters, _context, _executemany):
        if "FROM patrol_users" in statement and "FOR NO KEY UPDATE" in statement:
            reached_lock.set()
    event.listen(engine, "before_cursor_execute", observe_lock)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(db.select(User.id).where(User.id == user_id).with_for_update())
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(sync, reviewer, prepared, item)
                try:
                    assert reached_lock.wait(10), "Sync did not reach its authoritative account lock"
                    if mutation == "role":
                        connection.execute(db.update(User).where(User.id == user_id).values(role="executor"))
                    elif mutation == "category":
                        connection.execute(db.update(User).where(User.id == user_id).values(patrol_category="safety"))
                    elif mutation == "password":
                        connection.execute(db.update(User).where(User.id == user_id).values(auth_version=version + 1))
                    elif mutation == "binding":
                        connection.execute(db.update(DeviceBinding).where(DeviceBinding.id == binding_id).values(status="revoked"))
                    elif mutation == "logout":
                        with reviewer.session_transaction() as session:
                            nonce = session.get("sid") or session["csrf_token"]
                        digest = hashlib.sha256(f"{user_id}:{nonce}".encode()).hexdigest()
                        connection.execute(db.insert(RevokedSession).values(token_hash=digest, user_id=user_id,
                            auth_version=version, revoked_at=patrol.naive_utc(instant)))
                    else:
                        connection.execute(db.update(User).where(User.id == user_id).values(engineering_inspector_title=True))
                    transaction.commit()
                    response = pending.result(timeout=15)
                finally:
                    if transaction.is_active:
                        transaction.rollback()
        if mutation == "title-only":
            assert response.status_code == 200, response.text
        else:
            assert_error(response, status=403)
        with postgres_app.app_context():
            expected = int(mutation == "title-only")
            assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == expected
    finally:
        event.remove(engine, "before_cursor_execute", observe_lock)
