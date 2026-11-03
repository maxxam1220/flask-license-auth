"""Current admin authority and deterministic locking across account mutations."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from test_app import application, seeded, db, login, app_module  # noqa: F401
from test_postgres_features import postgres_app  # noqa: F401
from models import AuditLog, DeviceBinding, User


def is_user_lock(state):
    return (state.is_select and getattr(state.statement, "_for_update_arg", None) is not None
            and "FROM patrol_users" in str(state.statement))


@pytest.mark.parametrize("mutation", ["approve", "reject", "revoke", "create", "update", "reset-password"])
@pytest.mark.parametrize("revocation", [
    {"role": "inspector"}, {"active": False}, {"auth_version": 2}, {"must_change_password": True},
])
def test_user_and_device_mutations_recheck_locked_actor(application, seeded, mutation, revocation):
    target = seeded["inspector"]
    actor_id, target_id = seeded["manager"].id, target.id
    original_name, original_password = target.display_name, target.password_hash
    binding = DeviceBinding(user_id=target.id, token_hash="review-binding-hash",
                            status="approved" if mutation == "revoke" else "pending")
    db.session.add(binding)
    db.session.commit()
    binding_id, original_status = binding.id, binding.status
    client = application.test_client()
    login(client, "manager")
    data = {"username": "review-created", "display_name": "Changed name", "role": "inspector",
            "active": "on", "password": "Review-test-password-123!"}
    if mutation in ("approve", "reject", "revoke"):
        path = f"/admin/devices/{binding_id}/{mutation}"
    elif mutation == "create":
        path = "/admin/users/create"
    else:
        path = f"/admin/users/{target_id}/{mutation}"
    injected = {"done": False}
    def revoke_before_first_lock(state):
        if not injected["done"] and is_user_lock(state):
            injected["done"] = True
            db.session.execute(db.update(User).where(User.id == actor_id).values(**revocation)
                               .execution_options(synchronize_session=False))
    event.listen(Session, "do_orm_execute", revoke_before_first_lock)
    try:
        response = client.post(path, data=data)
    finally:
        event.remove(Session, "do_orm_execute", revoke_before_first_lock)
        db.session.rollback()
    assert injected["done"] and response.status_code == 403
    assert db.session.get(DeviceBinding, binding_id).status == original_status
    assert db.session.get(User, target_id).display_name == original_name
    assert db.session.get(User, target_id).password_hash == original_password
    assert db.session.scalar(db.select(User).where(User.username == "review-created")) is None
    assert db.session.query(AuditLog).count() == 0


@pytest.mark.parametrize("fields", [{"role": "inspector", "active": "on"}, {"role": "admin"}])
def test_admin_cannot_remove_own_admin_access(application, seeded, fields):
    actor_id = seeded["manager"].id
    client = application.test_client()
    login(client, "manager")
    response = client.post(f"/admin/users/{actor_id}/update", data={"display_name": "Manager Charlie", **fields})
    db.session.rollback()
    assert response.status_code == 400
    actor = db.session.get(User, actor_id)
    assert actor.active and actor.role == "admin" and actor.auth_version == 1
    assert db.session.query(AuditLog).count() == 0


def pg_admin_clients(application):
    with application.app_context():
        users = [User(username=f"admin{number}", display_name=f"Admin {number}", role="admin",
                      active=True, must_change_password=False, password_hash="unused-test-hash", auth_version=1)
                 for number in range(2)]
        db.session.add_all(users)
        db.session.commit()
        ids = [user.id for user in users]
    clients = []
    for user_id in ids:
        client = application.test_client()
        with client.session_transaction() as session:
            session["user_id"], session["auth_version"] = user_id, 1
        clients.append(client)
    return clients, ids


def simultaneously_after_authorization(actions):
    # Both requests have passed the initial admin decorator before either can
    # lock an account. A role revocation must be observed by the waiting action.
    barrier = threading.Barrier(len(actions))
    seen = set()
    guard = threading.Lock()
    def before_first_user_lock(state):
        if not is_user_lock(state):
            return
        thread_id = threading.get_ident()
        with guard:
            first = thread_id not in seen
            seen.add(thread_id)
        if first:
            barrier.wait(timeout=10)
    event.listen(Session, "do_orm_execute", before_first_user_lock)
    try:
        with ThreadPoolExecutor(max_workers=len(actions)) as workers:
            futures = [workers.submit(action) for action in actions]
            return [future.result(timeout=30).status_code for future in futures]
    finally:
        event.remove(Session, "do_orm_execute", before_first_user_lock)


def test_postgres_opposing_admin_demotions_preserve_one_admin_without_deadlock(postgres_app):
    clients, ids = pg_admin_clients(postgres_app)
    actions = [lambda index=index: clients[index].post(f"/admin/users/{ids[1-index]}/update", data={
        "display_name": f"Admin {1-index}", "role": "inspector", "active": "on"}) for index in range(2)]
    assert sorted(simultaneously_after_authorization(actions)) == [302, 403]
    with postgres_app.app_context():
        assert db.session.query(User).filter_by(role="admin", active=True).count() == 1
        assert db.session.query(AuditLog).filter_by(action="user_updated").count() == 1


def test_postgres_opposing_device_approvals_use_consistent_account_lock_order(postgres_app):
    clients, ids = pg_admin_clients(postgres_app)
    with postgres_app.app_context():
        bindings = [DeviceBinding(user_id=user_id, token_hash=f"pending-admin-device-{user_id}", status="pending") for user_id in ids]
        db.session.add_all(bindings)
        db.session.commit()
        binding_ids = [binding.id for binding in bindings]
    actions = [lambda index=index: clients[index].post(f"/admin/devices/{binding_ids[1-index]}/approve") for index in range(2)]
    assert simultaneously_after_authorization(actions) == [302, 302]
    with postgres_app.app_context():
        assert db.session.query(DeviceBinding).filter_by(status="approved").count() == 2
        assert db.session.query(AuditLog).filter_by(action="device_approved").count() == 2


def test_postgres_waiting_device_approval_observes_committed_actor_revocation(postgres_app):
    clients, ids = pg_admin_clients(postgres_app)
    with postgres_app.app_context():
        worker = User(username="worker", display_name="Worker", role="inspector", active=True,
                      must_change_password=False, password_hash="unused-test-hash")
        db.session.add(worker)
        db.session.flush()
        binding = DeviceBinding(user_id=worker.id, token_hash="worker-pending-device", status="pending")
        db.session.add(binding)
        db.session.commit()
        binding_id = binding.id
        # Keep the revocation uncommitted so the request's initial plain SELECT
        # still sees the admin. Its later row lock must wait and re-read it.
        db.session.execute(db.update(User).where(User.id == ids[1]).values(role="inspector", auth_version=2))
        reached_lock = threading.Event()
        def signal_lock(state):
            if is_user_lock(state):
                reached_lock.set()
        event.listen(Session, "do_orm_execute", signal_lock)
        try:
            with ThreadPoolExecutor(max_workers=1) as workers:
                future = workers.submit(clients[1].post, f"/admin/devices/{binding_id}/approve")
                try:
                    assert reached_lock.wait(timeout=10), "Request did not reach its account lock"
                finally:
                    db.session.commit()
                assert future.result(timeout=20).status_code == 403
        finally:
            event.remove(Session, "do_orm_execute", signal_lock)
            db.session.rollback()
        assert db.session.get(DeviceBinding, binding_id).status == "pending"
        assert db.session.query(AuditLog).count() == 0
