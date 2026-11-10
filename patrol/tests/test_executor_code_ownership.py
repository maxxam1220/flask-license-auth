"""Executor visits belong to original point IDs, never to their reusable labels."""
import pytest

import app as patrol
from models import Inspection, Point, db
from test_app import application
from test_executor_visits import synthetic_register
from test_offline_api import assert_error, entry, prepare, sync
from test_three_day_routes import stops
from test_workflow_checkin import payload


def rename(env, point, code):
    response = env.admin.post(f"/admin/points/{point.id}/update", data={
        "code": code, "name": point.name, "floor": point.floor, "category": point.category,
        "frequency": point.frequency, "workflow_mode": point.workflow_mode,
        "inspection_team": point.inspection_team, "active": "on", "state": patrol.management_state(point)})
    assert response.status_code == 302, response.text
    db.session.refresh(point)


def test_renamed_original_retains_online_identity_but_old_confirmation_cannot_be_saved(stops):
    env = stops
    old_code, point_id, token = env.point.code, env.point.id, env.point.qr_token
    stale = payload(env.executor, env.url)
    rename(env, env.point, "1F-NEW099")
    assert (env.point.id, env.point.qr_token) == (point_id, token)
    assert env.point.schedules[0].point_code == old_code
    assert env.executor.post(env.url + "/confirm", data=stale).status_code in (403, 409)
    assert db.session.query(Inspection).count() == 0
    fresh = payload(env.executor, env.url)
    assert fresh["stage"] == "visit" and fresh["point_revision"] != stale["point_revision"]
    assert env.executor.post(env.url + "/confirm", data=fresh).status_code == 302
    row = db.session.scalar(db.select(Inspection))
    assert row.point_id == point_id and row.point_code == "1F-NEW099" and row.executor_visit


def test_renamed_original_rejects_old_offline_revision_and_accepts_new_grant(stops):
    env = stops
    prepared = prepare(env.executor)
    old = entry(prepared, env.url, env.clock[0])
    rename(env, env.point, "1F-NEW098")
    assert_error(sync(env.executor, prepared, old), "point_changed")
    assert db.session.query(Inspection).count() == 0
    fresh = prepare(env.executor)
    allowed = next(point for point in fresh["points"] if point["id"] == env.point.id)
    assert allowed["stage"] == "visit" and allowed["code"] == "1F-NEW098"
    assert allowed["grant"] != old["grant"]
    result = sync(env.executor, fresh, entry(fresh, env.url, env.clock[0]))
    assert result.status_code == 200 and result.get_json()["ok"]
    assert db.session.query(Inspection).filter_by(point_id=env.point.id, executor_visit=True).count() == 1


def test_original_code_reuse_does_not_transfer_online_or_offline_access(stops):
    env = stops
    old_code = env.point.code
    other = env.create(code="1F-OTHER099")
    other_url = "/c/" + other.qr_token
    rename(env, env.point, "1F-NEW097")
    rename(env, other, old_code)
    assert payload(env.executor, env.url)["stage"] == "visit"
    assert env.executor.get(other_url).status_code == 404
    assert env.executor.post(other_url + "/confirm", data=payload(env.executor, env.url)).status_code == 404
    prepared = prepare(env.executor)
    ids = {point["id"] for point in prepared["points"] if point["stage"] == "visit"}
    assert env.point.id in ids and other.id not in ids
    forged = entry(prepared, env.url, env.clock[0]) | {"token": other.qr_token}
    assert_error(sync(env.executor, prepared, forged))
    # Ordinary inspectors can still inspect the point now bearing that label.
    fresh = payload(env.inspector, other_url)
    assert fresh["stage"] == "inspect"
    assert env.inspector.post(other_url + "/confirm", data=fresh).status_code == 302


def test_all_original_seven_can_be_renumbered_without_expanding_id_set(stops):
    env = stops
    points = [env.point, *(env.create(index) for index in range(1, 7))]
    expected = {point.id for point in points}
    for ordinal, point in enumerate(points):
        rename(env, point, f"1F-NEW{ordinal:03}")
    after = prepare(env.executor)
    assert {point["id"] for point in after["points"] if point["stage"] == "visit"} == expected
    assert all(payload(env.executor, "/c/" + point.qr_token)["stage"] == "visit" for point in points)


def test_historyless_fallback_cannot_override_original_owner_or_null_history(stops):
    env = stops
    old_code = env.point.code
    rename(env, env.point, "1F-NEW096")
    clone = Point(code=old_code, name="Different point", floor=1, category="general", frequency="three_day",
                  workflow_mode="spot", active=True, schedule_start=env.point.schedule_start,
                  created_at=env.point.created_at)
    db.session.add(clone)
    db.session.commit()
    assert env.executor.get("/c/" + clone.qr_token).status_code == 404
    # A code with no registered owner still cannot grant an existing scheduled
    # point access when that history never established its original code.
    null_history = env.create(index=1)
    for schedule in null_history.schedules:
        schedule.point_code = None
    db.session.commit()
    assert env.executor.get("/c/" + null_history.qr_token).status_code == 404


@pytest.mark.parametrize("change", [dict(category="safety", workflow_mode="standard"),
                                    dict(frequency="daily"), dict(active=False)])
def test_original_identity_does_not_bypass_current_workflow_frequency_or_availability(stops, change):
    env = stops
    rename(env, env.point, "1F-NEW095")
    stale = payload(env.executor, env.url)
    for name, value in change.items():
        setattr(env.point, name, value)
    db.session.commit()
    assert env.executor.get(env.url).status_code in (403, 404)
    assert env.executor.post(env.url + "/confirm", data=stale).status_code in (403, 404)
    assert env.point.id not in {point["id"] for point in prepare(env.executor)["points"]}
