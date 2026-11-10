"""Admin numbering routes retain QR identity and live patrol handoffs."""
from datetime import date, datetime, timezone
import re

import pytest

import app as patrol
from models import Inspection, PatrolExecution, Point, PointSchedule, db
from test_app import application, rendered_contexts
from test_workflow_checkin import payload, team


URL = "/admin/points/general-numbering"
NOW = datetime(2026, 11, 10, 2, tzinfo=timezone.utc)


@pytest.fixture
def numbered_team(application, monkeypatch):
    monkeypatch.setattr(patrol, "now_utc", lambda: NOW)
    executor, inspector, peer, admin, *urls = team(application)
    points = list(db.session.scalars(db.select(Point).order_by(Point.id)))
    for point, (code, floor) in zip(points, [("B2-G010", -2), ("1F-G025", 1), ("5F-G040", 5)]):
        point.code, point.floor, point.frequency = code, floor, "daily"
        point.created_at = datetime(2026, 1, 1)
        schedule = point.schedules[0]
        schedule.frequency, schedule.floor = point.frequency, floor
        schedule.point_code, schedule.point_name = point.code, point.name
    extras = {}
    for key, code, floor, active, deleted, category in [
        ("inactive", "3F-G070", 3, False, False, "general"),
        ("deleted", "5F-G080", 5, False, True, "general"),
        ("toilet", "B1F-W01", 1, True, False, "general"),
        ("safety", "1F-S001", 1, True, False, "safety"),
    ]:
        point = Point(code=code, name=key, floor=floor, active=active, category=category,
                      frequency="daily", workflow_mode="spot" if category == "general" else "standard",
                      schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1),
                      deleted_at=datetime(2026, 11, 1) if deleted else None)
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, category=category,
            frequency=point.frequency, workflow_mode=point.workflow_mode, active=active,
            floor=floor, point_code=code, point_name=point.name))
        db.session.add(point)
        extras[key] = point
    points[2].inspection_team = "engineering"
    db.session.commit()
    return dict(executor=executor, inspector=inspector, peer=peer, admin=admin,
                active_ids=[point.id for point in points], urls=urls,
                **{key: point.id for key, point in extras.items()})


def points_snapshot():
    return {p.id: (p.code, p.name, p.active, p.deleted_at, p.qr_token)
            for p in db.session.scalars(db.select(Point).order_by(Point.id))}


def schedule_snapshot():
    return {s.id: tuple(getattr(s, column.name) for column in PointSchedule.__table__.columns)
            for s in db.session.scalars(db.select(PointSchedule).order_by(PointSchedule.id))}


def preview_hash(client):
    response = client.get(URL)
    assert response.status_code == 200
    found = re.search(r'name="expected_plan" value="([a-f0-9]{64})"', response.text)
    assert found, response.text
    return found.group(1)


def enable_numbering(actors):
    response = actors["admin"].post(URL, data={"expected_plan": preview_hash(actors["admin"])})
    assert response.status_code == 302 and response.location.endswith(URL)
    db.session.expire_all()
    return response


def update_data(point, *, active=True):
    data = dict(code=point.code, name=point.name, floor=point.floor, category=point.category,
                frequency=point.frequency, workflow_mode=point.workflow_mode,
                inspection_team=point.inspection_team, expected_state=patrol.management_state(point))
    if active:
        data["active"] = "on"
    return data


def active_codes(actors):
    db.session.expire_all()
    return [db.session.get(Point, key).code for key in actors["active_ids"]]


def test_admin_preview_is_read_only_and_explains_scope_and_reprinting(application, numbered_team):
    before, schedules = points_snapshot(), schedule_snapshot()
    with rendered_contexts(application) as contexts:
        response = numbered_team["admin"].get(URL)
    assert response.status_code == 200
    assert contexts[-1][0] == "general_numbering.html"
    assert contexts[-1][1]["plan"]["changed"] == 5
    assert "包含由工務巡檢的點位" in response.text
    assert "廁所原編號與職安點位不變" in response.text
    assert "不更換 QR 網址" in response.text and "編號變更後請重印標籤" in response.text
    assert 'name="csrf_token"' in response.text and 'name="expected_plan"' in response.text
    assert "B2-G010" in response.text and "B2-G001" in response.text
    assert points_snapshot() == before and schedule_snapshot() == schedules


@pytest.mark.parametrize("role", ["executor", "inspector", "peer"])
def test_non_admin_cannot_preview_or_apply(application, numbered_team, role):
    before = points_snapshot()
    client = numbered_team[role]
    assert client.get(URL).status_code == 403
    assert client.post(URL, data={"expected_plan": "f" * 64}).status_code == 403
    assert points_snapshot() == before


def test_anonymous_numbering_requests_require_login(application, numbered_team):
    before = points_snapshot()
    client = application.test_client()
    for response in (client.get(URL), client.post(URL, data={"expected_plan": "f" * 64})):
        assert response.status_code == 302 and "/login" in response.location
    assert points_snapshot() == before


@pytest.mark.parametrize("digest,status", [(None, 400), ("bad", 400), ("f" * 64, 409)])
def test_missing_or_wrong_plan_hash_cannot_mutate(application, numbered_team, digest, status):
    before, schedules = points_snapshot(), schedule_snapshot()
    response = numbered_team["admin"].post(URL, data={} if digest is None else {"expected_plan": digest})
    assert response.status_code == status
    assert points_snapshot() == before and schedule_snapshot() == schedules


def test_stale_preview_hash_rejects_concurrent_point_edit(application, numbered_team):
    digest = preview_hash(numbered_team["admin"])
    point = db.session.get(Point, numbered_team["active_ids"][1])
    point.name = "Changed after preview"
    db.session.commit()
    before = points_snapshot()
    response = numbered_team["admin"].post(URL, data={"expected_plan": digest})
    assert response.status_code == 409 and "重新" in response.text
    assert points_snapshot() == before


def test_numbering_post_requires_valid_csrf_when_enabled(application, numbered_team):
    application.config["CSRF_ENABLED"] = True
    admin = numbered_team["admin"]
    digest = preview_hash(admin)
    before = points_snapshot()
    assert admin.post(URL, data={"expected_plan": digest}).status_code == 400
    assert points_snapshot() == before
    with admin.session_transaction() as session:
        token = session["csrf_token"]
    assert admin.post(URL, data={"expected_plan": digest, "csrf_token": token}).status_code == 302
    assert active_codes(numbered_team) == ["B2-G001", "1F-G002", "5F-G003"]


def test_already_contiguous_points_can_enable_automatic_numbering_without_code_changes(application, numbered_team):
    codes = dict(zip(numbered_team["active_ids"], ["B2-G001", "1F-G002", "5F-G003"]))
    codes.update({numbered_team["inactive"]: "3F-G100", numbered_team["deleted"]: "5F-G101"})
    for key, code in codes.items():
        db.session.get(Point, key).code = code
    db.session.commit()
    before = points_snapshot()
    with rendered_contexts(application) as contexts:
        response = numbered_team["admin"].get(URL)
    assert response.status_code == 200
    assert contexts[-1][1]["plan"]["changed"] == 0 and not contexts[-1][1]["plan"]["enabled"]
    assert "套用編號重排" in response.text and 'name="expected_plan"' in response.text
    enable_numbering(numbered_team)
    assert points_snapshot() == before
    assert "自動編號已啟用" in numbered_team["admin"].get(URL).text


def test_apply_preserves_qr_tokens_historical_records_and_old_schedule_snapshots(application, numbered_team):
    inspector, url = numbered_team["inspector"], numbered_team["urls"][1]
    assert inspector.post(url + "/confirm", data=payload(inspector, url) | {"note": "History remains"}).status_code == 302
    row = db.session.scalar(db.select(Inspection))
    original_record = (row.id, row.point_id, row.point_code, row.point_name, row.frequency, row.note, row.created_at)
    tokens = {p.id: p.qr_token for p in db.session.scalars(db.select(Point))}
    schedules = schedule_snapshot()
    enable_numbering(numbered_team)
    assert active_codes(numbered_team) == ["B2-G001", "1F-G002", "5F-G003"]
    assert db.session.get(Point, numbered_team["inactive"]).code == "3F-G100"
    assert db.session.get(Point, numbered_team["deleted"]).code == "5F-G101"
    assert db.session.get(Point, numbered_team["toilet"]).code == "B1F-W01"
    assert db.session.get(Point, numbered_team["safety"]).code == "1F-S001"
    assert {p.id: p.qr_token for p in db.session.scalars(db.select(Point))} == tokens
    assert all(schedule_snapshot()[key] == value for key, value in schedules.items())
    row = db.session.get(Inspection, original_record[0])
    assert (row.id, row.point_id, row.point_code, row.point_name, row.frequency, row.note, row.created_at) == original_record
    completed = numbered_team["admin"].get(URL)
    assert completed.status_code == 200 and "編號已連續排列" in completed.text
    assert "自動編號已啟用" in completed.text and "列印最新 QR 標籤" in completed.text
    assert 'name="expected_plan"' not in completed.text
    manager = numbered_team["admin"].get("/admin/points")
    assert manager.status_code == 200 and "G 編號已啟用自動排列" in manager.text
    assert 'href="/admin/points/general-numbering"' in manager.text


def test_disable_and_enable_reorders_all_codes_and_restores_original_order(application, numbered_team):
    enable_numbering(numbered_team)
    admin = numbered_team["admin"]
    point = db.session.get(Point, numbered_team["active_ids"][0])
    token = point.qr_token
    assert admin.post(f"/admin/points/{point.id}/update", data=update_data(point, active=False)).status_code == 302
    assert active_codes(numbered_team) == ["B2-G100", "1F-G001", "5F-G002"]
    point = db.session.get(Point, point.id)
    assert point.qr_token == token and not point.active
    assert admin.post(f"/admin/points/{point.id}/update", data=update_data(point)).status_code == 302
    assert active_codes(numbered_team) == ["B2-G001", "1F-G002", "5F-G003"]
    assert db.session.get(Point, point.id).qr_token == token


def test_delete_restore_and_reenable_keep_numbering_and_existing_qr_revocation_rules(application, numbered_team):
    enable_numbering(numbered_team)
    admin = numbered_team["admin"]
    point = db.session.get(Point, numbered_team["active_ids"][1])
    old_token, key = point.qr_token, point.id
    response = admin.post(f"/admin/points/{key}/delete", data={"expected_state": patrol.management_state(point)})
    assert response.status_code == 302
    assert active_codes(numbered_team) == ["B2-G001", "1F-G100", "5F-G002"]
    point = db.session.get(Point, key)
    assert point.deleted_at is not None and point.qr_token != old_token
    deleted_token = point.qr_token
    response = admin.post(f"/admin/points/{key}/restore", data={"expected_state": patrol.management_state(point)})
    assert response.status_code == 302
    db.session.expire_all()
    point = db.session.get(Point, key)
    assert point.deleted_at is None and not point.active
    assert point.code == "1F-G100" and point.qr_token == deleted_token
    assert admin.post(f"/admin/points/{key}/update", data=update_data(point)).status_code == 302
    assert active_codes(numbered_team) == ["B2-G001", "1F-G002", "5F-G003"]
    assert db.session.get(Point, key).qr_token == deleted_token


def test_new_general_g_point_joins_floor_order_without_changing_toilet_codes(application, numbered_team):
    enable_numbering(numbered_team)
    admin = numbered_team["admin"]
    response = admin.post("/admin/points/create", data=dict(code="2F-G999", name="New general equipment",
        floor=2, category="general", inspection_team="engineering", frequency="weekly", workflow_mode="spot"))
    assert response.status_code == 302
    db.session.expire_all()
    created = db.session.scalar(db.select(Point).where(Point.name == "New general equipment"))
    assert created.code == "2F-G003" and created.inspection_team == "engineering"
    assert active_codes(numbered_team) == ["B2-G001", "1F-G002", "5F-G004"]
    assert db.session.get(Point, numbered_team["toilet"]).code == "B1F-W01"


def test_older_point_editor_cannot_restore_pre_numbering_code(application, numbered_team):
    point = db.session.get(Point, numbered_team["active_ids"][1])
    stale_data, key = update_data(point), point.id
    enable_numbering(numbered_team)
    before = points_snapshot()
    response = numbered_team["admin"].post(f"/admin/points/{key}/update", data=stale_data)
    assert response.status_code == 409
    assert points_snapshot() == before


def test_pending_two_stage_execution_still_matches_after_renumbering(application, numbered_team):
    executor, inspector, url = numbered_team["executor"], numbered_team["inspector"], numbered_team["urls"][0]
    response = executor.post(url + "/confirm", data=payload(executor, url))
    assert response.status_code == 302
    first = db.session.scalar(db.select(PatrolExecution))
    first_id, original_code = first.id, first.point_code
    enable_numbering(numbered_team)
    with rendered_contexts(application) as contexts:
        page = inspector.get(url)
    assert page.status_code == 200 and contexts[-1][1]["can_confirm"]
    response = inspector.post(url + "/confirm", data=payload(inspector, url))
    assert response.status_code == 302
    inspection = db.session.scalar(db.select(Inspection))
    assert inspection.execution_id == first_id
    assert inspection.point_code == "B2-G001"
    assert db.session.get(PatrolExecution, first_id).point_code == original_code == "B2-G010"


def test_scheduled_change_blocker_is_visible_and_hides_apply_form(application, numbered_team):
    point = db.session.get(Point, numbered_team["active_ids"][1])
    point.pending_frequency, point.frequency_effective_date = "weekly", date(2026, 11, 12)
    db.session.commit()
    before = points_snapshot()
    with rendered_contexts(application) as contexts:
        response = numbered_team["admin"].get(URL)
    assert response.status_code == 200
    assert contexts[-1][1]["plan"]["blockers"]
    assert "目前尚無法套用" in response.text
    assert 'name="expected_plan"' not in response.text
    assert points_snapshot() == before
