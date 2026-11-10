"""Admin-created toilet labels keep their own floor-aware numbering scheme."""
from datetime import datetime

import pytest

import app as patrol
from checklist_catalog import checklist_for_point
from models import Point, User, db
from test_app import application


@pytest.fixture
def manager(application):
    user = User(username="toilet-code-admin", display_name="Test admin", role="admin",
                password_hash="unused-local-test-hash", active=True, must_change_password=False)
    db.session.add(user)
    db.session.commit()
    client = application.test_client()
    with client.session_transaction() as session:
        session.update(user_id=user.id, auth_version=user.auth_version, csrf_token="local-test-csrf")
    return client


def fields(code="AB1-M01", **changes):
    return dict(code=code, name="b1男廁所-甲", floor="-1", category="general",
                inspection_team="general", frequency="three_day", workflow_mode="spot") | changes


@pytest.mark.parametrize("raw,floor,expected", [
    ("AB1-M01", -1, "AB1-M01"), ("BB1-M02", -1, "BB1-M02"),
    (" ab1-m01 ", -1, "AB1-M01"), ("aB1M-w01", -1, "AB1m-W01"),
    ("a2fm-m01", 2, "A2Fm-M01"), ("A1M-W01", 11, "A1M-W01"),
    ("D4M-M04", 14, "D4M-M04"), ("CB2-W03", -2, "CB2-W03"),
])
def test_new_toilet_codes_are_canonical_and_match_selected_floor(application, manager, raw, floor, expected):
    response = manager.post("/admin/points/create", data=fields(raw, floor=str(floor)))
    assert response.status_code == 302, response.text
    point = db.session.scalar(db.select(Point))
    assert (point.code, point.floor, point.category, point.frequency, point.workflow_mode) == (
        expected, floor, "general", "three_day", "spot")
    assert point.schedules[0].point_code == expected and point.qr_token
    assert checklist_for_point(point)["key"] == "toilet_v1"


@pytest.mark.parametrize("changes", [
    {"floor": "-2"}, {"floor": "1"}, {"category": "safety", "workflow_mode": "standard"},
    {"category": "uncategorized"}, {"name": "B1 倉庫"}, {"name": ""},
    {"code": "AB3-M01"}, {"code": "AB1-X01"}, {"code": "AB1-M1"},
    {"code": "AB1-M001"}, {"code": "AAB1-M01"}, {"code": "ＡB1-M01"},
    {"code": "AB1-M０１"}, {"code": "AB1/M01"}, {"code": "AB1-M01<script>"},
    {"code": "A1M-M01"}, {"code": "A2Fm-M01"},
])
def test_custom_toilet_shape_does_not_bypass_floor_category_or_label_validation(application, manager, changes):
    response = manager.post("/admin/points/create", data=fields(**changes))
    assert response.status_code == 400
    assert db.session.query(Point).count() == 0


@pytest.mark.parametrize("archived", [False, True])
def test_case_variant_cannot_duplicate_existing_or_archived_toilet(application, manager, archived):
    existing = Point(code="ab1-m01", name="舊廁所", floor=-1, category="general",
                     frequency="three_day", workflow_mode="spot", active=not archived,
                     deleted_at=datetime(2026, 1, 1) if archived else None)
    db.session.add(existing)
    db.session.commit()
    response = manager.post("/admin/points/create", data=fields("AB1-M01"))
    assert response.status_code == 400 and "已被使用" in response.text
    assert db.session.query(Point).count() == 1


def test_editing_existing_toilet_keeps_qr_and_does_not_self_collide(application, manager):
    assert manager.post("/admin/points/create", data=fields()).status_code == 302
    point = db.session.scalar(db.select(Point))
    token = point.qr_token
    data = fields("ab1-m01", name="B1 男廁所-甲", active="on", expected_state=patrol.management_state(point))
    assert manager.post(f"/admin/points/{point.id}/update", data=data).status_code == 302
    assert point.code == "AB1-M01" and point.name == "B1 男廁所-甲" and point.qr_token == token


def test_standard_codes_keep_original_floor_and_non_toilet_rules(application, manager):
    response = manager.post("/admin/points/create", data=fields("B1-A01", name="B1 工作區"))
    assert response.status_code == 302
    assert db.session.scalar(db.select(Point)).code == "B1-A01"
    assert manager.post("/admin/points/create", data=fields("B1-A02", floor="2")).status_code == 400
    assert db.session.query(Point).count() == 1


def test_m_and_w_do_not_infer_gender_from_names(application, manager):
    assert manager.post("/admin/points/create", data=fields("BB1-M02", name="b1女廁所-乙")).status_code == 302
    assert db.session.scalar(db.select(Point)).name == "b1女廁所-乙"
