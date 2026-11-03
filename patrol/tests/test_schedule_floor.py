"""Floor edits preserve historical obligations and completed inspection snapshots."""
from datetime import datetime
import pytest

from test_app import application, seeded, app_module, db, login, rendered_contexts  # noqa: F401
from test_features import feature_point, clock
from models import Inspection, Point


def floor_context(application, client, day, floor, view="daily"):
    with rendered_contexts(application) as contexts:
        response = client.get(f"/dashboard?date={day}&floor={floor}&category=safety&view={view}")
    assert response.status_code == 200
    return contexts[-1][1]


def move(client, point, floor, code, name=None):
    return client.post(f"/admin/points/{point.id}/update", data={
        "code": code, "name": name or point.name, "floor": str(floor), "frequency": point.frequency,
        "category": point.category, "active": "on",
    })


def test_floor_move_keeps_previous_day_obligation_and_uses_new_floor_today(application, seeded, monkeypatch):
    point = feature_point(frequency="daily", floor=1, code="1F-FLOOR01")
    point.schedules[0].floor = 1
    db.session.commit()
    admin = application.test_client()
    login(admin, "manager")
    assert floor_context(application, admin, "2026-11-02", 1)["totals"]["total"] == 1
    clock(monkeypatch, 12)
    original_name = point.name
    assert move(admin, point, 2, "2F-FLOOR01", "搬遷後名稱").status_code == 302
    yesterday = floor_context(application, admin, "2026-11-02", 1)
    assert yesterday["totals"] == {"total": 1, "done": 0, "pending": 1}
    assert yesterday["cards"][0]["point"].code == "1F-FLOOR01"
    assert yesterday["cards"][0]["point"].name == original_name
    assert floor_context(application, admin, "2026-11-02", 2)["totals"]["total"] == 0
    today = floor_context(application, admin, "2026-11-03", 2)
    assert today["totals"]["total"] == 1
    assert today["cards"][0]["point"].name == "搬遷後名稱"
    assert floor_context(application, admin, "2026-11-03", 1)["totals"]["total"] == 0


def test_null_legacy_floor_is_frozen_before_moving_point(application, seeded):
    point = feature_point(frequency="daily", floor=1, code="1F-FLOOR02")
    assert point.schedules[0].floor is None
    admin = application.test_client()
    login(admin, "manager")
    assert move(admin, point, 11, "1M-FLOOR02").status_code == 302
    db.session.refresh(point)
    assert [s.floor for s in point.schedules] == [1, 11]
    assert [s.point_code for s in point.schedules] == ["1F-FLOOR02", "1M-FLOOR02"]
    assert all(s.point_name == point.name for s in point.schedules)
    assert floor_context(application, admin, "2026-11-02", 1)["totals"]["total"] == 1


def test_midday_floor_move_keeps_completed_am_and_only_moves_pending_pm(application, seeded):
    point = feature_point(floor=1, code="1F-FLOOR03")
    point.schedules[0].floor = 1
    row = Inspection(point_id=point.id, user_id=seeded["inspector"].id,
                     created_at=datetime(2026, 11, 3, 2), period_key="2026-11-03", frequency="daily2",
                     slot="am", category="safety", point_code=point.code, point_name=point.name,
                     point_floor=1, user_name=seeded["inspector"].display_name)
    db.session.add(row)
    db.session.commit()
    admin = application.test_client()
    login(admin, "manager")
    assert move(admin, point, 2, "2F-FLOOR03").status_code == 302
    old = floor_context(application, admin, "2026-11-03", 1)
    new = floor_context(application, admin, "2026-11-03", 2)
    assert old["totals"] == {"total": 1, "done": 1, "pending": 0}
    assert new["totals"] == {"total": 1, "done": 0, "pending": 1}
    assert old["cards"][0]["point"].code == "1F-FLOOR03"
    db.session.refresh(row)
    assert row.point_floor == 1 and row.point_code == "1F-FLOOR03"


def test_previous_week_stays_on_original_floor_after_move(application, seeded):
    point = feature_point(frequency="weekly", floor=-2, code="B2-FLOOR04")
    point.schedules[0].floor = -2
    db.session.commit()
    admin = application.test_client()
    login(admin, "manager")
    assert move(admin, point, 15, "5M-FLOOR04").status_code == 302
    assert floor_context(application, admin, "2026-10-28", -2, "weekly")["totals"]["total"] == 1
    assert floor_context(application, admin, "2026-10-28", 15, "weekly")["totals"]["total"] == 0


def test_new_point_and_same_day_moves_store_floor_in_order(application, seeded):
    admin = application.test_client()
    login(admin, "manager")
    response = admin.post("/admin/points/create", data={"code": "B1-FLOOR05", "name": "樓層歷程測試", "floor": "-1", "frequency": "daily", "category": "safety"})
    assert response.status_code == 302
    point = db.session.scalar(db.select(Point).where(Point.code == "B1-FLOOR05"))
    assert point.schedules[0].floor == -1
    assert move(admin, point, 1, "1F-FLOOR05").status_code == 302
    assert move(admin, point, 2, "2F-FLOOR05").status_code == 302
    db.session.refresh(point)
    assert [s.floor for s in point.schedules] == [-1, 1, 2]
    assert [s.point_code for s in point.schedules] == ["B1-FLOOR05", "1F-FLOOR05", "2F-FLOOR05"]
    context = floor_context(application, admin, "2026-11-03", 2)
    assert context["totals"]["total"] == 1


@pytest.mark.parametrize("hour,completed_pm", [(10, False), (12, False), (12, True)])
def test_same_floor_rename_uses_schedule_label_only_for_uncompleted_slots(application, seeded, monkeypatch, hour, completed_pm):
    point = feature_point(floor=1, code="1F-FLOOR06")
    original_code, original_name = point.code, point.name
    for slot in (["am", "pm"] if completed_pm else ["am"]):
        db.session.add(Inspection(point_id=point.id, user_id=seeded["inspector"].id,
                                  created_at=datetime(2026, 11, 3, 2 if slot == "am" else 4),
                                  period_key="2026-11-03", frequency="daily2", slot=slot,
                                  category="safety", point_code=original_code, point_name=original_name,
                                  point_floor=1, user_name=seeded["inspector"].display_name))
    db.session.commit()
    clock(monkeypatch, hour)
    admin = application.test_client()
    login(admin, "manager")
    assert move(admin, point, 1, "1F-RENAMED06", "更新後名稱").status_code == 302
    context = floor_context(application, admin, "2026-11-03", 1)
    card, = context["cards"]
    assert card["point"].code == (original_code if completed_pm else "1F-RENAMED06")
    assert card["point"].name == (original_name if completed_pm else "更新後名稱")
    assert card["slots"][1]["status"] == ("done" if completed_pm else "not_due" if hour < 12 else "pending")
    records = db.session.scalars(db.select(Inspection).where(Inspection.point_id == point.id)).all()
    assert all(row.point_code == original_code and row.point_name == original_name for row in records)
