"""Renumbering changes labels, never the identity behind a scanned QR.

All writes use isolated SQLite fixtures; no production attendance is created.
"""
import csv
import io
from datetime import timedelta

import pytest

import app as patrol
from checklist_catalog import checklist_for_point
from checklist_records import checklist_snapshot
from general_numbering import apply_general_numbering
from models import Inspection, PatrolExecution, Point, db
from test_app import application, rendered_contexts
from test_engineering_point_scope import teams
from test_general_numbering_routes import (NOW, numbered_team, enable_numbering,
                                           update_data)
from test_workflow_checkin import payload


def render(application, client, url):
    with rendered_contexts(application) as captured:
        response = client.get(url)
    assert response.status_code == 200, response.text
    return captured[-1][1], response


def test_old_qr_keeps_original_point_when_its_code_moves_to_another_point(application, numbered_team):
    e = numbered_team
    first, second = [db.session.get(Point, i) for i in e["active_ids"][:2]]
    first.workflow_mode = first.schedules[0].workflow_mode = "spot"
    second.floor = second.schedules[0].floor = first.floor
    db.session.commit()
    enable_numbering(e)
    original_url, other_url = e["urls"][:2]
    original_code = first.code
    stale = payload(e["inspector"], original_url)
    assert e["admin"].post(f"/admin/points/{first.id}/update", data=update_data(first, active=False)).status_code == 302
    db.session.expire_all()
    assert first.code == "B2-G100" and second.code == original_code
    assert e["inspector"].get(original_url).status_code == 403
    assert e["inspector"].post(original_url + "/confirm", data=stale).status_code == 403
    current, _ = render(application, e["inspector"], other_url)
    assert current["point"].id == second.id and current["point"].code == original_code
    response = e["inspector"].post(other_url + "/confirm", data=payload(e["inspector"], other_url))
    assert response.status_code == 302
    assert db.session.scalar(db.select(Inspection)).point_id == second.id
    assert e["admin"].post(f"/admin/points/{first.id}/update", data=update_data(first)).status_code == 302
    refreshed, _ = render(application, e["inspector"], original_url)
    assert refreshed["point"].id == first.id and refreshed["can_confirm"]


def test_weekly_execution_before_renumber_can_be_reviewed_next_day(application, numbered_team, monkeypatch):
    e = numbered_team
    point = db.session.get(Point, e["active_ids"][0])
    point.frequency = point.schedules[0].frequency = "weekly"
    db.session.commit()
    clock = [NOW - timedelta(days=1)]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    url = e["urls"][0]
    assert e["executor"].post(url + "/confirm", data=payload(e["executor"], url)).status_code == 302
    execution = db.session.scalar(db.select(PatrolExecution))
    original_execution = (execution.id, execution.point_id, execution.point_code, execution.created_at)
    clock[0] = NOW
    enable_numbering(e)
    before, _ = render(application, e["inspector"], "/ready")
    assert any(p["id"] == point.id for p in before["ready_points"])
    for client in (e["inspector"], e["peer"]):
        assert client.post(url + "/confirm", data=payload(client, url)).status_code == 302
    records = db.session.scalars(db.select(Inspection)).all()
    assert len(records) == 2
    assert {r.execution_id for r in records} == {execution.id}
    assert {r.point_id for r in records} == {point.id}
    assert {r.point_code for r in records} == {"B2-G001"}
    assert (execution.id, execution.point_id, execution.point_code, execution.created_at) == original_execution
    overview, _ = render(application, e["inspector"], "/dashboard?view=weekly")
    assert overview["totals"] == {"total": 1, "done": 1, "pending": 0}


def test_two_signed_rounds_remain_distinct_and_cannot_be_replayed_after_renumber(application, numbered_team):
    e = numbered_team
    point, url = db.session.get(Point, e["active_ids"][0]), e["urls"][0]
    point.frequency = point.schedules[0].frequency = "daily2"
    db.session.commit()
    for slot in ("am", "pm"):
        fields = payload(e["executor"], url)
        assert fields["slot"] == slot
        assert e["executor"].post(url + "/confirm", data=fields).status_code == 302
    executions = {row.slot: row.id for row in db.session.scalars(db.select(PatrolExecution))}
    assert set(executions) == {"am", "pm"}
    stale = payload(e["inspector"], url)
    enable_numbering(e)
    assert e["inspector"].post(url + "/confirm", data=stale).status_code == 409
    assert db.session.query(Inspection).count() == 0
    for slot in ("am", "pm"):
        fields = payload(e["inspector"], url)
        assert fields["slot"] == slot
        assert e["inspector"].post(url + "/confirm", data=fields).status_code == 302
        assert e["inspector"].post(url + "/confirm", data=fields).status_code == 302
    records = db.session.scalars(db.select(Inspection)).all()
    assert len(records) == 2
    assert {r.slot: r.execution_id for r in records} == executions
    assert all(r.point_id == point.id and r.point_code == point.code for r in records)
    assert not render(application, e["inspector"], url)[0]["can_confirm"]
    assert db.session.query(PatrolExecution).count() == 2


@pytest.mark.parametrize("name,profile,item", [
    ("4M男廁所-甲", "toilet_v1", "toilet.soap"),
])
def test_renumber_preserves_required_checklist_and_rejects_stale_confirmation(
        application, numbered_team, name, profile, item):
    e = numbered_team
    point = db.session.get(Point, e["active_ids"][0])
    point.name, point.floor = name, 14
    point.schedules[0].point_name, point.schedules[0].floor = name, 14
    db.session.commit()
    url = e["urls"][0]
    original = checklist_for_point(point)
    stale = payload(e["executor"], url)
    enable_numbering(e)
    assert checklist_for_point(point) == original and original["key"] == profile
    assert e["executor"].post(url + "/confirm", data=stale | {"checklist": [item]}).status_code == 409
    assert not db.session.query(PatrolExecution).count()
    for client, model in ((e["executor"], PatrolExecution), (e["inspector"], Inspection)):
        current = payload(client, url)
        assert client.post(url + "/confirm", data=current).status_code == 400
        assert client.post(url + "/confirm", data=current | {"checklist": [item]}).status_code == 302
        record = db.session.scalar(db.select(model))
        assert record.point_id == point.id and record.point_code == point.code
        assert checklist_snapshot(record)["selected"] == [item]


def test_existing_receipt_and_csv_keep_old_label_without_resetting_daily_limit(application, numbered_team):
    e = numbered_team
    point, url = db.session.get(Point, e["active_ids"][1]), e["urls"][1]
    old_code, old_name = point.code, point.name
    first = e["inspector"].post(url + "/confirm", data=payload(e["inspector"], url) | {"note": "Before renumber"})
    assert first.status_code == 302
    record = db.session.scalar(db.select(Inspection))
    enable_numbering(e)
    assert e["inspector"].get(first.location).status_code == 200
    assert record.point_code == old_code and record.point_name == old_name
    assert not render(application, e["inspector"], url)[0]["can_confirm"]
    assert e["peer"].post(url + "/confirm", data=payload(e["peer"], url)).status_code == 302
    records = db.session.scalars(db.select(Inspection).order_by(Inspection.id)).all()
    assert [r.point_id for r in records] == [point.id, point.id]
    assert [r.point_code for r in records] == [old_code, point.code]
    export = e["admin"].get("/records/export?date_from=2026-11-10&date_to=2026-11-10")
    assert export.status_code == 200
    rows = list(csv.reader(io.StringIO(export.data.decode("utf-8-sig"))))
    assert len(rows) == 3
    assert any(old_code in row for row in rows[1:]) and any(point.code in row for row in rows[1:])
    overview, _ = render(application, e["admin"], "/dashboard?view=daily")
    cards = [card for card in overview["cards"] if card["point"].id == point.id]
    assert len(cards) == 1 and cards[0]["status"] == "done"


@pytest.mark.parametrize("kind,foreign", [("general", "engineering"), ("engineering", "general")])
def test_renumber_cannot_cross_general_engineering_permissions(teams, kind, foreign):
    e = teams
    originals = {}
    for index, (key, point) in enumerate(e.points.items(), 11):
        if key == "safety":
            continue
        point.code = f"1F-G{index:03}"
        point.schedules[0].point_code = point.code
        originals[key] = "/c/" + point.qr_token
    db.session.commit()
    apply_general_numbering(e.clock[0], e.users["admin"].id)
    db.session.commit()
    client = e.clients[kind]
    assert client.get(originals[kind]).status_code == 200
    assert client.get(originals[foreign]).status_code == 404
    own_form = payload(client, originals[kind])
    assert client.post(originals[foreign] + "/confirm", data=own_form).status_code == 404
    assert client.post(originals[kind] + "/confirm", data=own_form).status_code == 302
    ready, _ = render(e.app, client, "/ready")
    assert all(p["id"] in {e.points[kind].id, e.points[kind + "_pair"].id} for p in ready["ready_points"])
    for key in (kind, foreign):
        assert e.clients["manager"].get(originals[key]).status_code == 200


def test_direct_executor_permission_follows_original_id_after_code_reuse(application, numbered_team):
    e = numbered_team
    owner, other = [db.session.get(Point, key) for key in e["active_ids"][:2]]
    owner.floor = other.floor = 1
    owner.code, other.code = "1F-G002", "1F-G003"
    owner.workflow_mode = other.workflow_mode = "spot"
    owner.frequency = other.frequency = "three_day"
    for point in (owner, other):
        schedule = point.schedules[0]
        schedule.floor, schedule.point_code = point.floor, point.code
        schedule.workflow_mode, schedule.frequency = point.workflow_mode, point.frequency
    application.config["EXECUTOR_VISIT_CODES"] = frozenset({owner.code})
    db.session.commit()
    enable_numbering(e)
    assert owner.code == "1F-G001" and other.code == "1F-G002"
    assert payload(e["executor"], e["urls"][0])["stage"] == "visit"
    assert e["executor"].get(e["urls"][1]).status_code == 404
    assert e["executor"].post(e["urls"][0] + "/confirm", data=payload(e["executor"], e["urls"][0])).status_code == 302
    record = db.session.scalar(db.select(Inspection))
    assert record.executor_visit and record.point_id == owner.id
    assert e["inspector"].post(e["urls"][1] + "/confirm", data=payload(e["inspector"], e["urls"][1])).status_code == 302
