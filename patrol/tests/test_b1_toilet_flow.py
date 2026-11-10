"""New coded B1 toilets keep single-stage, three-day and original role rules."""
from datetime import date, datetime, timedelta
from types import SimpleNamespace
import re

import pytest

import app as patrol
from checklist_catalog import checklist_for_point
from checklist_records import checklist_snapshot
from general_numbering import apply_general_numbering
from models import Inspection, PatrolExecution, Point, TAIPEI, db
from test_app import application, rendered_contexts
from test_offline_api import assert_error, entry, prepare, sync
from test_workflow_checkin import payload, team


NEW_TOILETS = (("AB1-M01", "b1男廁所-甲"), ("BB1-M02", "b1男廁所-乙"))


@pytest.fixture
def b1_toilets(application, monkeypatch):
    clock = [datetime(2026, 11, 10, 10, tzinfo=TAIPEI)]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    executor, inspector, peer, admin, *_ = team(application)
    application.config["EXECUTOR_VISIT_CODES"] = frozenset({
        "AB2-W01", "BB2-M02", "BB2-W02", "AB1m-W01",
        "1F-G011", "1F-G012", "1F-G016",
    })
    # Already-enabled automatic numbering mirrors the deployed management flow.
    apply_general_numbering(clock[0], None)
    db.session.commit()
    other_points = {p.id: (p.code, p.qr_token) for p in db.session.scalars(db.select(Point))}
    ids = []
    for code, name in NEW_TOILETS:
        response = admin.post("/admin/points/create", data={
            "code": code, "name": name, "floor": -1, "category": "general",
            "inspection_team": "general", "frequency": "three_day", "workflow_mode": "spot",
        })
        assert response.status_code == 302, response.text
        item = db.session.scalar(db.select(Point).where(Point.code == code))
        assert item is not None
        ids.append(item.id)
    return SimpleNamespace(app=application, clock=clock, executor=executor,
        inspector=inspector, peer=peer, admin=admin, ids=ids, original_points=other_points)


def point(env, ordinal=0):
    return db.session.get(Point, env.ids[ordinal])


def route(env, ordinal=0):
    return "/c/" + point(env, ordinal).qr_token


def context(env, path):
    with rendered_contexts(env.app) as contexts:
        response = env.inspector.get(path)
    assert response.status_code == 200, response.text
    return contexts[-1][1]


@pytest.mark.parametrize("ordinal", [0, 1])
def test_new_codes_create_exact_b1_single_stage_three_day_points_and_print(b1_toilets, ordinal):
    e, p = b1_toilets, point(b1_toilets, ordinal)
    assert (p.code, p.name) == NEW_TOILETS[ordinal]
    assert (p.floor, p.category, p.inspection_team, p.frequency, p.workflow_mode, p.active) == (
        -1, "general", "general", "three_day", "spot", True)
    assert p.schedule_start == date(2026, 11, 10)
    definition = checklist_for_point(p)
    assert definition["key"] == "toilet_v1" and len(definition["items"]) == 7
    page = e.admin.get("/admin/points/print", query_string={"ids": p.id})
    assert page.status_code == 200
    assert p.code in page.text and p.name in page.text
    assert "單段" in page.text and "每3日一次" in page.text
    assert re.findall(r"<h2>([^<]+)</h2>", page.text) == [p.code]
    assert e.inspector.get(route(e, ordinal)).status_code == 200


def test_custom_toilet_codes_and_qr_tokens_stay_outside_automatic_g_renumbering(b1_toilets):
    e = b1_toilets
    originals = {p.id: (p.code, p.qr_token) for p in db.session.scalars(db.select(Point))}
    assert {i: originals[i] for i in e.original_points} == e.original_points
    assert apply_general_numbering(e.clock[0], None)["changed"] == 0
    db.session.commit()
    assert {p.id: (p.code, p.qr_token) for p in db.session.scalars(db.select(Point))} == originals


@pytest.mark.parametrize("ordinal", [0, 1])
def test_inspection_is_direct_but_toilet_items_are_still_required(b1_toilets, ordinal):
    e, url = b1_toilets, route(b1_toilets, ordinal)
    fields = payload(e.inspector, url)
    assert fields["stage"] == "inspect" and fields["frequency"] == "three_day"
    assert fields["period_key"] == "2026-11-10" and fields["slot"] == "any"
    assert e.inspector.post(url + "/confirm", data=fields).status_code == 400
    assert db.session.query(Inspection).count() == 0
    accepted = fields | {"checklist": ["toilet.floor"]}
    assert e.inspector.post(url + "/confirm", data=accepted).status_code == 302
    assert e.inspector.post(url + "/confirm", data=accepted).status_code == 302
    rows = db.session.scalars(db.select(Inspection).where(Inspection.point_id == e.ids[ordinal])).all()
    assert len(rows) == 1 and rows[0].execution_id is None and not rows[0].executor_visit
    assert checklist_snapshot(rows[0])["selected"] == ["toilet.floor"]
    assert db.session.query(PatrolExecution).count() == 0


def test_new_toilets_do_not_expand_the_original_seven_executor_permissions(b1_toilets):
    e = b1_toilets
    for index in range(2):
        url = route(e, index)
        assert e.executor.get(url).status_code == 404
        assert e.executor.post(url + "/confirm", data=payload(e.inspector, url)).status_code == 404
    prepared = prepare(e.executor)
    assert not set(e.ids) & {p["id"] for p in prepared["points"]}
    inspected = prepare(e.inspector)
    selected = [p for p in inspected["points"] if p["id"] in e.ids]
    assert len(selected) == 2 and all(p["stage"] == "inspect" for p in selected)


def test_three_day_team_completion_keeps_per_person_daily_quota_and_due_only_missed(b1_toilets):
    e, p, url = b1_toilets, point(b1_toilets), route(b1_toilets)
    for client in (e.inspector, e.peer):
        form = payload(client, url) | {"checklist": ["toilet.soap"]}
        assert client.post(url + "/confirm", data=form).status_code == 302
        assert client.post(url + "/confirm", data=form).status_code == 302
    e.clock[0] += timedelta(days=1)
    assert e.inspector.post(url + "/confirm", data=payload(e.inspector, url) | {
        "checklist": ["toilet.mirror"]}).status_code == 302
    rows = db.session.scalars(db.select(Inspection).where(Inspection.point_id == p.id)).all()
    assert len(rows) == 3 and {r.period_key for r in rows} == {"2026-11-10"}
    assert {r.personal_day for r in rows} == {date(2026, 11, 10), date(2026, 11, 11)}
    cards = context(e, "/dashboard?view=three_day&date=2026-11-11")["cards"]
    assert next(c for c in cards if c["point"].id == p.id)["status"] == "done"
    query = "/missed?date_from=2026-11-12&date_to=2026-11-12&frequency=three_day"
    e.clock[0] = datetime(2026, 11, 12, 23, 59, tzinfo=TAIPEI)
    assert not set(e.ids) & {r["point_id"] for r in context(e, query)["occurrences"]}
    e.clock[0] = datetime(2026, 11, 13, 0, tzinfo=TAIPEI)
    assert set(e.ids) & {r["point_id"] for r in context(e, query)["occurrences"]} == {e.ids[1]}


def test_new_toilet_offline_inspection_requires_items_and_keeps_original_point(b1_toilets):
    e, url = b1_toilets, route(b1_toilets)
    prepared = prepare(e.inspector)
    pending = entry(prepared, url, e.clock[0])
    assert_error(sync(e.inspector, prepared, pending), "invalid_checklist")
    selected = pending | {"checklist": ["toilet.paper"]}
    response = sync(e.inspector, prepared, selected)
    assert response.status_code == 200 and response.json["status"] == "saved"
    assert sync(e.inspector, prepared, selected).json["status"] == "already_synced"
    record = db.session.scalar(db.select(Inspection))
    assert record.point_id == e.ids[0] and record.point_code == "AB1-M01"
    assert checklist_snapshot(record)["selected"] == ["toilet.paper"]
