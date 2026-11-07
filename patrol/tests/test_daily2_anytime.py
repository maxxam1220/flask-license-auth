"""Post-cutover daily rounds: real forms, personal/team limits and stale requests.

Only isolated SQLite fixtures or the explicitly allowed local PostgreSQL test
database are used; no production accounts or points are contacted.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from threading import Barrier
from types import SimpleNamespace

import pytest

from receipt_urls import without_voice_feedback

import app as patrol
from missed import TAIPEI, calculate_missed
from models import Inspection, InspectionPhoto, PatrolExecution, Point, User, db
from test_app import actors_only, application, approve_browser, login, rendered_contexts
from test_features import feature_point, png
from test_postgres_features import postgres_app, seed_clients
from test_ready_patrol import ready
from test_workflow_checkin import payload, team


DAY = date(2026, 11, 6)


def set_clock(monkeypatch, hour=9, minute=0):
    clock = [datetime.combine(DAY, datetime.min.time(), TAIPEI).replace(hour=hour, minute=minute)]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    return clock


def form(client, url):
    fields = payload(client, url)
    assert fields.get("round_ticket"), "An anytime round must carry its original signed confirmation"
    assert fields["period_key"] == patrol.local_dt(patrol.now_utc()).date().isoformat()
    return fields


def context(application, client, url):
    with rendered_contexts(application) as pages:
        response = client.get(url)
    assert response.status_code == 200
    return response, pages[-1][1]


def rows(point, model=Inspection):
    return db.session.scalars(db.select(model).where(model.point_id == point.id).order_by(model.id)).all()


@pytest.fixture
def anytime(application, monkeypatch):
    clock = set_clock(monkeypatch)
    executor, inspector, peer, admin, paired, direct, other = team(application)
    points = {point.qr_token: point for point in db.session.scalars(db.select(Point))}
    for point in points.values():
        point.created_at = datetime(2026, 1, 1)
    db.session.commit()
    return SimpleNamespace(clock=clock, executor=executor, inspector=inspector, peer=peer, admin=admin,
                           paired=paired, direct=direct, other=other,
                           pair_point=points[paired[3:]], direct_point=points[direct[3:]])


@pytest.mark.parametrize("hour", [9, 15], ids=["both-before-noon", "both-after-noon"])
def test_safety_team_can_finish_two_rounds_immediately_but_not_three(application, actors_only, monkeypatch, hour):
    clock = set_clock(monkeypatch, hour)
    point = feature_point()
    url = "/c/" + point.qr_token
    clients = []
    for name in ("inspector", "colleague"):
        browser = application.test_client()
        login(browser, name)
        approve_browser(browser, actors_only[name])
        clients.append(browser)
    first_tab = form(clients[0], url)
    other_tab = form(clients[1], url)
    assert first_tab["slot"] == other_tab["slot"] == "am"
    first = clients[0].post(url + "/confirm", data=first_tab)
    assert first.status_code == 302
    assert clients[1].post(url + "/confirm", data=other_tab).status_code == 302
    assert len(rows(point)) == 1  # A stale first-round form cannot become round two.
    second_tab = form(clients[1], url)
    assert second_tab["slot"] == "pm"
    assert clients[1].post(url + "/confirm", data=second_tab).status_code == 302
    saved = rows(point)
    assert [item.slot for item in saved] == ["am", "pm"]
    assert all(item.created_at == patrol.naive_utc(clock[0]) for item in saved)
    for browser in clients:
        page, current = context(application, browser, url)
        assert not current["can_confirm"] and 'id="inspection-form"' not in page.text
    assert clients[0].post(url + "/confirm", data=first_tab).status_code == 302
    assert len(rows(point)) == 2


def test_two_executions_can_precede_both_reviews_and_each_inspector_keeps_two_receipts(application, anytime):
    a = anytime
    execution_receipts = []
    for slot in ("am", "pm"):
        fields, second_tab = form(a.executor, a.paired), form(a.executor, a.paired)
        assert fields["slot"] == second_tab["slot"] == slot
        result = a.executor.post(a.paired + "/confirm", data=fields)
        assert result.status_code == 302 and result.location.startswith("/executions/")
        execution_receipts.append(result.location)
        assert without_voice_feedback(a.executor.post(a.paired + "/confirm", data=second_tab).location) == without_voice_feedback(result.location)
        assert not rows(a.pair_point)
    executions = rows(a.pair_point, PatrolExecution)
    assert len(executions) == 2 and not context(application, a.executor, a.paired)[1]["can_confirm"]
    assert {item.created_at for item in executions} == {patrol.naive_utc(a.clock[0])}
    assert a.pair_point.code in ready(application, a.inspector)
    original_first = None
    for actor in (a.inspector, a.peer):
        receipts = []
        for slot in ("am", "pm"):
            fields = form(actor, a.paired)
            assert fields["slot"] == slot
            result = actor.post(a.paired + "/confirm", data=fields)
            assert result.status_code == 302 and result.location.startswith("/checkins/")
            receipts.append(result.location)
            assert without_voice_feedback(actor.post(a.paired + "/confirm", data=fields).location) == without_voice_feedback(result.location)
            if actor is a.inspector and slot == "am":
                original_first = fields
                assert a.pair_point.code in ready(application, actor)
        assert without_voice_feedback(receipts[0]) != without_voice_feedback(receipts[1])
        assert not context(application, actor, a.paired)[1]["can_confirm"]
        assert a.pair_point.code not in ready(application, a.peer)
    saved = rows(a.pair_point)
    assert len(saved) == 4 and len({(item.user_id, item.slot) for item in saved}) == 4
    assert all(item.execution_id == next(first.id for first in executions if first.slot == item.slot) for item in saved)
    assert without_voice_feedback(a.inspector.post(a.paired + "/confirm", data=original_first).location) == f"/checkins/{saved[0].id}"
    assert len(rows(a.pair_point)) == 4 and len(rows(a.pair_point, PatrolExecution)) == 2


def test_single_execution_only_unlocks_one_review_and_ready_returns_after_second_execution(application, anytime):
    a = anytime
    assert not context(application, a.inspector, a.paired)[1]["can_confirm"]
    assert a.pair_point.code not in ready(application, a.inspector)
    assert a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired)).status_code == 302
    assert a.pair_point.code in ready(application, a.inspector)
    assert a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired)).status_code == 302
    page, blocked = context(application, a.inspector, a.paired)
    assert blocked["current_slot"] == "pm" and blocked["waiting_for_execution"] and not blocked["can_confirm"]
    assert 'id="inspection-form"' not in page.text and a.pair_point.code not in ready(application, a.inspector)
    assert a.pair_point.code in ready(application, a.executor)
    assert a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired)).status_code == 302
    assert a.pair_point.code in ready(application, a.inspector)
    assert a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired)).status_code == 302
    assert a.pair_point.code not in ready(application, a.peer)
    assert context(application, a.peer, a.paired)[1]["can_confirm"]  # Optional personal records remain available.


@pytest.mark.parametrize("operation", ["workflow", "disable", "delete"])
def test_pending_second_execution_still_blocks_management_changes(application, anytime, operation):
    a = anytime
    for _ in range(2):
        assert a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired)).status_code == 302
    assert a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired)).status_code == 302
    first, second = rows(a.pair_point, PatrolExecution)
    assert rows(a.pair_point)[0].execution_id == first.id
    assert not db.session.scalar(db.select(Inspection.id).where(Inspection.execution_id == second.id))
    path = f"/admin/points/{a.pair_point.id}"
    if operation == "delete":
        response = a.admin.post(path + "/delete")
    else:
        fields = dict(code=a.pair_point.code, name=a.pair_point.name, floor=a.pair_point.floor,
                      category="general", frequency="daily2", workflow_mode="two_stage", active="on")
        if operation == "workflow":
            fields["workflow_mode"] = "spot"
        else:
            del fields["active"]
        response = a.admin.post(path + "/update", data=fields)
    assert response.status_code == 409
    assert a.pair_point.active and a.pair_point.deleted_at is None and a.pair_point.workflow_mode == "two_stage"
    assert len(rows(a.pair_point, PatrolExecution)) == 2 and len(rows(a.pair_point)) == 1


def test_direct_general_rounds_are_personal_and_two_first_rounds_do_not_finish_team(application, anytime):
    a = anytime
    first_forms = [form(actor, a.direct) for actor in (a.inspector, a.peer)]
    for actor, fields in zip((a.inspector, a.peer), first_forms):
        assert fields["slot"] == "am"
        result = actor.post(a.direct + "/confirm", data=fields)
        assert result.status_code == 302
        assert without_voice_feedback(actor.post(a.direct + "/confirm", data=fields).location) == without_voice_feedback(result.location)
        assert form(actor, a.direct)["slot"] == "pm"
    _, dashboard = context(application, a.admin, "/dashboard?view=daily&category=general")
    card = next(card for card in dashboard["cards"] if card["point"].id == a.direct_point.id)
    assert sum(slot["status"] == "done" for slot in card["slots"]) == 1
    for actor in (a.inspector, a.peer):
        assert actor.post(a.direct + "/confirm", data=form(actor, a.direct)).status_code == 302
        assert not context(application, actor, a.direct)[1]["can_confirm"]
    assert len(rows(a.direct_point)) == 4


@pytest.mark.parametrize("tampering", ["slot", "ticket", "missing-ticket", "other-person", "other-point"])
def test_round_confirmation_cannot_be_forged_or_reused_for_a_different_scope(application, anytime, tampering):
    a = anytime
    fields = form(a.inspector, a.direct)
    actor, destination = a.inspector, a.direct
    if tampering == "slot":
        fields["slot"] = "pm"
    elif tampering == "ticket":
        fields["round_ticket"] = "invalid-signed-round"
    elif tampering == "missing-ticket":
        del fields["round_ticket"]
    elif tampering == "other-person":
        actor = a.peer
    else:
        destination = a.other
    response = actor.post(destination + "/confirm", data=fields)
    assert response.status_code == 409
    assert db.session.query(Inspection).count() == db.session.query(PatrolExecution).count() == 0


def test_noon_does_not_expire_an_unsubmitted_first_round(application, anytime):
    a = anytime
    a.clock[0] = a.clock[0].replace(hour=11, minute=59)
    fields = form(a.inspector, a.direct)
    a.clock[0] += timedelta(minutes=1)
    response = a.inspector.post(a.direct + "/confirm", data=fields)
    assert response.status_code == 302 and rows(a.direct_point)[0].slot == "am"
    assert form(a.inspector, a.direct)["slot"] == "pm"


@pytest.mark.parametrize("stage", ["execute", "two-stage-review", "direct-review"])
def test_midnight_expires_old_forms_before_creating_the_new_days_round(application, anytime, stage):
    a = anytime
    a.clock[0] = a.clock[0].replace(hour=23, minute=59)
    actor, url, model = (a.executor, a.paired, PatrolExecution) if stage == "execute" else (a.inspector, a.direct, Inspection)
    if stage == "two-stage-review":
        url = a.paired
        assert a.executor.post(url + "/confirm", data=form(a.executor, url)).status_code == 302
    fields = form(actor, url)
    a.clock[0] += timedelta(minutes=1)
    response = actor.post(url + "/confirm", data=fields)
    assert response.status_code == 409 and db.session.query(model).count() == 0
    if stage == "two-stage-review":
        assert not context(application, actor, url)[1]["can_confirm"]
        assert a.executor.post(url + "/confirm", data=form(a.executor, url)).status_code == 302
    fresh = form(actor, url)
    assert fresh["slot"] == "am" and fresh["period_key"] == "2026-11-07"
    assert actor.post(url + "/confirm", data=fresh).status_code == 302


def test_photo_processing_crossing_midnight_cannot_save_old_round_or_photo(application, anytime, monkeypatch):
    a = anytime
    a.clock[0] = a.clock[0].replace(hour=23, minute=59, second=59)
    fields = form(a.inspector, a.direct)
    original = patrol.process_uploads
    def delayed(files):
        result = original(files)
        a.clock[0] += timedelta(seconds=1)
        return result
    monkeypatch.setattr(patrol, "process_uploads", delayed)
    response = a.inspector.post(a.direct + "/confirm", data=fields | {"photos": (png(), "local-test.png")})
    assert response.status_code == 409
    assert db.session.query(Inspection).count() == db.session.query(InspectionPhoto).count() == 0


@pytest.mark.parametrize("completed", [0, 1, 2])
def test_missed_rounds_start_only_at_next_midnight_and_count_team_occurrences(application, anytime, completed):
    a = anytime
    for _ in range(completed):
        assert a.inspector.post(a.direct + "/confirm", data=form(a.inspector, a.direct)).status_code == 302
    # Another person's first round does not satisfy the second team occurrence.
    if completed == 1:
        assert a.peer.post(a.direct + "/confirm", data=form(a.peer, a.direct)).status_code == 302
    records = rows(a.direct_point)
    for hour in (12, 23):
        current = a.clock[0].replace(hour=hour, minute=59, second=59)
        assert calculate_missed([a.direct_point], records, DAY, DAY, current) == []
    deadline = datetime(2026, 11, 7, tzinfo=TAIPEI)
    missed = calculate_missed([a.direct_point], records, DAY, DAY, deadline)
    assert len(missed) == 2 - completed
    assert all(item["deadline"] == deadline.astimezone(timezone.utc) for item in missed)
    _, report = context(application, a.admin, "/missed?date_from=2026-11-06&date_to=2026-11-06&category=general")
    assert report["totals"]["missed"] == 0


@pytest.mark.parametrize("legacy_slot", ["am", "pm"])
def test_today_preexisting_halfday_record_consumes_one_round_without_rewriting_history(application, anytime, legacy_slot):
    a = anytime
    worker = db.session.scalar(db.select(User).where(User.username == "inspect"))
    historical = Inspection(user_id=worker.id, point_id=a.direct_point.id, created_at=datetime(2026, 11, 6, 0),
        frequency="daily2", period_key=DAY.isoformat(), slot=legacy_slot, workflow_mode="spot", personal_day=DAY,
        spot_request_id="historical-round-" + legacy_slot, category="general", point_code=a.direct_point.code,
        point_name=a.direct_point.name, point_floor=a.direct_point.floor, user_name=worker.display_name)
    db.session.add(historical)
    db.session.commit()
    snapshot = historical.id, historical.created_at, historical.slot
    fields = form(a.inspector, a.direct)
    assert fields["slot"] == ("pm" if legacy_slot == "am" else "am")
    assert a.inspector.post(a.direct + "/confirm", data=fields).status_code == 302
    assert len(rows(a.direct_point)) == 2 and not context(application, a.inspector, a.direct)[1]["can_confirm"]
    assert (historical.id, historical.created_at, historical.slot) == snapshot


def test_same_day_daily_to_twice_daily_does_not_bypass_existing_personal_limit(application, anytime):
    a = anytime
    a.direct_point.frequency = a.direct_point.schedules[0].frequency = "daily"
    db.session.commit()
    assert a.inspector.post(a.direct + "/confirm", data=payload(a.inspector, a.direct)).status_code == 302
    a.direct_point.frequency = a.direct_point.schedules[0].frequency = "daily2"
    db.session.commit()
    assert not context(application, a.inspector, a.direct)[1]["can_confirm"]
    assert len(rows(a.direct_point)) == 1 and rows(a.direct_point)[0].slot == "any"


@pytest.mark.parametrize("mode", ["standard", "spot", "execute"])
def test_postgres_same_round_concurrency_does_not_consume_both_rounds(postgres_app, monkeypatch, mode):
    set_clock(monkeypatch)
    if mode == "standard":
        actors = seed_clients(postgres_app)
        first, token, _ = actors[0]
        second = actors[1][0]
        url = "/c/" + token
        model, expected = Inspection, 1
    else:
        with postgres_app.app_context():
            executor, first, second, _, pair_url, direct_url, _ = team(postgres_app)
        url = pair_url if mode == "execute" else direct_url
        if mode == "execute":
            first = second = executor
        model, expected = (PatrolExecution, 1) if mode == "execute" else (Inspection, 2)
    candidates = [(first, form(first, url)), (second, form(second, url)), (first, form(first, url))]
    assert {fields["slot"] for _, fields in candidates} == {"am"}
    gate = Barrier(len(candidates))
    def submit(item):
        actor, fields = item
        gate.wait(timeout=10)
        return actor.post(url + "/confirm", data=fields).status_code
    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        assert list(pool.map(submit, candidates)) == [302] * len(candidates)
    with postgres_app.app_context():
        saved = db.session.scalars(db.select(model)).all()
        assert len(saved) == expected and {item.slot for item in saved} == {"am"}
    second_round = form(first, url)
    assert second_round["slot"] == "pm"
    assert first.post(url + "/confirm", data=second_round).status_code == 302
    with postgres_app.app_context():
        assert db.session.query(model).count() == expected + 1
