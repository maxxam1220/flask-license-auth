"""Three-day workflow, reporting and offline routes use isolated test data only."""
from datetime import date, datetime, timedelta
from types import SimpleNamespace

import pytest

import app as patrol
from missed import TAIPEI
from models import Inspection, OfflineSubmission, PatrolExecution, Point, PointSchedule, User, db
from receipt_urls import without_voice_feedback
from test_app import application, rendered_contexts
from test_executor_visits import synthetic_register  # noqa: F401: isolated authorized catalog fixture
from test_offline_api import assert_error, entry, prepare, sync
from test_workflow_checkin import payload, team


def local(day, hour=10, minute=0):
    return datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(hour=hour, minute=minute)


@pytest.fixture
def stops(application, synthetic_register, monkeypatch):
    clock = [local("2026-11-10")]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    executor, inspector, peer, admin, *_ = team(application)
    for item in db.session.scalars(db.select(Point)):
        item.created_at = datetime(2026, 1, 1)

    def create(index=0, *, frequency="three_day", code=None):
        values = synthetic_register[index] | {"frequency": frequency}
        if code:
            values["code"] = code
        point = Point(**values, active=True, inspection_team="general", schedule_start=date(2026, 1, 1),
                      created_at=datetime(2026, 1, 1))
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency="irregular",
            category="general", floor=1, point_code=point.code, point_name=point.name, workflow_mode="spot", active=True))
        if frequency != "irregular":
            point.schedules.append(PointSchedule(effective_date=date(2026, 11, 10), frequency=frequency,
                category="general", floor=1, point_code=point.code, point_name=point.name, workflow_mode="spot", active=True,
                workflow_changed_at=datetime(2026, 11, 9, 16)))
        db.session.add(point)
        db.session.commit()
        return point

    point = create()
    return SimpleNamespace(app=application, clock=clock, executor=executor, inspector=inspector, peer=peer,
                           admin=admin, point=point, create=create, url="/c/" + point.qr_token)


def rendered(env, client, path):
    with rendered_contexts(env.app) as contexts:
        response = client.get(path)
    assert response.status_code == 200, response.text
    return contexts[-1][1], response


def card(env, client=None, date_text="2026-11-10"):
    context, response = rendered(env, client or env.inspector, "/dashboard?view=three_day&date=" + date_text)
    return next(item for item in context["cards"] if item["point"].id == env.point.id), context, response


def checkin(client, url):
    response = client.post(url + "/confirm", data=payload(client, url))
    assert response.status_code == 302 and "/checkins/" in response.location, response.text
    return response


def edit(env, point, frequency):
    return env.admin.post(f"/admin/points/{point.id}/update", data={
        "code": point.code, "name": point.name, "floor": point.floor, "category": point.category,
        "inspection_team": point.inspection_team, "workflow_mode": point.workflow_mode,
        "frequency": frequency, "active": "on", "state": patrol.management_state(point),
    })


def test_all_seven_authorized_three_day_points_allow_executor_visits_once_daily_without_fulfilling_patrol(stops):
    e = stops
    points = [e.point, *(e.create(index) for index in range(1, 7))]
    for point in points:
        url = "/c/" + point.qr_token
        first, duplicate = payload(e.executor, url), payload(e.executor, url)
        assert first["stage"] == "visit" and first["frequency"] == "three_day"
        assert first["period_key"] == "2026-11-10" and first["slot"] == "any"
        saved = e.executor.post(url + "/confirm", data=first)
        repeated = e.executor.post(url + "/confirm", data=duplicate)
        assert saved.status_code == repeated.status_code == 302
        assert without_voice_feedback(saved.location) == without_voice_feedback(repeated.location)
        assert e.executor.get(saved.location).status_code == 200
    records = db.session.scalars(db.select(Inspection)).all()
    assert len(records) == 7 and all(record.executor_visit and record.frequency == "three_day" for record in records)
    assert db.session.query(PatrolExecution).count() == 0
    _, overview, response = card(e)
    assert overview["totals"] == {"total": 7, "done": 0, "pending": 7}
    assert "不定期與免排程點位" not in response.text
    e.clock[0] = local("2026-11-13", 0)
    missing, _ = rendered(e, e.inspector, "/missed?date_from=2026-11-12&date_to=2026-11-12&frequency=three_day")
    assert {row["point_id"] for row in missing["occurrences"]} == {point.id for point in points}
    own_records = e.executor.get("/records?stage=inspection&frequency=three_day&date_from=2026-11-10&date_to=2026-11-10")
    assert own_records.status_code == 200 and points[0].code in own_records.text


def test_executor_daily_limit_resets_next_day_without_changing_the_shared_period(stops):
    e = stops
    stale = payload(e.executor, e.url)
    first = e.executor.post(e.url + "/confirm", data=stale)
    assert first.status_code == 302
    e.clock[0] = local("2026-11-11")
    assert e.executor.post(e.url + "/confirm", data=stale).status_code == 409
    second = checkin(e.executor, e.url)
    assert without_voice_feedback(first.location) != without_voice_feedback(second.location)
    records = db.session.scalars(db.select(Inspection).order_by(Inspection.id)).all()
    assert [record.personal_day for record in records] == [date(2026, 11, 10), date(2026, 11, 11)]
    assert {record.period_key for record in records} == {"2026-11-10"}
    assert card(e, date_text="2026-11-11")[0]["status"] == "pending"


def test_inspector_completes_team_period_while_other_people_and_next_day_still_allow_personal_records(stops):
    e = stops
    checkin(e.executor, e.url)
    first, duplicate = payload(e.inspector, e.url), payload(e.inspector, e.url)
    saved = e.inspector.post(e.url + "/confirm", data=first)
    repeated = e.inspector.post(e.url + "/confirm", data=duplicate)
    assert without_voice_feedback(saved.location) == without_voice_feedback(repeated.location)
    current, overview, response = card(e)
    assert current["status"] == "done" and overview["totals"]["done"] == 1
    assert overview["view"] == "three_day" and "data-history-schedules" not in response.text
    assert all(label in response.text for label in ("每日巡檢", "週三巡檢", "週五巡檢"))
    checkin(e.peer, e.url)
    e.clock[0] = local("2026-11-11")
    checkin(e.inspector, e.url)
    assert db.session.query(Inspection).filter_by(point_id=e.point.id, executor_visit=False).count() == 3
    assert card(e, date_text="2026-11-11")[1]["totals"]["done"] == 1
    ready, _ = rendered(e, e.peer, "/ready")
    assert e.point.id not in {row["id"] for row in ready["ready_points"]}
    e.clock[0] = local("2026-11-13")
    assert card(e, date_text="2026-11-13")[0]["status"] == "pending"
    ready, _ = rendered(e, e.peer, "/ready")
    assert e.point.id in {row["id"] for row in ready["ready_points"]}


def test_unlisted_three_day_single_stage_point_does_not_gain_executor_access(stops):
    e = stops
    extra = e.create(code="Xq-UNLISTED-3DAY")
    url = "/c/" + extra.qr_token
    assert e.executor.get(url).status_code == 404
    assert e.executor.post(url + "/confirm", data=payload(e.executor, e.url)).status_code == 404
    prepared = prepare(e.executor)
    assert extra.id not in {point["id"] for point in prepared["points"]}
    checkin(e.inspector, url)


def test_simple_executor_today_list_retains_daily_visits_even_after_team_patrol_is_done(stops):
    e = stops
    executor = db.session.scalar(db.select(User).where(User.username == "exec"))
    executor.simple_executor_ui = True
    executor.ui_language = "id"
    db.session.commit()
    assert e.executor.get("/dashboard?view=three_day").location == "/ready"
    ready, _ = rendered(e, e.executor, "/ready")
    direct = next(row for row in ready["ready_points"] if row["id"] == e.point.id)
    assert direct["status_key"] == "visit" and direct["period_end"] == date(2026, 11, 12)
    checkin(e.inspector, e.url)
    ready, _ = rendered(e, e.executor, "/ready")
    assert e.point.id in {row["id"] for row in ready["ready_points"]}
    checkin(e.executor, e.url)
    ready, _ = rendered(e, e.executor, "/ready")
    assert e.point.id not in {row["id"] for row in ready["ready_points"]}
    e.clock[0] = local("2026-11-11")
    ready, _ = rendered(e, e.executor, "/ready")
    assert e.point.id in {row["id"] for row in ready["ready_points"]}


def test_month_start_report_includes_completion_from_prior_month_three_day_period(stops):
    e = stops
    # Feb 1 is Monday. Both weekly and monthly lookup windows start Feb 1,
    # whereas this three-day cycle starts Jan 30; neither old window suffices.
    e.clock[0] = local("2027-01-30")
    fields = payload(e.inspector, e.url)
    assert fields["period_key"] == "2027-01-30"
    assert e.inspector.post(e.url + "/confirm", data=fields).status_code == 302
    e.clock[0] = local("2027-02-02")
    current, overview, _ = card(e, date_text="2027-02-01")
    assert current["status"] == "done" and overview["totals"]["done"] == 1
    for suffix in ("", "&frequency=three_day"):
        missing, _ = rendered(e, e.inspector, "/missed?date_from=2027-02-01&date_to=2027-02-01" + suffix)
        assert e.point.id not in {row["point_id"] for row in missing["occurrences"]}
    exported = e.inspector.get("/missed/export?date_from=2027-02-01&date_to=2027-02-01&frequency=three_day")
    assert exported.status_code == 200 and e.point.code not in exported.text


@pytest.mark.parametrize("role,stage,visit", [("executor", "visit", True), ("inspector", "inspect", False)])
def test_offline_prepare_and_delayed_sync_keep_original_three_day_period(stops, role, stage, visit):
    e = stops
    client = getattr(e, role)
    e.clock[0] = local("2026-11-12", 23, 50)
    prepared = prepare(client)
    point = next(point for point in prepared["points"] if point["id"] == e.point.id)
    assert (point["frequency"], point["period_key"], point["stage"], point["slots"]) == (
        "three_day", "2026-11-10", stage, ["any"])
    delayed = entry(prepared, e.url, e.clock[0])
    e.clock[0] = local("2026-11-13", 0, 5)
    saved = sync(client, prepared, delayed)
    assert saved.status_code == 200 and saved.json["status"] == "saved", saved.json
    record = db.session.get(Inspection, saved.json["record_id"])
    assert record.period_key == "2026-11-10" and record.personal_day == date(2026, 11, 12)
    assert record.executor_visit is visit and client.get(saved.json["receipt_url"]).status_code == 200
    retried = sync(client, prepared, delayed)
    assert retried.status_code == 200 and retried.json["record_id"] == saved.json["record_id"]
    fresh = prepare(client)
    new_point = next(point for point in fresh["points"] if point["id"] == e.point.id)
    assert new_point["period_key"] == "2026-11-13" and new_point["used_slots"] == []
    assert sync(client, fresh, entry(fresh, e.url, e.clock[0])).status_code == 200
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 2


def test_setting_change_rejects_old_offline_grant_without_creating_any_receipt(stops):
    e = stops
    prepared = prepare(e.inspector)
    delayed = entry(prepared, e.url, e.clock[0])
    e.clock[0] += timedelta(minutes=1)
    assert edit(e, e.point, "weekly").status_code == 302
    assert_error(sync(e.inspector, prepared, delayed), "point_changed", status=409)
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0


def test_admin_edit_preserves_qr_history_and_requires_fresh_form_and_grant(stops):
    e = stops
    old = e.create(index=1, frequency="irregular")
    url = "/c/" + old.qr_token
    e.clock[0] = local("2026-11-09")
    saved = checkin(e.inspector, url)
    original = db.session.scalar(db.select(Inspection).where(Inspection.point_id == old.id))
    historical = (original.id, original.frequency, original.period_key, original.personal_day)
    prepared = prepare(e.peer)
    old_grant = entry(prepared, url, e.clock[0])
    stale_form = payload(e.peer, url)
    token = old.qr_token
    e.clock[0] = local("2026-11-10", 0)
    assert edit(e, old, "three_day").status_code == 302
    db.session.refresh(old)
    db.session.refresh(original)
    assert old.qr_token == token and old.frequency == "three_day"
    assert (original.id, original.frequency, original.period_key, original.personal_day) == historical
    assert e.inspector.get(saved.location).status_code == 200
    assert e.peer.post(url + "/confirm", data=stale_form).status_code == 409
    assert_error(sync(e.peer, prepared, old_grant), "point_changed", status=409)
    printed = e.admin.get("/admin/points/print", query_string={"ids": old.id})
    assert printed.status_code == 200 and "每3日一次" in printed.text and "不定期" not in printed.text
    fresh = payload(e.peer, url)
    assert fresh["frequency"] == "three_day" and fresh["period_key"] == "2026-11-10"
    missing, _ = rendered(e, e.inspector, "/missed?date_from=2026-11-01&date_to=2026-11-09&frequency=three_day")
    assert old.id not in {row["point_id"] for row in missing["occurrences"]}
    e.clock[0] = local("2026-11-13")
    missing, _ = rendered(e, e.inspector, "/missed?date_from=2026-11-12&date_to=2026-11-12&frequency=three_day")
    assert old.id in {row["point_id"] for row in missing["occurrences"]}
