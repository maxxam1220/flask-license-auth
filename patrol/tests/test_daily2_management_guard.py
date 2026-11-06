"""Daily round settings cannot strand already recorded personal attendance."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest

from models import AuditLog, Inspection, PatrolExecution, Point, PointSchedule, db
from test_app import application
from test_daily2_anytime import anytime, form, rows, set_clock
from test_postgres_features import postgres_app
from test_workflow_checkin import payload, team


def values(point, **changes):
    fields = dict(code=point.code, name=point.name, floor=point.floor, category=point.category,
                  frequency=point.frequency, workflow_mode=point.workflow_mode, active="on")
    fields.update(changes)
    return fields


def update(actor, point, **changes):
    return actor.post(f"/admin/points/{point.id}/update", data=values(point, **changes))


def dump(model, point_id=None):
    query = db.select(model).order_by(model.id)
    if point_id is not None:
        query = query.where(model.point_id == point_id)
    return [tuple(getattr(item, column.name) for column in model.__table__.columns)
            for item in db.session.scalars(query)]


def snapshot(point):
    return (tuple(getattr(point, column.name) for column in Point.__table__.columns),
            dump(PointSchedule, point.id), dump(Inspection, point.id),
            dump(PatrolExecution, point.id), dump(AuditLog))


def prepare_completed(a, scenario):
    if scenario == "daily-to-daily2":
        point, url, target = a.pair_point, a.paired, {"frequency": "daily2"}
        point.frequency = point.schedules[0].frequency = "daily"
        db.session.commit()
        assert a.executor.post(url + "/confirm", data=payload(a.executor, url)).status_code == 302
        for actor in (a.inspector, a.peer):
            assert actor.post(url + "/confirm", data=payload(actor, url)).status_code == 302
    elif scenario == "spot-to-two-stage":
        point, url, target = a.direct_point, a.direct, {"workflow_mode": "two_stage"}
        for actor in (a.inspector, a.peer):
            assert actor.post(url + "/confirm", data=form(actor, url)).status_code == 302
    else:
        point, url, target = a.pair_point, a.paired, {"frequency": "daily"}
        for _ in range(2):
            assert a.executor.post(url + "/confirm", data=form(a.executor, url)).status_code == 302
        for actor in (a.inspector, a.peer):
            for _ in range(2):
                assert actor.post(url + "/confirm", data=form(actor, url)).status_code == 302
    return point, url, target


@pytest.mark.parametrize("scenario", ["daily-to-daily2", "spot-to-two-stage", "daily2-to-daily"])
def test_daily_round_edits_preserve_attendance_and_settings_when_rejected(application, anytime, scenario):
    a = anytime
    point, _, target = prepare_completed(a, scenario)
    before = snapshot(point)
    response = update(a.admin, point, **target)
    assert response.status_code == 409
    db.session.expire_all()
    assert snapshot(point) == before  # No changed schedules, audit event or rewritten history.


@pytest.mark.parametrize("scenario", ["daily-to-daily2", "spot-to-two-stage"])
def test_same_changes_next_day_allow_both_new_executions_and_reviews(application, anytime, scenario):
    a = anytime
    point, url, target = prepare_completed(a, scenario)
    original_records, original_executions = dump(Inspection, point.id), dump(PatrolExecution, point.id)
    a.clock[0] = (a.clock[0] + timedelta(days=1)).replace(hour=0)
    assert update(a.admin, point, **target).status_code == 302
    for _ in range(2):
        assert a.executor.post(url + "/confirm", data=form(a.executor, url)).status_code == 302
    for actor in (a.inspector, a.peer):
        for _ in range(2):
            assert actor.post(url + "/confirm", data=form(actor, url)).status_code == 302
    assert dump(Inspection, point.id)[:len(original_records)] == original_records
    assert dump(PatrolExecution, point.id)[:len(original_executions)] == original_executions
    assert len(rows(point)) == len(original_records) + 4


def test_empty_point_and_completed_point_rename_remain_manageable(application, anytime):
    a = anytime
    assert update(a.admin, a.direct_point, workflow_mode="two_stage").status_code == 302
    for _ in range(2):
        assert a.executor.post(a.direct + "/confirm", data=form(a.executor, a.direct)).status_code == 302
        assert a.inspector.post(a.direct + "/confirm", data=form(a.inspector, a.direct)).status_code == 302
    old_records = dump(Inspection, a.direct_point.id)
    old_executions = dump(PatrolExecution, a.direct_point.id)
    assert update(a.admin, a.direct_point, name="重新命名點位").status_code == 302
    assert a.direct_point.name == "重新命名點位"
    assert dump(Inspection, a.direct_point.id) == old_records
    assert dump(PatrolExecution, a.direct_point.id) == old_executions
    # A completed two-stage point can still switch to the simpler spot flow.
    assert update(a.admin, a.direct_point, workflow_mode="spot").status_code == 302


def test_non_daily2_frequency_changes_keep_the_existing_contract(application, anytime):
    a = anytime
    point, url, _ = prepare_completed(a, "daily-to-daily2")
    assert update(a.admin, point, frequency="weekly").status_code == 302
    assert point.frequency == "weekly"


def test_postgres_setting_change_and_first_attendance_cannot_both_win(postgres_app, monkeypatch):
    set_clock(monkeypatch)
    with postgres_app.app_context():
        _, inspector, _, admin, _, url, _ = team(postgres_app)
        point = db.session.scalar(db.select(Point).where(Point.qr_token == url[3:]))
        point_id = point.id
        changed = values(point, frequency="daily")
    original = form(inspector, url)
    gate = Barrier(2)

    def submit_inspection():
        gate.wait(timeout=10)
        return inspector.post(url + "/confirm", data=original).status_code

    def submit_settings():
        gate.wait(timeout=10)
        return admin.post(f"/admin/points/{point_id}/update", data=changed).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        inspection = pool.submit(submit_inspection)
        settings = pool.submit(submit_settings)
        results = inspection.result(), settings.result()
    assert sorted(results) == [302, 409]
    with postgres_app.app_context():
        saved = db.session.scalars(db.select(Inspection).where(Inspection.point_id == point_id)).all()
        current = db.session.get(Point, point_id)
        if results[0] == 302:
            assert len(saved) == 1 and saved[0].frequency == current.frequency == "daily2"
        else:
            assert not saved and current.frequency == "daily"
