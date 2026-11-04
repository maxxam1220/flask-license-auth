"""Check today's work list against real scans, team completion and category boundaries."""
from datetime import date, datetime, timedelta

import pytest
from sqlalchemy import event

from missed import TAIPEI
from models import Point, User, db
from test_app import application, app_module, rendered_contexts
from test_features import feature_point
from test_workflow_checkin import payload, team


def ready(app, client, path="/dashboard/ready"):
    with rendered_contexts(app) as rendered:
        response = client.get(path)
    assert response.status_code == 200
    ctx = rendered[-1][1]
    return {row["code"]: row["status_key"] for row in ctx["ready_points"]}


def actors(app):
    result = team(app)
    for point in db.session.scalars(db.select(Point)):
        point.created_at = datetime(2026, 1, 1)
    db.session.commit()
    return result


def scan(client, url):
    r = client.post(url + "/confirm", data=payload(client, url))
    assert r.status_code == 302
    return r


def test_two_rounds_with_independent_report_dates_and_scope(application, monkeypatch):
    now = datetime(2026, 11, 4, 11, 59, tzinfo=TAIPEI)
    monkeypatch.setattr(app_module, "now_utc", lambda: now)
    executor, inspector, peer, admin, paired, single, _ = actors(application)
    other = feature_point(frequency="daily", category="safety", floor=11)
    singles = {"1F-G01": "inspect", "1F-G02": "inspect"}

    assert ready(application, executor) == {"1F-G00": "execute"}
    assert ready(application, inspector, "/dashboard?date=2025-01-01&view=monthly") == singles
    assert ready(application, inspector, "/dashboard/ready?category=safety") == singles
    assert ready(application, admin, "/dashboard/ready?floor=11") == {other.code: "inspect"}
    assert ready(application, admin, "/dashboard/ready?category=general&floor=11") == {}
    scan(executor, paired)
    assert ready(application, executor) == {}
    assert ready(application, inspector) == singles | {"1F-G00": "review"}
    # Administrators see a handoff for staffing, but cannot perform it.
    assert ready(application, admin, "/dashboard/ready?category=general") == singles | {"1F-G00": "review"}
    with rendered_contexts(application) as rendered:
        admin.get(paired)
    assert rendered[-1][1]["can_confirm"] is False
    scan(inspector, paired)
    scan(inspector, single)
    assert ready(application, peer) == {"1F-G02": "inspect"}
    with rendered_contexts(application) as rendered:
        peer.get(paired)
    assert rendered[-1][1]["can_confirm"] is True  # An optional extra visit is not pending work.

    now += timedelta(minutes=1)
    assert ready(application, inspector) == singles
    assert ready(application, executor) == {"1F-G00": "execute"}
    scan(executor, paired)
    assert ready(application, inspector)["1F-G00"] == "review"
    scan(peer, paired)
    assert "1F-G00" not in ready(application, inspector)


@pytest.mark.parametrize("frequency,start,next_period", [
    ("weekly", date(2026, 11, 4), date(2026, 11, 9)),
    ("monthly", date(2026, 11, 4), date(2026, 12, 1)),
])
def test_period_handoff_and_completed_team_do_not_reappear_on_fresh_day(application, monkeypatch, frequency, start, next_period):
    now = datetime.combine(start, datetime.min.time(), TAIPEI)
    monkeypatch.setattr(app_module, "now_utc", lambda: now)
    executor, inspector, peer, _, url, _, _ = actors(application)
    point = db.session.scalar(db.select(Point).where(Point.code == "1F-G00"))
    point.frequency = point.schedules[0].frequency = frequency
    db.session.commit()
    scan(executor, url)
    now += timedelta(days=1)
    assert ready(application, inspector)["1F-G00"] == "review"
    scan(inspector, url)
    now += timedelta(days=1)
    assert "1F-G00" not in ready(application, peer)
    assert "1F-G00" not in ready(application, executor)
    now = datetime.combine(next_period, datetime.min.time(), TAIPEI)
    assert "1F-G00" not in ready(application, inspector)
    assert ready(application, executor)["1F-G00"] == "execute"


def test_hide_optional_inactive_transferred_own_execution_and_future_points(application):
    executor, inspector, peer, admin, paired, _, _ = actors(application)
    scan(executor, paired)
    former_executor = db.session.scalar(db.select(User).where(User.username == "exec"))
    former_executor.role = "inspector"
    option = db.session.scalar(db.select(Point).where(Point.code == "1F-G01"))
    option.frequency = option.schedules[0].frequency = "irregular"
    retired = db.session.scalar(db.select(Point).where(Point.code == "1F-G02"))
    retired.active = False
    future = feature_point(code="2F-PTS", category="general")
    future.schedule_start = date(2028, 1, 1)
    transferred = feature_point(code="2F-OLD", category="general")
    transferred.category = "safety"
    legacy = feature_point(code="2F-LEG", category="general")
    legacy.schedules[0].legacy_unscheduled = True
    db.session.commit()
    assert ready(application, executor) == {}
    assert ready(application, inspector) == {"1F-G00": "review"}
    assert ready(application, peer, "/dashboard?category=general") == {"1F-G00": "review"}
    assert ready(application, admin, "/dashboard/ready?category=general") == {"1F-G00": "review"}
    assert application.test_client().get("/dashboard/ready").status_code == 302


def test_fragment_query_count_is_independent_of_point_count(application):
    _, inspector, _, _, _, _, _ = actors(application)
    def query_count():
        statements = []
        def measure(*args):
            statements.append(args[2])
        event.listen(db.engine, "before_cursor_execute", measure)
        try:
            response = inspector.get("/dashboard/ready")
            assert response.status_code == 200
        finally:
            event.remove(db.engine, "before_cursor_execute", measure)
        return len(statements)
    baseline = query_count()
    for n in range(15):
        feature_point(code=f"1F-Q{n:02d}", category="general")
    assert query_count() == baseline


def test_changed_frequency_preserves_the_personal_checkin_limit(application):
    _, inspector, peer, admin, _, url, _ = actors(application)
    point = db.session.scalar(db.select(Point).where(Point.code == "1F-G01"))
    point.frequency = point.schedules[0].frequency = "daily"
    db.session.commit()
    scan(inspector, url)
    point.frequency = point.schedules[0].frequency = "daily2"
    db.session.commit()
    assert point.code not in ready(application, inspector)
    with rendered_contexts(application) as rendered:
        inspector.get(url)
    assert rendered[-1][1]["can_confirm"] is False
    assert ready(application, peer)[point.code] == "inspect"
    assert ready(application, admin)[point.code] == "inspect"
