"""Formal missed-obligation start date never deletes trial receipts or point identity."""
import csv
import io
from datetime import date, datetime, time, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

import app as patrol
from models import AuditLog, Inspection, Point, PointSchedule, TAIPEI, User, db
from safety_leave import SafetyLeaveExclusion
from test_app import application, rendered_contexts  # noqa: F401


START = date(2026, 11, 16)


def local(day, hour=0, minute=0, second=0):
    return datetime.combine(date.fromisoformat(day), time(hour, minute, second), TAIPEI)


@pytest.fixture
def go_live(application, monkeypatch):
    application.config["MISSED_START_DATE"] = START
    clock = [local("2026-11-17")]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    users, clients = {}, {}
    for name, role, category, manager, engineer in (
        ("admin", "admin", None, False, False),
        ("safety", "inspector", "safety", False, False),
        ("general", "inspector", "general", False, False),
        ("engineering", "inspector", "general", False, True),
        ("manager", "inspector", "general", True, False),
        ("executor", "executor", "general", False, False),
    ):
        user = User(username="go-live-" + name, display_name=name, role=role, patrol_category=category,
            general_manager_title=manager, engineering_inspector_title=engineer,
            password_hash="isolated-fixture", active=True, must_change_password=False)
        db.session.add(user)
        db.session.flush()
        users[name] = user
        client = application.test_client()
        with client.session_transaction() as signed:
            signed.update(user_id=user.id, auth_version=user.auth_version,
                          sid="go-live-fixture-" + name, csrf_token="fixture-csrf-" + name)
        clients[name] = client
    specs = (
        ("safety", "safety", "general", "daily", "standard"),
        ("safety_twice", "safety", "general", "daily2", "standard"),
        ("general", "general", "general", "daily", "spot"),
        ("general_pair", "general", "general", "daily", "two_stage"),
        ("engineering", "general", "engineering", "daily", "spot"),
        ("engineering_pair", "general", "engineering", "daily", "two_stage"),
        ("wednesday", "general", "general", "weekly_wed", "two_stage"),
        ("friday", "general", "engineering", "weekly_fri", "spot"),
        ("three_day", "general", "general", "three_day", "spot"),
        ("weekly", "general", "general", "weekly", "spot"),
        ("monthly", "general", "engineering", "monthly", "spot"),
    )
    points = {}
    for ordinal, (name, category, team, frequency, mode) in enumerate(specs, 1):
        point = Point(code=f"1F-LIVE{ordinal:03}", name=name, floor=1, category=category,
            inspection_team=team, frequency=frequency, workflow_mode=mode,
            active=True, schedule_start=date(2026, 10, 1), created_at=datetime(2026, 10, 1),
            qr_token=f"unchanged-go-live-{ordinal:03}")
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=frequency,
            category=category, workflow_mode=mode, active=True, floor=1, point_code=point.code, point_name=name))
        db.session.add(point)
        points[name] = point
    db.session.flush()
    # Trial receipts remain available to ordinary record queries after go-live.
    for name in ("safety", "general", "engineering"):
        point, user = points[name], users[name]
        db.session.add(Inspection(point_id=point.id, user_id=user.id, user_name=user.display_name,
            frequency=point.frequency, workflow_mode=point.workflow_mode, category=point.category,
            period_key="2026-11-12", slot="any", created_at=datetime(2026, 11, 12, 1),
            personal_day=date(2026, 11, 12) if point.workflow_mode == "spot" else None,
            spot_request_id=f"trial-go-live-{name}" if point.workflow_mode == "spot" else None,
            point_code=point.code, point_name=point.name, point_floor=point.floor, note="trial evidence retained"))
    db.session.commit()
    return SimpleNamespace(app=application, clock=clock, users=users, clients=clients, points=points)


def page(env, path, *, actor="admin", **query):
    with rendered_contexts(env.app) as rendered:
        response = env.clients[actor].get(path, query_string=query)
    assert response.status_code == 200, response.text
    return rendered[-1][1], response


def missed(env, first, last, *, actor="admin", **filters):
    query = {"date_from": first, "date_to": last, **filters}
    context, response = page(env, "/missed", actor=actor, **query)
    exported = env.clients[actor].get("/missed/export", query_string=query)
    assert exported.status_code == 200
    rows = list(csv.reader(io.StringIO(exported.data.decode("utf-8-sig"))))[1:]
    assert len(rows) == context["totals"]["missed"]
    assert [(row[0], row[4]) for row in rows] == [
        (row["due_date"].isoformat(), row["code"]) for row in context["occurrences"]]
    assert all(date.fromisoformat(row[0]) >= START for row in rows)
    return context, response, rows


ROLE_TOTALS = (("admin", 7, 6), ("safety", 3, 2), ("general", 2, 2),
               ("engineering", 2, 2), ("manager", 4, 4), ("executor", 2, 2))


@pytest.mark.parametrize("actor,total,points", ROLE_TOTALS)
def test_all_roles_exclude_trial_due_dates_in_list_and_csv(go_live, actor, total, points):
    old, _, rows = missed(go_live, "2026-11-01", "2026-11-15", actor=actor)
    assert old["totals"] == {"missed": 0, "points": 0} and rows == []
    live, _, rows = missed(go_live, "2026-11-01", "2026-11-16", actor=actor, frequency="daily_all")
    assert live["totals"] == {"missed": total, "points": points}
    assert {row["due_date"] for row in live["occurrences"]} == {START}
    if actor == "safety":
        assert {row["category"] for row in live["occurrences"]} == {"safety"}
    elif actor in ("general", "engineering"):
        assert {row["inspection_team"] for row in live["occurrences"]} == {actor}
    elif actor == "executor":
        assert {row["workflow_mode"] for row in live["occurrences"]} == {"two_stage"}
    assert "2026-11-15" not in {row[0] for row in rows}


@pytest.mark.parametrize("at", [local("2026-11-16"), local("2026-11-16", 12),
                                local("2026-11-16", 23, 59, 59)])
def test_first_live_day_is_not_missed_until_following_taipei_midnight(go_live, at):
    go_live.clock[0] = at
    result, _, _ = missed(go_live, "2026-11-01", "2026-11-16", frequency="daily_all")
    assert result["totals"]["missed"] == 0
    overview, _ = page(go_live, "/dashboard", view="daily", date="2026-11-16")
    assert overview["totals"]["total"] == 7 and overview["missed_count"] == 0
    assert not any(slot["expired"] for card in overview["cards"] for slot in card["slots"])
    go_live.clock[0] = datetime(2026, 11, 16, 16, tzinfo=timezone.utc)
    after, _, _ = missed(go_live, "2026-11-01", "2026-11-16", frequency="daily_all")
    assert after["totals"]["missed"] == 7
    overview, _ = page(go_live, "/dashboard", view="daily", date="2026-11-16")
    assert overview["missed_count"] == 7


@pytest.mark.parametrize("view,target", [("weekly_wed", "2026-11-18"), ("weekly_fri", "2026-11-20")])
def test_fixed_weekdays_only_become_missed_after_the_actual_day(go_live, view, target):
    day = date.fromisoformat(target)
    go_live.clock[0] = local(target, 23, 59, 59)
    result, _, _ = missed(go_live, "2026-11-01", target, frequency=view)
    assert result["totals"]["missed"] == 0
    overview, _ = page(go_live, "/dashboard", view=view, date=target)
    assert overview["missed_count"] == 0 and overview["totals"]["total"] == 1
    go_live.clock[0] += timedelta(seconds=1)
    result, _, _ = missed(go_live, "2026-11-01", target, frequency=view)
    assert [(row["frequency"], row["due_date"]) for row in result["occurrences"]] == [(view, day)]
    overview, _ = page(go_live, "/dashboard", view=view, date=target)
    assert overview["missed_count"] == 1


@pytest.mark.parametrize("frequency,due", [("three_day", "2026-11-18"),
                                          ("weekly", "2026-11-22"), ("monthly", "2026-11-30")])
def test_longer_periods_are_filtered_by_due_date_not_period_start(go_live, frequency, due):
    go_live.clock[0] = local(due) + timedelta(days=1)
    result, _, _ = missed(go_live, "2026-10-01", due, frequency=frequency)
    assert [(row["frequency"], row["due_date"].isoformat()) for row in result["occurrences"]] == [(frequency, due)]
    if frequency == "monthly":
        assert result["occurrences"][0]["period_key"] == "2026-11-01"


@pytest.mark.parametrize("view,selected", [("daily", "2026-11-12"), ("three_day", "2026-11-13"),
    ("weekly", "2026-11-12"), ("monthly", "2026-10-12"),
    ("weekly_wed", "2026-11-11"), ("weekly_fri", "2026-11-13")])
def test_trial_dashboard_keeps_progress_but_removes_missed_flags(go_live, view, selected):
    overview, _ = page(go_live, "/dashboard", view=view, date=selected)
    assert overview["cards"]
    assert overview["missed_count"] == 0
    assert not any(card["missed_count"] for card in overview["cards"])
    assert not any(slot["expired"] for card in overview["cards"] for slot in card["slots"])
    if view == "daily":
        assert overview["totals"] == {"total": 7, "done": 3, "pending": 4}


@pytest.mark.parametrize("first,last", [("2026-11-21", "2026-11-22"),
                                       ("2026-12-25", "2026-12-27")])
def test_weekends_and_official_holiday_remain_exempt_for_all_units(go_live, first, last):
    go_live.clock[0] = local(last) + timedelta(days=1)
    for actor in ("admin", "safety", "general", "engineering", "manager", "executor"):
        result, _, _ = missed(go_live, first, last, actor=actor, frequency="daily_all")
        assert result["totals"]["missed"] == 0


def test_safety_leave_only_excludes_safety_and_cancellation_restores_live_date(go_live):
    env = go_live
    added = env.clients["safety"].post("/safety-leave/add", data={"date_from": "2026-11-16"})
    assert added.status_code == 302
    result, _, _ = missed(env, "2026-11-01", "2026-11-16", frequency="daily_all")
    assert result["totals"]["missed"] == 4
    assert {row["category"] for row in result["occurrences"]} == {"general"}
    entry = db.session.scalar(select(SafetyLeaveExclusion))
    assert env.clients["safety"].post(f"/safety-leave/{entry.id}/cancel").status_code == 302
    restored, _, _ = missed(env, "2026-11-01", "2026-11-16", frequency="daily_all")
    assert restored["totals"]["missed"] == 7


def snapshot(model):
    return [tuple(getattr(item, column.name) for column in model.__table__.columns)
            for item in db.session.scalars(select(model).order_by(model.id))]


def test_start_date_does_not_change_trial_receipts_qr_codes_or_schedules(go_live):
    before = {model: snapshot(model) for model in (Point, PointSchedule, Inspection, AuditLog)}
    missed(go_live, "2026-11-01", "2026-11-16", frequency="daily_all")
    records, _ = page(go_live, "/records", date_from="2026-11-12", date_to="2026-11-12")
    assert len(records["records"]) == 3
    assert {record.note for record in records["records"]} == {"trial evidence retained"}
    assert all(record.period_key == "2026-11-12" for record in records["records"])
    for point in go_live.points.values():
        response = go_live.clients["admin"].get(f"/admin/points/{point.id}/qr.svg")
        assert response.status_code == 200 and b"<svg" in response.data
    assert {model: snapshot(model) for model in before} == before


@pytest.mark.parametrize("actor,team,expected", [("admin", "general", 2), ("admin", "engineering", 2),
                                               ("manager", "general", 2), ("manager", "engineering", 2)])
def test_explicit_responsibility_filters_still_match_report_and_csv(go_live, actor, team, expected):
    result, _, _ = missed(go_live, "2026-11-01", "2026-11-16", actor=actor,
                          frequency="daily_all", inspection_team=team)
    assert result["totals"]["missed"] == expected
    assert {row["inspection_team"] for row in result["occurrences"]} == {team}


def test_factory_default_formal_start_date_is_parsed_without_fixture_override(monkeypatch):
    monkeypatch.delenv("MISSED_START_DATE", raising=False)
    app = patrol.create_app({"TESTING": True, "SECRET_KEY": "isolated-go-live-default",
        "SQLALCHEMY_DATABASE_URI": "sqlite://", "COOKIE_SECURE": False, "APP_ENV": "development"})
    assert app.config["MISSED_START_DATE"] == START
