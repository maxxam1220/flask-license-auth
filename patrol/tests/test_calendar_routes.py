"""Calendar policy across real ready, overview, receipt and missed-report routes."""
from datetime import date, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

import app as patrol
from missed import TAIPEI
from models import Inspection, Point, db
from safety_leave import SafetyLeaveExclusion
from test_app import application, seeded, login, rendered_contexts  # noqa: F401
from test_workflow_checkin import payload, team


def instant(day, hour=10):
    return datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(hour=hour)


def context(application, client, path):
    with rendered_contexts(application) as rendered:
        response = client.get(path)
    assert response.status_code == 200, response.text
    return rendered[-1][1], response


def scan(client, url):
    response = client.post(url + "/confirm", data=payload(client, url))
    assert response.status_code == 302 and response.location.startswith(("/checkins/", "/executions/")), response.text
    return response


@pytest.fixture
def calendar(application, monkeypatch):
    clock = [instant("2026-11-18")]
    monkeypatch.setattr(patrol, "now_utc", lambda: clock[0])
    executor, inspector, peer, admin, wed_url, fri_url, week_url = team(application)
    points = list(db.session.scalars(db.select(Point).order_by(Point.id)))
    for point, frequency in zip(points, ("weekly_wed", "weekly_fri", "weekly")):
        point.frequency = point.schedules[0].frequency = frequency
        point.created_at = datetime(2026, 1, 1)
    db.session.commit()
    return SimpleNamespace(app=application, clock=clock, executor=executor, inspector=inspector, peer=peer,
                           admin=admin, wed=points[0], fri=points[1], weekly=points[2],
                           wed_url=wed_url, fri_url=fri_url, week_url=week_url)


def ready(env, client=None):
    result, _ = context(env.app, client or env.inspector, "/ready")
    return {row["id"]: row["status_key"] for row in result["ready_points"]}


@pytest.mark.parametrize("day,inspection,execution", [
    ("2026-11-17", {"weekly"}, set()),
    ("2026-11-18", {"weekly"}, {"wed"}),
    ("2026-11-20", {"fri", "weekly"}, set()),
    ("2026-11-21", set(), set()),
    ("2026-11-22", set(), set()),
])
def test_ready_only_lists_scheduled_weekday_and_omits_weekends(calendar, day, inspection, execution):
    env = calendar
    env.clock[0] = instant(day)
    assert set(ready(env)) == {getattr(env, name).id for name in inspection}
    assert set(ready(env, env.executor)) == {getattr(env, name).id for name in execution}


def test_weekly_overview_merges_distinct_day_keys_and_counts_each_obligation_once(calendar):
    env = calendar
    scan(env.executor, env.wed_url)
    assert ready(env)[env.wed.id] == "review"
    scan(env.inspector, env.wed_url)
    initial, _ = context(env.app, env.inspector, "/dashboard?view=weekly&date=2026-11-18")
    assert initial["totals"] == {"total": 2, "done": 1, "pending": 1}
    assert next(card for card in initial["cards"] if card["point"].id == env.fri.id)["status"] == "not_due"
    env.clock[0] = instant("2026-11-20")
    scan(env.inspector, env.fri_url)
    scan(env.peer, env.fri_url)  # A second person's receipt remains one fulfilled obligation.
    scan(env.inspector, env.week_url)
    final, _ = context(env.app, env.inspector, "/dashboard?view=weekly&date=2026-11-20")
    assert final["totals"] == {"total": 3, "done": 3, "pending": 0}
    assert {card["point"].id for card in final["cards"]} == {env.wed.id, env.fri.id, env.weekly.id}
    assert {row.frequency: row.period_key for row in db.session.scalars(db.select(Inspection))} == {
        "weekly_wed": "2026-11-18", "weekly_fri": "2026-11-20", "weekly": "2026-11-16"}
    for name in ("records_query_url", "missed_query_url"):
        assert parse_qs(urlsplit(final[name]).query)["frequency"] == ["weekly_all"]
    records, page = context(env.app, env.inspector, final["records_query_url"])
    assert len(records["records"]) == 4
    assert '<span class="query-chip-value">每週巡檢（全部）</span>' in page.text


def test_offday_two_stage_receipt_is_retained_but_cannot_satisfy_or_unlock_fixed_day(calendar):
    env = calendar
    env.clock[0] = instant("2026-11-17")
    scan(env.executor, env.wed_url)
    scan(env.inspector, env.wed_url)
    env.clock[0] = instant("2026-11-18")
    assert env.wed.id not in ready(env)
    assert ready(env, env.executor) == {env.wed.id: "execute"}
    overview, _ = context(env.app, env.inspector, "/dashboard?view=weekly&date=2026-11-18")
    card = next(card for card in overview["cards"] if card["point"].id == env.wed.id)
    assert card["status"] == "pending" and card["slots"][0]["stage_status"] == "awaiting_execution"
    records, _ = context(env.app, env.inspector, "/records?frequency=weekly_wed&date_from=2026-11-17&date_to=2026-11-17")
    assert len(records["records"]) == 1 and records["records"][0].period_key == "2026-11-17"
    env.clock[0] = instant("2026-11-19")
    missed, _ = context(env.app, env.inspector, "/missed?frequency=weekly_wed&date_from=2026-11-18&date_to=2026-11-18")
    assert [(row["point_id"], row["missing_stage_label"]) for row in missed["occurrences"]] == [(env.wed.id, "未執行")]


def test_holiday_voluntary_receipt_does_not_inflate_weekly_obligation_or_done_count(calendar):
    env = calendar
    env.clock[0] = instant("2026-12-25")
    assert ready(env) == ready(env, env.executor) == {}
    scan(env.inspector, env.fri_url)
    overview, _ = context(env.app, env.inspector, "/dashboard?view=weekly&date=2026-12-25")
    assert overview["totals"] == {"total": 2, "done": 0, "pending": 2}
    card = next(card for card in overview["cards"] if card["point"].id == env.fri.id)
    assert card["status"] == "done" and not card["slots"][0]["counted"]
    env.clock[0] = instant("2026-12-26")
    missed, _ = context(env.app, env.inspector, "/missed?frequency=weekly_fri&date_from=2026-12-25&date_to=2026-12-25")
    assert missed["totals"]["missed"] == 0


@pytest.mark.parametrize("frequency,first,last", [
    ("weekly", "2026-11-16", "2026-11-22"),
    ("monthly", "2026-11-01", "2026-11-30"),
    ("three_day", "2026-11-13", "2026-11-15"),
])
def test_narrow_due_date_missed_query_loads_leave_for_whole_overlapping_period(application, seeded, monkeypatch, frequency, first, last):
    point = seeded["weekly"]
    point.frequency = point.schedules[0].frequency = frequency
    excluded = SafetyLeaveExclusion(date_from=date.fromisoformat(first), date_to=date.fromisoformat(last), created_by=seeded["inspector"].id)
    db.session.add(excluded)
    db.session.commit()
    clock = instant(last) + timedelta(days=1)
    monkeypatch.setattr(patrol, "now_utc", lambda: clock)
    client = application.test_client()
    login(client)
    query = f"frequency={frequency}&date_from={last}&date_to={last}"
    missing, _ = context(application, client, "/missed?" + query)
    assert missing["totals"] == {"missed": 0, "points": 0}
    assert point.code not in client.get("/missed/export?" + query).text
    excluded.cancelled_at, excluded.cancelled_by = datetime(2026, 11, 1), seeded["manager"].id
    db.session.commit()
    restored, _ = context(application, client, "/missed?" + query)
    assert [(row["point_id"], row["period_key"]) for row in restored["occurrences"]] == [(point.id, first)]


def test_calendar_coverage_warning_and_dashboard_view_allowlist(calendar):
    env = calendar
    env.clock[0] = instant("2028-01-03")
    for path in ("/ready", "/dashboard?date=2028-01-03"):
        result, page = context(env.app, env.inspector, path)
        assert result["calendar_unavailable"] is True
        assert "假日日曆尚未涵蓋此年份" in page.text
    for value in ("weekly_wed", "weekly_fri"):
        assert env.inspector.get("/dashboard?view=" + value).status_code == 200
    for value in ("weekly_all", "unknown"):
        assert env.inspector.get("/dashboard?view=" + value).status_code == 400
