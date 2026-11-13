"""Wednesday/Friday overview tabs must not change the underlying daily attendance identity."""
from datetime import date, datetime, timedelta
from urllib.parse import parse_qs, urlsplit
import re

import pytest

import app as patrol
from missed import period_bounds
from models import Inspection, Point, PointSchedule, db
from test_app import application
from test_calendar_routes import calendar, context, instant, scan
from test_frontend_navigation import Anchors
from test_workflow_checkin import payload


VIEWS = (("weekly_wed", "wed", "2026-11-18", 2), ("weekly_fri", "fri", "2026-11-20", 4))


def overview(env, view, selected, *, client=None):
    return context(env.app, client or env.inspector, f"/dashboard?view={view}&date={selected}")


def complete_week(env):
    env.clock[0] = instant("2026-11-18")
    scan(env.executor, env.wed_url)
    scan(env.inspector, env.wed_url)
    env.clock[0] = instant("2026-11-20")
    scan(env.inspector, env.fri_url)
    scan(env.peer, env.fri_url)
    scan(env.inspector, env.week_url)


@pytest.mark.parametrize("view,name,target,weekday", VIEWS)
def test_weekday_tabs_isolate_points_records_and_shared_completion_counts(calendar, view, name, target, weekday):
    env = calendar
    complete_week(env)
    result, response = overview(env, view, "2026-11-20")
    assert {card["point"].id for card in result["cards"]} == {getattr(env, name).id}
    assert result["totals"] == {"total": 1, "done": 1, "pending": 0}
    assert sum(item["total"] for item in result["floors"]) == 1
    assert sum(item["done"] for item in result["floors"]) == 1
    assert result["missed_count"] == 0
    card, = result["cards"]
    assert card["latest"].frequency == view and card["latest"].period_key == target
    assert result["weekday_schedule"]["day"] == date.fromisoformat(target)
    assert not result["weekday_schedule"]["exempt"]
    # The secondary peer receipt remains in history, not another obligation.
    assert db.session.query(Inspection).count() == 4
    daily, _ = overview(env, "daily", target)
    assert daily["cards"] == [] and daily["totals"]["total"] == 0
    tabs = re.search(r'<div class="segmented"[^>]*>(.*?)</div>', response.text, re.S)
    assert tabs is not None
    links = Anchors(tabs.group(1)).links
    assert [parse_qs(urlsplit(link["href"]).query)["view"][0] for link in links] == [
        "daily", "weekly_wed", "weekly_fri"]
    assert len([link for link in links if link.get("aria-current") == "page"]) == 1


@pytest.mark.parametrize("view,name,target,weekday", VIEWS)
def test_every_selected_day_in_week_uses_same_target_day_and_week_arrows(calendar, view, name, target, weekday):
    env = calendar
    complete_week(env)
    for day in range(16, 23):
        selected = f"2026-11-{day}"
        result, response = overview(env, view, selected)
        assert result["selected_date"] == date.fromisoformat(selected)
        assert result["weekday_schedule"]["day"] == date.fromisoformat(target)
        assert result["totals"] == {"total": 1, "done": 1, "pending": 0}
        assert result["cards"][0]["latest"].period_key == target
        assert result["previous_period"] == date(2026, 11, 9)
        assert result["following_period"] == date(2026, 11, 23)
        assert f'value="{selected}"' in response.text
        steps = {link["data-period-step"]: link for link in Anchors(response.text).links if "data-period-step" in link}
        assert steps["prev"]["aria-label"] == "上一週" and steps["next"]["aria-label"] == "下一週"
        for direction, expected in (("prev", "2026-11-09"), ("next", "2026-11-23")):
            query = parse_qs(urlsplit(steps[direction]["href"]).query)
            assert query["view"] == [view] and query["date"] == [expected]
        # Navigating the overview cannot rewrite a scan's actual-day period.
        assert period_bounds(date.fromisoformat(selected), view) == (date.fromisoformat(selected),) * 2
        assert patrol.period_for(getattr(env, name), instant(selected))[0] == selected


@pytest.mark.parametrize("view,name,target,weekday", VIEWS)
def test_linked_reports_keep_exact_weekday_filter_and_week_range(calendar, view, name, target, weekday):
    env = calendar
    complete_week(env)
    result, _ = overview(env, view, "2026-11-22")
    for key in ("records_query_url", "missed_query_url"):
        query = parse_qs(urlsplit(result[key]).query)
        assert query["frequency"] == [view]
        assert query["date_from"] == ["2026-11-16"] and query["date_to"] == ["2026-11-22"]
    records, _ = context(env.app, env.inspector, result["records_query_url"])
    assert len(records["records"]) == (1 if name == "wed" else 2)
    assert {item.frequency for item in records["records"]} == {view}
    missing, _ = context(env.app, env.inspector, result["missed_query_url"])
    assert missing["totals"]["missed"] == 0


@pytest.mark.parametrize("view,name,target,weekday", VIEWS)
def test_scan_and_receipt_progress_links_return_to_matching_weekday_view(calendar, view, name, target, weekday):
    env = calendar
    env.clock[0] = instant(target)
    url = getattr(env, name + "_url")
    if name == "wed":
        execution = scan(env.executor, url)
        receipt, _ = context(env.app, env.executor, execution.location)
        assert parse_qs(urlsplit(receipt["progress_url"]).query)["view"] == [view]
    form, _ = context(env.app, env.inspector, url)
    query = parse_qs(urlsplit(form["progress_url"]).query)
    assert query["view"] == [view] and query["date"] == [target]
    saved = scan(env.inspector, url)
    receipt, _ = context(env.app, env.inspector, saved.location)
    query = parse_qs(urlsplit(receipt["progress_url"]).query)
    assert query["view"] == [view] and query["date"] == [target]
    returned, _ = context(env.app, env.inspector, receipt["progress_url"])
    assert returned["totals"] == {"total": 1, "done": 1, "pending": 0}


@pytest.mark.parametrize("view,name,target,weekday", VIEWS)
def test_before_target_day_is_not_due_and_deadline_occurs_once_at_midnight(calendar, view, name, target, weekday):
    env = calendar
    env.clock[0] = instant("2026-11-16")
    before, _ = overview(env, view, "2026-11-16")
    assert before["totals"] == {"total": 0, "done": 0, "pending": 0}
    assert before["cards"][0]["status"] == "not_due"
    assert all(slot["stage_status"] not in ("awaiting_execution", "awaiting_inspection")
               for slot in before["cards"][0]["slots"])
    assert before["missed_count"] == 0
    env.clock[0] = instant(target)
    current, _ = overview(env, view, "2026-11-16")
    assert current["totals"] == {"total": 1, "done": 0, "pending": 1}
    assert current["cards"][0]["status"] == "pending" and current["missed_count"] == 0
    env.clock[0] = instant(target, 0) + timedelta(days=1)
    overdue, _ = overview(env, view, "2026-11-16")
    assert overdue["totals"] == current["totals"] and overdue["missed_count"] == 1
    assert len(overdue["cards"]) == 1 and len(overdue["cards"][0]["slots"]) == 1


def test_future_pending_weekday_preview_does_not_activate_current_point_early(calendar):
    env = calendar
    point = env.wed
    point.frequency = point.schedules[0].frequency = "three_day"
    point.pending_frequency, point.frequency_effective_date = "weekly_wed", date(2026, 11, 23)
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 23), frequency="weekly_wed",
        category=point.category, workflow_mode=point.workflow_mode, active=True, floor=point.floor,
        point_code=point.code, point_name=point.name, workflow_changed_at=datetime(2026, 11, 22, 16)))
    db.session.commit()
    env.clock[0] = instant("2026-11-18")
    current, _ = overview(env, "weekly_wed", "2026-11-18")
    assert current["cards"] == [] and current["totals"]["total"] == 0
    assert current["pending_schedule_notice"]
    query = parse_qs(urlsplit(current["pending_schedule_url"]).query)
    assert query["view"] == ["weekly_wed"]
    assert date(2026, 11, 23) <= date.fromisoformat(query["date"][0]) <= date(2026, 11, 29)
    future, _ = overview(env, "weekly_wed", "2026-11-27")
    assert {card["point"].id for card in future["cards"]} == {point.id}
    assert future["cards"][0]["status"] == "not_due" and future["totals"]["total"] == 0
    assert all(slot["stage_status"] not in ("awaiting_execution", "awaiting_inspection")
               for slot in future["cards"][0]["slots"])
    db.session.refresh(point)
    assert (point.frequency, point.pending_frequency, point.workflow_mode) == ("three_day", "weekly_wed", "two_stage")
    fields = payload(env.executor, env.wed_url)
    assert fields["frequency"] == "three_day" and fields["period_key"] == "2026-11-16"


@pytest.mark.parametrize("view,name,holiday", [("weekly_wed", "wed", "2027-06-09"),
                                             ("weekly_fri", "fri", "2026-12-25")])
def test_holiday_is_exempt_and_voluntary_record_visible_without_new_obligation(calendar, view, name, holiday):
    env = calendar
    env.clock[0] = instant(holiday)
    empty, response = overview(env, view, holiday)
    assert empty["weekday_schedule"]["exempt"] is True and "免巡" in response.text
    assert empty["totals"] == {"total": 0, "done": 0, "pending": 0}
    url = getattr(env, name + "_url")
    if name == "wed": scan(env.executor, url)
    scan(env.inspector, url)
    saved, response = overview(env, view, holiday)
    assert saved["weekday_schedule"]["exempt"] is True and "免巡" in response.text
    assert saved["totals"] == empty["totals"] and saved["missed_count"] == 0
    card, = saved["cards"]
    assert card["status"] == "done" and card["latest"].period_key == holiday
    assert not card["slots"][0]["counted"]
    env.clock[0] += timedelta(days=1)
    missed, _ = context(env.app, env.inspector, saved["missed_query_url"])
    assert missed["totals"]["missed"] == 0


@pytest.mark.parametrize("view,name,target,weekday", VIEWS)
@pytest.mark.parametrize("selected,begin,end,previous,following", [
    ("2000-01-01", "2000-01-01", "2000-01-02", None, "2000-01-03"),
    ("2100-12-31", "2100-12-27", "2100-12-31", "2100-12-20", None),
])
def test_date_picker_boundary_week_arrows_and_reports_stay_in_supported_range(calendar, view, name, target, weekday,
        selected, begin, end, previous, following):
    result, response = overview(calendar, view, selected)
    assert result["selected_date"] == date.fromisoformat(selected)
    assert result["previous_period"] == (date.fromisoformat(previous) if previous else None)
    assert result["following_period"] == (date.fromisoformat(following) if following else None)
    assert result["weekday_schedule"]["day"].weekday() == weekday
    for key in ("records_query_url", "missed_query_url"):
        query = parse_qs(urlsplit(result[key]).query)
        assert query["frequency"] == [view] and query["date_from"] == [begin] and query["date_to"] == [end]
        assert calendar.inspector.get(result[key]).status_code == 200
    for link in Anchors(response.text).links:
        if "data-period-step" in link:
            step = parse_qs(urlsplit(link["href"]).query)["date"][0]
            assert "2000-01-01" <= step <= "2100-12-31"
    assert calendar.inspector.get(f"/dashboard?view={view}&date=1999-12-31").status_code == 400
    assert calendar.inspector.get(f"/dashboard?view={view}&date=2101-01-01").status_code == 400


@pytest.mark.parametrize("view,name,target,weekday", VIEWS)
@pytest.mark.parametrize("actor", ["inspector", "executor"])
@pytest.mark.parametrize("legacy_labels", [False, True])
def test_recategorized_history_without_pending_attributes_never_crashes_or_exposes_new_team_labels(
        calendar, view, name, target, weekday, actor, legacy_labels):
    env = calendar
    point = getattr(env, name)
    original_name, original_code = point.name, point.code
    original = point.schedules[0]
    original.floor = point.floor
    # NULL legacy labels deliberately exercise executor direct_visit's fallback
    # code comparison before it discovers the point is now another category.
    original.point_name = None if legacy_labels else original_name
    original.point_code = None if legacy_labels else original_code
    point.category, point.workflow_mode, point.frequency = "safety", "standard", "daily"
    point.name, point.code = "PRIVATE-NEW-SAFETY-LOCATION", f"PRIVATE-SAFETY-{point.id}"
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 23), frequency="daily",
        category="safety", workflow_mode="standard", active=True, floor=point.floor,
        point_code=point.code, point_name=point.name, workflow_changed_at=datetime(2026, 11, 22, 16)))
    db.session.commit()
    env.clock[0] = instant("2026-11-25")
    client = getattr(env, actor)
    # historical_points masks this point with a SimpleNamespace that intentionally
    # has no pending_frequency/frequency_effective_date or current secret labels.
    result, response = overview(env, view, target, client=client)
    assert not result["pending_schedule_notice"] and not result["pending_schedule_url"]
    assert "PRIVATE-NEW-SAFETY-LOCATION" not in response.text and point.code not in response.text
    historical = [card for card in result["cards"] if card["point"].id == point.id]
    if actor == "executor" and name == "fri":
        # An old single-stage snapshot does not grant today's direct-visit right.
        assert historical == []
    else:
        assert len(historical) == 1 and historical[0]["point"].category == "general"
        assert historical[0]["point"].name == ("歷史巡檢點" if legacy_labels else original_name)
        assert historical[0]["point"].code == (f"#{point.id}" if legacy_labels else original_code)
    for baseline in ("daily", "weekly"):
        baseline_result, baseline_response = overview(env, baseline, target, client=client)
        assert "PRIVATE-NEW-SAFETY-LOCATION" not in baseline_response.text
    assert client.get(getattr(env, name + "_url")).status_code == 404
