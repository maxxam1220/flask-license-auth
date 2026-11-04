"""Report-only daily_all scope includes both daily schedules, never weekly ones."""
import csv
import io
from datetime import date, datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from test_app import application, actors_only as seeded, app_module, db, login, rendered_contexts  # noqa: F401
from models import Inspection, Point, PointSchedule
from missed import calculate_missed


@pytest.fixture
def report_points(application):
    points = {}
    for number, frequency in enumerate(("daily", "daily2", "weekly"), 1):
        point = Point(code=f"1F-SCOPE{number:02}", name=f"Scope {frequency}", floor=1, category="safety",
                      frequency=frequency, active=True, schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=frequency, active=True,
                                             category="safety", floor=1, point_code=point.code, point_name=point.name))
        db.session.add(point)
        points[frequency] = point
    db.session.commit()
    return points


def completed(user, point, day=1, note=""):
    row = Inspection(user_id=user.id, point_id=point.id, created_at=datetime(2026, 11, day, 2),
                     period_key="2026-10-26" if point.frequency == "weekly" else f"2026-11-{day:02}",
                     frequency=point.frequency, slot="am" if point.frequency == "daily2" else "any", category=point.category,
                     point_code=point.code, point_name=point.name, point_floor=point.floor, user_name=user.display_name, note=note)
    db.session.add(row)
    db.session.commit()
    return row


def csv_rows(response):
    return list(csv.reader(io.StringIO(response.data.decode("utf-8-sig"))))


def test_calculator_daily_all_keeps_two_daily_types_and_excludes_sunday_weekly(report_points):
    points = list(report_points.values())
    params = (points, [], date(2026, 11, 1), date(2026, 11, 1), app_module.now_utc())
    assert len(calculate_missed(*params)) == 4
    rows = calculate_missed(*params, frequency="daily_all")
    assert len(rows) == 3
    assert {(row["frequency"], row["slot"]) for row in rows} == {("daily", "any"), ("daily2", "am"), ("daily2", "pm")}


def test_missed_daily_all_and_csv_preserve_shared_completion_and_privacy(application, seeded, report_points):
    completed(seeded["colleague"], report_points["daily2"], note="PRIVATE-COLLEAGUE-NOTE")
    client = application.test_client()
    login(client)
    query = "date_from=2026-11-01&date_to=2026-11-01&category=safety&floor=1&frequency=daily_all"
    with rendered_contexts(application) as contexts:
        response = client.get("/missed?" + query)
    assert response.status_code == 200
    context = contexts[-1][1]
    assert context["totals"] == {"missed": 2, "points": 2}
    assert {(row["frequency"], row["slot"]) for row in context["occurrences"]} == {("daily", "any"), ("daily2", "pm")}
    assert "PRIVATE-COLLEAGUE-NOTE" not in response.get_data(as_text=True)
    assert "Inspector Bravo" not in response.get_data(as_text=True)
    exported = csv_rows(client.get("/missed/export?" + query))
    assert len(exported) == 3
    assert {row[6] for row in exported[1:]} == {"每日一次", "每日兩次"}
    assert all(row[4] != report_points["weekly"].code for row in exported[1:])


@pytest.mark.parametrize("username,expected", [("inspector", 2), ("manager", 3)])
def test_records_daily_all_and_csv_keep_existing_personal_access_scope(application, seeded, report_points, username, expected):
    completed(seeded["inspector"], report_points["daily"])
    completed(seeded["inspector"], report_points["daily2"])
    completed(seeded["inspector"], report_points["weekly"])
    completed(seeded["colleague"], report_points["daily"], day=2, note="PRIVATE-COLLEAGUE-NOTE")
    client = application.test_client()
    login(client, username)
    query = "date_from=2026-11-01&date_to=2026-11-02&category=safety&floor=1&frequency=daily_all"
    with rendered_contexts(application) as contexts:
        response = client.get("/records?" + query)
    assert response.status_code == 200
    rows = contexts[-1][1]["records"]
    assert len(rows) == expected and {row.frequency for row in rows} == {"daily", "daily2"}
    exported = csv_rows(client.get("/records/export?" + query))
    assert len(exported) == expected + 1 and {row[5] for row in exported[1:]} == {"每日一次", "每日兩次"}
    if username == "inspector":
        assert all(row.user_id == seeded["inspector"].id for row in rows)
        assert all("PRIVATE-COLLEAGUE-NOTE" not in cell for row in exported for cell in row)


@pytest.mark.parametrize("frequency", ["daily", "daily2", "weekly"])
def test_exact_frequency_report_filters_remain_exact(application, seeded, report_points, frequency):
    for point in report_points.values():
        completed(seeded["inspector"], point)
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get("/records", query_string={"date_from": "2026-11-01", "date_to": "2026-11-01", "frequency": frequency}).status_code == 200
    rows = contexts[-1][1]["records"]
    assert len(rows) == 1 and rows[0].frequency == frequency


def test_daily_all_return_filter_survives_detail_validation(application, seeded, report_points):
    row = completed(seeded["inspector"], report_points["daily"])
    client = application.test_client()
    login(client)
    source = "/records?date_from=2026-11-01&date_to=2026-11-01&category=safety&frequency=daily_all"
    with rendered_contexts(application) as contexts:
        assert client.get(f"/records/{row.id}", query_string={"return_to": source}).status_code == 200
    assert contexts[-1][1]["back_url"] == source
    assert app_module.normalise_return_to("/records?frequency=monthly", seeded["inspector"]) == "/records?frequency=monthly"
    assert app_module.normalise_return_to("/records?frequency=bogus", seeded["inspector"]) is None


def test_daily_all_never_becomes_a_stored_point_frequency(application, seeded, report_points):
    client = application.test_client()
    login(client, "manager")
    point = report_points["daily"]
    for endpoint, code in (("/admin/points/create", "1F-INVALID"), (f"/admin/points/{point.id}/update", point.code)):
        response = client.post(endpoint, data={"code": code, "name": "Invalid grouped frequency", "floor": "1",
                                               "category": "safety", "frequency": "daily_all", "active": "on"})
        assert response.status_code == 400
    assert db.session.get(Point, point.id).frequency == "daily"
    assert db.session.scalar(db.select(Point).where(Point.frequency == "daily_all")) is None


def test_sunday_daily_dashboard_link_does_not_pull_weekly_missed(application, seeded, report_points):
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get("/dashboard?date=2026-11-01&view=daily&category=safety&floor=1").status_code == 200
    context = contexts[-1][1]
    assert context["totals"] == {"total": 3, "done": 0, "pending": 3}
    target = context["missed_query_url"]
    assert parse_qs(urlsplit(target).query)["frequency"] == ["daily_all"]
    with rendered_contexts(application) as contexts:
        assert client.get(target).status_code == 200
    assert contexts[-1][1]["totals"] == {"missed": 3, "points": 2}
