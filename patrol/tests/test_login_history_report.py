"""Coverage for the administrator's sign-in history and Taipei calendar bounds."""
from datetime import datetime
from urllib.parse import parse_qs, urlsplit

from models import LoginEvent, db
from test_app import application, seeded  # noqa: F401
from test_frontend_navigation import Anchors
from test_workflow_reports import context, open_as


PATH = "/admin/login-records"


def event(user, when, kind="mobile", browser="Safari"):
    return LoginEvent(user_id=user.id, username=user.username, display_name=user.display_name,
                      client_type=kind, browser=browser, created_at=when)


def test_report_rejects_all_non_admin_roles_even_when_selecting_a_user(application, seeded):
    staff = seeded["inspector"]
    target = f"{PATH}?user_id={seeded['manager'].id}&client_type=mobile"
    assert urlsplit(application.test_client().get(target).location).path == "/login"
    for role, category, titled in (("inspector", "safety", False), ("inspector", "general", False),
                                    ("inspector", "general", True), ("executor", "general", False)):
        staff.role, staff.patrol_category, staff.general_manager_title = role, category, titled
        db.session.commit()
        response = open_as(application, staff).get(target)
        assert response.status_code == 403
        assert 'id="login-results"' not in response.text


def test_local_date_boundaries_and_inactive_account_history(application, seeded):
    staff, other = seeded["inspector"], seeded["colleague"]
    old_name = staff.display_name
    rows = [event(staff, datetime(2026, 11, 1, 15, 59, 59)), event(staff, datetime(2026, 11, 1, 16)),
            event(staff, datetime(2026, 11, 2, 15, 59, 59)), event(staff, datetime(2026, 11, 2, 16)),
            event(staff, datetime(2026, 11, 2, 8), "desktop", "Edge"), event(other, datetime(2026, 11, 2, 9))]
    db.session.add_all(rows)
    staff.display_name, staff.active = "New name", False
    db.session.commit()
    admin = open_as(application, seeded["manager"])
    page = context(application, admin, PATH)
    assert (page["filters"]["date_from"], page["filters"]["date_to"]) == ("2026-10-28", "2026-11-03")
    selected = f"{PATH}?date_from=2026-11-02&date_to=2026-11-02&user_id={staff.id}&client_type=mobile"
    result = context(application, admin, selected)
    assert [row.id for row in result["events"]] == [rows[2].id, rows[1].id]
    assert result["selected_user"].display_name == "New name"
    assert all(row.display_name == old_name for row in result["events"])
    html = admin.get(selected).text
    assert old_name in html and "已停用" in html
    assert "2026-11-02 00:00:00" in html and "2026-11-02 23:59:59" in html


def test_filters_survive_pagination_and_identical_timestamps(application, seeded):
    worker = seeded["colleague"]
    rows = [event(worker, datetime(2025, 11, 3, 2), "tablet", "Safari") for _ in range(51)]
    db.session.add_all(rows)
    db.session.commit()
    admin = open_as(application, seeded["manager"])
    selected = f"{PATH}?date_from=2025-11-03&date_to=2025-11-03&user_id={worker.id}&client_type=tablet"
    assert [row.id for row in context(application, admin, selected)["events"]] == [r.id for r in rows[:0:-1]]
    next_link = next(a["href"] for a in Anchors(admin.get(selected).text).links if a.get("rel") == "next")
    assert parse_qs(urlsplit(next_link).query) == parse_qs(urlsplit(selected + "&page=2").query)
    assert urlsplit(next_link).fragment == "login-results"
    assert [row.id for row in context(application, admin, next_link)["events"]] == [rows[0].id]
    excess = admin.get(selected + "&page=300")
    assert excess.status_code == 302 and parse_qs(urlsplit(excess.location).query) == parse_qs(urlsplit(next_link).query)
    for invalid in ("page=-1", "user_id=abc", "user_id=2147483647", "client_type=watch",
                    "date_from=2024-01-01&date_to=2026-01-01", "date_from=2026-11-04&date_to=2026-11-01"):
        assert admin.get(PATH + "?" + invalid).status_code == 400
