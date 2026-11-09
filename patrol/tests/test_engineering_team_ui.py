"""Responsible-team controls stay usable across reports and printed QR labels."""
from datetime import date
from html import unescape
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from models import Point, User, db
from test_app import application  # noqa: F401
from test_workflow_checkin import team


def setup_teams(application):
    executor, general, engineering, admin, pair, spot, _ = team(application)
    person = db.session.scalar(db.select(User).where(User.username == "peer"))
    person.engineering_inspector_title = True
    point = db.session.scalar(db.select(Point).where(Point.qr_token == spot[3:]))
    point.inspection_team = "engineering"
    point.frequency = point.schedules[0].frequency = "weekly"
    point.name = "工務測試設備"
    db.session.commit()
    return general, engineering, admin, point


@pytest.mark.parametrize("path", ["/dashboard", "/ready", "/records", "/missed", "/issues"])
def test_general_manager_can_filter_both_teams_but_inspectors_have_simple_scope(application, path):
    general, engineering, admin, point = setup_teams(application)
    for client in (general, engineering):
        response = client.get(path)
        assert response.status_code == 200
        assert '<select name="inspection_team">' not in response.text
    person = db.session.scalar(db.select(User).where(User.username == "inspect"))
    person.general_manager_title = True
    db.session.commit()
    response = general.get(path, query_string={"inspection_team": "engineering"})
    assert response.status_code == 200
    assert '<select name="inspection_team">' in response.text
    assert '<option value="engineering" selected>工務</option>' in response.text
    assert "總務全組" not in response.text
    # Navigation and export links must retain the active responsibility filter.
    scoped_paths = {"/dashboard", "/ready", "/records", "/records/export", "/missed", "/missed/export", "/issues"}
    for href in re.findall(r'href="([^"]+)"', response.text):
        url = urlsplit(unescape(href))
        if url.path in scoped_paths and "重設" not in href:
            query = parse_qs(url.query, keep_blank_values=True)
            assert query.get("inspection_team") in (["engineering"], [""]), href


def test_qr_labels_show_current_team_and_scheduled_frequency_without_rotating_url(application):
    general, engineering, admin, point = setup_teams(application)
    token = point.qr_token
    point.pending_frequency = "daily"
    point.frequency_effective_date = date(2026, 11, 10)
    db.session.commit()
    labels = admin.get("/admin/points/print", query_string={"ids": point.id})
    assert labels.status_code == 200
    assert "qr-label-engineering" in labels.text and "工務巡檢</span>" in labels.text
    assert "單段 · 每日一次" in labels.text
    assert "2026-11-10" not in labels.text and "之前" not in labels.text
    assert point.qr_token == token and point.frequency == "weekly"
    management = admin.get("/admin/points", query_string={"inspection_team": "engineering"})
    assert management.status_code == 200
    assert "2026-11-10 起：每日一次" in management.text
    assert 'data-inspection-team-control' in management.text


def test_management_and_print_filters_expose_engineering_as_responsibility(application):
    general, engineering, admin, point = setup_teams(application)
    for path in ("/admin/points", "/admin/points/print"):
        page = admin.get(path, query_string={"inspection_team": "engineering"})
        assert page.status_code == 200
        assert '<option value="engineering" selected>工務</option>' in page.text
        assert point.code in page.text
