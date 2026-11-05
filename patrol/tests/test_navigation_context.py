"""Follow contextual links through real routes, preserving scope and privacy."""
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from test_app import application, seeded, app_module, db, login, record, rendered_contexts  # noqa: F401
from test_frontend_navigation import Anchors
from test_inspector_issues import make_case
from test_workflow_reports import point as general_point


@pytest.mark.parametrize('view,frequency,start,end', [
    ('daily', 'daily_all', '2026-10-28', '2026-10-28'),
    ('weekly', 'weekly', '2026-10-26', '2026-11-01'),
])
def test_dashboard_record_link_keeps_period_and_floor(application, seeded, view, frequency, start, end):
    point = seeded['weekly' if view == 'weekly' else 'daily']
    own = record(seeded['inspector'], point, datetime(2026, 10, 28, 3, tzinfo=timezone.utc))
    other = record(seeded['colleague'], seeded['daily' if view == 'weekly' else 'weekly'])
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get(f'/dashboard?view={view}&date=2026-10-28&floor={point.floor}&category={point.category}').status_code == 200
    target = contexts[-1][1]['records_query_url']
    params = parse_qs(urlsplit(target).query)
    assert params == dict(date_from=[start], date_to=[end], floor=[str(point.floor)], category=['safety'], frequency=[frequency])
    with rendered_contexts(application) as contexts:
        response = client.get(target)
    assert response.status_code == 200
    assert [item.id for item in contexts[-1][1]['records']] == [own.id]
    assert other.user_name not in response.get_data(as_text=True)


@pytest.mark.parametrize('kind,view', [('daily', 'daily'), ('weekly', 'weekly')])
def test_scan_return_and_saved_receipt_open_matching_progress(application, seeded, kind, view):
    point = seeded[kind]
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get(f'/c/{point.qr_token}').status_code == 200
    target = contexts[-1][1]['progress_url']
    params = parse_qs(urlsplit(target).query)
    assert params['view'] == [view] and params['floor'] == [str(point.floor)]
    assert params['date'] == ['2026-11-02' if kind == 'weekly' else '2026-11-03']
    saved = record(seeded['inspector'], point, datetime(2026, 10, 28, 4, tzinfo=timezone.utc))
    # The receipt must keep the recorded scope even after a point is relocated.
    original_floor = saved.point_floor
    point.floor, point.frequency, point.category = 4, 'daily2', 'general'
    db.session.commit()
    with rendered_contexts(application) as contexts:
        assert client.get(f'/checkins/{saved.id}').status_code == 200
    target = contexts[-1][1]['progress_url']
    params = parse_qs(urlsplit(target).query)
    assert params['view'] == [view] and params['floor'] == [str(original_floor)]
    assert params['category'] == ['safety']
    assert params['date'] == ['2026-10-26' if kind == 'weekly' else '2026-10-28']
    with rendered_contexts(application) as contexts:
        assert client.get(target).status_code == 200
    assert any(card['latest'] and card['latest'].id == saved.id for card in contexts[-1][1]['cards'])


def test_other_inspector_cannot_use_receipt_context_to_view_private_record(application, seeded):
    saved = record(seeded['colleague'], seeded['weekly'])
    client = application.test_client()
    login(client)
    assert client.get(f'/checkins/{saved.id}').status_code == 403


@pytest.mark.parametrize("day", ["2000-01-01", "2100-12-31"])
def test_partial_boundary_week_links_to_valid_reports(application, seeded, day):
    client = application.test_client()
    login(client, "manager")
    with rendered_contexts(application) as rendered:
        assert client.get(f"/dashboard?date={day}&view=weekly&category=safety&floor=1").status_code == 200
    for key in ("records_query_url", "missed_query_url"):
        url = rendered[-1][1][key]
        assert client.get(url).status_code == 200
        query = parse_qs(urlsplit(url).query)
        assert "2000-01-01" <= query["date_from"][0] <= day <= query["date_to"][0] <= "2100-12-31"
        assert (query["category"], query["floor"], query["frequency"]) == (["safety"], ["1"], ["weekly"])


def test_irregular_point_badge_leads_to_filtered_open_case_and_clears_after_resolution(application, seeded):
    user = seeded["inspector"]
    user.patrol_category = "general"
    point = general_point("1F-SPOT", "spot", frequency="irregular")
    case = make_case(user, point, 1)
    case.frequency, case.workflow_mode, case.spot_request_id = "irregular", "spot", "a" * 64
    case.personal_day = case.created_at.date()
    # An older open report belongs to the department that previously owned the point.
    older = make_case(seeded["colleague"], point, 2)
    older.category = "safety"
    db.session.commit()
    client = application.test_client()
    login(client, "manager")
    path = "/dashboard?category=general"
    def links():
        html = client.get(path).text.split('class="spot-point-list"', 1)[1].split("</ul>", 1)[0]
        return [a for a in Anchors(html).links if a.get("class") == "open-issue-badge"]
    badge, = links()
    assert "1 件" in badge["aria-label"]
    with rendered_contexts(application) as rendered:
        assert client.get(badge["href"]).status_code == 200
    assert [row.id for row in rendered[-1][1]["records"]] == [case.id]
    assert client.post(f"/issues/{case.id}/resolve", data={"expected_event_id": "0", "note": "現場已修復"}).status_code == 302
    assert links() == []
