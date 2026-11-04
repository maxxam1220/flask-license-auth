"""Follow contextual links through real routes, preserving scope and privacy."""
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from test_app import application, seeded, app_module, db, login, record, rendered_contexts  # noqa: F401


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
