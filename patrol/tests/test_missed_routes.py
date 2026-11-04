"""Missed reports use shared point obligations, never personal blame or notes."""
import csv
import io
from datetime import datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from test_app import application, actors_only as seeded, app_module, db, login, rendered_contexts  # noqa: F401
from test_features import feature_point
from models import AuditLog, Inspection, InspectionPhoto


def historical_point(**kwargs):
    point = feature_point(**kwargs)
    point.created_at = datetime(2026, 1, 1)
    db.session.commit()
    return point


def report_context(application, client, query=""):
    with rendered_contexts(application) as contexts:
        response = client.get('/missed?date_from=2026-11-02&date_to=2026-11-03&category=safety' + query)
    assert response.status_code == 200
    return response, contexts[-1][1]


def test_report_counts_only_expired_slots_and_any_employee_completion(application, seeded):
    point = historical_point()
    row = Inspection(point_id=point.id, user_id=seeded['colleague'].id, user_name='PRIVATE COLLEAGUE',
        created_at=datetime(2026, 11, 2, 2), period_key='2026-11-02', frequency='daily2', slot='am',
        category='safety', point_code=point.code, point_name=point.name, point_floor=point.floor,
        note='PRIVATE REPORT NOTE')
    db.session.add(row)
    db.session.commit()
    inspector = application.test_client()
    login(inspector)
    response, context = report_context(application, inspector)
    assert context['totals'] == {'missed': 2, 'points': 1}
    assert {(r['due_date'].isoformat(), r['slot']) for r in context['occurrences']} == {('2026-11-02', 'pm'), ('2026-11-03', 'am')}
    assert 'PRIVATE' not in response.get_data(as_text=True)
    assert db.session.query(Inspection).count() == 1
    assert db.session.query(AuditLog).count() == 0


def test_csv_matches_all_filtered_results_and_sanitizes_labels(application, seeded):
    point = historical_point()
    point.name = '=HYPERLINK("https://example.test")'
    db.session.commit()
    client = application.test_client()
    login(client)
    response, context = report_context(application, client, '&floor=11&frequency=daily2')
    exported = client.get('/missed/export?date_from=2026-11-02&date_to=2026-11-03&category=safety&floor=11&frequency=daily2')
    assert exported.status_code == 200
    data = list(csv.reader(io.StringIO(exported.data.decode('utf-8-sig'))))
    assert len(data) - 1 == context['totals']['missed'] == 3
    assert all(row[5].startswith("'=HYPERLINK") and row[-1] == '1' for row in data[1:])
    assert all(len(row) == len(data[0]) for row in data)
    assert db.session.query(Inspection).count() == db.session.query(InspectionPhoto).count() == 0


def test_pagination_total_summary_and_export_are_not_limited_to_one_page(application, seeded):
    historical_point()
    client = application.test_client()
    login(client, 'manager')
    query = '/missed?date_from=2026-10-01&date_to=2026-11-02&category=safety&floor=11&frequency=daily2'
    with rendered_contexts(application) as contexts:
        response = client.get(query + '&page=2')
    assert response.status_code == 200
    context = contexts[-1][1]
    assert context['totals'] == {'missed': 66, 'points': 1}
    assert len(context['occurrences']) == 16
    assert context['point_summaries'][0]['missed_count'] == 66
    exported = client.get(query.replace('/missed?', '/missed/export?'))
    assert len(list(csv.reader(io.StringIO(exported.data.decode('utf-8-sig'))))) == 67
    redirected = client.get(query + '&page=999')
    assert redirected.status_code == 302
    params = parse_qs(urlsplit(redirected.location).query)
    assert params['page'] == ['2'] and params['floor'] == ['11'] and params['frequency'] == ['daily2']


@pytest.mark.parametrize('query', [
    'date_from=2026-11-04&date_to=2026-11-03',
    'date_from=2025-01-01&date_to=2026-11-03',
    'date_from=bad', 'category=bad', 'floor=13', 'frequency=monthly', 'page=0',
])
def test_invalid_report_filters_fail_closed(application, seeded, query):
    client = application.test_client()
    login(client)
    assert client.get('/missed?' + query).status_code == 400


def test_weekly_due_date_and_future_ranges_are_clear_and_not_backfilled(application, seeded):
    historical_point(frequency='weekly')
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get('/missed?date_from=2026-10-27&date_to=2026-11-01&category=safety').status_code == 200
    assert contexts[-1][1]['totals']['missed'] == 1
    assert contexts[-1][1]['occurrences'][0]['due_date'].isoformat() == '2026-11-01'
    with rendered_contexts(application) as contexts:
        assert client.get('/missed?date_from=2026-11-03&date_to=2026-11-08&category=safety').status_code == 200
    assert contexts[-1][1]['totals']['missed'] == 0


def test_reports_require_login_and_never_mutate_data(application, seeded):
    client = application.test_client()
    for path in ('/missed', '/missed/export'):
        response = client.get(path)
        assert response.status_code == 302 and urlsplit(response.location).path == '/login'
    assert db.session.query(Inspection).count() == 0


@pytest.mark.parametrize('created_hour', [4, 7])
def test_new_noon_or_afternoon_point_dashboard_does_not_count_expired_am(application, seeded, monkeypatch, created_hour):
    from datetime import date, timezone

    point = feature_point()
    point.created_at = datetime(2026, 11, 3, created_hour)  # Taipei noon or 15:00.
    point.schedule_start = date(2026, 11, 3)
    db.session.commit()
    monkeypatch.setattr(app_module, 'now_utc', lambda: datetime(2026, 11, 3, 10, tzinfo=timezone.utc))
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get('/dashboard?date=2026-11-03&category=safety').status_code == 200
    context = contexts[-1][1]
    assert context['totals'] == {'total': 1, 'done': 0, 'pending': 1}
    assert [(slot['key'], slot['status']) for slot in context['cards'][0]['slots']] == [('pm', 'pending')]
    with rendered_contexts(application) as contexts:
        assert client.get('/missed?date_from=2026-11-03&date_to=2026-11-03&category=safety').status_code == 200
    assert contexts[-1][1]['totals']['missed'] == 0


def test_dashboard_retains_completed_legacy_am_before_point_creation_timestamp(application, seeded, monkeypatch):
    from datetime import date, timezone

    point = feature_point()
    point.created_at = datetime(2026, 11, 3, 7)
    point.schedule_start = date(2026, 11, 3)
    db.session.add(Inspection(point_id=point.id, user_id=seeded['inspector'].id, user_name='Historical inspector',
        created_at=datetime(2026, 11, 3, 2), period_key='2026-11-03', frequency='daily2', slot='am',
        category='safety', point_code=point.code, point_name=point.name, point_floor=point.floor))
    db.session.commit()
    monkeypatch.setattr(app_module, 'now_utc', lambda: datetime(2026, 11, 3, 10, tzinfo=timezone.utc))
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get('/dashboard?date=2026-11-03&category=safety').status_code == 200
    context = contexts[-1][1]
    assert context['totals'] == {'total': 2, 'done': 1, 'pending': 1}
    assert [(slot['key'], slot['status']) for slot in context['cards'][0]['slots']] == [('am', 'done'), ('pm', 'pending')]


def test_dashboard_creation_cutoff_preserves_schedule_start_not_due(application, seeded, monkeypatch):
    from datetime import date, timezone

    point = feature_point()
    point.created_at = datetime(2026, 11, 1)
    point.schedule_start = date(2026, 11, 4)
    db.session.commit()
    monkeypatch.setattr(app_module, 'now_utc', lambda: datetime(2026, 11, 3, 10, tzinfo=timezone.utc))
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        assert client.get('/dashboard?date=2026-11-03&category=safety').status_code == 200
    context = contexts[-1][1]
    assert context['totals'] == {'total': 0, 'done': 0, 'pending': 0}
    assert all(slot['status'] == 'not_due' for slot in context['cards'][0]['slots'])


@pytest.mark.parametrize('created_hour,complete_pm,expected_progress,expected_badge', [
    (7, False, '已完成 0 / 1 次', '待巡檢'),
    (7, True, '已完成 1 / 1 次', '已完成'),
    (3, False, '已完成 0 / 2 次', '待巡檢'),
])
def test_daily2_dashboard_footer_uses_eligible_slots(application, seeded, monkeypatch,
                                                    created_hour, complete_pm, expected_progress, expected_badge):
    from datetime import date, timezone
    import re
    from test_app import approve_browser
    from test_features import submit

    point = feature_point()
    point.created_at = datetime(2026, 11, 3, created_hour)  # Taipei 15:00 or 11:00.
    point.schedule_start = date(2026, 11, 3)
    db.session.commit()
    monkeypatch.setattr(app_module, 'now_utc', lambda: datetime(2026, 11, 3, 10, tzinfo=timezone.utc))
    client = application.test_client()
    login(client)
    if complete_pm:
        approve_browser(client, seeded['inspector'])
        assert submit(client, point, slot='pm').status_code == 302

    response = client.get('/dashboard?date=2026-11-03&category=safety')
    assert response.status_code == 200
    cards = re.findall(r'<article class="point-card[^\"]*">(.*?)</article>', response.get_data(as_text=True), re.S)
    assert len(cards) == 1
    assert f'<small>{expected_progress}</small>' in cards[0]
    badge_class = 'badge-done' if complete_pm else 'badge-todo'
    assert f'<span class="badge {badge_class}">{expected_badge}</span>' in cards[0]
