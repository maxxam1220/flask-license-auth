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


def test_missed_csv_protects_full_width_formula_in_historical_location(application, seeded):
    point = historical_point()
    schedule = point.schedules[0]
    schedule.point_name = "＝1+1"
    db.session.commit()
    client = application.test_client()
    login(client)
    response = client.get('/missed/export?date_from=2026-11-02&date_to=2026-11-02')
    assert response.status_code == 200
    _, *rows = csv.reader(io.StringIO(response.data.decode("utf-8-sig")))
    assert len(rows) == 2 and all(row[5] == "'＝1+1" for row in rows)
    assert schedule.point_name == "＝1+1"


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


def test_archiving_legacy_point_without_schedule_preserves_past_and_expired_slots(application, seeded, monkeypatch):
    from test_features import clock

    point = historical_point()
    db.session.delete(point.schedules[0])
    db.session.commit()
    admin = application.test_client()
    login(admin, 'manager')
    clock(monkeypatch, 14)
    before = report_context(application, admin)[1]['occurrences']
    assert len(before) == 3
    assert admin.post(f'/admin/points/{point.id}/delete').status_code == 302
    assert admin.post(f'/admin/points/{point.id}/restore').status_code == 302
    assert report_context(application, admin)[1]['occurrences'] == before


def test_transfer_of_legacy_point_keeps_the_previous_teams_schedule(application, seeded, monkeypatch):
    from test_features import clock

    point = historical_point()
    db.session.delete(point.schedules[0])
    db.session.commit()
    clock(monkeypatch, 14)
    admin = application.test_client()
    login(admin, 'manager')
    worker = application.test_client()
    login(worker)
    before = report_context(application, worker)[1]['occurrences']
    assert admin.post(f'/admin/points/{point.id}/update', data={
        'code': '2F-HISTORY', 'name': 'New general office', 'category': 'general', 'floor': '2',
        'frequency': 'monthly', 'workflow_mode': 'spot', 'active': 'on',
    }).status_code == 302
    body, context = report_context(application, worker)
    assert context['occurrences'] == before and len(before) == 3
    assert b'New general office' not in body.data
    exported = worker.get('/missed/export?date_from=2026-11-02&date_to=2026-11-03')
    assert b'New general office' not in exported.data
    assert len(list(csv.reader(io.StringIO(exported.data.decode('utf-8-sig'))))) == 4


@pytest.mark.parametrize('archive_hour,activate_hour,expected', [(10, 11, ['am', 'pm']),
                         (10, 12, ['pm']), (10, 14, ['pm']), (13, 14, ['am', 'pm'])])
def test_safety_reactivation_cannot_make_archived_morning_overdue(application, seeded, monkeypatch,
                                                                  archive_hour, activate_hour, expected):
    from test_features import clock

    point = historical_point()
    admin = application.test_client()
    login(admin, 'manager')
    clock(monkeypatch, archive_hour)
    assert admin.post(f'/admin/points/{point.id}/delete').status_code == 302
    assert admin.post(f'/admin/points/{point.id}/restore').status_code == 302
    clock(monkeypatch, activate_hour)
    fields = {'code': point.code, 'name': 'Restored point', 'frequency': 'daily2', 'floor': str(point.floor),
              'category': 'safety'}
    # Renaming the inactive point need not immediately reactivate it.
    assert admin.post(f'/admin/points/{point.id}/update', data=fields).status_code == 302
    assert admin.post(f'/admin/points/{point.id}/update', data=fields | {'active': 'on'}).status_code == 302
    clock(monkeypatch, 8, day=4)
    occurrences = report_context(application, admin)[1]['occurrences']
    assert sorted(row['slot'] for row in occurrences if row['due_date'].isoformat() == '2026-11-03') == expected


def test_no_op_or_partially_known_schedule_does_not_invent_a_baseline(application, seeded):
    from datetime import date
    from models import PointSchedule

    point = historical_point()
    db.session.delete(point.schedules[0])
    db.session.commit()
    admin = application.test_client()
    login(admin, 'manager')
    fields = dict(code=point.code, name=point.name, floor=str(point.floor), category=point.category,
                  frequency=point.frequency, active='on')
    assert admin.post(f'/admin/points/{point.id}/update', data=fields).status_code == 302
    assert not point.schedules
    existing_date = date(2026, 10, 7)
    point.schedules.append(PointSchedule(effective_date=existing_date, active=True, frequency=point.frequency,
                                         category=point.category, floor=point.floor))
    db.session.commit()
    assert admin.post(f'/admin/points/{point.id}/update', data=fields | {'name': 'Another name'}).status_code == 302
    assert [s.effective_date for s in point.schedules] == [existing_date, date(2026, 11, 3)]


def test_partial_history_keeps_receipts_without_guessing_the_earlier_department(application, seeded):
    from datetime import date

    point = historical_point()
    point.schedules[0].effective_date = date(2026, 11, 3)
    receipt = Inspection(point_id=point.id, user_id=seeded['colleague'].id, period_key='2026-11-02',
                         created_at=datetime(2026, 11, 2, 0), frequency='daily2', slot='am', category='general',
                         point_code='1F-ORIGINAL', point_name='Original office', point_floor=1, user_name='Reporter')
    db.session.add(receipt)
    db.session.commit()
    admin = application.test_client()
    login(admin, 'manager')
    worker = application.test_client()
    login(worker)
    with rendered_contexts(application) as contexts:
        assert admin.get('/dashboard?date=2026-11-02&category=general').status_code == 200
    assert contexts[-1][1]['totals'] == {'total': 1, 'done': 1, 'pending': 0}
    assert contexts[-1][1]['cards'][0]['point'].code == '1F-ORIGINAL'
    with rendered_contexts(application) as contexts:
        response = worker.get('/dashboard?date=2026-11-02')
    assert contexts[-1][1]['cards'] == [] and b'Original office' not in response.data
    occurrences = report_context(application, worker)[1]['occurrences']
    assert [(row['due_date'], row['slot']) for row in occurrences] == [(date(2026, 11, 3), 'am')]
    assert db.session.get(Inspection, receipt.id) is not None


def test_partial_irregular_history_does_not_show_a_future_catalog_entry(application, seeded):
    from datetime import date

    point = historical_point(frequency='irregular', category='general')
    point.workflow_mode = point.schedules[0].workflow_mode = 'spot'
    point.schedules[0].effective_date = date(2026, 11, 3)
    db.session.commit()
    admin = application.test_client()
    login(admin, 'manager')
    for day, expected in [('2026-11-02', []), ('2026-11-03', [point.code])]:
        with rendered_contexts(application) as contexts:
            assert admin.get('/dashboard?date=' + day + '&category=general').status_code == 200
        assert [p.code for p in contexts[-1][1]['irregular_points']] == expected


@pytest.mark.parametrize('archive_utc_hour,expected_slots', [(3, []), (4, ['am']), (7, ['am'])])
def test_restored_inactive_point_edits_keep_only_overdue_slots_in_original_department(application, seeded, monkeypatch,
                                                                                      archive_utc_hour, expected_slots):
    from datetime import timezone

    point = historical_point()
    old_code, old_name = point.code, point.name
    admin = application.test_client()
    login(admin, 'manager')
    worker = application.test_client()
    login(worker)
    monkeypatch.setattr(app_module, 'now_utc', lambda: datetime(2026, 11, 3, archive_utc_hour, tzinfo=timezone.utc))
    assert admin.post(f'/admin/points/{point.id}/delete').status_code == 302
    assert admin.post(f'/admin/points/{point.id}/restore').status_code == 302
    # An inactive edit records a new schedule row but cannot rewrite the
    # old department's noon deadline, location or printed name.
    assert admin.post(f'/admin/points/{point.id}/update', data={
        'code': '2F-RESTORED', 'name': 'Private general office', 'floor': '2', 'category': 'general',
        'frequency': 'weekly',
    }).status_code == 302
    monkeypatch.setattr(app_module, 'now_utc', lambda: datetime(2026, 11, 5, 4, tzinfo=timezone.utc))
    query = '?date_from=2026-11-03&date_to=2026-11-04&floor=11&frequency=daily2'
    with rendered_contexts(application) as contexts:
        response = worker.get('/missed' + query)
    assert response.status_code == 200 and b'Private general office' not in response.data
    results = contexts[-1][1]['occurrences']
    assert [(row['due_date'].isoformat(), row['slot'], row['code'], row['name']) for row in results] == [
        ('2026-11-03', slot, old_code, old_name) for slot in expected_slots]
    exported = worker.get('/missed/export' + query)
    assert exported.status_code == 200 and b'Private general office' not in exported.data
    csv_rows = list(csv.reader(io.StringIO(exported.data.decode('utf-8-sig'))))[1:]
    assert [(row[0], row[3], row[4], row[5], row[7]) for row in csv_rows] == [
        ('2026-11-03', '1M', old_code, old_name, '上午') for _ in expected_slots]
    with rendered_contexts(application) as contexts:
        admin.get('/missed?date_from=2026-11-03&date_to=2026-11-04&floor=2&category=general')
    assert contexts[-1][1]['occurrences'] == []


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
    'date_from=bad', 'category=bad', 'floor=13', 'frequency=bogus', 'page=0',
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
    (3, False, '已完成 0 / 2 次', '漏打 1 次'),
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
    badge_class = 'badge-done' if complete_pm else 'badge-missed' if created_hour == 3 else 'badge-todo'
    assert f'<span class="badge {badge_class}">{expected_badge}</span>' in cards[0]
