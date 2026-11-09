"""Point-team authorization across pages, exports, direct URLs and offline writes."""
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

import app as patrol
from issues import open_issue_for
from models import (DeviceBinding, Inspection, InspectionPhoto, IssueEvent, OfflineSubmission,
                    PatrolExecution, Point, PointSchedule, User, db)
from test_app import application, rendered_contexts  # noqa: F401
from test_offline_api import entry, prepare, sync
from test_frontend_navigation import Anchors
from test_workflow_checkin import payload


DATES = 'date_from=2026-11-01&date_to=2026-11-09'


def rendered(app, client, path):
    with rendered_contexts(app) as contexts:
        response = client.get(path)
    assert response.status_code == 200, (path, response.status_code, response.text[:500])
    return contexts[-1][1], response.text


@pytest.fixture
def teams(application, monkeypatch):
    clock = [datetime(2026, 11, 9, 2, tzinfo=timezone.utc)]
    monkeypatch.setattr(patrol, 'now_utc', lambda: clock[0])
    users, clients, bindings, points, records, executions = {}, {}, {}, {}, {}, {}
    for kind in ('general', 'engineering', 'manager', 'executor', 'safety', 'admin'):
        role = 'admin' if kind == 'admin' else 'executor' if kind == 'executor' else 'inspector'
        user = User(username=f'team-{kind}', display_name=f'{kind} staff', role=role, password_hash='not-used',
                    patrol_category=None if kind == 'admin' else 'safety' if kind == 'safety' else 'general',
                    general_manager_title=kind == 'manager', engineering_inspector_title=kind == 'engineering',
                    must_change_password=False, active=True)
        db.session.add(user)
        db.session.flush()
        token = f'team-{kind}-browser-token'
        binding = DeviceBinding(user_id=user.id, token_hash=patrol.hash_device_token(token), status='approved')
        db.session.add(binding)
        db.session.flush()
        client = application.test_client()
        with client.session_transaction() as session:
            session.update(user_id=user.id, auth_version=user.auth_version, csrf_token=f'team-csrf-{kind}')
        client.set_cookie('patrol_device', token)
        users[kind], clients[kind], bindings[kind] = user, client, binding
    for team in ('general', 'engineering'):
        for mode, frequency in (('spot', 'daily'), ('two_stage', 'weekly')):
            key = team if mode == 'spot' else team + '_pair'
            point = Point(code=f'{key.upper()}-PRIVATE', name=f'{key} private location', floor=1,
                category='general', inspection_team=team, frequency=frequency, workflow_mode=mode,
                active=True, schedule_start=date(2026, 11, 1), created_at=datetime(2026, 11, 1))
            point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=frequency,
                category='general', workflow_mode=mode, floor=1, point_code=point.code, point_name=point.name, active=True))
            db.session.add(point)
            db.session.flush()
            points[key] = point
            if mode == 'spot':
                record = Inspection(point_id=point.id, user_id=users[team].id, binding_id=bindings[team].id,
                    created_at=datetime(2026, 11, 8, 2), period_key='2026-11-08', frequency='daily', slot='any',
                    category='general', workflow_mode='spot', spot_request_id=f'{team}-old-inspection',
                    personal_day=date(2026, 11, 8), point_code=point.code, point_name=point.name, point_floor=1,
                    user_name=users[team].display_name, note=f'{team.upper()}-PRIVATE-NOTE', is_abnormal=True)
                photo = f'{team}-photo-bytes'.encode()
                record.photos.append(InspectionPhoto(data=photo, size_bytes=len(photo), width=1, height=1))
                open_issue_for(record)
                db.session.add(record)
                records[team] = record
            else:
                first = PatrolExecution(point_id=point.id, user_id=users['executor'].id,
                    binding_id=bindings['executor'].id, created_at=datetime(2026, 11, 9, 1),
                    period_key='2026-11-09', frequency='weekly', slot='any', category='general',
                    point_code=point.code, point_name=point.name, point_floor=1, user_name='executor staff')
                db.session.add(first)
                executions[team] = first
    safety = Point(code='SAFETY-PRIVATE', name='safety private location', floor=1, category='safety',
        frequency='daily', schedule_start=date(2026, 11, 1), created_at=datetime(2026, 11, 1), active=True)
    safety.schedules.append(PointSchedule(effective_date=safety.schedule_start, frequency='daily', category='safety',
        floor=1, point_code=safety.code, point_name=safety.name, active=True))
    db.session.add(safety)
    points['safety'] = safety
    db.session.commit()
    return SimpleNamespace(app=application, clock=clock, users=users, clients=clients, bindings=bindings,
                           points=points, records=records, executions=executions)


@pytest.mark.parametrize('kind,foreign', [('general', 'engineering'), ('engineering', 'general')])
def test_team_lists_counts_exports_and_forged_filters_do_not_cross(teams, kind, foreign):
    t = teams
    client = t.clients[kind]
    for suffix in ('', f'&inspection_team={foreign}', '&category=safety'):
        dashboard, html = rendered(t.app, client, '/dashboard?view=daily' + suffix)
        assert {c['point'].id for c in dashboard['cards']} == {t.points[kind].id}
        assert set(dashboard['open_issue_counts']) == {t.points[kind].id}
        assert t.points[foreign].code not in html and t.records[foreign].note not in html
        ready, html = rendered(t.app, client, '/ready?floor=1' + suffix)
        assert {p['id'] for p in ready['ready_points']} == {t.points[kind].id, t.points[kind + '_pair'].id}
        refreshed, _ = rendered(t.app, client, '/dashboard/ready?floor=1' + suffix)
        assert {p['id'] for p in refreshed['ready_points']} == {t.points[kind].id, t.points[kind + '_pair'].id}
        records, html = rendered(t.app, client, '/records?' + DATES + suffix)
        assert [r.id for r in records['records']] == [t.records[kind].id]
        assert t.records[foreign].note not in html
        executions, html = rendered(t.app, client, '/records?stage=execution&' + DATES + suffix)
        assert [r.id for r in executions['executions']] == [t.executions[kind].id]
        issues, html = rendered(t.app, client, '/issues?status=all' + suffix)
        assert [r.id for r in issues['records']] == [t.records[kind].id]
        assert issues['open_total'] == 1
        missed, html = rendered(t.app, client, '/missed?' + DATES + suffix)
        assert {r['point_id'] for r in missed['occurrences']} <= {t.points[kind].id, t.points[kind + '_pair'].id}
        assert missed['occurrences']
        for route in ('/records/export?', '/records/export?stage=execution&', '/missed/export?'):
            response = client.get(route + DATES + suffix)
            assert response.status_code == 200
            assert t.points[kind].code in response.text or t.points[kind + '_pair'].code in response.text
            assert t.points[foreign].code not in response.text and t.points[foreign + '_pair'].code not in response.text
            assert t.records[foreign].note not in response.text


@pytest.mark.parametrize('kind,foreign', [('general', 'engineering'), ('engineering', 'general')])
def test_foreign_receipts_photos_issues_and_qr_urls_are_denied(teams, kind, foreign):
    t = teams
    client, record, point = t.clients[kind], t.records[foreign], t.points[foreign]
    for path in (f'/records/{record.id}', f'/checkins/{record.id}', f'/photos/{record.photos[0].id}',
                 f'/executions/{t.executions[foreign].id}/success', f'/issues?point_id={point.id}',
                 f'/c/{point.qr_token}'):
        response = client.get(path)
        assert response.status_code in (403, 404), (path, response.status_code)
        assert point.code not in response.text and record.note not in response.text
    for path, data in ((f'/c/{point.qr_token}/confirm', {'frequency': 'daily'}),
                       (f'/issues/{record.id}/resolve', {'note': '', 'expected_event_id': 'bad'})):
        response = client.post(path, data=data)
        assert response.status_code == 404
        assert record.note not in response.text
    client.get('/devices', query_string={'next': f'/c/{point.qr_token}'})
    with client.session_transaction() as session:
        assert 'after_binding' not in session
    assert record.issue.status == 'open' and db.session.query(IssueEvent).count() == 0


@pytest.mark.parametrize('kind', ['manager', 'admin'])
def test_manager_sees_both_teams_and_can_filter_without_management_escalation(teams, kind):
    t = teams
    client = t.clients[kind]
    both, _ = rendered(t.app, client, '/records?' + DATES + '&category=general')
    assert {r.id for r in both['records']} == {r.id for r in t.records.values()}
    for team in ('general', 'engineering'):
        filters = f'category=general&inspection_team={team}'
        records, _ = rendered(t.app, client, '/records?' + DATES + '&' + filters)
        assert [r.id for r in records['records']] == [t.records[team].id]
        issues, _ = rendered(t.app, client, '/issues?' + filters)
        assert [r.id for r in issues['records']] == [t.records[team].id]
        assert issues['open_total'] == 1
        dashboard, _ = rendered(t.app, client, '/dashboard?view=daily&' + filters)
        assert {c['point'].id for c in dashboard['cards']} == {t.points[team].id}
        missed, html = rendered(t.app, client, '/missed?' + DATES + '&' + filters)
        assert {r['point_id'] for r in missed['occurrences']} <= {t.points[team].id, t.points[team + '_pair'].id}
        export = next(link['href'] for link in Anchors(html).links if urlsplit(link['href']).path == '/missed/export')
        assert parse_qs(urlsplit(export).query)['inspection_team'] == [team]
        response = client.get(export)
        foreign = 'general' if team == 'engineering' else 'engineering'
        assert response.status_code == 200 and t.points[foreign].code not in response.text
        assert client.get(f'/photos/{t.records[team].photos[0].id}').data == f'{team}-photo-bytes'.encode()
    if kind == 'manager':
        for path in ('/admin/points', '/admin/users', '/admin/devices'):
            assert client.get(path).status_code == 403
        assert client.post(f'/issues/{t.records["engineering"].id}/resolve',
            data={'note': 'manager verified the repair', 'expected_event_id': '0'}).status_code == 302
        assert t.records['engineering'].issue.status == 'resolved'
        assert client.post(f'/admin/issues/{t.records["engineering"].id}/reopen',
            data={'note': 'manager cannot reopen', 'expected_event_id': '0'}).status_code == 403


def test_point_handover_blocks_old_form_grant_and_old_team_history(teams):
    t = teams
    client, point = t.clients['general'], t.points['general']
    url = '/c/' + point.qr_token
    form = payload(client, url)
    prepared = prepare(client)
    pending = entry(prepared, url, t.clock[0])
    assert {p['id'] for p in prepared['points']} == {point.id, t.points['general_pair'].id}
    point.inspection_team = 'engineering'
    db.session.commit()
    assert client.post(url + '/confirm', data=form).status_code in (403, 404, 409)
    response = sync(client, prepared, pending)
    assert response.status_code in (403, 404, 409) and response.json['ok'] is False
    assert db.session.query(OfflineSubmission).count() == 0
    assert db.session.query(Inspection).count() == 2
    assert point.id not in {p['id'] for p in prepare(client)['points']}
    engineer = t.clients['engineering']
    assert point.id in {p['id'] for p in prepare(engineer)['points']}
    assert client.get(f'/records/{t.records["general"].id}').status_code in (403, 404)
    assert engineer.get(f'/records/{t.records["general"].id}').status_code == 200
    assert t.records['general'].category == 'general'


def test_role_handover_rejects_prepared_wrong_team_even_with_same_binding(teams):
    t = teams
    client, point = t.clients['general'], t.points['general']
    prepared = prepare(client)
    pending = entry(prepared, '/c/' + point.qr_token, t.clock[0])
    t.users['general'].engineering_inspector_title = True
    db.session.commit()
    response = sync(client, prepared, pending)
    assert response.status_code >= 400 and response.json['ok'] is False
    assert db.session.query(OfflineSubmission).count() == 0
    assert t.bindings['general'].status == 'approved'


def test_engineering_weekly_handoff_and_personal_daily_quota_stay_unchanged(teams):
    t = teams
    executor, engineer, manager = (t.clients[k] for k in ('executor', 'engineering', 'manager'))
    point = t.points['engineering_pair']
    url = '/c/' + point.qr_token
    executable = prepare(executor)
    assert {p['id'] for p in executable['points']} == {t.points[k + '_pair'].id for k in ('general', 'engineering')}
    assert all(p['stage'] == 'execute' for p in executable['points'])
    original_first = t.executions['engineering'].id
    # Existing execution is shared across days of the same week.
    t.clock[0] += timedelta(days=1)
    first_form = payload(engineer, url)
    assert engineer.post(url + '/confirm', data=first_form).status_code == 302
    assert engineer.post(url + '/confirm', data=first_form).status_code == 302
    assert db.session.query(Inspection).filter_by(point_id=point.id).count() == 1
    assert manager.post(url + '/confirm', data=payload(manager, url)).status_code == 302
    assert db.session.query(Inspection).filter_by(point_id=point.id).count() == 2
    t.clock[0] += timedelta(days=1)
    assert engineer.post(url + '/confirm', data=payload(engineer, url)).status_code == 302
    reports = db.session.scalars(select(Inspection).where(Inspection.point_id == point.id)).all()
    assert len(reports) == 3 and {r.execution_id for r in reports} == {original_first}
    assert {r.period_key for r in reports} == {'2026-11-09'}
    assert 'id="inspection-form"' not in executor.get(url).text
    # A new week requires a new first stage; the executor still may sign it.
    t.clock[0] = datetime(2026, 11, 16, 2, tzinfo=timezone.utc)
    assert 'id="inspection-form"' not in engineer.get(url).text
    assert executor.post(url + '/confirm', data=payload(executor, url)).status_code == 302
    assert engineer.post(url + '/confirm', data=payload(engineer, url)).status_code == 302
    assert db.session.query(PatrolExecution).filter_by(point_id=point.id).count() == 2


def test_safety_cannot_read_either_general_team_and_admin_two_stage_remains_management_only(teams):
    t = teams
    for team in ('general', 'engineering'):
        point, record = t.points[team], t.records[team]
        assert t.clients['safety'].get('/c/' + point.qr_token).status_code == 404
        assert t.clients['safety'].get(f'/records/{record.id}').status_code == 404
        pair = t.points[team + '_pair']
        assert 'id="inspection-form"' not in t.clients['admin'].get('/c/' + pair.qr_token).text
