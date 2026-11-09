"""A durable next-day frequency cutover never reinterprets old forms or history."""
from datetime import date, datetime, timezone

from sqlalchemy import select

from models import Inspection, OfflineSubmission, Point, PointSchedule, db
from test_engineering_point_scope import application, teams, rendered  # noqa: F401
from test_offline_api import entry, prepare, sync
from test_workflow_checkin import payload


def schedule(teams, key, old, target):
    t = teams
    point = t.points[key]
    point.frequency = point.schedules[0].frequency = old
    point.pending_frequency = target
    point.frequency_effective_date = date(2026, 11, 10)
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 10), frequency=target,
        category=point.category, workflow_mode=point.workflow_mode, active=point.active,
        floor=point.floor, point_code=point.code, point_name=point.name,
        workflow_changed_at=datetime(2026, 11, 9, 16)))
    t.clock[0] = datetime(2026, 11, 9, 15, 59, tzinfo=timezone.utc)
    db.session.commit()
    return point, '/c/' + point.qr_token


def test_midnight_daily2_to_daily_blocks_stale_online_and_offline_without_rewriting_history(teams):
    t = teams
    point, url = schedule(t, 'general', 'daily2', 'daily')
    client = t.clients['general']
    first = payload(client, url)
    assert first['frequency'] == 'daily2' and first['slot'] == 'am'
    assert client.post(url + '/confirm', data=first).status_code == 302
    second = payload(client, url)
    assert second['slot'] == 'pm'
    prepared = prepare(client)
    delayed = entry(prepared, url, t.clock[0], slot='pm', note='old second round')
    old_id = db.session.scalar(select(Inspection.id).where(Inspection.point_id == point.id,
        Inspection.period_key == '2026-11-09'))
    original_token = point.qr_token
    t.clock[0] = datetime(2026, 11, 9, 16, tzinfo=timezone.utc)
    fresh_form = payload(client, url)
    assert fresh_form['frequency'] == 'daily' and fresh_form['slot'] == 'any'
    assert fresh_form['period_key'] == '2026-11-10'
    db.session.refresh(point)
    assert (point.frequency, point.pending_frequency, point.frequency_effective_date) == ('daily', None, None)
    assert point.qr_token == original_token
    assert client.post(url + '/confirm', data=second).status_code == 409
    rejected = sync(client, prepared, delayed)
    assert rejected.status_code == 409 and rejected.json['ok'] is False
    assert db.session.query(OfflineSubmission).count() == 0
    original = db.session.get(Inspection, old_id)
    assert (original.frequency, original.slot, original.period_key) == ('daily2', 'am', '2026-11-09')
    # Re-preparation must issue a new single-round capability, not reuse the old pm grant.
    current = prepare(client)
    candidate = next(p for p in current['points'] if p['id'] == point.id)
    assert candidate['frequency'] == 'daily' and candidate['slots'] == ['any']
    saved = sync(client, current, entry(current, url, t.clock[0]))
    assert saved.status_code == 200 and saved.json['status'] == 'saved'
    repeat = sync(client, current, entry(current, url, t.clock[0]))
    assert repeat.status_code == 409 and repeat.json['code'] == 'duplicate'
    missed, _ = rendered(t.app, client, '/missed?date_from=2026-11-09&date_to=2026-11-09')
    rows = [row for row in missed['occurrences'] if row['point_id'] == point.id]
    assert [(row['frequency'], row['slot']) for row in rows] == [('daily2', 'pm')]


def test_daily_to_weekly_uses_same_qr_and_week_key_after_cutover(teams):
    t = teams
    point, url = schedule(t, 'engineering', 'daily', 'weekly')
    engineer = t.clients['engineering']
    old_form = payload(engineer, url)
    original_token = point.qr_token
    labels = t.clients['admin'].get('/admin/points/print', query_string={'ids': str(point.id)})
    assert labels.status_code == 200
    assert '工務巡檢' in labels.text and '每週一次' in labels.text
    assert '2026-11-10' in labels.text or '2026/11/10' in labels.text
    t.clock[0] = datetime(2026, 11, 9, 16, tzinfo=timezone.utc)
    weekly = payload(engineer, url)
    assert weekly['frequency'] == 'weekly' and weekly['period_key'] == '2026-11-09'
    assert point.qr_token == original_token
    assert engineer.post(url + '/confirm', data=old_form).status_code == 409
    result = engineer.post(url + '/confirm', data=weekly)
    assert result.status_code == 302
    ready, _ = rendered(t.app, engineer, '/ready')
    assert point.id not in {row['id'] for row in ready['ready_points']}
    dashboard, _ = rendered(t.app, engineer, '/dashboard?view=weekly')
    card = next(card for card in dashboard['cards'] if card['point'].id == point.id)
    assert card['latest'].frequency == 'weekly'
    assert card['latest'].period_key == '2026-11-09'
    # Other eligible inspectors may still add their own same-day evidence.
    assert t.clients['manager'].post(url + '/confirm', data=payload(t.clients['manager'], url)).status_code == 302
    assert db.session.query(Inspection).filter_by(point_id=point.id, frequency='weekly').count() == 2
