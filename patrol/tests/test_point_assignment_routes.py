"""The one-time authorized revision is previewed, scoped and replay-safe."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

import app as patrol
from models import AuditLog, Point, PointSchedule, User, db
from point_assignment_revision import ENGINEERING_POINTS, REVISION_ACTION
from test_app import rendered_contexts
from test_catalog import catalogue_app  # noqa: F401
from test_classification_management import form_revision
from test_point_assignment_revision import assignment_points  # noqa: F401


PATH = '/admin/points/revision-20261109'


@pytest.fixture
def route(catalogue_app, assignment_points, monkeypatch):
    app = catalogue_app
    app.config.update(CSRF_ENABLED=False, COOKIE_SECURE=False)
    clock = [datetime(2026, 11, 9, 2, tzinfo=timezone.utc)]
    monkeypatch.setattr(patrol, 'now_utc', lambda: clock[0])
    users = {'executor': db.session.get(User, 1), 'general': db.session.get(User, 2)}
    for kind in ('admin', 'manager', 'engineering', 'safety'):
        users[kind] = User(username=f'revision-{kind}', display_name=kind, password_hash='not-used',
            role='admin' if kind == 'admin' else 'inspector',
            patrol_category=None if kind == 'admin' else 'safety' if kind == 'safety' else 'general',
            general_manager_title=kind == 'manager', engineering_inspector_title=kind == 'engineering',
            active=True, must_change_password=False)
        db.session.add(users[kind])
    db.session.commit()
    clients = {}
    for kind, user in users.items():
        client = app.test_client()
        with client.session_transaction() as session:
            session.update(user_id=user.id, auth_version=user.auth_version, csrf_token='revision-csrf-' + kind)
        clients[kind] = client
    return SimpleNamespace(app=app, points=assignment_points, clients=clients, clock=clock)


def preview(route):
    with rendered_contexts(route.app) as contexts:
        response = route.clients['admin'].get(PATH)
    assert response.status_code == 200
    return response, contexts[-1][1]


def snapshot():
    points = [(p.id, p.code, p.name, p.frequency, p.inspection_team, p.qr_token,
               p.pending_frequency, p.frequency_effective_date, p.active, p.deleted_at)
              for p in db.session.scalars(select(Point).order_by(Point.id))]
    schedules = [(s.id, s.point_id, s.effective_date, s.frequency, s.active)
                 for s in db.session.scalars(select(PointSchedule).order_by(PointSchedule.id))]
    audits = [(r.id, r.action, r.target, r.detail)
              for r in db.session.scalars(select(AuditLog).order_by(AuditLog.id))]
    return points, schedules, audits


def test_only_system_admin_can_preview_or_apply_the_revision(route):
    before = snapshot()
    for kind in ('manager', 'general', 'engineering', 'executor', 'safety'):
        client = route.clients[kind]
        assert client.get(PATH).status_code == 403
        assert client.post(PATH, data={'expected_plan': '0' * 64}).status_code == 403
    anonymous = route.app.test_client()
    assert anonymous.get(PATH).location.startswith('/login')
    assert anonymous.post(PATH, data={'expected_plan': '0' * 64}).location.startswith('/login')
    assert snapshot() == before


def test_preview_is_read_only_and_contains_the_authorized_concrete_plan(route):
    before = snapshot()
    response, context = preview(route)
    plan = context['plan']
    assert plan['team_changed'] == 11 and plan['frequency_changed'] == 10
    assert plan['effective_date'] == '2026-11-10'
    assert len(context['expected_plan']) == 64
    assert 'expected_plan' in response.text and '消防泵浦室' in response.text
    assert not plan['already_applied'] and not context['revision_error']
    assert snapshot() == before


@pytest.mark.parametrize('digest,status', [('', 400), ('not-a-plan', 400), ('0' * 64, 409)])
def test_missing_or_fake_preview_digest_never_applies_any_point(route, digest, status):
    before = snapshot()
    response = route.clients['admin'].post(PATH, data={'expected_plan': digest})
    assert response.status_code == status
    assert snapshot() == before


def test_missing_catalog_reports_the_problem_without_partial_changes(route):
    point = db.session.get(Point, route.points['B2-G003'])
    point.code = 'MISSING-CATALOG-ITEM'
    db.session.commit()
    before = snapshot()
    response, context = preview(route)
    assert context['plan'] is None and context['revision_error']
    assert not context['expected_plan']
    assert 'B2-G003' in response.text
    assert route.clients['admin'].post(PATH, data={'expected_plan': '0' * 64}).status_code == 409
    assert snapshot() == before


def test_concurrent_admin_change_invalidates_the_previously_reviewed_plan(route):
    _, context = preview(route)
    point = db.session.get(Point, route.points['QA-G2'])
    point.name = 'Changed after preview'
    db.session.commit()
    before = snapshot()
    response = route.clients['admin'].post(PATH, data={'expected_plan': context['expected_plan']})
    assert response.status_code == 409
    assert snapshot() == before
    assert db.session.query(AuditLog).filter_by(action=REVISION_ACTION).count() == 0


def test_double_submit_applies_once_and_completed_page_stays_readable_after_effective_date(route):
    _, context = preview(route)
    data = {'expected_plan': context['expected_plan']}
    first = route.clients['admin'].post(PATH, data=data)
    assert first.status_code == 200
    after = snapshot()
    assert db.session.query(AuditLog).filter_by(action=REVISION_ACTION).count() == 1
    assert db.session.query(Point).filter_by(inspection_team='engineering').count() == 11
    assert db.session.query(Point).filter(Point.pending_frequency.is_not(None)).count() == 10
    assert route.clients['admin'].post(PATH, data=data).status_code == 200
    assert snapshot() == after
    route.clock[0] = datetime(2026, 11, 11, 2, tzinfo=timezone.utc)
    _, completed = preview(route)
    assert completed['plan']['already_applied'] and not completed['revision_error']
    activated = snapshot()
    assert route.clients['admin'].post(PATH, data=data).status_code == 200
    assert snapshot() == activated
    assert db.session.query(AuditLog).filter_by(action=REVISION_ACTION).count() == 1


def test_pending_frequency_blocks_edit_delete_and_restore_but_allows_qr_rotation(route):
    _, context = preview(route)
    assert route.clients['admin'].post(PATH, data={'expected_plan': context['expected_plan']}).status_code == 200
    admin = route.clients['admin']
    point = db.session.get(Point, route.points['QA-G2'])
    base = f'/admin/points/{point.id}'
    before = snapshot()
    assert admin.post(base + '/update', data={'code': point.code, 'name': 'Unsafe pending edit', 'floor': '1',
        'category': 'general', 'frequency': 'weekly', 'workflow_mode': 'spot', 'active': 'on'}).status_code == 409
    assert admin.post(base + '/delete').status_code == 409
    assert snapshot() == before
    # A legacy/inconsistent archived row must not bypass the same guard on restore.
    point.deleted_at = datetime(2026, 11, 8, 1)
    db.session.commit()
    archived = snapshot()
    assert admin.post(base + '/restore').status_code == 409
    assert snapshot() == archived
    point.deleted_at = None
    db.session.commit()
    old_token = point.qr_token
    revision = form_revision(admin, '/admin/points', base + '/rotate-qr')
    assert admin.post(base + '/rotate-qr', data={'expected_state': revision}).status_code == 302
    db.session.refresh(point)
    assert point.qr_token != old_token
    assert point.pending_frequency == 'daily' and point.frequency_effective_date.isoformat() == '2026-11-10'
    assert point.frequency == 'daily2'  # Rotation must not activate tomorrow's schedule early.


def test_same_named_safety_points_keep_frequency_team_tokens_and_schedules(route):
    safety_ids = []
    for code, (name, floor, _old_frequency, _mode, _new_frequency) in ENGINEERING_POINTS.items():
        point = Point(code='SAFETY-' + code, name=name, floor=floor, category='safety',
            frequency='daily2', workflow_mode='standard', qr_token='safety-unchanged-' + code,
            created_at=datetime(2026, 1, 1), schedule_start=datetime(2026, 1, 1).date(), active=True)
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency='daily2',
            category='safety', workflow_mode='standard', point_code=point.code, point_name=point.name,
            floor=point.floor, active=True))
        db.session.add(point)
        db.session.flush()
        safety_ids.append(point.id)
    db.session.commit()
    def safety_snapshot():
        points = db.session.execute(select(*Point.__table__.columns).where(Point.id.in_(safety_ids)).order_by(Point.id)).all()
        schedules = db.session.execute(select(*PointSchedule.__table__.columns).where(
            PointSchedule.point_id.in_(safety_ids)).order_by(PointSchedule.id)).all()
        return points, schedules
    before = safety_snapshot()
    _, context = preview(route)
    assert context['plan']['team_changed'] == 11 and context['plan']['frequency_changed'] == 10
    assert route.clients['admin'].post(PATH, data={'expected_plan': context['expected_plan']}).status_code == 200
    assert safety_snapshot() == before
    route.clock[0] = datetime(2026, 11, 11, 2, tzinfo=timezone.utc)
    assert route.clients['admin'].get(PATH).status_code == 200
    assert safety_snapshot() == before
    assert all(p.frequency == 'daily2' and p.inspection_team == 'general' and p.pending_frequency is None
               for p in db.session.scalars(select(Point).where(Point.id.in_(safety_ids))))
