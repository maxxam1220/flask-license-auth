"""Current team ownership supplements immutable record-category authorization."""
from datetime import date, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from models import DeviceBinding, Inspection, PatrolExecution, Point, User, db
from patrol_access import (apply_point_scope, can_access_point, can_access_point_team,
                           can_read_inspection, inspection_team_scope)
from test_app import application  # noqa: F401


def actor(kind):
    return SimpleNamespace(id=7, role='admin' if kind == 'admin' else 'executor' if kind == 'executor' else 'inspector',
        patrol_category=None if kind in ('admin', 'unassigned') else 'safety' if kind == 'safety' else 'general',
        general_manager_title=kind == 'manager', engineering_inspector_title=kind == 'engineering')


@pytest.mark.parametrize('kind,scope', [('admin', None), ('manager', None), ('executor', None),
    ('safety', None), ('general', 'general'), ('engineering', 'engineering'), ('unassigned', '')])
def test_inspection_team_scope_does_not_replace_category_scope(kind, scope):
    user = actor(kind)
    assert inspection_team_scope(user) == scope
    general = SimpleNamespace(category='general', inspection_team='general')
    engineering = SimpleNamespace(category='general', inspection_team='engineering')
    safety = SimpleNamespace(category='safety', inspection_team='general')
    assert can_access_point(user, general) == (kind in ('admin', 'manager', 'executor', 'general'))
    assert can_access_point(user, engineering) == (kind in ('admin', 'manager', 'executor', 'engineering'))
    assert can_access_point(user, safety) == (kind in ('admin', 'safety'))


def test_missing_invalid_actor_or_point_fails_closed():
    point = SimpleNamespace(category='general', inspection_team='general')
    assert inspection_team_scope(None) == ''
    assert not can_access_point(None, point)
    assert not can_access_point(actor('general'), None)
    assert not can_access_point_team(actor('engineering'), None)
    corrupt = actor('manager')
    corrupt.engineering_inspector_title = True
    assert inspection_team_scope(corrupt) == ''
    assert not can_access_point(corrupt, point)
    point.inspection_team = 'untrusted'
    assert not can_access_point(actor('general'), point)


def test_history_transfers_with_point_without_rewriting_category_or_author():
    point = SimpleNamespace(category='general', inspection_team='general')
    record = SimpleNamespace(category='general', point=point, user_id=99, executor_visit=False,
                             workflow_mode='spot', frequency='daily')
    assert can_read_inspection(actor('general'), record)
    assert not can_read_inspection(actor('engineering'), record)
    point.inspection_team = 'engineering'
    assert not can_read_inspection(actor('general'), record)
    assert can_read_inspection(actor('engineering'), record)
    assert can_read_inspection(actor('manager'), record)
    assert not can_read_inspection(actor('safety'), record)
    assert not can_read_inspection(actor('executor'), record)
    assert (record.category, record.user_id) == ('general', 99)
    # A later category move still uses the submitted category for old receipts.
    point.category = 'safety'
    assert can_read_inspection(actor('engineering'), record)
    assert not can_access_point(actor('engineering'), point)
    record.category, record.user_id = 'safety', 7
    assert can_read_inspection(actor('safety'), record)
    assert not can_read_inspection(actor('engineering'), record)


def test_executor_still_reads_only_own_irregular_direct_visits():
    record = SimpleNamespace(category='general', point=SimpleNamespace(inspection_team='engineering'),
        user_id=7, executor_visit=True, workflow_mode='spot', frequency='irregular')
    assert can_read_inspection(actor('executor'), record)
    record.user_id = 8
    assert not can_read_inspection(actor('executor'), record)


@pytest.fixture
def scope_rows(application):
    user = User(username='scope-worker', display_name='scope worker', role='executor', patrol_category='general',
                password_hash='not-used', active=True)
    db.session.add(user)
    db.session.flush()
    binding = DeviceBinding(user_id=user.id, token_hash='scope-binding', status='approved')
    db.session.add(binding)
    db.session.flush()
    points, records, executions = [], [], []
    for index, (category, team) in enumerate((('general', 'general'), ('general', 'engineering'), ('safety', 'general'))):
        point = Point(code=f'SCOPE-{index}', name=f'point {index}', floor=1, category=category,
                      inspection_team=team, frequency='daily', schedule_start=date(2026, 1, 1))
        db.session.add(point)
        db.session.flush()
        record = Inspection(user_id=user.id, point_id=point.id, category=category, frequency='daily',
            period_key='2026-11-09', slot='any', point_code=point.code, point_name=point.name,
            point_floor=point.floor, user_name=user.display_name, created_at=datetime(2026, 11, 9, 1))
        db.session.add(record)
        if category == 'general':
            execution = PatrolExecution(user_id=user.id, point_id=point.id, binding_id=binding.id,
                category=category, frequency='daily', period_key='2026-11-09', slot='any',
                point_code=point.code, point_name=point.name, point_floor=1, user_name=user.display_name)
            db.session.add(execution)
            executions.append(execution)
        points.append(point)
        records.append(record)
    db.session.commit()
    return points, records, executions


@pytest.mark.parametrize('model,index', [(Point, 0), (Inspection, 1), (PatrolExecution, 2)])
def test_sql_scopes_rows_counts_and_explicit_filters_consistently(scope_rows, model, index):
    rows = scope_rows[index]
    base = select(model.id).where(model.category == 'general')
    for kind, expected in [('general', [rows[0].id]), ('engineering', [rows[1].id]),
                           ('manager', [rows[0].id, rows[1].id]), ('admin', [rows[0].id, rows[1].id]),
                           ('executor', [rows[0].id, rows[1].id]), ('unassigned', [])]:
        query = apply_point_scope(base, actor(kind), model)
        assert db.session.scalars(query.order_by(model.id)).all() == expected
        assert db.session.scalar(select(func.count()).select_from(query.subquery())) == len(expected)
    assert db.session.scalars(apply_point_scope(base, actor('general'), model, 'engineering')).all() == [rows[0].id]
    assert db.session.scalars(apply_point_scope(base, actor('engineering'), model, 'general')).all() == [rows[1].id]
    for kind in ('manager', 'admin'):
        assert db.session.scalars(apply_point_scope(select(model.id), actor(kind), model, 'engineering')).all() == [rows[1].id]
        assert db.session.scalars(apply_point_scope(base, actor(kind), model, 'invalid')).all() == []


def test_sql_history_follows_reassignment_and_does_not_drop_safety_history(scope_rows):
    points, records, _ = scope_rows
    points[0].inspection_team = 'engineering'
    db.session.commit()
    query = select(Inspection.id).where(Inspection.category == 'general')
    assert db.session.scalars(apply_point_scope(query, actor('general'), Inspection)).all() == []
    assert set(db.session.scalars(apply_point_scope(query, actor('engineering'), Inspection))) == {records[0].id, records[1].id}
    safety = select(Inspection.id).where(Inspection.category == 'safety')
    assert db.session.scalars(apply_point_scope(safety, actor('safety'), Inspection)).all() == [records[2].id]
    assert [row.category for row in records] == ['general', 'general', 'safety']
