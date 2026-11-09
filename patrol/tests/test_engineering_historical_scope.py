"""Team ownership scopes historical schedules independently of current category."""
from datetime import date

import pytest

from models import PointSchedule, db
from test_app import application  # noqa: F401
from test_engineering_point_scope import teams, rendered  # noqa: F401


def transfer_to_safety(t):
    point = t.points['general']
    point.category, point.workflow_mode = 'safety', 'standard'
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 9), frequency='daily',
        category='safety', workflow_mode='standard', floor=1, point_code='CURRENT-SAFETY',
        point_name='Current safety location', active=True))
    db.session.commit()
    return point


@pytest.mark.parametrize('kind,team_filter,visible', [
    ('general', '', True), ('engineering', '', False), ('manager', '', True),
    ('manager', 'general', True), ('manager', 'engineering', False),
    ('admin', 'general', True), ('admin', 'engineering', False),
])
def test_old_general_schedules_follow_current_team_after_category_move(teams, kind, team_filter, visible):
    t = teams
    point = transfer_to_safety(t)
    filters = '&inspection_team=' + team_filter if team_filter else ''
    client = t.clients[kind]
    context, html = rendered(t.app, client,
        '/missed?date_from=2026-11-01&date_to=2026-11-07' + filters)
    own_rows = [row for row in context['occurrences'] if row['point_id'] == point.id]
    assert len(own_rows) == (7 if visible else 0)
    assert all(row['category'] == 'general' for row in own_rows)
    assert ('GENERAL-PRIVATE' in html) is visible
    csv = client.get('/missed/export?date_from=2026-11-01&date_to=2026-11-07' + filters)
    assert csv.status_code == 200
    assert ('GENERAL-PRIVATE' in csv.text) is visible
    dashboard, html = rendered(t.app, client, '/dashboard?view=daily&date=2026-11-07' + filters)
    own_cards = [card for card in dashboard['cards'] if card['point'].id == point.id]
    assert len(own_cards) == (1 if visible else 0)
    assert all(card['point'].category == 'general' for card in own_cards)
    assert ('GENERAL-PRIVATE' in html) is visible


def test_explicit_admin_team_filter_cannot_include_safety_snapshots(teams):
    t = teams
    point = t.points['safety']
    point.category, point.workflow_mode, point.inspection_team = 'general', 'spot', 'engineering'
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 9), frequency='daily',
        category='general', workflow_mode='spot', floor=1, point_code='NEW-ENGINEERING',
        point_name='New engineering location', active=True))
    db.session.commit()
    for kind, team_filter, visible in [('safety', '', True), ('engineering', '', False),
                                     ('manager', 'engineering', False), ('admin', 'engineering', False)]:
        filters = '&inspection_team=' + team_filter if team_filter else ''
        client = t.clients[kind]
        context, _ = rendered(t.app, client,
            '/missed?date_from=2026-11-01&date_to=2026-11-07' + filters)
        rows = [row for row in context['occurrences'] if row['point_id'] == point.id]
        assert len(rows) == (7 if visible else 0), (kind, rows)
        csv = client.get('/missed/export?date_from=2026-11-01&date_to=2026-11-07' + filters)
        assert csv.status_code == 200 and ('SAFETY-PRIVATE' in csv.text) is visible
        dashboard, _ = rendered(t.app, client, '/dashboard?view=daily&date=2026-11-07' + filters)
        cards = [card for card in dashboard['cards'] if card['point'].id == point.id]
        assert len(cards) == (1 if visible else 0), (kind, cards)
