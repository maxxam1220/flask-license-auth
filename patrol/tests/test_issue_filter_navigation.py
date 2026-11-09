"""Issue navigation preserves responsibility and makes cross-date counts reachable."""
from datetime import timedelta
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest

from models import User, db
from test_app import application, FIXED_NOW, record  # noqa: F401
from test_engineering_team_ui import setup_teams


class Links(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.items = []
        self.current = None
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.current = dict(attrs) | {'text': ''}

    def handle_data(self, data):
        if self.current is not None:
            self.current['text'] += data

    def handle_endtag(self, tag):
        if tag == 'a' and self.current is not None:
            self.items.append(self.current)
            self.current = None


def query(link):
    return parse_qs(urlsplit(link['href']).query, keep_blank_values=True)


@pytest.mark.parametrize('role', ['admin', 'general_manager'])
@pytest.mark.parametrize('team', ['general', 'engineering'])
def test_issue_status_and_point_cancel_preserve_team_dates_and_floor(application, role, team):
    general, _, admin, point = setup_teams(application)
    point.inspection_team = team
    manager = db.session.scalar(db.select(User).where(User.username == 'inspect'))
    manager.general_manager_title = True
    db.session.commit()
    client = admin if role == 'admin' else general
    params = {'inspection_team': team, 'category': 'general', 'floor': str(point.floor),
              'point_id': str(point.id), 'date_from': '2026-10-01', 'date_to': '2026-11-03'}
    page = client.get('/issues', query_string=params)
    assert page.status_code == 200
    assert ('工務目前未結案' if team == 'engineering' else '總務目前未結案') in page.text
    links = Links(page.text).items
    tabs = [link for link in links if link['text'].strip() in ['未結案', '已結案', '全部異常']]
    assert len(tabs) == 3
    for link in tabs:
        assert {key: query(link)[key][0] for key in params} == params
        moved = client.get(link['href'])
        assert moved.status_code == 200
        assert f'<option value="{team}" selected>' in moved.text
    cancel = next(link for link in links if '取消點位篩選' in link['text'])
    assert 'point_id' not in query(cancel)
    assert {key: query(cancel)[key][0] for key in params if key != 'point_id'} == {key: value for key, value in params.items() if key != 'point_id'}
    summary = next(link for link in links if '查看全部未結案' in link['text'])
    assert query(summary) == {'inspection_team': [team], 'date_from': [''], 'date_to': ['']}
    reset = next(link for link in links if '重設篩選' in link['text'])
    assert query(reset) == {'status': ['open'], 'inspection_team': ['']}


def test_point_issue_counts_and_archive_links_open_old_cases_outside_default_week(application):
    _, _, admin, point = setup_teams(application)
    owner = db.session.scalar(db.select(User).where(User.username == 'peer'))
    old_case = record(owner, point, FIXED_NOW - timedelta(days=30))
    old_case.is_abnormal = True
    old_case.note = 'Old case remains open beyond the default week.'
    db.session.commit()
    assert old_case.note not in admin.get('/issues').text
    for path in [f'/c/{point.qr_token}', f'/checkins/{old_case.id}', '/admin/points']:
        page = admin.get(path)
        assert page.status_code == 200
        badge = next(link for link in Links(page.text).items if 'open-issue-badge' in link.get('class', '') and query(link).get('point_id') == [str(point.id)])
        assert query(badge)['date_from'] == query(badge)['date_to'] == ['']
        assert old_case.note in admin.get(badge['href']).text
    point.active = False
    point.deleted_at = FIXED_NOW.replace(tzinfo=None)
    db.session.commit()
    archive = admin.get('/admin/points?list=deleted')
    history = next(link for link in Links(archive.text).items if '查看歷史案件' in link['text'])
    assert query(history)['status'] == ['all']
    assert query(history)['date_from'] == query(history)['date_to'] == ['']
    assert old_case.note in admin.get(history['href']).text


@pytest.mark.parametrize('role', ['admin', 'general_manager'])
@pytest.mark.parametrize('team', ['general', 'engineering'])
def test_page_recovery_preserves_team_filter_and_explicit_all_dates(application, role, team):
    general, _, admin, _ = setup_teams(application)
    manager = db.session.scalar(db.select(User).where(User.username == 'inspect'))
    manager.general_manager_title = True
    db.session.commit()
    client = admin if role == 'admin' else general
    response = client.get('/issues', query_string={
        'inspection_team': team, 'date_from': '', 'date_to': '', 'page': '999', 'status': 'all',
    })
    assert response.status_code == 302
    target = parse_qs(urlsplit(response.headers['Location']).query, keep_blank_values=True)
    assert target['inspection_team'] == [team]
    assert target['date_from'] == target['date_to'] == ['']
    assert target['status'] == ['all'] and target['page'] == ['1']
    assert client.get(response.headers['Location']).status_code == 200
