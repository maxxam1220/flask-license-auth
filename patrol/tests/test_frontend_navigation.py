"""Rendered mobile navigation and filter context, using isolated SQLite fixtures."""
from datetime import datetime
from html import unescape
from html.parser import HTMLParser
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from test_app import application, seeded, db, login, record  # noqa: F401: shared fixtures
from test_features import feature_point


class Anchors(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.links = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.links.append(dict(attrs))


def mobile_links(response):
    assert response.status_code == 200
    nav = re.search(r'<nav class="mobile-nav"[^>]*>(.*?)</nav>', response.get_data(as_text=True), re.S)
    assert nav
    return Anchors(nav.group(1)).links


@pytest.mark.parametrize('username', ['inspector', 'manager'])
@pytest.mark.parametrize('page', ['/missed', '/issues'])
def test_mobile_has_five_destinations_and_highlights_current_page(application, seeded, username, page):
    client = application.test_client()
    login(client, username)
    links = mobile_links(client.get(page))
    assert [link['href'] for link in links] == ['/dashboard', '/records', '/missed', '/issues', '/devices']
    active = [link for link in links if link.get('aria-current') == 'page']
    assert len(active) == 1 and active[0]['href'] == page
    assert 'active' in active[0]['class'].split()


@pytest.mark.parametrize('origin,expected', [('/issues?status=open', '/issues'), ('/records?abnormal=1', '/records')])
def test_detail_navigation_tracks_validated_list_origin(application, seeded, origin, expected):
    row = record(seeded['inspector'], seeded['daily'])
    row.is_abnormal = True
    db.session.commit()
    client = application.test_client()
    login(client)
    links = mobile_links(client.get(f'/records/{row.id}', query_string={'return_to': origin}))
    assert [link['href'] for link in links if link.get('aria-current') == 'page'] == [expected]


def test_records_chips_show_all_actual_filters_and_escape_long_names(application, seeded):
    long_name = '長姓名' + 'AbCd' * 20 + '<測試>'
    seeded['inspector'].display_name = long_name
    db.session.commit()
    client = application.test_client()
    login(client, 'manager')
    response = client.get('/records', query_string={
        'category': 'safety', 'floor': '11', 'frequency': 'daily_all',
        'abnormal': '0', 'user_id': str(seeded['inspector'].id),
    })
    assert response.status_code == 200
    source = response.get_data(as_text=True)
    values = [unescape(value) for value in re.findall(r'<span class="query-chip-value">(.*?)</span>', source, re.S)]
    assert values == ['職安', '1M', '每日巡檢（含兩次）', '一般紀錄', long_name]
    assert '<測試>' not in source
    # With no JavaScript, the original form remains rendered and visible.
    fields = re.search(r'<div id="records-query-fields"[^>]*>', source).group(0)
    assert 'hidden' not in fields
    assert re.search(r'<select name="frequency">.*?<option value="daily_all" selected>', source, re.S)


def test_missed_chips_and_pagination_preserve_filters_and_target_results(application, seeded):
    point = feature_point()
    point.created_at = datetime(2026, 1, 1)
    db.session.commit()
    client = application.test_client()
    login(client)
    filters = {'date_from': '2026-10-01', 'date_to': '2026-11-02', 'category': 'safety', 'floor': '11', 'frequency': 'daily_all'}
    response = client.get('/missed', query_string=filters)
    assert response.status_code == 200
    source = response.get_data(as_text=True)
    values = [unescape(value) for value in re.findall(r'<span class="query-chip-value">(.*?)</span>', source, re.S)]
    # The assigned category is an access boundary, not an adjustable filter.
    assert values == ['1M', '每日巡檢（含兩次）']
    assert '<select name="category"' not in source
    fields = re.search(r'<div id="missed-query-fields"[^>]*>', source).group(0)
    assert 'hidden' not in fields
    next_link = next(link for link in Anchors(source).links if link.get('rel') == 'next')
    destination = urlsplit(next_link['href'])
    assert destination.path == '/missed' and destination.fragment == 'missed-results'
    assert parse_qs(destination.query) == {key: [value] for key, value in (filters | {'page': '2'}).items()}
    previous = next(link for link in Anchors(client.get(next_link['href']).get_data(as_text=True)).links if link.get('rel') == 'prev')
    assert urlsplit(previous['href']).fragment == 'missed-results'


@pytest.mark.parametrize('role, label', [('safety', '職安巡檢員'), ('general', '總務巡檢員')])
def test_inspector_pages_show_role_without_repeating_category_controls(application, seeded, role, label):
    seeded['inspector'].patrol_category = role
    db.session.commit()
    client = application.test_client()
    login(client)
    for path in ('/dashboard', '/records', '/missed', '/issues'):
        response = client.get(path)
        assert response.status_code == 200
        source = response.get_data(as_text=True)
        assert label in source
        assert '全部分類' not in source
        assert 'aria-label="巡檢分類"' not in source and 'name="category"' not in source
        assert '<span class="query-chip-label">分類</span>' not in source


def test_admin_role_selects_require_explicit_assignment_and_keep_self_locked(application, seeded):
    seeded['inspector'].patrol_category = None
    db.session.commit()
    client = application.test_client()
    login(client, 'manager')
    response = client.get('/admin/users')
    assert response.status_code == 200
    source = response.get_data(as_text=True)
    selects = re.findall(r'<select name="role"([^>]*)>(.*?)</select>', source, re.S)
    assert selects and all('required' in attrs for attrs, _ in selects)
    assert all(set(re.findall(r'<option value="([^"]+)"', options)) == {'safety', 'general', 'general_manager', 'general_executor', 'admin'} for _, options in selects)
    assert 'value="" selected disabled>請選擇角色' in source
    assert 'value="" selected disabled>尚未指派，請選擇角色' in source
    assert any('disabled' in attrs and 'value="admin" selected' in options for attrs, options in selects)
    assert '<input type="hidden" name="role" value="admin">' in source


def test_legacy_empty_point_snapshots_do_not_reveal_new_teams_point_name(application, seeded):
    point = seeded['daily']
    row = record(seeded['inspector'], point)
    row.point_name = row.point_code = ''
    row.is_abnormal = True
    point.name, point.code, point.category = '另一組的現場機房', '1F-SECRET', 'general'
    db.session.commit()
    client = application.test_client()
    login(client)
    for path in ('/records', '/issues', f'/records/{row.id}'):
        response = client.get(path)
        assert response.status_code == 200
        content = response.get_data(as_text=True)
        assert '歷史巡檢點' in content and ('#' + str(point.id)) in content
        assert point.name not in content and point.code not in content


def test_points_management_archive_preserves_context_and_has_no_qr_or_edit_actions(application, seeded):
    client = application.test_client()
    login(client, 'manager')
    point = seeded['daily']
    filters = {'category': 'safety', 'floor': '1'}
    current = client.get('/admin/points', query_string=filters).get_data(as_text=True)
    create = re.search(r'<form method="post" action="[^"]*?/create[^"]*"(.*?)</form>', current, re.S).group(1)
    choices = re.findall(r'<input type="radio" name="category"([^>]+)>', create)
    assert len(choices) == 2 and all('required' in choice for choice in choices)
    assert any('value="safety"' in choice and 'checked' in choice for choice in choices)
    assert not any('uncategorized' in choice for choice in choices)
    actions = [unescape(a) for a in re.findall(r'<form [^>]*action="([^"]+)"', current)]
    delete_action = next(a for a in actions if urlsplit(a).path.endswith(f'/{point.id}/delete'))
    assert parse_qs(urlsplit(delete_action).query) == {k: [v] for k, v in filters.items()}
    assert 'data-confirm-title="刪除巡檢點"' in current
    response = client.post(delete_action)
    assert response.status_code == 302
    assert parse_qs(urlsplit(response.location).query) == {k:[v] for k,v in filters.items()}

    deleted = client.get('/admin/points', query_string={**filters, 'list':'deleted'}).get_data(as_text=True)
    assert '已刪除（1）' in deleted and 'data-confirm-title="還原巡檢點"' in deleted
    assert '查看歷史案件' in deleted
    assert '新增巡檢點' not in deleted and '編輯或刪除點位' not in deleted
    assert '列印 QR 標籤' not in deleted and '開啟確認頁' not in deleted and '/rotate-qr' not in deleted
    restore = unescape(re.search(r'<form method="post" action="([^"]*?/restore[^"]*)"', deleted).group(1))
    assert parse_qs(urlsplit(restore).query) == {k:[v] for k,v in filters.items()}
    restored = client.post(restore)
    assert restored.status_code == 302
    assert parse_qs(urlsplit(restored.location).query) == {k:[v] for k,v in (filters | {'list':'deleted'}).items()}
    current = client.get('/admin/points', query_string=filters).get_data(as_text=True)
    assert '已停用' in current and '開啟確認頁' not in current
