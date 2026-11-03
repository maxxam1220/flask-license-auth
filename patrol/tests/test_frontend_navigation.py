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
    assert values == ['職安', '1M', '每日巡檢（含兩次）']
    fields = re.search(r'<div id="missed-query-fields"[^>]*>', source).group(0)
    assert 'hidden' not in fields
    next_link = next(link for link in Anchors(source).links if link.get('rel') == 'next')
    destination = urlsplit(next_link['href'])
    assert destination.path == '/missed' and destination.fragment == 'missed-results'
    assert parse_qs(destination.query) == {key: [value] for key, value in (filters | {'page': '2'}).items()}
    previous = next(link for link in Anchors(client.get(next_link['href']).get_data(as_text=True)).links if link.get('rel') == 'prev')
    assert urlsplit(previous['href']).fragment == 'missed-results'
