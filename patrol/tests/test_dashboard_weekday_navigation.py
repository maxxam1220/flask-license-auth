"""Rendered weekday tabs stay simple while existing direct report URLs remain valid."""
import re
from urllib.parse import parse_qs, urlsplit

import pytest
from flask import before_render_template

from i18n import translate
from models import User, db
from test_app import application  # noqa: F401
from test_calendar_routes import calendar, context, instant  # noqa: F401
from test_frontend_navigation import Anchors


def primary_tabs(source):
    return re.search(r'<div class="segmented"[^>]*data-period-tabs>(.*?)</div>', source, re.S).group(1)


def view(link):
    return parse_qs(urlsplit(link["href"]).query)["view"][0]


def test_daily_primary_tabs_only_show_daily_wednesday_friday_without_history_menu(calendar):
    _, page = context(calendar.app, calendar.inspector, "/dashboard?floor=1")
    primary = primary_tabs(page.text)
    links = Anchors(primary).links
    assert [view(link) for link in links] == ["daily", "weekly_wed", "weekly_fri"]
    assert [view(link) for link in links if link["aria-current"] == "page"] == ["daily"]
    assert all(parse_qs(urlsplit(link["href"]).query)["floor"] == ["1"] for link in links)
    assert all(label in primary for label in ("每日巡檢", "週三巡檢", "週五巡檢"))
    assert "data-history-schedules" not in page.text


@pytest.mark.parametrize("selected,label,day", [("weekly_wed", "週三", "2026-11-18"), ("weekly_fri", "週五", "2026-11-20")])
def test_fixed_tabs_use_whole_week_navigation_and_explicit_due_day(calendar, selected, label, day):
    result, page = context(calendar.app, calendar.inspector, f"/dashboard?view={selected}&date=2026-11-19&floor=1")
    links = Anchors(page.text).links
    primary = Anchors(primary_tabs(page.text)).links
    assert [view(link) for link in primary if link["aria-current"] == "page"] == [selected]
    steps = {link["data-period-step"]: link for link in links if "data-period-step" in link}
    assert steps["prev"]["aria-label"] == "上一週" and steps["next"]["aria-label"] == "下一週"
    assert parse_qs(urlsplit(steps["prev"]["href"]).query)["date"] == ["2026-11-09"]
    assert parse_qs(urlsplit(steps["next"]["href"]).query)["date"] == ["2026-11-23"]
    assert all(view(link) == selected for link in steps.values())
    assert 'aria-label="所選週巡檢次數"' in page.text
    assert f'<time datetime="{day}">{day}</time>（{label}）' in page.text
    assert "指定當日巡檢，當日結束才列漏打" in page.text
    assert result["week_label"] in page.text
    assert "data-history-schedules" not in page.text


@pytest.mark.parametrize("selected", ["three_day", "weekly", "monthly"])
def test_legacy_schedule_direct_urls_remain_valid_without_history_menu(calendar, selected):
    result, page = context(calendar.app, calendar.inspector, "/dashboard?view=" + selected)
    assert result["view"] == selected
    assert "data-history-schedules" not in page.text
    primary = Anchors(primary_tabs(page.text)).links
    assert [view(link) for link in primary] == ["daily", "weekly_wed", "weekly_fri"]
    assert not [link for link in primary if link["aria-current"] == "page"]


@pytest.mark.parametrize("locale", ["id", "vi"])
def test_new_schedule_tabs_translate_without_reintroducing_history_menu(calendar, locale):
    actor = db.session.scalar(db.select(User).where(User.username == "inspect"))
    actor.ui_language = locale
    db.session.commit()
    _, page = context(calendar.app, calendar.inspector, "/dashboard")
    primary = primary_tabs(page.text)
    for label in ("週三巡檢", "週五巡檢"):
        assert translate(label, locale) in primary and label not in primary
    assert "data-history-schedules" not in page.text


def test_pending_schedule_hint_uses_explicit_new_schedule_destination(calendar):
    message = "7 個點位預定於 2026-11-16 啟用新排程。"
    def hint(sender, template, context, **extra):
        if template.name == "dashboard.html":
            context.update(pending_schedule_notice=message,
                           pending_schedule_url="/dashboard?view=weekly_wed&date=2026-11-16")
    before_render_template.connect(hint, calendar.app)
    try:
        _, page = context(calendar.app, calendar.inspector, "/dashboard")
    finally:
        before_render_template.disconnect(hint, calendar.app)
    rendered_hint = re.search(r'<div[^>]*data-pending-schedule>(.*?)</div>', page.text, re.S).group(1)
    assert message in rendered_hint
    assert "其他／歷史排程" not in rendered_hint
    link, = Anchors(rendered_hint).links
    assert parse_qs(urlsplit(link["href"]).query) == {"view": ["weekly_wed"], "date": ["2026-11-16"]}


def test_holiday_empty_state_explains_exemption_instead_of_missing_setup(calendar):
    calendar.clock[0] = instant("2026-12-25")
    result, page = context(calendar.app, calendar.inspector, "/dashboard?view=weekly_fri")
    assert result["cards"] == [] and result["weekday_schedule"]["exempt"]
    assert "本期免巡" in page.text and "2026-12-25 為假日或請休排除日" in page.text
    assert "尚無巡檢點" not in page.text


def test_future_weekday_card_says_it_has_not_started_rather_than_unscheduled(calendar):
    _, page = context(calendar.app, calendar.inspector, "/dashboard?view=weekly_fri&date=2026-11-18")
    assert "尚未到指定巡檢日" in page.text
    assert "此日未列入巡檢" not in page.text
