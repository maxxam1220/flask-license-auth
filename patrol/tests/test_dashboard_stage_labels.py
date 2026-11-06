"""Check dashboard labels against actual executor and inspector submissions."""
from datetime import datetime, timezone
import re

from models import Point, db
from test_app import application, app_module
from test_workflow_checkin import payload, team


def point_card(client, code, day="2026-11-04"):
    response = client.get("/dashboard", query_string={"date": day, "category": "general"})
    assert response.status_code == 200
    cards = re.findall(r'<article class="point-card[^"]*">(.*?)</article>', response.text, re.S)
    card, = (card for card in cards if f'<span class="point-code">{code}</span>' in card)
    summary = card.split("<h3>", 1)[0]
    badges = re.findall(r'<span class="badge (badge-[\w-]+)">([^<]+)</span>', summary)
    return card, badges


def visit(client, url):
    response = client.post(url + "/confirm", data=payload(client, url))
    assert response.status_code == 302


def setup_rounds(app):
    actors = team(app)
    for point in db.session.scalars(db.select(Point)):
        point.created_at = datetime(2026, 1, 1)
    db.session.commit()
    return actors


def test_two_rounds_show_which_stage_is_open_and_count_finished_slots(application, monkeypatch):
    executor, inspector, colleague, _, paired, direct, _ = setup_rounds(application)
    now = datetime(2026, 11, 4, 2, tzinfo=timezone.utc)  # 10:00 Taipei
    monkeypatch.setattr(app_module, "now_utc", lambda: now)
    card, badges = point_card(inspector, "1F-G00")
    assert badges == [("badge-signin", "未簽到")]
    assert "尚未開始" in card
    direct_card, direct_badges = point_card(inspector, "1F-G01")
    assert direct_badges == [("badge-todo", "待巡檢")] and "未簽到" not in direct_card

    visit(executor, paired)
    card, badges = point_card(inspector, "1F-G00")
    assert badges == [("badge-review", "已簽到、待巡檢")] and "已完成 0 / 2 次" in card
    visit(inspector, paired)
    visit(colleague, paired)
    partial = [("badge-partial", "部分完成 1/2")]
    card, badges = point_card(inspector, "1F-G00")
    assert badges == partial and "已完成 1 / 2 次" in card and "尚未開始" in card
    visit(inspector, direct)
    assert point_card(inspector, "1F-G01")[1] == partial

    now = now.replace(hour=4)  # New slot at exactly 12:00.
    card, badges = point_card(inspector, "1F-G00")
    assert badges == partial and "未簽到" in card and "尚未開始" not in card
    visit(executor, paired)
    card, badges = point_card(inspector, "1F-G00")
    assert badges == partial and "已簽到、待巡檢" in card
    visit(inspector, paired)
    card, badges = point_card(inspector, "1F-G00")
    assert badges == [("badge-done", "已完成")] and "已完成 2 / 2 次" in card


def test_live_stage_and_partial_completion_keep_missed_morning_visible(application, monkeypatch):
    executor, inspector, _, _, paired, _, _ = setup_rounds(application)
    now = datetime(2026, 11, 4, 4, tzinfo=timezone.utc)
    monkeypatch.setattr(app_module, "now_utc", lambda: now)
    missed = ("badge-missed", "漏打 1 次")
    card, badges = point_card(inspector, "1F-G00")
    assert badges == [("badge-signin", "未簽到"), missed] and "已到期、未簽到" in card
    visit(executor, paired)
    assert point_card(inspector, "1F-G00")[1] == [("badge-review", "已簽到、待巡檢"), missed]
    visit(inspector, paired)
    assert point_card(inspector, "1F-G00")[1] == [("badge-partial", "部分完成 1/2"), missed]
    tomorrow, badges = point_card(inspector, "1F-G00", "2026-11-05")
    assert badges == [("badge-not_due", "尚未開始")] and "未簽到" not in tomorrow
