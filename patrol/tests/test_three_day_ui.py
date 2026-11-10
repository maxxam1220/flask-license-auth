"""Three-day labels, calendar navigation and translated receipts use the real routes."""
from datetime import date, datetime, timezone
import re

import pytest

import app as patrol
from i18n import translate
from models import Inspection, Point, User, db
from test_app import application, rendered_contexts
from test_workflow_checkin import payload, team


@pytest.fixture
def three_day_team(application, monkeypatch):
    monkeypatch.setattr(patrol, "now_utc", lambda: datetime(2026, 11, 11, 2, tzinfo=timezone.utc))
    clients = team(application)
    for point in db.session.scalars(db.select(Point)):
        point.frequency = "three_day"
        point.schedule_start = date(2026, 11, 10)
        point.created_at = datetime(2026, 1, 1)
        schedule = point.schedules[0]
        schedule.frequency = "three_day"
        schedule.effective_date = date(2026, 11, 10)
    db.session.commit()
    return clients


def test_dashboard_three_day_tabs_and_period_navigation(application, three_day_team):
    inspector = three_day_team[1]
    with rendered_contexts(application) as contexts:
        response = inspector.get("/dashboard?view=three_day&date=2026-11-11")
    assert response.status_code == 200
    context = contexts[-1][1]
    assert context["view"] == "three_day"
    assert context["totals"] == {"total": 3, "done": 0, "pending": 3}
    nav = re.search(r'<div class="segmented".*?</div>', response.text, re.S).group()
    assert re.findall(r'>([^<>]+)</a>', nav) == ["每日巡檢", "3日巡檢", "每週巡檢"]
    assert "view=monthly" not in nav
    assert "11/10" in response.text and "11/12" in response.text
    assert 'aria-label="前3日"' in response.text and 'aria-label="後3日"' in response.text
    assert "不定期與免排程點位" not in response.text
    assert "每3日一次" in response.text


def test_three_day_management_reports_and_print_share_frequency_label(application, three_day_team):
    admin = three_day_team[3]
    for url in ("/admin/points", "/records?frequency=three_day", "/missed?frequency=three_day"):
        response = admin.get(url)
        assert response.status_code == 200
        assert re.search(r'<option value="three_day"[^>]*>每3日一次</option>', response.text)
    point = db.session.scalar(db.select(Point).order_by(Point.id))
    printed = admin.get("/admin/points/print", query_string={"ids": point.id})
    assert printed.status_code == 200 and "每3日一次" in printed.text
    missed = admin.get("/missed?frequency=three_day")
    assert "每連續 3 日為一期" in missed.text


@pytest.mark.parametrize("locale,label", [("id", "1 kali setiap 3 hari"), ("vi", "1 lần mỗi 3 ngày")])
def test_executor_three_day_form_and_receipt_have_localized_frequency_and_dates(application, three_day_team, locale, label):
    executor, _, _, _, url, _, _ = three_day_team
    user = db.session.scalar(db.select(User).where(User.username == "exec"))
    user.ui_language, user.simple_executor_ui = locale, True
    db.session.commit()
    page = executor.get(url)
    assert page.status_code == 200 and label in page.text
    assert "2026-11-10" in page.text and "2026-11-12" in page.text
    result = executor.post(url + "/confirm", data=payload(executor, url))
    assert result.status_code == 302
    receipt = executor.get(result.location)
    assert receipt.status_code == 200
    assert translate("有效期間", locale) in receipt.text
    assert "2026-11-10" in receipt.text and "2026-11-12" in receipt.text
    assert "月巡" not in receipt.text and "週巡" not in receipt.text


def test_inspector_three_day_confirmation_and_receipt_do_not_call_it_a_month(application, three_day_team):
    _, inspector, _, _, _, url, _ = three_day_team
    page = inspector.get(url)
    assert page.status_code == 200 and "每3日一次" in page.text
    assert "3日巡檢期間" in page.text
    period = re.search(r'<dl class="period-handoff".*?</dl>', page.text, re.S).group()
    assert "執行簽到" not in period and "尚未簽到" not in period
    assert "本次兩階段巡檢期間" not in page.text
    assert "無須執行人員先簽到" not in period
    assert "本期只要有人完成，即達成團隊進度。" in page.text
    result = inspector.post(url + "/confirm", data=payload(inspector, url))
    assert result.status_code == 302
    receipt = inspector.get(result.location)
    assert receipt.status_code == 200 and "3日巡檢期間" in receipt.text
    assert "月巡期間" not in receipt.text and "週巡期間" not in receipt.text
    assert "第二階段" not in receipt.text and "執行簽到" not in receipt.text
    record = db.session.scalar(db.select(Inspection))
    detail = inspector.get(f"/records/{record.id}")
    assert detail.status_code == 200 and "3日巡檢期間" in detail.text
    assert "兩階段作業紀錄" not in detail.text and "執行簽到" not in detail.text


@pytest.mark.parametrize("locale", ["id", "vi"])
def test_three_day_catalog_describes_direct_signin_as_separate_from_patrol(locale):
    for source in ("每3日一次", "3日巡檢", "直接簽到不取代巡檢。"):
        result = translate(source, locale)
        assert result != source and not re.search(r"[\u4e00-\u9fff]", result)


def test_full_executor_rescan_does_not_describe_direct_visit_as_completed_inspection(application, three_day_team):
    executor, _, _, _, _, url, _ = three_day_team
    point = db.session.scalar(db.select(Point).where(Point.qr_token == url[3:]))
    application.config["EXECUTOR_VISIT_CODES"] = frozenset({point.code})
    point.schedules[0].point_code = point.code
    db.session.commit()
    saved = executor.post(url + "/confirm", data=payload(executor, url))
    assert saved.status_code == 302
    repeated = executor.get(url)
    assert repeated.status_code == 200
    result = re.search(r'<div class="checkin-result-note".*?</div></div>', repeated.text, re.S).group()
    assert "完成直接簽到" in result
    assert "完成巡檢" not in result
