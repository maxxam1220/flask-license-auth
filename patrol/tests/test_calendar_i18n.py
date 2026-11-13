"""Executor screens translate fixed weekdays and exempt-day guidance, not just catalogs."""
import pytest

from i18n import translate
from models import User, db
from test_app import application  # noqa: F401
from test_daily2_anytime import anytime  # noqa: F401
from test_executor_localized_workflows import visible_text
from test_offline_calendar import fixed_point


def localize_executor(env, locale):
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.ui_language, actor.simple_executor_ui = locale, True
    db.session.commit()


@pytest.mark.parametrize("locale", ["id", "vi"])
@pytest.mark.parametrize("frequency,day,label", [
    ("weekly_wed", "2026-11-18", "每週三"),
    ("weekly_fri", "2026-11-20", "每週五"),
])
def test_executor_ready_screen_renders_fixed_weekday_in_selected_language(application, anytime, locale, frequency, day, label):
    localize_executor(anytime, locale)
    point, _ = fixed_point(anytime, frequency, day, paired=True)
    page = anytime.executor.get("/ready")
    assert page.status_code == 200
    text = visible_text(page)
    assert point.code in text
    assert translate(label, locale) in text and label not in text
    assert translate("今日到期", locale) in text


@pytest.mark.parametrize("locale", ["id", "vi"])
def test_executor_holiday_exemption_is_visible_and_translated(application, anytime, locale):
    localize_executor(anytime, locale)
    point, _ = fixed_point(anytime, "weekly_fri", "2026-12-25", paired=True)
    page = anytime.executor.get("/ready")
    assert page.status_code == 200
    text = visible_text(page)
    source = "假日或請休不列入應巡與漏打，仍可掃碼留紀錄。"
    assert translate(source, locale) in text and source not in text
    assert point.code not in text
