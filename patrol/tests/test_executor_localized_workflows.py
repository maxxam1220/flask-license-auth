"""Localized recovery remains actionable without changing attendance or authority."""
from datetime import timedelta
from html.parser import HTMLParser
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from receipt_urls import without_voice_feedback

import app as patrol
from i18n import translate
from models import DeviceBinding, OfflineSubmission, PatrolExecution, User, db
from test_app import PASSWORD, application
from test_daily2_anytime import anytime
from test_offline_api import entry, prepare, sync
from test_workflow_checkin import payload


def visible_text(response):
    """Ignore the embedded translation catalog; assertions must inspect rendered copy."""
    class Text(HTMLParser):
        def __init__(self):
            super().__init__()
            self.hidden = 0
            self.parts = []
        def handle_starttag(self, tag, attrs):
            if tag in ("script", "style"):
                self.hidden += 1
        def handle_endtag(self, tag):
            if tag in ("script", "style"):
                self.hidden -= 1
        def handle_data(self, data):
            if not self.hidden:
                self.parts.append(data)
    parser = Text()
    parser.feed(response.text)
    return " ".join(parser.parts)


@pytest.fixture(params=["id", "vi"])
def localized_worker(anytime, request):
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.ui_language, actor.simple_executor_ui = request.param, True
    actor.set_password(PASSWORD)
    db.session.commit()
    return anytime, actor, request.param


def localized_error(response, locale, status, code):
    data = response.get_json()
    assert response.status_code == status and data["ok"] is False and data["code"] == code
    assert re.search(r"[\u4e00-\u9fff]", data["message_source"])
    assert data["message"] == translate(data["message_source"], locale)
    assert not re.search(r"[\u4e00-\u9fff]", data["message"]), data
    return data


def test_default_chinese_account_keeps_existing_interface_and_error_text(application, anytime):
    page = anytime.executor.get(anytime.paired)
    assert '<html lang="zh-Hant">' in page.text
    assert 'class="checkin-wrap executor-checkin"' not in page.text
    response = anytime.executor.get("/api/offline/sync")
    assert response.status_code == 405
    assert response.json["message"] == response.json["message_source"] == "同步未完成，暫存仍保留；請重新連線後再試。"


def test_offline_retries_keep_error_source_and_respect_live_language(application, localized_worker):
    a, actor, locale = localized_worker
    prepared = prepare(a.executor)
    first = entry(prepared, a.paired, a.clock[0])
    assert sync(a.executor, prepared, first).status_code == 200
    duplicate = entry(prepared, a.paired, a.clock[0])
    old_error = localized_error(sync(a.executor, prepared, duplicate), locale, 409, "duplicate")
    actor.ui_language = "vi" if locale == "id" else "id"
    db.session.commit()
    new_error = localized_error(sync(a.executor, prepared, duplicate), actor.ui_language, 409, "duplicate")
    assert old_error["message_source"] == new_error["message_source"]
    assert old_error["message"] != new_error["message"]
    assert prepare(a.executor)["owner"] == prepared["owner"]
    assert sync(a.executor, prepared, first).json["status"] == "already_synced"
    assert db.session.query(PatrolExecution).count() == db.session.query(OfflineSubmission).count() == 1


@pytest.mark.parametrize("denial", ["expired-session", "password", "device", "csrf", "foreign-owner", "wrong-method"])
def test_offline_auth_validation_and_framework_errors_return_translatable_sources(application, localized_worker, denial):
    a, actor, locale = localized_worker
    prepared = prepare(a.executor)
    item = entry(prepared, a.paired, a.clock[0])
    if denial == "expired-session":
        actor.auth_version += 1
        db.session.commit()
        response, status, code = a.executor.get("/api/offline/status"), 401, "login_required"
    elif denial == "password":
        actor.must_change_password = True
        db.session.commit()
        response, status, code = a.executor.get("/api/offline/prepare"), 403, "password_required"
    elif denial == "device":
        db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == actor.id)).status = "revoked"
        db.session.commit()
        response, status, code = sync(a.executor, prepared, item), 403, "device_required"
    elif denial == "csrf":
        application.config["CSRF_ENABLED"] = True
        response = a.executor.post("/api/offline/sync", data={"entry": json.dumps(item)}, headers={"X-CSRF-Token": "invalid"})
        status, code = 400, "request_rejected"
    elif denial == "foreign-owner":
        other = prepare(a.inspector)
        response, status, code = sync(a.executor, prepared, entry(other, a.direct, a.clock[0])), 403, "owner_changed"
    else:
        response, status, code = a.executor.get("/api/offline/sync"), 405, "request_rejected"
    localized_error(response, locale, status, code)
    assert db.session.query(PatrolExecution).count() == db.session.query(OfflineSubmission).count() == 0


def test_device_status_race_keeps_binding_and_returns_localized_matching_recovery(application, localized_worker):
    a, actor, locale = localized_worker
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == actor.id))
    response = a.executor.post(f"/devices/{binding.id}/revoke", data={"reviewed_status": "pending", "next": a.paired})
    assert response.status_code == 409
    assert translate("查看最新綁定", locale) in visible_text(response)
    assert translate("返回今日待簽到", locale) not in visible_text(response)
    assert f'href="/devices?next=' in response.text
    assert binding.status == "approved"


def test_oversize_and_invalid_filter_errors_translate_and_keep_original_checkin_recovery(application, localized_worker):
    a, actor, locale = localized_worker
    invalid_filter = a.executor.get("/ready?category=invalid")
    assert invalid_filter.status_code == 400
    assert translate("分類選項不正確。", locale) in visible_text(invalid_filter)
    fields = payload(a.executor, a.paired)
    application.config["MAX_CONTENT_LENGTH"] = 64
    response = a.executor.post(a.paired + "/confirm", data=fields)
    assert response.status_code == 413
    assert translate("Retry · 返回此點重新確認", locale) in visible_text(response)
    assert f'href="{a.paired}"' in response.text
    assert translate("上傳內容太大，這次打卡未儲存。請重新選取照片，最多 3 張，每張不超過 8 MB。", locale) in visible_text(response)
    assert db.session.query(PatrolExecution).count() == 0


def test_daily_two_allows_two_executions_before_review_and_never_three(application, localized_worker):
    a, actor, locale = localized_worker
    first_fields = payload(a.executor, a.paired)
    first = a.executor.post(a.paired + "/confirm", data=first_fields)
    assert first.status_code == 302
    second_fields = payload(a.executor, a.paired)
    assert first_fields["slot"] == "am" and second_fields["slot"] == "pm"
    second = a.executor.post(a.paired + "/confirm", data=second_fields)
    assert second.status_code == 302 and without_voice_feedback(second.location) != without_voice_feedback(first.location)
    closed = a.executor.get(a.paired)
    assert 'id="inspection-form"' not in closed.text
    assert translate("本次已登記執行，不需重複簽到。", locale) in visible_text(closed)
    assert without_voice_feedback(a.executor.post(a.paired + "/confirm", data=first_fields).location) == without_voice_feedback(first.location)
    assert without_voice_feedback(a.executor.post(a.paired + "/confirm", data=second_fields).location) == without_voice_feedback(second.location)
    assert db.session.query(PatrolExecution).count() == 2


@pytest.mark.parametrize("frequency", ["weekly", "monthly"])
def test_long_period_repeat_stays_closed_and_translated_on_next_day(application, localized_worker, frequency):
    a, actor, locale = localized_worker
    point = a.pair_point
    point.frequency = point.schedules[0].frequency = frequency
    db.session.commit()
    fields = payload(a.executor, a.paired)
    first = a.executor.post(a.paired + "/confirm", data=fields)
    assert first.status_code == 302
    a.clock[0] += timedelta(days=1)
    closed = a.executor.get(a.paired)
    assert 'id="inspection-form"' not in closed.text
    assert translate("本週期已登記執行，不需重複簽到。", locale) in visible_text(closed)
    assert without_voice_feedback(a.executor.post(a.paired + "/confirm", data=fields).location) == without_voice_feedback(first.location)
    assert db.session.query(PatrolExecution).count() == 1


def test_expired_submission_then_password_recovery_preserves_scanned_destination(application, localized_worker):
    a, actor, locale = localized_worker
    fields = payload(a.executor, a.paired)
    actor.auth_version += 1
    db.session.commit()
    expired = a.executor.post(a.paired + "/confirm", data=fields)
    assert expired.status_code == 302 and urlsplit(expired.location).path == "/login"
    assert parse_qs(urlsplit(expired.location).query)["next"] == [a.paired]
    login_page = a.executor.get(expired.location)
    assert f'<html lang="{locale}">' in login_page.text
    assert db.session.query(PatrolExecution).count() == 0
    actor.must_change_password = True
    db.session.commit()
    signed_in = a.executor.post("/login", data={"username": actor.username, "password": PASSWORD, "next": a.paired})
    assert signed_in.location == "/change-password"
    mismatch = a.executor.post("/change-password", data={"current_password": PASSWORD,
        "new_password": PASSWORD + "new", "confirm_password": "mismatch"})
    assert translate("兩次輸入的新密碼不同。", locale) in visible_text(mismatch)
    changed = a.executor.post("/change-password", data={"current_password": PASSWORD,
        "new_password": PASSWORD + "new", "confirm_password": PASSWORD + "new"})
    assert changed.location == a.paired
