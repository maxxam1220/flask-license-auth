"""The executable mobile issue flow is localized without translating staff evidence."""
from html.parser import HTMLParser
from io import BytesIO
import re

import pytest

from i18n import translate
from models import db
from test_app import application
from test_engineering_point_scope import teams
from test_executor_localized_workflows import visible_text
from test_features import png


class IssueLabels(HTMLParser):
    def __init__(self, response):
        super().__init__()
        self.values = []
        self.feed(response.text)

    def handle_starttag(self, tag, attrs):
        self.values.extend(value for name, value in attrs if name in (
            "aria-label", "alt", "placeholder", "data-confirm", "data-confirm-title",
            "data-confirm-label", "data-loading-text") and value)


def chinese_ui_labels(response, note):
    # The company name and the reporter's note are intentionally kept verbatim.
    copy = visible_text(response).replace("福和生鮮農產股份有限公司", "").replace(note, "")
    return re.findall(r"[\u3400-\u9fff]+", copy)


@pytest.mark.parametrize("locale", ["vi", "id"])
def test_issue_list_photo_errors_confirmation_and_history_in_executor_language(teams, locale):
    actor = teams.users["executor"]
    actor.ui_language, actor.simple_executor_ui = locale, True
    record = teams.records["general"]
    record.note = "巡檢人員"  # A typed note may even match a translation key.
    db.session.commit()
    client = teams.clients["executor"]
    listing = client.get("/issues?date_from=&date_to=")
    assert listing.status_code == 200
    assert translate("查看與處理", locale) in visible_text(listing)
    assert record.note in visible_text(listing)
    assert chinese_ui_labels(listing, record.note) == []

    detail = client.get(f"/records/{record.id}?return_to=/issues")
    assert detail.status_code == 200
    labels = IssueLabels(detail).values
    assert translate("結案這筆異常", locale) in labels
    assert translate("開啟第 {number} 張巡檢照片（新分頁）", locale, number=1) in labels
    assert not re.search(r"[\u3400-\u9fff]", " ".join(labels))
    assert chinese_ui_labels(detail, record.note) == []

    url = f"/issues/{record.id}/resolve"
    error = client.post(url, data={"expected_event_id": "0", "photos": (BytesIO(b"invalid"), "file.jpg")})
    assert error.status_code == 400
    assert translate("第 {number} 張照片無法讀取，請重新選擇有效的 JPG、PNG、WebP 或 HEIC 圖片。",
                     locale, number=1) in visible_text(error)
    closed = client.post(url, data={"expected_event_id": "0", "photos": (png(), "repair.png")},
                         follow_redirects=True)
    assert closed.status_code == 200
    assert translate("案件已結案。", locale) in visible_text(closed)
    assert translate("未填寫處理說明。", locale) in visible_text(closed)
    assert translate("結案照片 {number}", locale, number=1) in visible_text(closed)
    assert record.note in visible_text(closed)
    assert chinese_ui_labels(closed, record.note) == []
