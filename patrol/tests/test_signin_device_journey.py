"""A QR login and a second browser must not disrupt the original patrol phone."""
from urllib.parse import parse_qs, urlsplit

from models import DeviceBinding
from test_app import PASSWORD, application, approve_browser, db, login, seeded


def test_password_setup_stays_on_the_scanned_point(application, seeded):
    user = seeded["inspector"]
    user.must_change_password = True
    db.session.commit()
    browser = application.test_client()
    qr = "/c/" + seeded["daily"].qr_token
    login(browser, next=qr)
    setup = browser.get("/change-password")
    assert "完成後會回到原巡檢點" in setup.text and 'action="/logout"' in setup.text
    assert 'aria-label="手機主要導覽"' not in setup.text
    # Another tab or a stale menu cannot silently replace the intended point.
    other_tab = browser.get("/dashboard")
    assert parse_qs(urlsplit(other_tab.location).query)["next"] == [qr]
    changed = "Different-test-password-234!"
    assert browser.post("/change-password", data={"current_password": PASSWORD, "new_password": changed,
                                                   "confirm_password": changed}).location == qr
    assert 'aria-label="手機主要導覽"' in browser.get(qr).text


def test_replacement_request_is_distinct_from_first_binding_and_preserves_working_phone(application, seeded):
    user = seeded["inspector"]
    phone, desktop, colleague = (application.test_client() for _ in range(3))
    login(phone)
    login(desktop)
    login(colleague, "colleague")
    original = approve_browser(phone, user)
    original.label = "Original Phone"
    db.session.commit()
    assert "Original Phone" not in colleague.get("/devices").text
    assert "需要換機" not in colleague.get("/devices").text
    assert "此帳號已有其他瀏覽器可打卡" in desktop.get("/dashboard").text
    assert "此帳號已有其他瀏覽器可打卡" not in phone.get("/dashboard").text
    qr = "/c/" + seeded["daily"].qr_token
    page = desktop.get("/devices", query_string={"next": qr})
    assert "目前可打卡：Original Phone" in page.text and '<details class="binding-replace">' in page.text
    assert 'value="' + qr + '"' in page.text
    sent = desktop.post("/devices/request", data={"label": "New Browser", "next": qr}, follow_redirects=True)
    assert "撤回申請" in sent.text and "核准前，原本的綁定仍可打卡" in sent.text
    pending = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.label == "New Browser"))
    assert pending.status == "pending"
    assert 'id="inspection-form"' in phone.get(qr).text
    assert 'id="inspection-form"' not in desktop.get(qr).text
    cancelled = desktop.post(f"/devices/{pending.id}/revoke", data={"next": qr}, follow_redirects=True)
    assert "已撤回「New Browser」的綁定申請" in cancelled.text
    assert original.status == "approved" and pending.status == "revoked"
    assert 'id="inspection-form"' in phone.get(qr).text
