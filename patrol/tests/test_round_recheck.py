"""An inspector who scans early can complete two distinct shifts at the same QR."""
from datetime import timedelta
from html import unescape
from io import BytesIO
import re

import app as patrol
from models import DeviceBinding, Inspection, PatrolExecution, db
from test_app import FIXED_NOW, application
from test_workflow_checkin import payload, team


def form_fields(html, form_id):
    form = re.search(r'<form\b[^>]*\bid="' + form_id + r'"[^>]*>(.*?)</form>', html, re.S)
    assert form
    return {key: unescape(value) for key, value in re.findall(
        r'<input type="hidden" name="([^"]+)" value="([^"]*)"', form[1], re.S)}


def test_recheck_handoff_carries_unsent_report_through_noon_without_writing(application, monkeypatch):
    now = FIXED_NOW - timedelta(minutes=1)
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    executor, inspector, _, _, qr, other_qr, _ = team(application)
    assert "重新確認簽到狀態" in inspector.get(qr).text
    assert 'id="inspection-form"' not in inspector.get(qr).text
    executor.post(qr + "/confirm", data=payload(executor, qr))
    first_shift = payload(inspector, qr)
    now += timedelta(minutes=1)
    note = '查看「設備 A」\n閥門 <1> & 照片'
    stale = inspector.post(qr + "/confirm", data=first_shift | {
        "note": note, "is_abnormal": "on", "photos": (BytesIO(b"synthetic-original-photo"), "check.png")})
    assert stale.status_code == 409 and "草稿來自 2026-11-03 上午" in stale.text
    assert "照片需重新選擇" in stale.text and 'id="inspection-form"' not in stale.text
    carried = form_fields(stale.text, "handoff-recheck")
    assert carried["note"] == note and carried["is_abnormal"] == "on"
    assert "photos" not in carried
    again = inspector.post(qr, data=carried)
    assert form_fields(again.text, "handoff-recheck") == carried
    assert inspector.post(other_qr, data=carried).status_code == 302
    assert note not in inspector.get(other_qr).text
    assert db.session.query(Inspection).count() == 0
    executor.post(qr + "/confirm", data=payload(executor, qr))
    ready = inspector.post(qr, data=carried)
    assert ready.status_code == 200 and "草稿來自 2026-11-03 上午" in ready.text
    assert note in unescape(ready.text) and 'name="is_abnormal" value="on" checked' in ready.text
    assert db.session.query(Inspection).count() == 0
    current = form_fields(ready.text, "inspection-form")
    assert current["slot"] == "pm"
    assert inspector.post(qr + "/confirm", data=current | {"note": note, "is_abnormal": "on"}).status_code == 302
    saved = db.session.scalars(db.select(Inspection)).one()
    assert saved.slot == saved.execution.slot == "pm" and saved.note == note and saved.is_abnormal
    assert not saved.photos and db.session.query(PatrolExecution).count() == 2


def test_recheck_revalidates_login_csrf_and_binding(application, monkeypatch):
    monkeypatch.setattr(patrol, "now_utc", lambda: FIXED_NOW)
    _, inspector, _, _, qr, _, _ = team(application)
    point = db.session.scalar(db.select(patrol.Point).where(patrol.Point.qr_token == qr[3:]))
    fields = {"draft_point": str(point.id), "note": "local draft", "is_abnormal": "on"}
    application.config["CSRF_ENABLED"] = True
    assert inspector.post(qr, data=fields).status_code == 400
    with inspector.session_transaction() as session:
        fields["csrf_token"], user_id = session["csrf_token"], session["user_id"]
    mine = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == user_id))
    mine.status = "revoked"
    db.session.commit()
    assert inspector.post(qr, data=fields).location == qr
    signed_out = application.test_client().post(qr, data=fields)
    assert signed_out.location.startswith("/login?next=")
    assert "local" not in signed_out.location and not db.session.query(Inspection).count()


def test_rescanned_receipt_separates_patrol_actions_from_record_search(application):
    executor, inspector, _, _, qr, _, _ = team(application)
    for actor, stage in ((executor, "執行簽到收據"), (inspector, "巡檢收據")):
        receipt = actor.post(qr + "/confirm", data=payload(actor, qr)).location
        link = re.search(r'href="(' + re.escape(receipt) + r'\?[^"]*)"', actor.get(qr).text)
        rescan_page = actor.get(unescape(link[1]))
        assert stage in rescan_page.text and 'data-qr-entry="next"' in rescan_page.text
        assert "返回查詢結果" not in rescan_page.text
        search_page = actor.get(receipt, query_string={"return_to": "/records?floor=1&page=2"})
        assert "返回查詢結果" in search_page.text and 'data-qr-entry="next"' not in search_page.text
