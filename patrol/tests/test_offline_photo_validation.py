"""Photo failures remain recoverable and expose no private payload in logs."""
from io import BytesIO
import logging

import pytest

from images import MAX_INPUT_BYTES
from models import Inspection, InspectionIssue, InspectionPhoto, OfflineSubmission, db
from test_app import application
from test_daily2_anytime import anytime
from test_features import png
from test_offline_api import assert_error, entry, prepare, sync


@pytest.mark.parametrize("case,reason", [
    ("empty", "photo_empty"), ("name", "photo_name"),
    ("oversize", "photo_size"), ("count", "photo_fields"),
])
def test_photo_validation_is_specific_and_allows_same_id_retry(application, anytime, caplog, case, reason):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0], note="private inspection note", is_abnormal=True)
    photo = (png(), "private-photo-name.png")
    if case == "empty":
        photos = [(BytesIO(b""), photo[1])]
    elif case == "name":
        photos = [(png(), "")]
    elif case == "oversize":
        photos = [(BytesIO(b"x" * (MAX_INPUT_BYTES + 1)), photo[1])]
    else:
        photos = [(png(), photo[1]) for _ in range(4)]
    with caplog.at_level(logging.WARNING, logger=application.logger.name):
        response = sync(anytime.inspector, prepared, item, photos=photos)
    rejected = assert_error(response, "invalid_entry", status=400)
    assert rejected["reason"] == reason
    assert "暫存照片" in rejected["message"] and "仍保留" in rejected["message"]
    assert "offline_sync_rejected" in caplog.text and f"reason={reason}" in caplog.text
    assert all(private not in caplog.text for private in (item["note"], item["grant"], item["token"], photo[1]))
    assert all(db.session.query(model).count() == 0 for model in
               (Inspection, InspectionPhoto, InspectionIssue, OfflineSubmission))
    # No receipt or quota was consumed by the failed attachment. Retrying the
    # same immutable ID with the intact original file is safe and idempotent.
    saved = sync(anytime.inspector, prepared, item, photos=[(png(), photo[1])])
    assert saved.status_code == 200 and saved.get_json()["status"] == "saved"
    repeated = sync(anytime.inspector, prepared, item, photos=[(png(), photo[1])])
    assert repeated.status_code == 200 and repeated.get_json()["status"] == "already_synced"
    assert all(db.session.query(model).count() == 1 for model in
               (Inspection, InspectionPhoto, InspectionIssue, OfflineSubmission))


@pytest.mark.parametrize("field,value,reason", [
    ("client_id", "not-a-uuid", "entry_id"),
    ("observed_at", "not-a-time", "entry_time"),
    ("is_abnormal", "true", "entry_types"),
    ("note", "bad\x00note", "entry_note"),
    ("checklist", "bad", "entry_checklist"),
])
def test_nonphoto_errors_do_not_blame_photos(application, anytime, field, value, reason):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0], **{field: value})
    rejected = assert_error(sync(anytime.inspector, prepared, item), "invalid_entry", status=400)
    assert rejected["reason"] == reason and "照片" not in rejected["message"]
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0


def test_photo_decode_and_http_size_failures_explain_recovery(application, anytime, caplog):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0], note="private note")
    name = "private-photo-name.png"
    with caplog.at_level(logging.WARNING, logger=application.logger.name):
        invalid = sync(anytime.inspector, prepared, item, photos=[(BytesIO(b"broken image"), name)])
        assert_error(invalid, "invalid_photos", status=400)
        assert "reason=invalid_photos" in caplog.text
        application.config["MAX_CONTENT_LENGTH"] = 1024
        too_large = sync(anytime.inspector, prepared, item, photos=[(BytesIO(b"x" * 2048), name)])
        rejected = assert_error(too_large, "request_rejected", status=413)
    assert "較小的照片" in rejected["message"]
    assert "reason=request_rejected http=413" in caplog.text
    assert all(value not in caplog.text for value in (item["note"], item["grant"], item["token"], name))
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0
