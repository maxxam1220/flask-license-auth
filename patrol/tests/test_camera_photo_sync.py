"""JPEG camera attachments with MPF auxiliary images use the normal API paths."""
from io import BytesIO

import pytest
from PIL import Image

import images
from models import (Inspection, InspectionIssue, InspectionPhoto, IssueEvent,
                    IssueEventPhoto, OfflineSubmission, db)
from test_app import application
from test_daily2_anytime import anytime
from test_offline_api import assert_error, entry, prepare, sync
from test_workflow_checkin import payload


def camera_jpeg(primary="green", auxiliary="gray"):
    """A JPEG byte stream browsers can label image/jpeg, with MPF metadata."""
    output = BytesIO()
    exif = Image.Exif()
    exif[274] = 6
    exif[270] = "Private camera metadata"
    Image.new("RGB", (40, 25), primary).save(output, format="MPO", save_all=True,
        append_images=[Image.new("RGB", (12, 8), auxiliary)], exif=exif)
    raw = output.getvalue()
    assert raw.startswith(b"\xff\xd8\xff")
    with Image.open(BytesIO(raw)) as source:
        assert source.format == "MPO" and source.n_frames == 2
    return raw


def attachment(raw):
    return BytesIO(raw), "IMG_0001.jpg", "image/jpeg"


def assert_primary_photo(row):
    assert row.mime_type == "image/jpeg" and (row.width, row.height) == (25, 40)
    with Image.open(BytesIO(row.data)) as photo:
        assert photo.format == "JPEG" and not photo.getexif()
        assert b"Private camera metadata" not in row.data
        red, green, blue = photo.getpixel((10, 10))
        assert green > 100 and red < 10 and blue < 10


@pytest.mark.parametrize("count", [1, 3])
def test_offline_camera_photos_save_with_issue_and_same_uuid_retry_once(application, anytime, count):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0], note="Camera abnormality", is_abnormal=True)
    raw = camera_jpeg()
    response = sync(anytime.inspector, prepared, item, photos=[attachment(raw) for _ in range(count)])
    assert response.status_code == 200 and response.get_json()["status"] == "saved", response.text
    # Treat the first acknowledgement as lost: resend exactly the same original
    # bytes and ID, including the unused auxiliary image bytes in the hash.
    repeated = sync(anytime.inspector, prepared, item, photos=[attachment(raw) for _ in range(count)])
    assert repeated.status_code == 200 and repeated.get_json()["status"] == "already_synced"
    assert all(db.session.query(model).count() == 1 for model in
               (Inspection, InspectionIssue, OfflineSubmission))
    assert db.session.query(InspectionPhoto).count() == count
    for photo in db.session.scalars(db.select(InspectionPhoto)):
        assert_primary_photo(photo)
    changed_auxiliary = camera_jpeg(auxiliary="red")
    changed = sync(anytime.inspector, prepared, item,
        photos=[attachment(changed_auxiliary)] + [attachment(raw) for _ in range(count - 1)])
    assert_error(changed, "payload_conflict", status=409)
    assert db.session.query(InspectionPhoto).count() == count


def test_previously_blocked_camera_jpeg_retries_original_id_without_reencoding(application, anytime, monkeypatch):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0], note="Original phone draft", is_abnormal=True)
    raw = camera_jpeg()
    with monkeypatch.context() as old_server:
        old_server.setattr(images, "ALLOWED_FORMATS", images.ALLOWED_FORMATS - {"MPO"})
        rejected = sync(anytime.inspector, prepared, item, photos=[attachment(raw)])
    assert_error(rejected, "invalid_photos", status=400)
    assert "請使用 JPG、PNG、WebP 或 HEIC 格式" in rejected.get_json()["message_source"]
    assert all(db.session.query(model).count() == 0 for model in
               (Inspection, InspectionIssue, InspectionPhoto, OfflineSubmission))
    saved = sync(anytime.inspector, prepared, item, photos=[attachment(raw)])
    assert saved.status_code == 200 and saved.get_json()["client_id"] == item["client_id"]
    assert saved.get_json()["status"] == "saved"
    record = db.session.scalar(db.select(Inspection))
    assert record.note == item["note"] and record.is_abnormal
    assert_primary_photo(record.photos[0])


def test_online_camera_checkin_and_resolution_share_normalized_photo_support(application, anytime):
    raw = camera_jpeg()
    fields = payload(anytime.inspector, anytime.direct)
    response = anytime.inspector.post(anytime.direct + "/confirm", data=fields | {
        "note": "Camera report", "is_abnormal": "on", "photos": attachment(raw)})
    assert response.status_code == 302, response.text
    record = db.session.scalar(db.select(Inspection))
    assert record is not None and record.is_abnormal and record.issue.status == "open"
    assert len(record.photos) == 1
    assert_primary_photo(record.photos[0])
    original_photo = record.photos[0].data
    resolved = anytime.inspector.post(f"/issues/{record.id}/resolve", data={
        "expected_event_id": "0", "note": "Camera repair evidence", "photos": attachment(raw)})
    assert resolved.status_code == 302, resolved.text
    db.session.refresh(record.issue)
    assert record.issue.status == "resolved"
    assert db.session.query(IssueEvent).count() == db.session.query(IssueEventPhoto).count() == 1
    assert_primary_photo(db.session.scalar(db.select(IssueEventPhoto)))
    assert record.photos[0].data == original_photo

