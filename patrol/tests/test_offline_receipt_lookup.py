"""Receipt lookup cannot create, overwrite, or expose another user's record."""
from uuid import uuid4

import pytest

from models import DeviceBinding, Inspection, InspectionPhoto, OfflineSubmission, User, db
from test_app import application
from test_daily2_anytime import anytime
from test_features import png
from test_offline_api import assert_error, entry, prepare, sync


def lookup(client, prepared, identifier, **changes):
    query = {"owner": prepared["owner"]} | changes
    return client.get(f"/api/offline/receipt/{identifier}", query_string=query)


def test_absent_receipt_does_not_consume_quota_and_success_is_read_only(application, anytime):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0], note="Original report", is_abnormal=True)
    absent = lookup(anytime.inspector, prepared, item["client_id"])
    assert absent.status_code == 200
    assert absent.get_json() == dict(ok=True, status="not_received", client_id=item["client_id"], owner=prepared["owner"])
    assert "no-store" in absent.headers["Cache-Control"]
    assert db.session.query(OfflineSubmission).count() == db.session.query(Inspection).count() == 0
    result = sync(anytime.inspector, prepared, item, photos=[(png(), "original.png")])
    assert result.status_code == 200
    original_hash = db.session.scalar(db.select(OfflineSubmission)).payload_hash
    original_photo = db.session.scalar(db.select(InspectionPhoto)).data
    for _ in range(2):
        found = lookup(anytime.inspector, prepared, item["client_id"])
        assert found.status_code == 200 and "no-store" in found.headers["Cache-Control"]
        data = found.get_json()
        assert data["status"] == "already_synced" and data["owner"] == prepared["owner"]
        assert data["client_id"] == item["client_id"]
        assert data["receipt_url"] == result.get_json()["receipt_url"]
        assert "note" not in data and "photos" not in data and "payload_hash" not in data
    # Looking up an existing receipt cannot authorize replacing its evidence.
    changed = sync(anytime.inspector, prepared, item | {"note": "Replacement"}, photos=[(png(), "new.png")])
    assert_error(changed, "payload_conflict", status=409)
    assert db.session.scalar(db.select(OfflineSubmission)).payload_hash == original_hash
    assert db.session.scalar(db.select(InspectionPhoto)).data == original_photo
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 1


def test_receipt_lookup_requires_approved_current_identity_and_binding(application, anytime):
    prepared = prepare(anytime.inspector)
    item = entry(prepared, anytime.direct, anytime.clock[0])
    assert sync(anytime.inspector, prepared, item).status_code == 200
    assert_error(lookup(application.test_client(), prepared, item["client_id"]), status=401)
    assert_error(lookup(anytime.inspector, prepared, item["client_id"], owner="old-owner"), "owner_changed", status=403)
    peer = prepare(anytime.peer)
    hidden = lookup(anytime.peer, peer, item["client_id"])
    assert hidden.get_json()["status"] == "not_received"
    user = db.session.scalar(db.select(User).where(User.username == "inspect"))
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == user.id))
    binding.status = "revoked"
    db.session.commit()
    assert_error(lookup(anytime.inspector, prepared, item["client_id"]), "device_required", status=403)


@pytest.mark.parametrize("identifier", ["not-a-uuid", str(uuid4()).upper()])
def test_invalid_receipt_ids_fail_without_writes(application, anytime, identifier):
    prepared = prepare(anytime.inspector)
    assert_error(lookup(anytime.inspector, prepared, identifier), "invalid_receipt_id", status=400)
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0
