"""Retired food checklists remain readable only through their original signed grants."""
from datetime import timedelta
from uuid import uuid4

import pytest

import app as patrol
import checklist_catalog as catalog
import offline
from checklist_records import checklist_snapshot
from general_numbering import apply_general_numbering
from models import DeviceBinding, Inspection, OfflineSubmission, PatrolExecution, Point, User, db
from test_app import application
from test_general_numbering_routes import NOW, numbered_team
from test_offline_api import assert_error, entry, prepare, sync
from test_workflow_checkin import payload


def food_point(actors, name="員工餐廳", index=1):
    point = db.session.get(Point, actors["active_ids"][index])
    point.name, point.floor, point.code = name, 14, f"4M-G{29 + index:03d}"
    for schedule in point.schedules:
        schedule.point_name, schedule.floor, schedule.point_code = name, 14, point.code
    db.session.commit()
    return point


def old_prepare(client, monkeypatch):
    """Generate a genuine signed grant using the formerly deployed definition."""
    current = catalog.checklist_for_point

    def previous(point):
        return catalog.retired_checklist_for_point(point) or current(point)

    with monkeypatch.context() as old:
        old.setattr(catalog, "checklist_for_point", previous)
        old.setattr(offline, "checklist_for_point", previous)
        return prepare(client)


@pytest.mark.parametrize("name,key,selected", [
    ("員工餐廳", "dining_v1", "dining.a1"),
    ("廚房", "kitchen_v1", "kitchen.b1"),
])
@pytest.mark.parametrize("stage", ["execute", "inspect", "direct"])
def test_original_signed_food_drafts_preserve_selected_history(application, numbered_team, monkeypatch,
                                                              name, key, selected, stage):
    a = numbered_team
    index = 1 if stage == "direct" else 0
    point = food_point(a, name, index)
    url = a["urls"][index]
    client = a["executor" if stage == "execute" else "inspector"]
    if stage == "inspect":
        # The first stage can already use the new no-checklist flow.
        assert a["executor"].post(url + "/confirm", data=payload(a["executor"], url)).status_code == 302
    prepared = old_prepare(client, monkeypatch)
    item = entry(prepared, url, NOW, checklist=[selected])
    response = sync(client, prepared, item)
    assert response.status_code == 200 and response.json["status"] == "saved", response.text
    record = db.session.scalar(db.select(PatrolExecution if stage == "execute" else Inspection))
    assert record.point_id == point.id
    saved = checklist_snapshot(record)
    assert saved["key"] == key and saved["selected"] == [selected]
    assert sync(client, prepared, item).json["status"] == "already_synced"
    assert_error(sync(client, prepared, item | {"client_id": str(uuid4())}), "duplicate")
    assert db.session.query(OfflineSubmission).count() == 1


@pytest.mark.parametrize("name,selected", [("餐廳", "dining.a1"), ("廚房", "kitchen.b1")])
def test_new_grants_do_not_accept_retired_choices(application, numbered_team, name, selected):
    a = numbered_team
    point = food_point(a, name)
    prepared = prepare(a["inspector"])
    definition = next(p for p in prepared["points"] if p["id"] == point.id)
    assert definition["checklist"] is None
    item = entry(prepared, a["urls"][1], NOW)
    assert_error(sync(a["inspector"], prepared, item | {"checklist": [selected]}), "invalid_checklist")
    assert sync(a["inspector"], prepared, item).status_code == 200
    assert checklist_snapshot(db.session.scalar(db.select(Inspection))) is None


@pytest.mark.parametrize("choices", [[], ["toilet.soap"], ["dining.a1", "dining.a1"], ["kitchen.b1"]])
def test_old_dining_grant_requires_its_original_valid_selection(application, numbered_team, monkeypatch, choices):
    a = numbered_team
    food_point(a)
    prepared = old_prepare(a["inspector"], monkeypatch)
    item = entry(prepared, a["urls"][1], NOW, checklist=choices)
    assert_error(sync(a["inspector"], prepared, item), "invalid_checklist")
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0


@pytest.mark.parametrize("field,value", [
    ("name", "餐廳"), ("floor", 4), ("inspection_team", "engineering"),
    ("frequency", "weekly"), ("workflow_mode", "two_stage"),
    ("qr_token", "retired-checklist-new-token"), ("active", False),
    ("deleted_at", NOW.replace(tzinfo=None)), ("code", "4M-G099"),
])
def test_retired_profile_never_bypasses_actual_point_changes(application, numbered_team, monkeypatch, field, value):
    a = numbered_team
    point = food_point(a)
    prepared = old_prepare(a["inspector"], monkeypatch)
    item = entry(prepared, a["urls"][1], NOW, checklist=["dining.a1"])
    setattr(point, field, value)
    db.session.commit()
    assert_error(sync(a["inspector"], prepared, item), "point_changed")
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0


def test_retired_profile_and_automatic_renumber_can_both_match_original_id(application, numbered_team, monkeypatch):
    a = numbered_team
    point = food_point(a)
    prepared = old_prepare(a["inspector"], monkeypatch)
    item = entry(prepared, a["urls"][1], NOW, checklist=["dining.a2"])
    old_code = point.code
    admin = db.session.scalar(db.select(User).where(User.username == "admin"))
    apply_general_numbering(NOW, admin.id)
    db.session.commit()
    assert point.code != old_code
    assert sync(a["inspector"], prepared, item).status_code == 200
    record = db.session.scalar(db.select(Inspection))
    assert record.point_id == point.id and record.point_code == point.code
    assert checklist_snapshot(record)["selected"] == ["dining.a2"]


def test_old_signed_both_stages_continue_after_checklist_retirement(application, numbered_team, monkeypatch):
    a = numbered_team
    food_point(a, index=0)
    executor = old_prepare(a["executor"], monkeypatch)
    inspector = old_prepare(a["inspector"], monkeypatch)
    first = entry(executor, a["urls"][0], NOW, checklist=["dining.a1"])
    final = entry(inspector, a["urls"][0], NOW, checklist=["dining.a2"])
    assert_error(sync(a["inspector"], inspector, final), "waiting_execution", retryable=True)
    assert sync(a["executor"], executor, first).status_code == 200
    assert sync(a["inspector"], inspector, final).status_code == 200
    record = db.session.scalar(db.select(Inspection))
    assert checklist_snapshot(record)["selected"] == ["dining.a2"]
    assert checklist_snapshot(record.execution)["selected"] == ["dining.a1"]


@pytest.mark.parametrize("reason", ["expired", "binding", "role", "tampered"])
def test_old_food_grant_retains_expiry_binding_role_and_signature_guards(application, numbered_team, monkeypatch, reason):
    a = numbered_team
    food_point(a)
    prepared = old_prepare(a["inspector"], monkeypatch)
    item = entry(prepared, a["urls"][1], NOW, checklist=["dining.a1"])
    if reason == "expired":
        monkeypatch.setattr(patrol, "now_utc", lambda: NOW + timedelta(days=2))
        code = "expired"
    elif reason == "binding":
        user = db.session.scalar(db.select(User).where(User.username == "inspect"))
        db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == user.id)).status = "revoked"
        db.session.commit()
        code = "device_required"
    elif reason == "role":
        user = db.session.scalar(db.select(User).where(User.username == "inspect"))
        user.patrol_category = "safety"
        db.session.commit()
        code = "owner_changed"
    else:
        body, signature = item["grant"].rsplit(".", 1)
        # Change encoded signature bytes, not unused bits in the final base64 character.
        item["grant"] = body + "." + ("a" if signature[0] != "a" else "b") + signature[1:]
        code = "invalid_grant"
    assert_error(sync(a["inspector"], prepared, item), code)
    assert db.session.query(Inspection).count() == db.session.query(OfflineSubmission).count() == 0
