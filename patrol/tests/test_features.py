"""New patrol categories, half-day slots and private attachment regressions."""
from datetime import date, datetime, timezone
import csv
import io

from PIL import Image
import pytest
from sqlalchemy import event, inspect
from sqlalchemy.exc import IntegrityError

from test_app import (  # noqa: F401: shared isolated fixtures
    application, seeded, app_module, db, login, approve_browser, rendered_contexts,
)
from models import Inspection, InspectionPhoto, Point, PointSchedule


def feature_point(frequency="daily2", category="safety", floor=11, code="1M-NEW01"):
    point = Point(code=code, name="新巡檢點", floor=floor, category=category,
                  frequency=frequency, active=True, schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
    point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=frequency,
                                         category=category, active=True))
    db.session.add(point)
    db.session.commit()
    return point


def clock(monkeypatch, hour, minute=0, day=3):
    instant = datetime(2026, 11, day, hour - 8 if hour >= 8 else hour + 16, minute, tzinfo=timezone.utc)
    if hour < 8:
        from datetime import timedelta
        instant -= timedelta(days=1)
    monkeypatch.setattr(app_module, "now_utc", lambda: instant)
    return instant


def png():
    buffer = io.BytesIO()
    Image.new("RGB", (20, 20), "red").save(buffer, "PNG")
    buffer.seek(0)
    return buffer


def submit(client, point, slot="pm", period="2026-11-03", **fields):
    return client.post(f"/c/{point.qr_token}/confirm", data={"slot": slot, "period_key": period, "frequency": point.frequency, **fields})


def logged_browser(application, seeded, username="inspector"):
    client = application.test_client()
    login(client, username)
    approve_browser(client, seeded[username])
    return client


def test_same_qr_records_am_pm_once_each_and_uses_server_noon(application, seeded, monkeypatch):
    point = feature_point()
    client = logged_browser(application, seeded)
    token = point.qr_token
    clock(monkeypatch, 11, 59)
    with rendered_contexts(application) as contexts:
        assert client.get(f"/c/{token}").status_code == 200
    assert contexts[-1][1]["current_slot"] == "am"
    assert submit(client, point, "am").status_code == 302
    assert submit(client, point, "am").status_code == 302
    clock(monkeypatch, 12)
    with rendered_contexts(application) as contexts:
        assert client.get(f"/c/{token}").status_code == 200
    assert contexts[-1][1]["current_slot"] == "pm"
    assert contexts[-1][1]["existing"] is None
    assert submit(client, point, "pm").status_code == 302
    assert submit(client, point, "pm").status_code == 302
    rows = db.session.scalars(db.select(Inspection).where(Inspection.point_id == point.id).order_by(Inspection.id)).all()
    assert [(row.slot, row.period_key) for row in rows] == [("am", "2026-11-03"), ("pm", "2026-11-03")]
    assert rows[0].created_at.hour == 3 and rows[1].created_at.hour == 4
    assert point.qr_token == token


@pytest.mark.parametrize("slot,period", [("am", "2026-11-03"), ("pm", "2026-11-02"), ("any", "2026-11-03"), ("", "")])
def test_stale_or_missing_daily2_confirmation_preserves_note_without_write(application, seeded, slot, period):
    point = feature_point()
    client = logged_browser(application, seeded)
    with rendered_contexts(application) as contexts:
        response = submit(client, point, slot, period, note="保留現場說明", is_abnormal="on")
    assert response.status_code == 409
    context = contexts[-1][1]
    assert context["current_slot"] == "pm" and context["note"] == "保留現場說明"
    assert context["is_abnormal"] is True and context["form_error"]
    assert db.session.query(Inspection).count() == 0


def test_time_change_while_processing_photos_rejects_before_write(application, seeded, monkeypatch):
    point = feature_point()
    client = logged_browser(application, seeded)
    clock(monkeypatch, 11, 59)
    original = app_module.process_uploads
    def processing(files):
        result = original(files)
        clock(monkeypatch, 12)
        return result
    monkeypatch.setattr(app_module, "process_uploads", processing)
    response = submit(client, point, "am", photos=(png(), "photo.png"))
    assert response.status_code == 409
    assert db.session.query(Inspection).count() == db.session.query(InspectionPhoto).count() == 0


def test_daily2_dashboard_counts_two_and_masks_colleague_details(application, seeded, monkeypatch):
    point = feature_point()
    author = logged_browser(application, seeded, "colleague")
    clock(monkeypatch, 10)
    assert submit(author, point, "am", note="PRIVATE-NOTE", photos=(png(), "photo.png")).status_code == 302
    viewer = application.test_client()
    login(viewer)
    with rendered_contexts(application) as contexts:
        response = viewer.get("/dashboard?category=safety&floor=11")
    assert response.status_code == 200
    context = contexts[-1][1]
    assert context["totals"] == {"total": 2, "done": 1, "pending": 1}
    card, = context["cards"]
    assert [(slot["key"], slot["status"], slot["record"]) for slot in card["slots"]] == [("am", "done", None), ("pm", "not_due", None)]
    assert card["latest"] is None
    assert "PRIVATE-NOTE" not in response.get_data(as_text=True)
    assert "Inspector Bravo" not in response.get_data(as_text=True)
    with rendered_contexts(application) as contexts:
        viewer.get(f"/c/{point.qr_token}")
    assert set(contexts[-1][1]["existing"]) == {"created_at", "user"}


def test_daily2_next_day_requires_two_new_slots(application, seeded, monkeypatch):
    point = feature_point()
    client = logged_browser(application, seeded)
    assert submit(client, point).status_code == 302
    clock(monkeypatch, 10, day=4)
    assert submit(client, point, "am", "2026-11-04").status_code == 302
    with rendered_contexts(application) as contexts:
        client.get("/dashboard?category=safety")
    assert contexts[-1][1]["totals"] == {"total": 2, "done": 1, "pending": 1}


def test_daily_weekly_keep_any_slot_backward_compatible(application, seeded):
    client = logged_browser(application, seeded)
    for key in ("daily", "weekly"):
        assert client.post(f"/c/{seeded[key].qr_token}/confirm", data={"frequency": seeded[key].frequency}).status_code == 302
    assert {row.slot for row in db.session.scalars(db.select(Inspection))} == {"any"}


def test_unique_constraint_rejects_duplicate_same_slot_but_permits_other_slot(application, seeded):
    point = feature_point()
    client = logged_browser(application, seeded)
    submit(client, point)
    row = db.session.scalar(db.select(Inspection))
    fields = {key: getattr(row, key) for key in ("user_id", "point_id", "period_key", "frequency", "category", "point_code", "point_name", "point_floor")}
    db.session.add(Inspection(**fields, slot="am"))
    db.session.commit()
    db.session.add(Inspection(**fields, slot="pm"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    assert db.session.query(Inspection).count() == 2


@pytest.mark.parametrize("floor,code", [(-2, "B2-NEW01"), (-1, "B1-NEW01"), (11, "1M-NEW01"), (14, "4M-NEW01"), (15, "5M-NEW01")])
def test_admin_creates_extended_floor_with_category_and_schedule(application, seeded, floor, code):
    client = application.test_client()
    login(client, "manager")
    response = client.post("/admin/points/create", data={"code": code, "name": "新樓層點位", "floor": str(floor), "category": "general", "frequency": "daily2"})
    assert response.status_code == 302
    point = db.session.scalar(db.select(Point).where(Point.code == code))
    assert point.floor == floor and point.category == "general" and point.frequency == "daily2"
    assert point.schedules[0].category == "general"
    assert client.get(f"/admin/points?floor={floor}&category=general").status_code == 200


def test_category_snapshot_history_filter_and_qr_preserved(application, seeded, monkeypatch):
    point = feature_point(frequency="daily", floor=-1, code="B1-NEW01")
    token = point.qr_token
    client = logged_browser(application, seeded, "manager")
    assert submit(client, point, "any", note="消防檢查").status_code == 302
    clock(monkeypatch, 12, day=4)
    response = client.post(f"/admin/points/{point.id}/update", data={"code": point.code, "name": point.name, "floor": "-1", "category": "general", "frequency": "daily", "active": "on"})
    assert response.status_code == 302
    assert point.qr_token == token
    assert db.session.scalar(db.select(Inspection)).category == "safety"
    assert point.schedules[-1].category == "general"
    with rendered_contexts(application) as contexts:
        client.get("/dashboard?date=2026-11-03&category=safety&floor=-1")
    assert contexts[-1][1]["totals"] == {"total": 1, "done": 1, "pending": 0}
    with rendered_contexts(application) as contexts:
        client.get("/records?category=safety&floor=-1")
    assert len(contexts[-1][1]["records"]) == 1
    with rendered_contexts(application) as contexts:
        client.get("/admin/points/print?category=safety&floor=-1")
    assert contexts[-1][1]["points"] == []
    with rendered_contexts(application) as contexts:
        client.get("/admin/points/print?category=general&floor=-1")
    assert [row.id for row in contexts[-1][1]["points"]] == [point.id]


def test_same_day_reclassification_never_adds_duplicate_slot_obligation(application, seeded, monkeypatch):
    point = feature_point()
    client = logged_browser(application, seeded, "manager")
    clock(monkeypatch, 10)
    assert submit(client, point, "am").status_code == 302
    clock(monkeypatch, 12)
    assert client.post(f"/admin/points/{point.id}/update", data={"code": point.code, "name": point.name,
        "floor": "11", "category": "general", "frequency": "daily2", "active": "on"}).status_code == 302
    with rendered_contexts(application) as contexts:
        client.get("/dashboard?floor=11")
    assert contexts[-1][1]["totals"] == {"total": 2, "done": 1, "pending": 1}
    with rendered_contexts(application) as contexts:
        client.get("/dashboard?floor=11&category=general")
    context = contexts[-1][1]
    assert context["totals"] == {"total": 1, "done": 0, "pending": 1}
    assert [slot["key"] for card in context["cards"] for slot in card["slots"]] == ["pm"]
    assert submit(client, point, "pm").status_code == 302
    rows = db.session.scalars(db.select(Inspection).where(Inspection.point_id == point.id).order_by(Inspection.id)).all()
    assert [(row.slot, row.category) for row in rows] == [("am", "safety"), ("pm", "general")]


def test_notes_abnormal_photos_are_atomic_private_and_exported_safely(application, seeded):
    point = feature_point()
    client = logged_browser(application, seeded)
    response = submit(client, point, note="=HYPERLINK(\"test\")\n現場異常", is_abnormal="on", photos=[(png(), "photo1.png"), (png(), "photo2.png")])
    assert response.status_code == 302
    row = db.session.scalar(db.select(Inspection))
    assert row.note.startswith("=HYPERLINK") and row.is_abnormal
    assert row.category == "safety" and row.slot == "pm" and len(row.photos) == 2
    photo_id = row.photos[0].id
    db.session.expire_all()
    photo = db.session.get(InspectionPhoto, photo_id)
    assert "data" in inspect(photo).unloaded
    response = client.get(f"/photos/{photo_id}")
    assert response.status_code == 200 and response.mimetype == "image/jpeg"
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert Image.open(io.BytesIO(response.data)).format == "JPEG"
    assert client.get(f"/records/{row.id}").status_code == 200
    other = application.test_client()
    login(other, "colleague")
    assert other.get(f"/photos/{photo_id}").status_code == 403
    assert other.get(f"/records/{row.id}").status_code == 403
    anonymous = application.test_client()
    assert anonymous.get(f"/photos/{photo_id}").status_code == 302
    admin = application.test_client()
    login(admin, "manager")
    assert admin.get(f"/photos/{photo_id}").status_code == 200
    output = client.get("/records/export?category=safety&floor=11&abnormal=1").get_data(as_text=True)
    exported = list(csv.reader(io.StringIO(output.lstrip("\ufeff"))))
    assert len(exported) == 2 and exported[1][1] == "1M"
    assert exported[1][7:12] == ["職安", "下午", "是", "'=HYPERLINK(\"test\")\n現場異常", "2"]
    assert len(list(csv.reader(io.StringIO(client.get("/records/export?abnormal=0").get_data(as_text=True))))) == 1


def test_duplicate_does_not_process_or_append_photos(application, seeded, monkeypatch):
    point = feature_point()
    client = logged_browser(application, seeded)
    assert submit(client, point, note="first", photos=(png(), "first.png")).status_code == 302
    def unexpected(files):
        raise AssertionError("Duplicate check-in must not process attachments")
    monkeypatch.setattr(app_module, "process_uploads", unexpected)
    assert submit(client, point, note="changed", photos=(png(), "second.png")).status_code == 302
    assert db.session.query(Inspection).count() == 1 and db.session.query(InspectionPhoto).count() == 1
    assert db.session.scalar(db.select(Inspection)).note == "first"


def test_invalid_second_photo_rolls_back_everything_and_preserves_form(application, seeded):
    point = feature_point()
    client = logged_browser(application, seeded)
    with rendered_contexts(application) as contexts:
        response = submit(client, point, note="保留文字", is_abnormal="on", photos=[(png(), "valid.png"), (io.BytesIO(b"not an image"), "bad.png")])
    assert response.status_code == 400
    assert contexts[-1][1]["note"] == "保留文字" and contexts[-1][1]["is_abnormal"]
    assert db.session.query(Inspection).count() == db.session.query(InspectionPhoto).count() == 0


def test_photo_capacity_rejection_keeps_existing_photos_and_no_new_checkin(application, seeded):
    point = feature_point()
    client = logged_browser(application, seeded)
    assert submit(client, point, photos=(png(), "first.png")).status_code == 302
    used = db.session.scalar(db.select(db.func.sum(InspectionPhoto.size_bytes)))
    application.config["PHOTO_STORAGE_LIMIT_BYTES"] = used + 1
    other_point = feature_point(code="1M-NEW02")
    with rendered_contexts(application) as contexts:
        response = submit(client, other_point, note="保留說明", photos=(png(), "over.png"))
    assert response.status_code == 409 and contexts[-1][1]["note"] == "保留說明"
    assert db.session.query(Inspection).count() == 1 and db.session.query(InspectionPhoto).count() == 1
    assert submit(client, other_point, note="改為無照片").status_code == 302
    assert db.session.query(Inspection).count() == 2


def test_photo_quota_context_is_admin_only_and_uses_all_photo_bytes(application, seeded):
    point = feature_point()
    client = logged_browser(application, seeded)
    submit(client, point, photos=(png(), "photo.png"))
    expected = db.session.scalar(db.select(db.func.sum(InspectionPhoto.size_bytes)))
    with rendered_contexts(application) as contexts:
        client.get("/records")
    assert "photo_storage_used" not in contexts[-1][1]
    admin = application.test_client()
    login(admin, "manager")
    with rendered_contexts(application) as contexts:
        admin.get("/records?category=general")
    assert contexts[-1][1]["photo_storage_used"] == expected
    assert contexts[-1][1]["photo_storage_limit"] == application.config["PHOTO_STORAGE_LIMIT_BYTES"]


@pytest.mark.parametrize("note", ["x" * 2001, "bad\x00note"])
def test_invalid_note_does_not_reach_database(application, seeded, note):
    point = feature_point()
    client = logged_browser(application, seeded)
    params = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        params.extend(parameters)
    event.listen(db.engine, "before_cursor_execute", capture)
    try:
        response = submit(client, point, note=note)
    finally:
        event.remove(db.engine, "before_cursor_execute", capture)
    assert response.status_code == 400 and db.session.query(Inspection).count() == 0
    assert not any(isinstance(value, str) and "\x00" in value for value in params)


@pytest.mark.parametrize("query", ["category=foreign", "category=%00", "floor=0", "floor=12", "abnormal=maybe"])
def test_invalid_record_filters_return_400(application, seeded, query):
    client = application.test_client()
    login(client)
    assert client.get("/records?" + query).status_code == 400
    assert client.get("/records/export?" + query).status_code == 400
