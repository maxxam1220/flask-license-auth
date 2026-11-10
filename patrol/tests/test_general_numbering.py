"""Numbering changes display codes, never point identity, workflow or history."""
from datetime import date, datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Event

import pytest
from sqlalchemy import select

import general_numbering as numbering
from general_workflow import execution_in_slot
from missed import calculate_missed
from models import AuditLog, Inspection, PatrolExecution, Point, PointSchedule, User, db
from test_app import application
from test_postgres_features import postgres_app
from test_workflow_checkin import payload, team


NOW = datetime(2026, 11, 10, 2, tzinfo=timezone.utc)
DAY = date(2026, 11, 10)
BEFORE = date(2026, 1, 1)


def point(code, floor=1, *, active=True, deleted=False, category="general", mode="spot",
          frequency="daily", schedule=True, **kwargs):
    item = Point(code=code, name="Point " + code, floor=floor, category=category, active=active,
                 deleted_at=datetime(2026, 11, 8, 1) if deleted else None,
                 frequency=frequency, workflow_mode=mode if category == "general" else "standard",
                 schedule_start=BEFORE, created_at=datetime(2026, 1, 1), **kwargs)
    if schedule:
        item.schedules.append(PointSchedule(effective_date=BEFORE, frequency=frequency, category=category,
            workflow_mode=item.workflow_mode, active=active and not deleted,
            retired_at=item.deleted_at))
    db.session.add(item)
    db.session.flush()
    return item


def apply(when=NOW, expected_plan=None):
    result = numbering.apply_general_numbering(when, None, expected_plan)
    db.session.commit()
    return result


def test_preview_orders_globally_by_floor_and_ignores_toilet_and_other_categories(application):
    second = point("1F-G003")
    first = point("B2-G099", -2)
    mezzanine = point("1M-G018", 11)
    second_floor = point("2F-G002", 2)
    inactive = point("B1-G008", -1, active=False, inspection_team="engineering")
    deleted = point("5F-G067", 5, active=False, deleted=True)
    toilet = point("AB2-W01", -2)
    safety = point("1F-S001", category="safety")
    db.session.commit()
    original = {p.id: (p.code, len(p.schedules)) for p in [first, second, mezzanine, second_floor, inactive, deleted, toilet, safety]}
    preview = numbering.preview_general_numbering(NOW)
    assert preview["changed"] == 6 and preview["active_count"] == 4 and preview["inactive_count"] == 2
    assert {c["id"]: c["new_code"] for c in preview["changes"]} == {
        first.id: "B2-G001", second.id: "1F-G002", mezzanine.id: "1M-G003", second_floor.id: "2F-G004",
        inactive.id: "B1-G100", deleted.id: "5F-G101"}
    assert not preview["enabled"] and preview["day"] == "2026-11-10" and not preview["blockers"]
    assert {p.id: (p.code, len(p.schedules)) for p in db.session.scalars(select(Point))} == original
    assert not numbering.numbering_enabled() and db.session.query(AuditLog).count() == 0


def test_apply_stages_unique_code_swaps_and_preserves_current_settings_and_tokens(application):
    earlier_floor = point("B2-G002", -2, mode="two_stage", frequency="weekly", inspection_team="engineering")
    displaced = point("1F-G001")
    third = point("1F-G002")
    db.session.commit()
    before = {p.id: (p.qr_token, p.frequency, p.workflow_mode, p.inspection_team, p.active) for p in [earlier_floor, displaced, third]}
    preview = numbering.preview_general_numbering(NOW)
    assert apply(expected_plan=preview) == preview
    assert [earlier_floor.code, displaced.code, third.code] == ["B2-G001", "1F-G002", "1F-G003"]
    assert numbering.numbering_enabled()
    for p in [earlier_floor, displaced, third]:
        assert (p.qr_token, p.frequency, p.workflow_mode, p.inspection_team, p.active) == before[p.id]
        assert len(p.schedules) == 2 and p.schedules[-1].effective_date == DAY
        assert p.schedules[-1].point_code == p.code
        assert p.schedules[0].point_code in ("B2-G002", "1F-G001", "1F-G002")
    audit = db.session.scalar(select(AuditLog).where(AuditLog.action == numbering.NUMBERING_ACTION))
    assert json.loads(audit.detail)["origin_order"] == {str(earlier_floor.id): 2, str(displaced.id): 1, str(third.id): 2}
    assert all(p.qr_token not in audit.detail for p in [earlier_floor, displaced, third])


def test_disable_restore_and_new_points_keep_the_original_order_without_drift(application):
    first = point("1F-G002")
    middle = point("1F-G011")
    last = point("1F-G016")
    db.session.commit()
    apply()
    first.active = False
    apply()
    assert [first.code, middle.code, last.code] == ["1F-G100", "1F-G001", "1F-G002"]
    first.active = True
    apply()
    assert [first.code, middle.code, last.code] == ["1F-G001", "1F-G002", "1F-G003"]
    inserted = point("1F-G010")
    apply()
    assert [first.code, inserted.code, middle.code, last.code] == ["1F-G001", "1F-G002", "1F-G003", "1F-G004"]
    first.active = False
    last.active = False
    apply()
    first.active = last.active = True
    apply()
    assert [first.code, inserted.code, middle.code, last.code] == ["1F-G001", "1F-G002", "1F-G003", "1F-G004"]


def test_original_order_uses_current_manual_codes_not_old_schedule_snapshots(application):
    first = point("B2-G002", -2)
    first.schedules[0].point_code = "1F-G013"
    second = point("B2-G003", -2)
    db.session.commit()
    result = apply()
    assert [first.code, second.code] == ["B2-G001", "B2-G002"]
    assert result["origin_order"][str(first.id)] == 2
    assert first.schedules[0].point_code == "1F-G013"


def test_deleted_code_is_freed_without_changing_retirement_or_history(application):
    deleted = point("1F-G001", active=False, deleted=True)
    active = point("1F-G020")
    db.session.commit()
    old_time, old_token = deleted.deleted_at, deleted.qr_token
    apply()
    assert active.code == "1F-G001" and deleted.code == "1F-G100"
    assert deleted.deleted_at == old_time and not deleted.active and deleted.qr_token == old_token
    assert deleted.schedules[0].point_code == "1F-G001"
    assert deleted.schedules[-1].retired_at == old_time and not deleted.schedules[-1].active


def test_non_general_code_collision_blocks_every_rename(application):
    general = point("1F-G050")
    point("1F-G001", category="safety", active=False, deleted=True)
    db.session.commit()
    preview = numbering.preview_general_numbering(NOW)
    assert [b["reason"] for b in preview["blockers"]] == ["code_conflict"]
    with pytest.raises(numbering.GeneralNumberingError, match="已被其他點位"):
        numbering.apply_general_numbering(NOW, None, preview)
    assert general.code == "1F-G050" and len(general.schedules) == 1
    assert db.session.query(AuditLog).count() == 0


@pytest.mark.parametrize("future", ["pending", "snapshot", "start"])
def test_future_settings_fail_closed_before_codes_or_snapshots_change(application, future):
    item = point("1F-G050")
    if future == "pending":
        item.pending_frequency = "weekly"
        item.frequency_effective_date = DAY + timedelta(days=1)
    elif future == "snapshot":
        item.schedules.append(PointSchedule(effective_date=DAY + timedelta(days=1), frequency="weekly",
            category="general", workflow_mode="spot", active=True, point_code=item.code))
    else:
        item.schedule_start = DAY + timedelta(days=1)
    db.session.commit()
    count = len(item.schedules)
    preview = numbering.preview_general_numbering(NOW)
    assert preview["blockers"][0]["reason"] == "future_schedule"
    with pytest.raises(numbering.GeneralNumberingError, match="預約"):
        numbering.apply_general_numbering(NOW, None)
    assert item.code == "1F-G050" and len(item.schedules) == count
    assert db.session.query(AuditLog).count() == 0


@pytest.mark.parametrize("stale", ["next_day", "same_day_name", "outside_point_code", "snapshot"])
def test_stale_confirmation_covers_taipei_day_and_all_point_state(application, stale):
    item = point("1F-G050")
    outside = point("1F-S001", category="safety")
    db.session.commit()
    preview = numbering.preview_general_numbering(datetime(2026, 11, 10, 15, 59, tzinfo=timezone.utc))
    now = datetime(2026, 11, 10, 15, 59, 30, tzinfo=timezone.utc)
    if stale == "next_day":
        now = datetime(2026, 11, 10, 16, tzinfo=timezone.utc)
    elif stale == "same_day_name":
        item.name = "Changed by another administrator"
    elif stale == "outside_point_code":
        outside.code = "1F-S002"
    else:
        item.schedules[0].point_name = "Changed historical label"
    db.session.commit()
    with pytest.raises(numbering.GeneralNumberingError, match="資料或日期已變更"):
        numbering.apply_general_numbering(now, None, preview["state_digest"])
    assert item.code == "1F-G050" and db.session.query(AuditLog).count() == 0


def test_more_than_99_active_g_points_never_overlap_inactive_range(application):
    for index in range(100):
        point(f"1F-G{index + 200:03d}", schedule=False)
    db.session.commit()
    preview = numbering.preview_general_numbering(NOW)
    assert any(b["reason"] == "active_capacity" for b in preview["blockers"])
    with pytest.raises(numbering.GeneralNumberingError, match="超過 99"):
        numbering.apply_general_numbering(NOW, None)
    assert db.session.query(PointSchedule).count() == db.session.query(AuditLog).count() == 0


def test_service_never_commits_caller_changes_and_rollback_restores_everything(application):
    item = point("1F-G015", schedule=False)
    db.session.commit()
    item.name = "Edited in caller transaction"
    numbering.apply_general_numbering(NOW, None)
    assert item.code == "1F-G001" and len(item.schedules) == 2 and numbering.numbering_enabled()
    db.session.rollback()
    assert item.code == "1F-G015" and item.name == "Point 1F-G015"
    assert item.schedules == [] and not numbering.numbering_enabled()


def test_initial_noop_enables_once_and_later_noops_add_no_history(application):
    item = point("1F-G001")
    db.session.commit()
    assert apply()["changed"] == 0
    assert numbering.numbering_enabled() and db.session.query(AuditLog).count() == 1
    assert apply()["changed"] == 0
    assert len(item.schedules) == 1 and db.session.query(AuditLog).count() == 1
    new = point("1F-G002")
    assert apply()["changed"] == 0
    marker = db.session.scalar(select(AuditLog).order_by(AuditLog.id.desc()))
    assert json.loads(marker.detail)["origin_order"][str(new.id)] == 2
    assert db.session.query(AuditLog).count() == 2


@pytest.mark.parametrize("detail", ["not json", "{}", '{"origin_order":{"1":true}}'])
def test_corrupt_persisted_order_never_silently_restarts_numbering(application, detail):
    item = point("1F-G055")
    db.session.add(AuditLog(action=numbering.NUMBERING_ACTION, detail=detail))
    db.session.commit()
    with pytest.raises(numbering.GeneralNumberingError, match="排序紀錄"):
        numbering.apply_general_numbering(NOW, None)
    assert item.code == "1F-G055" and len(item.schedules) == 1


def test_rename_keeps_prior_day_missed_label_and_workflow_cutoff(application):
    item = point("1F-G099", mode="two_stage")
    changed = datetime(2026, 11, 1, 1)
    item.schedules[0].workflow_changed_at = changed
    db.session.commit()
    apply()
    result = calculate_missed([item], [], date(2026, 11, 9), DAY,
                              datetime(2026, 11, 11, 2, tzinfo=timezone.utc))
    assert {(row["due_date"], row["code"]) for row in result} == {
        (date(2026, 11, 9), "1F-G099"), (DAY, "1F-G001")}
    assert all(s.workflow_changed_at == changed for s in item.schedules)


def test_pending_execution_can_be_reviewed_after_numbering_with_same_qr(application, monkeypatch):
    import app as patrol
    monkeypatch.setattr(patrol, "now_utc", lambda: NOW)
    executor, inspector, _, _, url, _, _ = team(application)
    item = db.session.scalar(select(Point).where(Point.qr_token == url[3:]))
    item.frequency = item.schedules[0].frequency = "weekly"
    db.session.commit()
    response = executor.post(url + "/confirm", data=payload(executor, url))
    assert response.status_code == 302
    first = db.session.scalar(select(PatrolExecution))
    assert first and first.point_code == "1F-G00"
    token = item.qr_token
    apply()
    assert item.code == "1F-G001" and item.qr_token == token
    assert execution_in_slot(item, first.period_key, first.slot).id == first.id
    response = inspector.post(url + "/confirm", data=payload(inspector, url))
    assert response.status_code == 302
    final = db.session.scalar(select(Inspection))
    assert final and final.execution_id == first.id and final.point_code == item.code
    assert first.point_code == "1F-G00" and first.point_id == item.id


def test_floor_transfer_uses_current_floor_with_stable_numeric_origin(application):
    item = point("B2-G004", -2)
    second = point("1F-G009")
    db.session.commit()
    apply()
    item.floor = 2
    apply()
    assert second.code == "1F-G001" and item.code == "2F-G002"
    assert item.schedules[0].floor == -2 and item.schedules[-1].floor == 2


def test_postgres_swap_rollback_and_persistent_point_id_order(postgres_app):
    with postgres_app.app_context():
        first = point("B2-G002", -2)
        second = point("1F-G001")
        third = point("1F-G002")
        db.session.commit()
        ids = [first.id, second.id, third.id]
        original = [first.code, second.code, third.code]
        numbering.apply_general_numbering(NOW, None)
        assert [first.code, second.code, third.code] == ["B2-G001", "1F-G002", "1F-G003"]
        db.session.rollback()
        assert [first.code, second.code, third.code] == original
        assert not numbering.numbering_enabled()
        apply()
        second.active = False
        apply()
        assert [first.code, second.code, third.code] == ["B2-G001", "1F-G100", "1F-G002"]
        db.session.remove()
        # Reopen a completely new session: the retained original number, not
        # current G100, determines where a reenabled point belongs.
        first, second, third = [db.session.get(Point, identifier) for identifier in ids]
        second.active = True
        apply()
        assert [first.code, second.code, third.code] == ["B2-G001", "1F-G002", "1F-G003"]
        marker = db.session.scalar(select(AuditLog).where(AuditLog.action == numbering.NUMBERING_ACTION)
                                   .order_by(AuditLog.id.desc()))
        assert json.loads(marker.detail)["origin_order"] == {str(ids[0]): 2, str(ids[1]): 1, str(ids[2]): 2}


def test_postgres_concurrent_edits_wait_for_shared_lock_and_renumber_current_state(postgres_app):
    with postgres_app.app_context():
        items = [point(f"1F-G{number:03d}") for number in (2, 11, 16)]
        db.session.commit()
        apply()
        ids = [p.id for p in items]
    holding, waiting, acquired, release = Event(), Event(), Event(), Event()

    def first_edit():
        with postgres_app.app_context():
            numbering.lock_general_numbering()
            item = db.session.scalar(select(Point).where(Point.id == ids[0]).with_for_update())
            item.active = False
            holding.set()
            if not release.wait(10):
                raise AssertionError("The test did not release the first transaction")
            numbering.apply_general_numbering(NOW, None)
            db.session.commit()

    def second_edit():
        with postgres_app.app_context():
            # Prime a stale identity map before the first edit commits. Apply
            # must reload other points after acquiring the shared lock.
            db.session.scalars(select(Point).order_by(Point.id)).all()
            waiting.set()
            numbering.lock_general_numbering()
            acquired.set()
            item = db.session.scalar(select(Point).where(Point.id == ids[2]).with_for_update())
            item.active = False
            numbering.apply_general_numbering(NOW, None)
            db.session.commit()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(first_edit)
        assert holding.wait(10)
        second = pool.submit(second_edit)
        try:
            assert waiting.wait(10)
            assert not acquired.wait(0.2), "A second transaction bypassed the numbering lock"
        finally:
            release.set()
        first.result(timeout=20)
        second.result(timeout=20)
    with postgres_app.app_context():
        items = [db.session.get(Point, identifier) for identifier in ids]
        assert [(p.code, p.active) for p in items] == [
            ("1F-G100", False), ("1F-G001", True), ("1F-G101", False)]
        assert db.session.query(AuditLog).filter_by(action=numbering.NUMBERING_ACTION).count() == 3
