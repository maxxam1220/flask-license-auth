"""Marked-sheet updates are atomic, bounded, identity-preserving and replay-safe."""
from datetime import date, datetime, timezone
import json
import re

import pytest
from sqlalchemy import select

import app as patrol
from general_numbering import NUMBERING_ACTION
from models import AuditLog, DeviceBinding, Inspection, PatrolExecution, Point, PointSchedule, User, db
import point_calendar_revision as revision
from test_catalog import catalogue_app


NOW = datetime(2026, 11, 13, 2, tzinfo=timezone.utc)


@pytest.fixture
def calendar_points(catalogue_app):
    for pid, (code, name, floor, frequency, mode, *_rest) in revision.POINT_CHANGES.items():
        db.session.add(Point(id=pid, code=code, name=name, floor=floor, category="general", inspection_team="general",
            frequency=frequency, workflow_mode=mode, active=True, qr_token=f"preserved-{pid}",
            schedule_start=date(2026, 11, 4), created_at=datetime(2026, 11, 4)))
    for pid, (code, floor) in revision.EXISTING_LOBBIES.items():
        db.session.add(Point(id=pid, code=code, name=revision.LOBBY_NAME, floor=floor, category="general",
            frequency="daily", workflow_mode="two_stage", active=True, qr_token=f"preserved-{pid}",
            schedule_start=date(2026, 11, 4), created_at=datetime(2026, 11, 4)))
    db.session.add(Point(id=44, code="B2-G001", name="停車場", floor=-2, category="general", frequency="daily",
        workflow_mode="two_stage", active=True, qr_token="preserved-44", schedule_start=date(2026, 11, 4)))
    db.session.add(Point(id=45, code="B2-G101", name="1.2客梯廁所", floor=-2, category="general", frequency="daily",
        workflow_mode="two_stage", active=False, qr_token="preserved-45", schedule_start=date(2026, 11, 4)))
    db.session.add(Point(id=1, code="B2-S001", name="1.2客梯梯廳", floor=-2, category="safety", frequency="daily",
        workflow_mode="standard", active=True, qr_token="preserved-safety", schedule_start=date(2026, 11, 4)))
    for p in db.session.scalars(select(Point)).all():
        p.schedules.append(PointSchedule(effective_date=p.schedule_start, frequency=p.frequency,
            category=p.category, workflow_mode=p.workflow_mode, active=p.active,
            floor=p.floor, point_code=p.code, point_name=p.name))
    for uid, role in [(1, "admin"), (2, "executor"), (3, "inspector")]:
        db.session.add(User(id=uid, username=f"u{uid}", display_name=f"User {uid}", role=role,
            patrol_category="general" if role != "admin" else None, password_hash="fixture", active=True))
        db.session.add(DeviceBinding(id=uid, user_id=uid, token_hash=str(uid)*64, status="approved"))
    db.session.flush()
    origins = {str(p.id): int(p.code.split("-G")[1]) for p in db.session.scalars(select(Point)) if "-G" in p.code}
    db.session.add(AuditLog(action=NUMBERING_ACTION, detail=json.dumps({"origin_order": origins})))
    db.session.commit()


def preview():
    return revision.revise_calendar_points(instant=NOW)


def apply(plan=None):
    return revision.revise_calendar_points(apply=True, instant=NOW, actor_id=1,
        expected_plan=revision.calendar_revision_digest(plan or preview()))


def old_schedules():
    return {s.id: tuple(getattr(s, c.name) for c in PointSchedule.__table__.columns)
            for s in db.session.scalars(select(PointSchedule))}


def add_execution(point_id=68, *, old=False):
    point = db.session.get(Point, point_id)
    row = PatrolExecution(point_id=point_id, user_id=2, binding_id=2, frequency="weekly",
        period_key="2026-11-02" if old else "2026-11-09", slot="any", category="general",
        point_code=point.code, point_name=point.name, point_floor=point.floor, user_name="User 2",
        created_at=datetime(2026, 11, 3 if old else 10, 2))
    db.session.add(row)
    db.session.commit()
    return row


def test_preview_apply_and_replay_preserve_history_ids_qr_and_safety(calendar_points):
    schedules = old_schedules()
    before = {p.id: (p.name, p.floor, p.category, p.inspection_team, p.qr_token, p.active)
              for p in db.session.scalars(select(Point))}
    plan = preview()
    assert (plan["changed"], plan["created"], plan["unchanged_lobbies"]) == (15, 5, 3)
    assert plan["effective_date"] == "2026-11-16" and plan["new_points_effective_date"] == "2026-11-13"
    assert not plan["blockers"]
    assert db.session.query(Point).count() == len(before)
    assert old_schedules() == schedules
    result = apply(plan)
    assert len(result["new_points"]) == 5
    assert db.session.query(Point).count() == len(before) + 5
    for pid, state in before.items():
        p = db.session.get(Point, pid)
        assert (p.name, p.floor, p.category, p.inspection_team, p.qr_token, p.active) == state
        if pid in revision.POINT_CHANGES:
            assert (p.frequency, p.workflow_mode) == revision.POINT_CHANGES[pid][3:5]
            assert p.pending_frequency == revision.POINT_CHANGES[pid][5]
            assert p.frequency_effective_date == date(2026, 11, 16)
            future = p.schedules[-1]
            assert (future.frequency, future.workflow_mode) == revision.POINT_CHANGES[pid][5:7]
            assert (future.point_code, future.point_name, future.floor) == (p.code, p.name, p.floor)
            assert future.workflow_changed_at == datetime(2026, 11, 15, 16)
            audited = next(c for c in result["changes"] if c["point_id"] == pid)
            assert audited["activation_identity"] == dict(code=p.code, name=p.name, floor=p.floor,
                category="general", inspection_team="general", active=True)
    assert db.session.get(Point, 1).code == "B2-S001"
    assert not db.session.get(Point, 45).active and db.session.get(Point, 45).name == "1.2客梯廁所"
    assert {k: v for k, v in old_schedules().items() if k in schedules} == schedules
    for row in result["new_points"]:
        point = db.session.get(Point, row["point_id"])
        assert point.category == point.inspection_team == "general"
        assert (point.name, point.frequency, point.workflow_mode, point.schedule_start) == (
            revision.LOBBY_NAME, "daily", "two_stage", date(2026, 11, 13))
        assert point.created_at == NOW.replace(tzinfo=None) and point.qr_token
        assert point.id in result["reprint_ids"] and "G9" not in point.code
    changed = db.session.get(Point, 47)
    changed.name = "後續調整"
    db.session.commit()
    assert apply()["already_applied"]
    assert changed.name == "後續調整" and db.session.query(Point).count() == len(before) + 5
    assert db.session.query(AuditLog).filter_by(action=revision.REVISION_ACTION).count() == 1


@pytest.mark.parametrize("field,value", [("name", "別處"), ("code", "AB2-M03"), ("floor", -1),
    ("frequency", "daily"), ("workflow_mode", "two_stage"), ("active", False),
    ("inspection_team", "engineering"), ("deleted_at", datetime(2026, 11, 12))])
def test_changed_identity_refuses_entire_import(calendar_points, field, value):
    setattr(db.session.get(Point, 47), field, value)
    db.session.commit()
    count = db.session.query(PointSchedule).count()
    with pytest.raises(ValueError, match="不一致"):
        preview()
    assert db.session.query(PointSchedule).count() == count
    assert not db.session.query(AuditLog).filter_by(action=revision.REVISION_ACTION).count()


def test_current_week_pending_execution_remains_reviewable_until_cutover(calendar_points):
    first = add_execution()
    before_execution = tuple(getattr(first, c.name) for c in PatrolExecution.__table__.columns)
    plan = preview()
    assert not plan["blockers"]
    apply(plan)
    assert tuple(getattr(first, c.name) for c in PatrolExecution.__table__.columns) == before_execution
    assert db.session.get(Point, first.point_id).frequency == "weekly"
    record = Inspection(point_id=first.point_id, user_id=3, binding_id=3, execution_id=first.id,
        frequency=first.frequency, period_key=first.period_key, slot=first.slot, category="general",
        workflow_mode="two_stage", personal_day=date(2026, 11, 13), created_at=datetime(2026, 11, 13, 1),
        point_code=first.point_code, point_name=first.point_name, point_floor=first.point_floor, user_name="User 3")
    db.session.add(record)
    db.session.commit()
    before = tuple(getattr(record, c.name) for c in Inspection.__table__.columns)
    assert not preview()["blockers"]
    apply()
    assert tuple(getattr(record, c.name) for c in Inspection.__table__.columns) == before


@pytest.mark.parametrize("period_key", ["2026-11-16", "unknown"])
def test_pending_execution_after_cutover_or_unknown_period_blocks_all(calendar_points, period_key):
    first = add_execution()
    first.period_key = period_key
    db.session.commit()
    plan = preview()
    assert any(row["reason"] == "pending_execution" for row in plan["blockers"])
    schedules = old_schedules()
    with pytest.raises(ValueError, match="未套用任何修改"):
        apply(plan)
    assert old_schedules() == schedules and db.session.get(Point, 47).pending_frequency is None


def test_expired_execution_and_non_target_pending_execution_do_not_block(calendar_points):
    add_execution(old=True)
    add_execution(point_id=44)
    assert not preview()["blockers"]
    apply()
    assert db.session.query(PatrolExecution).count() == 2


def test_stale_hash_missing_hash_and_unknown_actor_refuse(calendar_points):
    plan = preview()
    db.session.get(Point, 1).name = "他人修改職安"
    db.session.commit()
    with pytest.raises(ValueError, match="預覽資料"):
        apply(plan)
    for actor, expected in [(1, None), (1, "0" * 64), (2, revision.calendar_revision_digest(preview()))]:
        with pytest.raises(ValueError):
            revision.revise_calendar_points(apply=True, instant=NOW, actor_id=actor, expected_plan=expected)
    assert db.session.get(Point, 47).frequency == "three_day"


def test_duplicate_lobby_and_existing_lobby_difference_refuse(calendar_points):
    db.session.add(Point(code="B1-X001", name=revision.LOBBY_NAME, floor=-1, frequency="daily",
                         workflow_mode="two_stage", category="general", active=False))
    db.session.commit()
    with pytest.raises(ValueError, match="同名梯廳"):
        preview()


def test_numbering_or_commit_failure_rolls_back_all(calendar_points, monkeypatch):
    before = old_schedules()
    point_count = db.session.query(Point).count()
    real_apply = revision.apply_general_numbering
    def fail_numbering(*args, **kwargs):
        real_apply(*args, **kwargs)
        raise RuntimeError("Injected failure")
    monkeypatch.setattr(revision, "apply_general_numbering", fail_numbering)
    with pytest.raises(RuntimeError, match="Injected"):
        apply()
    assert db.session.query(Point).count() == point_count and old_schedules() == before
    assert db.session.get(Point, 47).frequency == "three_day"
    assert not db.session.query(AuditLog).filter_by(action=revision.REVISION_ACTION).count()


def test_future_pending_change_blocks(calendar_points):
    p = db.session.get(Point, 47)
    p.pending_frequency, p.frequency_effective_date = "daily", date(2026, 12, 1)
    db.session.commit()
    plan = preview()
    assert any(b["reason"] == "future_schedule" and b["point_id"] == 47 for b in plan["blockers"])
    with pytest.raises(ValueError, match="待處理"):
        apply(plan)


def test_current_pending_execution_at_unchanged_lobby_is_preserved(calendar_points):
    point = db.session.get(Point, 79)
    pending = PatrolExecution(point_id=point.id, user_id=2, binding_id=2, frequency="daily",
        period_key="2026-11-13", slot="any", category="general", point_code=point.code,
        point_name=point.name, point_floor=point.floor, user_name="User 2",
        created_at=NOW.replace(tzinfo=None))
    db.session.add(pending)
    db.session.commit()
    before = tuple(getattr(pending, c.name) for c in PatrolExecution.__table__.columns)
    assert not preview()["blockers"]
    apply()
    assert tuple(getattr(pending, c.name) for c in PatrolExecution.__table__.columns) == before


def test_admin_route_requires_login_role_csrf_preview_and_retains_safe_replay(calendar_points, catalogue_app, monkeypatch):
    monkeypatch.setattr(patrol, "now_utc", lambda: NOW)
    url = "/admin/points/calendar-revision"
    client = catalogue_app.test_client()
    assert client.get(url).status_code == 302
    with client.session_transaction() as signed:
        signed.update(user_id=3, auth_version=1, sid="fixture-inspector", csrf_token="fixture-csrf")
    assert client.get(url).status_code == 403
    assert client.post(url, data={"csrf_token": "fixture-csrf"}).status_code == 403
    with client.session_transaction() as signed:
        signed.update(user_id=1, auth_version=1, sid="fixture-admin", csrf_token="fixture-csrf")
    page = client.get(url)
    assert page.status_code == 200 and "每週三" in page.text
    expected = re.search(r'name="expected_plan" value="([a-f0-9]{64})"', page.text)[1]
    assert client.post(url, data={"expected_plan": expected}).status_code == 400
    assert client.post(url, data={"csrf_token": "fixture-csrf", "expected_plan": "invalid"}).status_code == 409
    result = client.post(url, data={"csrf_token": "fixture-csrf", "expected_plan": expected})
    assert result.status_code == 200 and "調整已完成" in result.text
    assert client.post(url, data={"csrf_token": "fixture-csrf", "expected_plan": expected}).status_code == 200
    assert db.session.query(AuditLog).filter_by(action=revision.REVISION_ACTION).count() == 1


def test_preprinted_qr_uses_approved_new_frequency_and_workflow_before_cutover(calendar_points, catalogue_app, monkeypatch):
    monkeypatch.setattr(patrol, "now_utc", lambda: NOW)
    apply()
    client = catalogue_app.test_client()
    with client.session_transaction() as signed:
        signed.update(user_id=1, auth_version=1, sid="fixture-print", csrf_token="fixture-csrf")
    page = client.get("/admin/points/print?ids=54,47,68")
    assert page.status_code == 200, page.text
    labels = re.findall(r'<article class="qr-label[^>]*>(.*?)</article>', page.text, re.S)
    assert len(labels) == 3
    lobby = next(label for label in labels if "1.2客梯梯廳" in label)
    toilet = next(label for label in labels if "b2男廁所-甲" in label)
    meeting = next(label for label in labels if "201會議室" in label)
    assert "兩階段 · 每日一次" in lobby
    assert "單段 · 每週三" in toilet
    assert "兩階段 · 每週五" in meeting
    for label in labels:
        assert "每3日一次" not in label and "每週一次" not in label
        assert "2026-11-16" not in label and "起：" not in label
        assert "SCAN → OK 確認打卡" in label
    point = db.session.get(Point, 54)
    assert (point.frequency, point.workflow_mode) == ("three_day", "spot")
    assert (point.pending_frequency, point.frequency_effective_date) == ("daily", date(2026, 11, 16))


def test_entire_batch_activates_at_next_period_once_and_keeps_original_evidence(calendar_points):
    from point_assignment_revision import activate_due_point_frequencies
    pending = add_execution(point_id=71)
    before = tuple(getattr(pending, c.name) for c in PatrolExecution.__table__.columns)
    for point_id in (47, 54, 55, 59):
        point = db.session.get(Point, point_id)
        db.session.add(Inspection(point_id=point_id, user_id=3, binding_id=3,
            frequency="three_day", period_key="2026-11-13", slot="any", category="general",
            workflow_mode="spot", personal_day=date(2026, 11, 13), created_at=NOW.replace(tzinfo=None),
            spot_request_id=f"preserved-spot-receipt-{point_id}",
            point_code=point.code, point_name=point.name, point_floor=point.floor, user_name="User 3"))
    db.session.commit()
    receipts = {r.id: tuple(getattr(r, c.name) for c in Inspection.__table__.columns)
                for r in db.session.scalars(select(Inspection))}
    apply()
    snapshots = old_schedules()
    assert activate_due_point_frequencies(datetime(2026, 11, 15, 15, 59, 59, tzinfo=timezone.utc))["activated"] == 0
    result = activate_due_point_frequencies(datetime(2026, 11, 15, 16, tzinfo=timezone.utc))
    assert result["activated"] == 15
    for pid, spec in revision.POINT_CHANGES.items():
        point = db.session.get(Point, pid)
        assert (point.frequency, point.workflow_mode) == spec[5:7]
        assert point.pending_frequency is None and point.frequency_effective_date is None
        assert point.qr_token == f"preserved-{pid}"
    assert old_schedules() == snapshots
    assert {r.id: tuple(getattr(r, c.name) for c in Inspection.__table__.columns)
            for r in db.session.scalars(select(Inspection))} == receipts
    assert tuple(getattr(pending, c.name) for c in PatrolExecution.__table__.columns) == before
    assert activate_due_point_frequencies(datetime(2026, 11, 16, tzinfo=timezone.utc))["activated"] == 0
