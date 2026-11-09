"""The authorized revision preserves IDs, tokens, original workflows and history."""
from datetime import date, datetime, timezone

import pytest
from sqlalchemy import select

from models import AuditLog, DeviceBinding, Inspection, PatrolExecution, Point, PointSchedule, User, db
import point_assignment_revision as revision
from test_catalog import catalogue_app


NOW = datetime(2026, 11, 9, 2, tzinfo=timezone.utc)


@pytest.fixture
def assignment_points(catalogue_app):
    points = {}
    for code, (name, floor, old_frequency, mode, _) in revision.ENGINEERING_POINTS.items():
        points[code] = Point(code=code, name=name, floor=floor, category="general", frequency=old_frequency,
            workflow_mode=mode, qr_token="unchanged-" + code, schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
    for i in range(4):
        points[f"QA-G{i}"] = Point(code=f"QA-G{i}", name=f"Other general point {i}", floor=1,
            category="general", frequency="daily2", workflow_mode="two_stage" if i < 2 else "spot",
            qr_token=f"unchanged-QA-G{i}", schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
    points["SAFETY"] = Point(code="SAFETY", name="Safety stays twice", floor=1, category="safety", frequency="daily2",
        workflow_mode="standard", qr_token="unchanged-safety", schedule_start=date(2026, 1, 1))
    for p in points.values():
        p.schedules.append(PointSchedule(effective_date=date(2026, 1, 1), frequency=p.frequency,
            category=p.category, workflow_mode=p.workflow_mode, active=True, floor=p.floor,
            point_code=p.code, point_name=p.name))
        db.session.add(p)
    for role, identifier in (("executor", 1), ("inspector", 2)):
        db.session.add(User(id=identifier, username=role, display_name=role, password_hash="fixture", role=role,
            patrol_category="general", active=True, must_change_password=False))
        db.session.add(DeviceBinding(id=identifier, user_id=identifier, token_hash=str(identifier)*64, status="approved"))
    db.session.commit()
    return {code: point.id for code, point in points.items()}


def add_record(points, code, *, execution=False, instant=datetime(2026, 11, 9, 1), frequency=None):
    p = db.session.get(Point, points[code])
    frequency = frequency or p.frequency
    common = dict(point_id=p.id, frequency=frequency, period_key=instant.date().isoformat(), slot="am" if frequency=="daily2" else "any",
        category="general", point_code=p.code, point_name=p.name, point_floor=p.floor,
        created_at=instant, user_name="original")
    row = PatrolExecution(**common, user_id=1, binding_id=1) if execution else Inspection(**common,
        user_id=2, binding_id=2, workflow_mode="spot", personal_day=instant.date(), note="Original note",
        spot_request_id="original-test-record-"+code)
    db.session.add(row); db.session.commit()
    return row.id


def test_preview_then_apply_keeps_history_and_tokens_and_is_replay_safe(assignment_points):
    add_record(assignment_points, "QA-G2", instant=datetime(2026, 11, 8, 1))
    initial = {p.id: (p.qr_token, p.frequency, p.workflow_mode, len(p.schedules)) for p in db.session.scalars(select(Point))}
    preview = revision.revise_point_assignments(instant=NOW, effective_date=date(2026, 11, 9))
    assert (preview["changed"], preview["team_changed"], preview["frequency_changed"]) == (15, 11, 10)
    assert not preview["blockers"] and not preview["already_applied"]
    assert db.session.query(AuditLog).count() == 0
    assert all(p.inspection_team == "general" for p in db.session.scalars(select(Point)))
    result = revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))
    assert result == preview
    for p in db.session.scalars(select(Point)):
        token, old_frequency, mode, count = initial[p.id]
        assert p.qr_token == token and p.workflow_mode == mode
        assert p.schedules[0].frequency == old_frequency
        assert len(p.schedules) == count + (p.code != "SAFETY")
        if p.code in revision.ENGINEERING_POINTS:
            assert p.inspection_team == "engineering"
            assert p.frequency == revision.ENGINEERING_POINTS[p.code][4]
        elif p.code.startswith("QA-G"):
            assert p.frequency == "daily" and p.inspection_team == "general"
        else:
            assert p.frequency == "daily2" and p.inspection_team == "general"
    original = db.session.scalar(select(Inspection))
    assert original.note == "Original note" and original.frequency == "daily2"
    assert original.period_key == "2026-11-08"  # Immutable historical snapshot, not recomputed.
    moved = db.session.get(Point, assignment_points["5F-G067"])
    moved.frequency = "monthly"
    db.session.commit()
    assert revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))["already_applied"]
    assert db.session.get(Point, moved.id).frequency == "monthly"
    assert db.session.query(AuditLog).filter_by(action=revision.REVISION_ACTION).count() == 1


@pytest.mark.parametrize("execution", [False, True])
def test_started_today_blocks_the_whole_revision_without_partial_assignment(assignment_points, execution):
    add_record(assignment_points, "QA-G0", execution=execution)
    preview = revision.revise_point_assignments(instant=NOW, effective_date=date(2026, 11, 9))
    assert any(b["code"] == "QA-G0" and b["reason"] == "today_started" for b in preview["blockers"])
    with pytest.raises(ValueError, match="未套用任何修改"):
        revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))
    assert all(p.inspection_team == "general" for p in db.session.scalars(select(Point)))
    assert db.session.query(AuditLog).count() == 0
    assert db.session.query(PointSchedule).count() == 16


def test_pending_prior_day_execution_blocks_frequency_change(assignment_points):
    p = db.session.get(Point, assignment_points["QA-G0"])
    row = PatrolExecution(point_id=p.id, user_id=1, binding_id=1, created_at=datetime(2026, 11, 8, 1),
        frequency="monthly", period_key="2026-11-01", slot="any", category="general", point_code=p.code,
        point_name=p.name, point_floor=p.floor, user_name="executor")
    db.session.add(row);db.session.commit()
    preview = revision.revise_point_assignments(instant=NOW, effective_date=date(2026, 11, 9))
    assert any(b["reason"] == "pending_execution" for b in preview["blockers"])
    with pytest.raises(ValueError):revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))


def test_team_transfer_keeps_pending_execution_available_for_new_team(assignment_points):
    execution_id = add_record(assignment_points, "5F-G066", execution=True)
    assert not revision.revise_point_assignments(instant=NOW, effective_date=date(2026, 11, 9))["blockers"]
    revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))
    p = db.session.get(Point, assignment_points["5F-G066"])
    assert (p.inspection_team, p.workflow_mode, p.frequency) == ("engineering", "two_stage", "daily")
    assert db.session.get(PatrolExecution, execution_id).point_id == p.id


@pytest.mark.parametrize("change", ["missing", "name", "floor", "mode", "category", "frequency", "deleted"])
def test_conflicting_identity_is_rejected_before_any_write(assignment_points, change):
    p = db.session.get(Point, assignment_points["B2-G003"])
    if change == "missing":p.code="different-code"
    elif change == "name":p.name="Different room"
    elif change == "floor":p.floor=1
    elif change == "mode":p.workflow_mode="two_stage"
    elif change == "category":p.category="safety";p.workflow_mode="standard"
    elif change == "frequency":p.frequency="daily"
    else:p.deleted_at=datetime(2026, 11, 8)
    db.session.commit()
    with pytest.raises(ValueError):revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))
    assert db.session.query(AuditLog).count() == 0
    assert all(p.inspection_team == "general" for p in db.session.scalars(select(Point)))


def test_revision_failure_rolls_back_after_flush(assignment_points, monkeypatch):
    def failed_commit():
        db.session.flush()
        raise RuntimeError("Injected revision failure")
    monkeypatch.setattr(db.session, "commit", failed_commit)
    with pytest.raises(RuntimeError, match="Injected revision"):
        revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))
    assert all(p.inspection_team == "general" for p in db.session.scalars(select(Point)))
    assert db.session.query(AuditLog).count() == 0
    assert db.session.query(PointSchedule).count() == 16


def test_missing_initial_schedule_is_preserved_before_revision(assignment_points):
    p = db.session.get(Point, assignment_points["5F-G067"])
    db.session.query(PointSchedule).filter_by(point_id=p.id).delete()
    db.session.commit()
    revision.revise_point_assignments(apply=True, instant=NOW, effective_date=date(2026, 11, 9))
    db.session.expire_all()
    p = db.session.get(Point, p.id)
    assert [(s.effective_date, s.frequency) for s in p.schedules] == [
        (date(2026, 1, 1), "daily"), (date(2026, 11, 9), "weekly")]


def test_tomorrow_schedule_allows_todays_execution_and_activates_at_taipei_midnight(assignment_points):
    first_id = add_record(assignment_points, "QA-G0", execution=True)
    tomorrow = date(2026, 11, 10)
    preview = revision.revise_point_assignments(instant=NOW, effective_date=tomorrow)
    assert not preview["blockers"] and preview["effective_date"] == "2026-11-10"
    assert preview["changed"] == 15 and preview["frequency_changed"] == 10
    revision.revise_point_assignments(apply=True, instant=NOW, effective_date=tomorrow)
    for p in db.session.scalars(select(Point)):
        if p.code.startswith("QA-G") or p.code in {f"5F-G{i:03d}" for i in range(67, 73)}:
            assert p.frequency in ("daily", "daily2")
            assert p.frequency_effective_date == tomorrow and p.pending_frequency in ("daily", "weekly")
            assert p.schedules[-1].effective_date == tomorrow
            assert p.schedules[-1].workflow_changed_at == datetime(2026, 11, 9, 16)
        if p.code in revision.ENGINEERING_POINTS:
            assert p.inspection_team == "engineering"
    assert revision.activate_due_point_frequencies(datetime(2026, 11, 9, 15, 59, 59, tzinfo=timezone.utc))["activated"] == 0
    activated = revision.activate_due_point_frequencies(datetime(2026, 11, 9, 16, tzinfo=timezone.utc))
    assert activated["activated"] == 10
    assert db.session.get(Point, assignment_points["QA-G0"]).frequency == "daily"
    assert db.session.get(Point, assignment_points["5F-G067"]).frequency == "weekly"
    assert all(p.pending_frequency is None and p.frequency_effective_date is None for p in db.session.scalars(select(Point)))
    first = db.session.get(PatrolExecution, first_id)
    assert first.frequency == "daily2" and first.period_key == "2026-11-09"
    assert revision.activate_due_point_frequencies(datetime(2026, 11, 10, 0, tzinfo=timezone.utc))["activated"] == 0
    assert db.session.query(AuditLog).filter_by(action=revision.ACTIVATION_ACTION).count() == 1


def test_default_effective_date_is_tomorrow_and_rejects_past(assignment_points):
    assert revision.revise_point_assignments(instant=NOW)["effective_date"] == "2026-11-10"
    with pytest.raises(ValueError, match="過去排程"):
        revision.revise_point_assignments(apply=True, instant=NOW, effective_date="2026-11-08")


def test_existing_schedule_is_not_overwritten_by_revision(assignment_points):
    p = db.session.get(Point, assignment_points["QA-G0"])
    p.pending_frequency="weekly";p.frequency_effective_date=date(2026,11,12)
    db.session.commit()
    assert any(b["reason"] == "scheduled_change_exists" for b in revision.revise_point_assignments(instant=NOW)["blockers"])
    with pytest.raises(ValueError):revision.revise_point_assignments(apply=True, instant=NOW)
    assert db.session.query(AuditLog).count()==0
    assert db.session.get(Point,p.id).pending_frequency=="weekly"


def test_activation_refuses_changed_snapshot_and_rolls_back_whole_batch(assignment_points):
    revision.revise_point_assignments(apply=True, instant=NOW)
    p = db.session.get(Point, assignment_points["QA-G0"])
    p.name="Unexpected concurrent rename"
    db.session.commit()
    with pytest.raises(ValueError, match="預約頻率設定不一致"):
        revision.activate_due_point_frequencies(datetime(2026,11,9,16,tzinfo=timezone.utc))
    assert db.session.query(Point).filter(Point.pending_frequency.is_not(None)).count()==10
    assert db.session.query(AuditLog).filter_by(action=revision.ACTIVATION_ACTION).count()==0


def test_scheduled_history_keeps_old_due_days_before_cutover(assignment_points):
    from missed import calculate_missed
    revision.revise_point_assignments(apply=True, instant=NOW)
    p = db.session.get(Point, assignment_points["QA-G2"])
    due = calculate_missed([p], [], date(2026,11,9), date(2026,11,10), datetime(2026,11,11,1,tzinfo=timezone.utc))
    assert sorted((r["due_date"],r["frequency"]) for r in due) == [
        (date(2026,11,9),"daily2"),(date(2026,11,9),"daily2"),(date(2026,11,10),"daily")]


def test_deployment_replay_after_fixed_effective_date_remains_noop(assignment_points):
    revision.revise_point_assignments(apply=True, instant=NOW, effective_date="2026-11-10")
    result = revision.revise_point_assignments(apply=True,
        instant=datetime(2026,11,12,tzinfo=timezone.utc), effective_date="2026-11-10")
    assert result["already_applied"]
    assert db.session.query(AuditLog).filter_by(action=revision.REVISION_ACTION).count()==1


def test_confirmed_plan_digest_accepts_unchanged_preview(assignment_points):
    plan = revision.revise_point_assignments(instant=NOW, effective_date="2026-11-10")
    digest = revision.revision_plan_digest(plan)
    assert len(digest) == 64
    assert digest == revision.revision_plan_digest(dict(reversed(list(plan.items()))))
    result = revision.revise_point_assignments(apply=True, instant=NOW,
        effective_date="2026-11-10", expected_plan=digest)
    assert result == plan


def test_stale_confirmed_plan_does_not_partially_apply_after_concurrent_edit(assignment_points):
    plan = revision.revise_point_assignments(instant=NOW, effective_date="2026-11-10")
    point = db.session.get(Point, assignment_points["QA-G2"])
    point.name = "Changed after manager preview"
    db.session.commit()
    with pytest.raises(ValueError, match="頁面資料已變更"):
        revision.revise_point_assignments(apply=True, instant=NOW,
            effective_date="2026-11-10", expected_plan=revision.revision_plan_digest(plan))
    assert all(p.inspection_team == "general" and p.pending_frequency is None for p in db.session.scalars(select(Point)))
    assert db.session.query(AuditLog).count() == 0
    assert db.session.query(PointSchedule).count() == 16
    assert db.session.get(Point, point.id).name == "Changed after manager preview"


@pytest.mark.parametrize("digest", ["篡"*64, "", "f"*64, 42])
def test_invalid_plan_digest_fails_closed_without_server_error(assignment_points, digest):
    with pytest.raises(ValueError, match="頁面資料已變更"):
        revision.revise_point_assignments(apply=True, instant=NOW,
            effective_date="2026-11-10", expected_plan=digest)
    assert db.session.query(AuditLog).count() == 0
    assert all(p.inspection_team == "general" and p.pending_frequency is None for p in db.session.scalars(select(Point)))


def test_same_name_safety_points_and_history_never_follow_general_revision(assignment_points):
    from patrol_access import apply_point_scope, can_access_point, can_read_inspection, patrol_scope

    safety_user = User(id=3, username="safety-owner", display_name="Safety owner", password_hash="fixture",
        role="inspector", patrol_category="safety", active=True, must_change_password=False)
    engineering_user = User(id=4, username="engineering-owner", display_name="Engineering owner", password_hash="fixture",
        role="inspector", patrol_category="general", engineering_inspector_title=True,
        active=True, must_change_password=False)
    db.session.add_all([safety_user, engineering_user])
    safety_points = []
    for index, (_code, (name, floor, _frequency, _mode, _target)) in enumerate(revision.ENGINEERING_POINTS.items(), 1):
        # The same real room names may legitimately exist in separate departments.
        point = Point(code=f"SAFETY-S{index:03d}", name=name, floor=floor, category="safety",
            frequency="daily2", workflow_mode="standard", qr_token=f"safety-untouched-qr-{index}",
            schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
        point.schedules.append(PointSchedule(effective_date=date(2026, 1, 1), category="safety",
            frequency="daily", workflow_mode="standard", active=True, floor=floor, point_code=point.code, point_name=name))
        point.schedules.append(PointSchedule(effective_date=date(2026, 11, 8), category="safety",
            frequency="daily2", workflow_mode="standard", active=True, floor=floor, point_code=point.code, point_name=name))
        db.session.add(point)
        safety_points.append(point)
    db.session.flush()
    for point in safety_points:
        db.session.add(Inspection(user_id=3, point_id=point.id, created_at=datetime(2026, 11, 9, 1),
            frequency="daily2", period_key="2026-11-09", slot="am", category="safety", workflow_mode="standard",
            point_code=point.code, point_name=point.name, point_floor=point.floor, user_name="Safety owner",
            note="Safety historical note stays unchanged"))
    db.session.commit()

    def safety_snapshot():
        return {model.__tablename__: [tuple(row) for row in db.session.execute(
            select(*model.__table__.columns).where(model.category == "safety").order_by(model.id))]
            for model in (Point, PointSchedule, Inspection)}

    before = safety_snapshot()
    preview = revision.revise_point_assignments(instant=NOW, effective_date="2026-11-10")
    assert preview["changed"] == 15 and preview["frequency_changed"] == 10
    assert all(change["code"] not in {p.code for p in safety_points} for change in preview["changes"])
    revision.revise_point_assignments(apply=True, instant=NOW, effective_date="2026-11-10",
        expected_plan=revision.revision_plan_digest(preview))
    assert safety_snapshot() == before
    assert revision.activate_due_point_frequencies(datetime(2026, 11, 9, 16, tzinfo=timezone.utc))["activated"] == 10
    assert safety_snapshot() == before

    general_user = db.session.get(User, 2)
    for point in safety_points:
        assert point.frequency == "daily2" and point.category == "safety" and point.inspection_team == "general"
        assert can_access_point(safety_user, point)
        assert not can_access_point(general_user, point)
        assert not can_access_point(engineering_user, point)
    for record in db.session.scalars(select(Inspection).where(Inspection.category == "safety")):
        assert can_read_inspection(safety_user, record)
        assert not can_read_inspection(general_user, record)
        assert not can_read_inspection(engineering_user, record)
    for user in (general_user, engineering_user):
        visible = db.session.scalars(apply_point_scope(
            select(Point).where(Point.category == patrol_scope(user)), user)).all()
        assert not ({p.id for p in visible} & {p.id for p in safety_points})
