"""Weekday schema upgrades preserve evidence and schedule changes prospectively."""
from datetime import date, datetime, timezone
import json
import subprocess
import sys

import pytest
from sqlalchemy import CheckConstraint, MetaData, func, inspect, select
from sqlalchemy.exc import IntegrityError

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import AuditLog, Inspection, PatrolExecution, Point, PointSchedule, SchemaVersion, db
from point_assignment_revision import activate_due_point_frequencies
from safety_leave import SafetyLeaveExclusion
from test_catalog import catalogue_app
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store
from test_three_day_migration import v17, _execution, _visit, _signature


@pytest.fixture
def v18(engine, v17):
    """Use the legacy evidence fixture with exact v18 DDL and no leave table."""
    return legacy_calendar_schema(engine, 18, migrations.FREQUENCY_CHECKS_V18)


@pytest.fixture
def v19(engine, v17):
    return legacy_calendar_schema(engine, 19, migrations.FREQUENCY_CHECKS_V19)


def legacy_calendar_schema(engine, version, checks):
    with engine.connect() as connection:
        sqlite = connection.dialect.name == "sqlite"
        if sqlite:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        else:
            connection.begin()
        quote = connection.dialect.identifier_preparer.quote
        for table, name, _, _ in migrations._frequency_constraint_rules():
            expression = checks[name]
            if sqlite:
                migrations._sqlite_rebuild(connection, table, [],
                    new_constraints=[CheckConstraint(expression, name=name)], replace_checks={name})
            else:
                connection.exec_driver_sql(f"ALTER TABLE {quote(table)} DROP CONSTRAINT {quote(name)}")
                connection.exec_driver_sql(f"ALTER TABLE {quote(table)} ADD CONSTRAINT {quote(name)} CHECK ({expression})")
        if version == 18:
            SafetyLeaveExclusion.__table__.drop(connection)
        connection.execute(SchemaVersion.__table__.update().values(version=version))
        connection.commit()
        if sqlite:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()
        reflected = MetaData()
        reflected.reflect(connection)
    return reflected


def test_v18_upgrade_keeps_all_rows_indexes_qr_and_foreign_children(engine, v18):
    with engine.connect() as connection:
        before = snapshot(connection, v18)
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        after = snapshot(connection, v18)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert connection.scalar(select(func.count(SafetyLeaveExclusion.id))) == 0
        assert connection.scalar(select(Point.qr_token).where(Point.id == 2)) == "preserved-qr-2"
        if engine.dialect.name == "sqlite":
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    signature = _signature(engine)
    assert upgrade_schema(engine) == LATEST_VERSION
    assert signature == _signature(engine)
    assert {i["name"] for i in inspect(engine).get_indexes("patrol_points")} >= {"custom_preserved_point_name"}


@pytest.mark.parametrize("frequency", ["weekly_wed", "weekly_fri"])
def test_new_frequency_rejected_before_upgrade_and_accepted_after(engine, v18, frequency):
    statements = [
        Point.__table__.update().where(Point.id == 2).values(pending_frequency=frequency,
                                                           frequency_effective_date=date(2026, 11, 13)),
        PatrolExecution.__table__.insert().values(**_execution(frequency=frequency)),
        Inspection.__table__.insert().values(**_visit(frequency=frequency)),
    ]
    with engine.begin() as connection:
        for statement in statements:
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(statement)
    upgrade_schema(engine)
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(statement)


def test_authorized_original_executor_visit_can_retain_daily_frequency(engine, v18):
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.execute(Inspection.__table__.insert().values(**_visit(frequency="daily")))
        assert connection.scalar(select(Inspection.frequency).where(Inspection.id == 3)) == "daily"


@pytest.mark.parametrize("changes", [{"slot": "am"}, {"category": "safety"}, {"note": "not allowed"},
                                    {"is_abnormal": True}, {"workflow_mode": "two_stage"}, {"frequency": "bogus"}])
def test_frequency_expansion_keeps_executor_visit_constraints(engine, v18, changes):
    upgrade_schema(engine)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(Inspection.__table__.insert().values(**_visit(frequency="weekly_wed") | changes))


def test_leave_dates_cancellation_and_user_foreign_keys_are_enforced(engine, v18):
    upgrade_schema(engine)
    row = dict(date_from=date(2026, 11, 18), date_to=date(2026, 11, 18), note="",
               created_by=2, created_at=datetime(2026, 11, 13))
    invalid = [dict(date_to=date(2026, 11, 17)), dict(created_by=999), dict(cancelled_by=2),
               dict(cancelled_at=datetime(2026, 11, 14)), dict(date_from=None)]
    with engine.begin() as connection:
        for change in invalid:
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(SafetyLeaveExclusion.__table__.insert().values(**row | change))
        connection.execute(SafetyLeaveExclusion.__table__.insert().values(**row))
        connection.execute(SafetyLeaveExclusion.__table__.insert().values(**row | dict(
            cancelled_by=2, cancelled_at=datetime(2026, 11, 14))))


def test_failure_rolls_back_new_table_frequency_checks_and_data(engine, v18, monkeypatch):
    before_schema = _signature(engine)
    with engine.connect() as connection:
        before = snapshot(connection, v18)
    original = migrations._validate_current
    def fail(connection):
        original(connection)
        raise RuntimeError("Injected calendar validation failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="Injected calendar"):
        upgrade_schema(engine)
    assert before_schema == _signature(engine)
    with engine.connect() as connection:
        assert snapshot(connection, v18) == before
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 18


def test_existing_partial_leave_table_fails_closed_and_preserves_version(engine, v18):
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE patrol_safety_leave_exclusions (id INTEGER PRIMARY KEY)")
    before = _signature(engine)
    with pytest.raises(SchemaMigrationError, match="safety leave"):
        upgrade_schema(engine)
    assert before == _signature(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 18


def test_fresh_installation_imports_leave_model_without_importing_app(tmp_path):
    # A separate interpreter proves metadata does not depend on Flask route imports.
    result = subprocess.run([sys.executable, "-c", "from sqlalchemy import create_engine,inspect; "
        "from migrations import upgrade_schema,LATEST_VERSION; "
        "e=create_engine('sqlite://'); assert upgrade_schema(e)==LATEST_VERSION; "
        "assert inspect(e).has_table('patrol_safety_leave_exclusions')"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_known_partially_upgraded_v17_checks_are_accepted(engine, v18):
    with engine.begin() as connection:
        connection.execute(SchemaVersion.__table__.update().values(version=17))
    assert upgrade_schema(engine) == LATEST_VERSION


@pytest.mark.parametrize("frequency", ["weekly_mwf", "weekly_tts"])
def test_v19_upgrade_expands_all_three_checks(engine, v19, frequency):
    statements = (
        Point.__table__.update().where(Point.id == 2).values(pending_frequency=frequency,
            frequency_effective_date=date(2026, 11, 27)),
        PatrolExecution.__table__.insert().values(**_execution(frequency=frequency)),
        Inspection.__table__.insert().values(**_visit(frequency=frequency)),
    )
    with engine.begin() as connection:
        for statement in statements:
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(statement)
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(statement)


STAIR_CASES = ((56, "B2-G002", "甲梯", "weekly_tts"), (116, "B2-G003", "乙梯", "weekly_mwf"))


def seed_stairs(connection):
    for point_id, code, name, _ in STAIR_CASES:
        common = dict(active=True, category="general", workflow_mode="two_stage", floor=-2, frequency="daily")
        connection.execute(Point.__table__.insert().values(**common, id=point_id, code=code, name=name,
            qr_token=f"keep-stairs-{point_id}", schedule_start=date(2026, 11, 10)))
        connection.execute(PointSchedule.__table__.insert().values(**common, point_id=point_id,
            effective_date=date(2026, 11, 10), point_code=code, point_name=name))


def test_v19_stair_assignment_retains_histories_qrs_and_old_day_through_midnight(engine, v19, monkeypatch):
    with engine.begin() as connection:
        seed_stairs(connection)
        before = snapshot(connection, v19)
    migrate = migrations._schedule_b2_stairs
    # At this UTC instant Taipei has already rolled over to Thursday the 26th.
    instant = datetime(2026, 11, 25, 17, tzinfo=timezone.utc)
    monkeypatch.setattr(migrations, "_schedule_b2_stairs", lambda conn, _: migrate(conn, instant))
    assert upgrade_schema(engine) == LATEST_VERSION == 20
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        after = snapshot(connection, v19)
        for table in ("patrol_points", "patrol_point_schedules", "patrol_audit_logs", "patrol_schema_versions"):
            before.pop(table)
            after.pop(table)
        assert before == after
        for point_id, code, name, frequency in STAIR_CASES:
            point = connection.execute(select(Point.__table__).where(Point.id == point_id)).mappings().one()
            assert (point.frequency, point.pending_frequency, point.frequency_effective_date, point.qr_token) == (
                "daily", frequency, date(2026, 11, 27), f"keep-stairs-{point_id}")
            snapshots = connection.execute(select(PointSchedule.point_code, PointSchedule.point_name,
                PointSchedule.frequency, PointSchedule.workflow_mode, PointSchedule.effective_date,
                PointSchedule.workflow_changed_at).where(PointSchedule.point_id == point_id)
                .order_by(PointSchedule.effective_date)).all()
            assert snapshots == [
                (code, name, "daily", "two_stage", date(2026, 11, 10), None),
                (code, name, frequency, "two_stage", date(2026, 11, 27), datetime(2026, 11, 26, 16)),
            ]
            audit = connection.execute(select(AuditLog.detail).where(AuditLog.target == f"point:{point_id}",
                AuditLog.action == "b2_stair_frequency_scheduled")).scalar_one()
            assert json.loads(audit) == dict(code=code, before="daily", after=frequency, effective_date="2026-11-27")


def test_v19_stair_conflict_rolls_back_both_points_and_version(engine, v19):
    with engine.begin() as connection:
        seed_stairs(connection)
        connection.execute(Point.__table__.update().where(Point.id == 116).values(
            pending_frequency="monthly", frequency_effective_date=date(2027, 2, 1)))
        before = snapshot(connection, v19)
    with pytest.raises(SchemaMigrationError, match="B2-G003"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, v19) == before


def test_both_stairs_activate_at_taipei_midnight(catalogue_app):
    with db.engine.begin() as connection:
        seed_stairs(connection)
        migrations._schedule_b2_stairs(connection, datetime(2026, 11, 26, 1, tzinfo=timezone.utc))
    assert activate_due_point_frequencies(datetime(2026, 11, 26, 15, 59, 59, tzinfo=timezone.utc))["activated"] == 0
    midnight = datetime(2026, 11, 26, 16, tzinfo=timezone.utc)
    assert activate_due_point_frequencies(midnight)["activated"] == 2
    assert activate_due_point_frequencies(midnight)["activated"] == 0
    for point_id, code, _, frequency in STAIR_CASES:
        point = db.session.get(Point, point_id)
        assert (point.code, point.frequency, point.pending_frequency, point.frequency_effective_date) == (
            code, frequency, None, None)
