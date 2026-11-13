"""Schema 19 preserves evidence while adding weekday rules and leave exclusions."""
from datetime import date, datetime
import subprocess
import sys

import pytest
from sqlalchemy import CheckConstraint, MetaData, func, inspect, select
from sqlalchemy.exc import IntegrityError

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import Inspection, PatrolExecution, Point, SchemaVersion, db
from safety_leave import SafetyLeaveExclusion
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store
from test_three_day_migration import v17, _execution, _visit, _signature


@pytest.fixture
def v18(engine, v17):
    """Use the legacy evidence fixture with exact v18 DDL and no leave table."""
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
            expression = migrations.FREQUENCY_CHECKS_V18[name]
            if sqlite:
                migrations._sqlite_rebuild(connection, table, [],
                    new_constraints=[CheckConstraint(expression, name=name)], replace_checks={name})
            else:
                connection.exec_driver_sql(f"ALTER TABLE {quote(table)} DROP CONSTRAINT {quote(name)}")
                connection.exec_driver_sql(f"ALTER TABLE {quote(table)} ADD CONSTRAINT {quote(name)} CHECK ({expression})")
        SafetyLeaveExclusion.__table__.drop(connection)
        connection.execute(SchemaVersion.__table__.update().values(version=18))
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
    assert upgrade_schema(engine) == LATEST_VERSION == 19
    with engine.connect() as connection:
        after = snapshot(connection, v18)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert connection.scalar(select(func.count(SafetyLeaveExclusion.id))) == 0
        assert connection.scalar(select(Point.qr_token).where(Point.id == 2)) == "preserved-qr-2"
        if engine.dialect.name == "sqlite":
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    signature = _signature(engine)
    assert upgrade_schema(engine) == 19
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
        "from migrations import upgrade_schema; "
        "e=create_engine('sqlite://'); assert upgrade_schema(e)==19; "
        "assert inspect(e).has_table('patrol_safety_leave_exclusions')"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_known_partially_upgraded_v17_checks_are_accepted(engine, v18):
    with engine.begin() as connection:
        connection.execute(SchemaVersion.__table__.update().values(version=17))
    assert upgrade_schema(engine) == 19
