"""Additive offline receipts, on isolated SQLite and opt-in local PostgreSQL."""
from datetime import date, datetime, timedelta
import os
from uuid import uuid4

import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, func, inspect, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import (DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, LoginEvent, OfflineSubmission,
                    PatrolExecution, Point, PointSchedule, SchemaVersion, User, db)
from test_migrations import engine as sqlite_store, snapshot
from test_postgres import engine as postgres_store, schema_signature


@pytest.fixture(params=["sqlite", "postgres"])
def engine(request):
    if request.param == "postgres" and not os.environ.get("PATROL_TEST_POSTGRES_URL"):
        pytest.skip("Set PATROL_TEST_POSTGRES_URL for the disposable local PostgreSQL database.")
    return request.getfixturevalue("postgres_store" if request.param == "postgres" else "sqlite_store")


@pytest.fixture
def v11(engine):
    """Populate the exact pre-offline tables, including binary data and a foreign application's FK."""
    instant = datetime(2026, 11, 6, 1)
    with engine.begin() as connection:
        db.metadata.create_all(connection, tables=[table for table in db.metadata.sorted_tables
            if table.name.startswith("patrol_") and table.name != OfflineSubmission.__tablename__])
        for identifier, role in ((17, "executor"), (18, "inspector")):
            connection.execute(User.__table__.insert().values(id=identifier, username=role, display_name=role,
                password_hash="untouched-hash", role=role, patrol_category="general", active=True,
                must_change_password=False, auth_version=1, created_at=instant))
            connection.execute(DeviceBinding.__table__.insert().values(id=identifier + 20, user_id=identifier,
                token_hash=str(identifier) * 32, label="existing browser", status="approved", created_at=instant))
        connection.execute(Point.__table__.insert().values(id=23, code="1F-G01", name="Existing point", floor=1,
            category="general", frequency="daily2", workflow_mode="two_stage", active=True,
            qr_token="existing-qr-unchanged", schedule_start=date(2026, 1, 1), created_at=instant))
        connection.execute(PointSchedule.__table__.insert().values(id=31, point_id=23, effective_date=date(2026, 1, 1),
            category="general", frequency="daily2", workflow_mode="two_stage", active=True,
            floor=1, point_code="1F-G01", point_name="Existing point"))
        common = dict(point_id=23, created_at=instant, frequency="daily2", period_key="2026-11-06", slot="am",
                      category="general", point_code="1F-G01", point_name="Existing point", point_floor=1)
        connection.execute(PatrolExecution.__table__.insert().values(**common, id=61, user_id=17, binding_id=37, user_name="executor"))
        connection.execute(Inspection.__table__.insert().values(**common, id=71, user_id=18, binding_id=38,
            user_name="inspector", workflow_mode="two_stage", execution_id=61, personal_day=date(2026, 11, 6),
            note="Original abnormal note", is_abnormal=True))
        connection.execute(InspectionPhoto.__table__.insert().values(id=81, inspection_id=71, data=b"existing-photo-bytes",
            size_bytes=20, width=10, height=10, created_at=instant))
        connection.execute(InspectionIssue.__table__.insert().values(inspection_id=71, status="open", opened_at=instant))
        connection.execute(LoginEvent.__table__.insert().values(user_id=18, username="inspector", display_name="inspector",
            client_type="mobile", browser="Safari", created_at=instant))
        connection.execute(SchemaVersion.__table__.insert().values(version=11, applied_at=instant))
        other = MetaData()
        User.__table__.to_metadata(other)
        foreign = Table("unrelated_attendance", other, Column("id", Integer, primary_key=True),
                        Column("patrol_user", Integer, ForeignKey("patrol_users.id")), Column("note", String(50)))
        foreign.create(connection)
        connection.execute(foreign.insert().values(id=1, patrol_user=18, note="untouched outside patrol"))
        result = MetaData()
        result.reflect(connection)
        return result


def submission(**changes):
    return dict(user_id=18, binding_id=38, client_id=str(uuid4()), payload_hash="a" * 64,
                observed_at=datetime(2026, 11, 6, 1), received_at=datetime(2026, 11, 6, 2),
                inspection_id=71, execution_id=None) | changes


def test_fresh_offline_schema_creation_and_second_run_are_idempotent(engine):
    assert upgrade_schema(engine) == LATEST_VERSION == 12
    before = schema_signature(engine) if engine.dialect.name == "postgresql" else None
    assert upgrade_schema(engine) == 12
    if before is not None:
        assert schema_signature(engine) == before
    with engine.connect() as connection:
        assert connection.scalar(select(func.count(OfflineSubmission.id))) == 0
        assert connection.execute(select(SchemaVersion.version)).scalars().all() == [12]


def test_v11_upgrade_adds_only_empty_offline_table_and_preserves_shared_data(engine, v11):
    with engine.connect() as connection:
        before = snapshot(connection, v11)
        old_tables = set(inspect(connection).get_table_names())
    assert upgrade_schema(engine) == 12
    with engine.connect() as connection:
        after = snapshot(connection, v11)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert set(inspect(connection).get_table_names()) == old_tables | {OfflineSubmission.__tablename__}
        assert connection.scalar(select(func.count(OfflineSubmission.id))) == 0
    with Session(engine) as session:
        assert session.get(Inspection, 71).offline_submission is None
        assert session.get(PatrolExecution, 61).offline_submission is None
    assert upgrade_schema(engine) == 12


def test_receipt_relationships_keep_claimed_and_received_times_separate(engine, v11):
    upgrade_schema(engine)
    with Session(engine) as session:
        final = session.get(Inspection, 71)
        first = session.get(PatrolExecution, 61)
        old_time = final.created_at
        recorded = OfflineSubmission(**submission())
        executed = OfflineSubmission(**submission(user_id=17, binding_id=37, inspection_id=None, execution_id=61))
        session.add_all((recorded, executed))
        session.commit()
        session.expire_all()
        assert final.offline_submission is recorded and recorded.inspection is final
        assert first.offline_submission is executed and executed.execution is first
        assert recorded.observed_at == old_time and recorded.received_at == old_time + timedelta(hours=1)
        assert final.created_at == first.created_at == old_time


@pytest.mark.parametrize("change", [
    {"inspection_id": None}, {"execution_id": 61}, {"inspection_id": 99999},
    {"user_id": 99999}, {"binding_id": 99999}, {"client_id": "short"}, {"payload_hash": "short"},
])
def test_offline_rows_require_exactly_one_existing_result_and_valid_identity(engine, v11, change):
    upgrade_schema(engine)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(OfflineSubmission.__table__.insert().values(**submission(**change)))
        assert connection.scalar(select(func.count(OfflineSubmission.id))) == 0


def test_client_uuid_and_each_receipt_are_unique_independently(engine, v11):
    upgrade_schema(engine)
    original = submission()
    with engine.begin() as connection:
        connection.execute(OfflineSubmission.__table__.insert().values(**original))
        for changes in ({"inspection_id": None, "execution_id": 61}, {"client_id": str(uuid4())}):
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(OfflineSubmission.__table__.insert().values(**(original | changes)))
        # The UUID is per user, and NULL receipt columns do not collide.
        connection.execute(OfflineSubmission.__table__.insert().values(**(original | dict(
            user_id=17, binding_id=37, inspection_id=None, execution_id=61))))
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(OfflineSubmission.__table__.insert().values(**submission(
                inspection_id=None, execution_id=61)))
        assert connection.scalar(select(func.count(OfflineSubmission.id))) == 2


def test_v12_failure_rolls_back_new_table_version_and_all_existing_data(engine, v11, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, v11)
        table_names = inspect(connection).get_table_names()
    original = migrations._validate_current
    def stop_before_commit(connection):
        original(connection)
        raise RuntimeError("Injected offline migration failure")
    monkeypatch.setattr(migrations, "_validate_current", stop_before_commit)
    with pytest.raises(RuntimeError, match="Injected offline"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, v11) == before
        assert inspect(connection).get_table_names() == table_names
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 11


def test_partial_offline_table_with_wrong_index_is_rejected_without_version_upgrade(engine, v11):
    with engine.begin() as connection:
        OfflineSubmission.__table__.create(connection)
        connection.exec_driver_sql("DROP INDEX patrol_offline_user_received")
        connection.exec_driver_sql("CREATE INDEX patrol_offline_user_received ON patrol_offline_submissions (received_at)")
    with pytest.raises(SchemaMigrationError, match="invalid offline submission index"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 11


def test_postgres_offline_schema_compiles_additive_constraints():
    ddl = str(CreateTable(OfflineSubmission.__table__).compile(dialect=postgresql.dialect()))
    assert "UNIQUE (user_id, client_id)" in ddl
    assert "UNIQUE (inspection_id)" in ddl and "UNIQUE (execution_id)" in ddl
    assert "FOREIGN KEY(inspection_id) REFERENCES patrol_inspections (id)" in ddl
    assert "FOREIGN KEY(execution_id) REFERENCES patrol_executions (id)" in ddl
    assert "observed_at TIMESTAMP WITHOUT TIME ZONE NOT NULL" in ddl
    assert "received_at TIMESTAMP WITHOUT TIME ZONE NOT NULL" in ddl
