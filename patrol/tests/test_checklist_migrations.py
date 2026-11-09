"""Schema 17 adds optional-history snapshots without changing existing receipts."""
from datetime import date, datetime, timedelta
import hashlib
from uuid import UUID

import pytest
from sqlalchemy import MetaData, event, func, inspect, select

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import (DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, IssueEvent, IssueEventPhoto,
                    OfflineSubmission, PatrolExecution, Point, SchemaVersion, User, db)
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store


NOW = datetime(2026, 11, 9, 5)


def _execution(identifier=51, day=0):
    instant = NOW + timedelta(days=day)
    return dict(id=identifier, user_id=17, point_id=23, binding_id=37, created_at=instant,
                frequency="daily", period_key=instant.date().isoformat(), slot="any", category="general",
                point_code="A1M-W01", point_name="1M女廁所-甲", point_floor=11, user_name="Original executor")


def _inspection(identifier=61, execution_id=51, day=0):
    instant = NOW + timedelta(days=day)
    return dict(id=identifier, user_id=18, point_id=23, binding_id=38, created_at=instant,
                frequency="daily", period_key=instant.date().isoformat(), slot="any", category="general",
                point_code="A1M-W01", point_name="1M女廁所-甲", point_floor=11, user_name="Original inspector",
                workflow_mode="two_stage", execution_id=execution_id, personal_day=instant.date(),
                note="Original abnormal note", is_abnormal=True)


def _digest(rows):
    # No ORM identity or display serialization participates in the data digest.
    payload = repr({name: [tuple(row) for row in values] for name, values in sorted(rows.items())
                    if name != SchemaVersion.__tablename__})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@pytest.fixture
def v16(engine):
    with engine.begin() as connection:
        db.metadata.create_all(connection, tables=[table for table in db.metadata.sorted_tables
                                                   if table.name.startswith("patrol_")])
        # Freeze the immediately preceding schema; only these columns are new
        # in v17 and neither is referenced by the earlier integrity triggers.
        for model in (PatrolExecution, Inspection):
            connection.exec_driver_sql(f"ALTER TABLE {model.__tablename__} DROP COLUMN checklist_data")
        metadata = MetaData()
        metadata.reflect(connection)
        for identifier, role in ((17, "executor"), (18, "inspector")):
            connection.execute(User.__table__.insert().values(id=identifier, username=role, display_name=role,
                password_hash="preserved-password-hash", role=role, patrol_category="general", active=True,
                must_change_password=False, auth_version=7, created_at=NOW))
            connection.execute(DeviceBinding.__table__.insert().values(id=identifier + 20, user_id=identifier,
                token_hash=str(identifier) * 32, label="Original phone", status="approved", created_at=NOW))
        connection.execute(Point.__table__.insert().values(id=23, code="A1M-W01", name="1M女廁所-甲", floor=11,
            category="general", inspection_team="general", frequency="daily", workflow_mode="two_stage", active=True,
            qr_token="preserved-toilet-qr-token", schedule_start=date(2026, 1, 1), created_at=NOW))
        connection.execute(metadata.tables[PatrolExecution.__tablename__].insert().values(**_execution()))
        connection.execute(metadata.tables[Inspection.__tablename__].insert().values(**_inspection()))
        connection.execute(InspectionPhoto.__table__.insert().values(id=81, inspection_id=61, data=b"original-photo",
            size_bytes=14, width=10, height=20, created_at=NOW))
        connection.execute(InspectionIssue.__table__.insert().values(inspection_id=61, status="resolved", opened_at=NOW,
            resolved_at=NOW, resolved_by_id=18, resolved_by_name="Original inspector", resolution_note="Existing repair"))
        connection.execute(IssueEvent.__table__.insert().values(id=71, inspection_id=61, actor_id=18,
            actor_name="Original inspector", action="resolved", note="Existing repair", created_at=NOW))
        connection.execute(IssueEventPhoto.__table__.insert().values(id=82, event_id=71, data=b"repair-evidence",
            size_bytes=15, width=20, height=10, created_at=NOW))
        connection.execute(OfflineSubmission.__table__.insert().values(id=91, user_id=18, binding_id=38,
            client_id=str(UUID(int=91)), payload_hash="a" * 64, observed_at=NOW, received_at=NOW, inspection_id=61))
        connection.execute(OfflineSubmission.__table__.insert().values(id=92, user_id=17, binding_id=37,
            client_id=str(UUID(int=92)), payload_hash="b" * 64, observed_at=NOW, received_at=NOW, execution_id=51))
        connection.execute(SchemaVersion.__table__.insert().values(version=16, applied_at=NOW))
        connection.exec_driver_sql("CREATE TABLE unrelated_checklist_link (id INTEGER PRIMARY KEY, "
            "inspection_id INTEGER REFERENCES patrol_inspections(id), execution_id INTEGER REFERENCES patrol_executions(id))")
        connection.exec_driver_sql("INSERT INTO unrelated_checklist_link VALUES (1, 61, 51)")
        metadata.reflect(connection)
        return metadata


def test_v17_adds_only_two_empty_columns_and_preserves_all_history_and_hashes(engine, v16):
    with engine.connect() as connection:
        before = snapshot(connection, v16)
        old_tables = set(inspect(connection).get_table_names())
    statements = []
    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert upgrade_schema(engine) == LATEST_VERSION == 17
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not any(s.lstrip().upper().startswith(("DROP ", "DELETE ", "UPDATE ")) for s in statements)
    alters = [s.strip().upper() for s in statements if s.lstrip().upper().startswith("ALTER ")]
    assert len(alters) == 2
    assert {statement.split(" ADD COLUMN ")[0] for statement in alters} == {
        "ALTER TABLE PATROL_EXECUTIONS", "ALTER TABLE PATROL_INSPECTIONS"}
    assert all(" ADD COLUMN CHECKLIST_DATA " in statement for statement in alters)
    with engine.connect() as connection:
        after = snapshot(connection, v16)
        assert _digest(after) == _digest(before)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert set(inspect(connection).get_table_names()) == old_tables
        assert connection.scalar(select(Inspection.checklist_data).where(Inspection.id == 61)) == ""
        assert connection.scalar(select(PatrolExecution.checklist_data).where(PatrolExecution.id == 51)) == ""
        assert connection.scalars(select(OfflineSubmission.payload_hash).order_by(OfflineSubmission.id)).all() == ["a" * 64, "b" * 64]


def test_v17_old_worker_inserts_still_default_both_snapshot_columns_to_empty(engine, v16):
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.execute(v16.tables[PatrolExecution.__tablename__].insert().values(**_execution(501, day=1)))
        connection.execute(v16.tables[Inspection.__tablename__].insert().values(**_inspection(601, 501, day=1)))
        assert connection.scalar(select(PatrolExecution.checklist_data).where(PatrolExecution.id == 501)) == ""
        assert connection.scalar(select(Inspection.checklist_data).where(Inspection.id == 601)) == ""
        assert connection.scalar(select(Inspection.execution_id).where(Inspection.id == 601)) == 501


def test_v17_migration_repeat_keeps_new_snapshots_and_does_not_rewrite_old_receipts(engine, v16):
    upgrade_schema(engine)
    values = ('{"key":"toilet_v1","selected":["toilet.mirror"]}',
              '{"key":"toilet_v1","selected":["toilet.floor"]}')
    with engine.begin() as connection:
        connection.execute(PatrolExecution.__table__.update().where(PatrolExecution.id == 51).values(checklist_data=values[0]))
        connection.execute(Inspection.__table__.update().where(Inspection.id == 61).values(checklist_data=values[1]))
        before = snapshot(connection, v16)
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert snapshot(connection, v16) == before
        assert connection.scalar(select(PatrolExecution.checklist_data).where(PatrolExecution.id == 51)) == values[0]
        assert connection.scalar(select(Inspection.checklist_data).where(Inspection.id == 61)) == values[1]
        assert connection.scalar(select(func.count()).where(SchemaVersion.version == 17)) == 1


def test_v17_failure_rolls_back_both_columns_version_and_all_data(engine, v16, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, v16)
    original = migrations._validate_current
    def fail(connection):
        original(connection)
        raise RuntimeError("Injected checklist migration failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="Injected checklist"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, v16) == before
        for model in (Inspection, PatrolExecution):
            assert "checklist_data" not in {column["name"] for column in inspect(connection).get_columns(model.__tablename__)}


@pytest.mark.parametrize("model", [Inspection, PatrolExecution])
@pytest.mark.parametrize("definition", ["TEXT DEFAULT ''", "VARCHAR(1000) NOT NULL DEFAULT ''",
                                      "INTEGER NOT NULL DEFAULT 0", "TEXT NOT NULL DEFAULT 'wrong'"])
def test_v17_invalid_partial_column_type_nullable_or_default_refuses_upgrade(engine, v16, model, definition):
    with engine.begin() as connection:
        connection.exec_driver_sql(f"ALTER TABLE {model.__tablename__} ADD COLUMN checklist_data {definition}")
        before = snapshot(connection, v16)
    with pytest.raises(SchemaMigrationError):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, v16) == before
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 16
        other = Inspection if model is PatrolExecution else PatrolExecution
        assert "checklist_data" not in {column["name"] for column in inspect(connection).get_columns(other.__tablename__)}
