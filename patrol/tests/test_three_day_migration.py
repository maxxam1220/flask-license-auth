"""Schema 18 expands frequency checks without rewriting existing audit evidence."""
from datetime import date, datetime

import pytest
from sqlalchemy import CheckConstraint, Column, ForeignKey, Integer, MetaData, String, Table, func, inspect, select
from sqlalchemy.exc import IntegrityError

import migrations
from migrations import LATEST_VERSION, upgrade_schema
from models import (DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, OfflineSubmission,
                    PatrolExecution, Point, PointSchedule, SchemaVersion, User, db,
                    protect_execution_link, protect_legacy_exemptions)
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store
from test_postgres import schema_signature


OLD_CHECKS = {
    "patrol_point_pending_frequency": ("(pending_frequency IS NULL AND frequency_effective_date IS NULL) OR "
        "(pending_frequency IS NOT NULL AND frequency_effective_date IS NOT NULL AND "
        "(pending_frequency = 'daily' OR pending_frequency = 'daily2' OR pending_frequency = 'weekly' "
        "OR pending_frequency = 'monthly' OR pending_frequency = 'irregular'))"),
    "patrol_execution_valid_slot": ("(frequency IN ('daily','weekly','monthly','irregular') AND slot = 'any') OR "
        "(frequency = 'daily2' AND slot IN ('am','pm'))"),
    "patrol_executor_visit_fields": ("NOT executor_visit OR (workflow_mode = 'spot' AND category = 'general' "
        "AND frequency = 'irregular' AND slot = 'any' AND note = '' AND NOT is_abnormal)"),
}


def _signature(engine):
    if engine.dialect.name == "postgresql":
        return schema_signature(engine)
    with engine.connect() as connection:
        return connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name").all()


@pytest.fixture
def v17(engine):
    metadata = MetaData()
    for table in db.metadata.sorted_tables:
        table.to_metadata(metadata)
    for table in metadata.tables.values():
        for collection in [table.constraints, *(column.constraints for column in table.columns)]:
            for constraint in list(collection):
                if constraint.name in OLD_CHECKS:
                    collection.remove(constraint)
                    table.append_constraint(CheckConstraint(OLD_CHECKS[constraint.name], name=constraint.name))
    Table("unrelated_evidence", metadata, Column("id", Integer, primary_key=True),
          Column("inspection_id", Integer, ForeignKey("patrol_inspections.id")), Column("value", String(30)))
    instant = datetime(2026, 11, 9, 1)
    with engine.begin() as connection:
        metadata.create_all(connection)
        protect_execution_link(connection)
        protect_legacy_exemptions(connection)
        for identifier, role in ((1, "executor"), (2, "inspector")):
            connection.execute(User.__table__.insert().values(id=identifier, username=role, display_name=role,
                password_hash="preserved-password-hash", role=role, patrol_category="general", active=True,
                must_change_password=False, auth_version=1, created_at=instant))
            connection.execute(DeviceBinding.__table__.insert().values(id=identifier, user_id=identifier,
                token_hash=str(identifier) * 64, status="approved", label="preserved binding", created_at=instant))
        for identifier, frequency, mode in ((1, "weekly", "two_stage"), (2, "irregular", "spot")):
            connection.execute(Point.__table__.insert().values(id=identifier, code=f"B2-OLD{identifier}",
                name="Preserved point", floor=-2, category="general", frequency=frequency, workflow_mode=mode,
                active=True, qr_token=f"preserved-qr-{identifier}", schedule_start=date(2026, 11, 9), created_at=instant))
            connection.execute(PointSchedule.__table__.insert().values(point_id=identifier,
                effective_date=date(2026, 11, 9), frequency=frequency, category="general", workflow_mode=mode,
                active=True, floor=-2, point_code=f"B2-OLD{identifier}", point_name="Preserved point"))
        common = dict(point_id=1, created_at=instant, period_key="2026-11-09", frequency="weekly", slot="any",
                      category="general", point_code="B2-OLD1", point_name="Preserved point", point_floor=-2)
        connection.execute(PatrolExecution.__table__.insert().values(**common, id=1, user_id=1, binding_id=1,
            user_name="executor", checklist_data='{"selected":["old.item"]}'))
        connection.execute(Inspection.__table__.insert().values(**common, id=1, user_id=2, binding_id=2,
            user_name="inspector", workflow_mode="two_stage", execution_id=1, personal_day=date(2026, 11, 9),
            note="Existing abnormal evidence", is_abnormal=True, checklist_data='{"selected":["old.item"]}'))
        connection.execute(InspectionPhoto.__table__.insert().values(id=1, inspection_id=1,
            data=b"unchanged-photo", size_bytes=15, width=10, height=10, created_at=instant))
        connection.execute(InspectionIssue.__table__.insert().values(inspection_id=1, status="open", opened_at=instant))
        connection.execute(OfflineSubmission.__table__.insert().values(user_id=2, binding_id=2,
            client_id="00000000-0000-4000-8000-000000000001", payload_hash="a" * 64,
            observed_at=instant, received_at=instant, inspection_id=1, execution_id=None))
        connection.execute(metadata.tables["unrelated_evidence"].insert().values(id=1, inspection_id=1, value="untouched"))
        connection.execute(SchemaVersion.__table__.insert().values(version=17, applied_at=instant))
        connection.exec_driver_sql("CREATE INDEX custom_preserved_point_name ON patrol_points(name)")
        connection.exec_driver_sql("CREATE INDEX custom_preserved_inspection_note ON patrol_inspections(note)")
        reflected = MetaData()
        reflected.reflect(connection)
    return reflected


def _execution(**changes):
    return dict(id=3, point_id=1, user_id=1, binding_id=1, created_at=datetime(2026, 11, 10),
        period_key="2026-11-10", frequency="three_day", slot="any", category="general",
        point_code="B2-OLD1", point_name="Preserved point", point_floor=-2, user_name="executor") | changes


def _visit(**changes):
    return dict(id=3, point_id=2, user_id=1, binding_id=1, created_at=datetime(2026, 11, 10),
        personal_day=date(2026, 11, 10), period_key="2026-11-10", frequency="three_day", slot="any",
        category="general", workflow_mode="spot", spot_request_id="three-day-visit", executor_visit=True,
        point_code="B2-OLD2", point_name="Preserved point", point_floor=-2, user_name="executor", note="",
        is_abnormal=False) | changes


def test_v17_upgrade_preserves_rows_children_indexes_and_is_idempotent(engine, v17):
    with engine.connect() as connection:
        before = snapshot(connection, v17)
    assert upgrade_schema(engine) == LATEST_VERSION == 18
    with engine.connect() as connection:
        after = snapshot(connection, v17)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert connection.scalar(select(Point.frequency).where(Point.id == 2)) == "irregular"
        assert connection.scalar(select(Point.qr_token).where(Point.id == 2)) == "preserved-qr-2"
        if engine.dialect.name == "sqlite":
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
    indexes = {i["name"] for table in ("patrol_points", "patrol_inspections") for i in inspect(engine).get_indexes(table)}
    assert {"custom_preserved_point_name", "custom_preserved_inspection_note"} <= indexes
    signature = _signature(engine)
    assert upgrade_schema(engine) == 18
    assert _signature(engine) == signature
    with engine.connect() as connection:
        assert connection.scalar(select(func.count()).where(SchemaVersion.version == 18)) == 1


def test_three_day_values_rejected_before_migration_then_accepted(engine, v17):
    with engine.begin() as connection:
        for statement in (Point.__table__.update().where(Point.id == 2).values(
                pending_frequency="three_day", frequency_effective_date=date(2026, 11, 10)),
                PatrolExecution.__table__.insert().values(**_execution()),
                Inspection.__table__.insert().values(**_visit())):
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(statement)
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.execute(Point.__table__.update().where(Point.id == 2).values(
            pending_frequency="three_day", frequency_effective_date=date(2026, 11, 10)))
        connection.execute(PatrolExecution.__table__.insert().values(**_execution()))
        connection.execute(Inspection.__table__.insert().values(**_visit()))
        assert connection.scalar(select(Inspection.frequency).where(Inspection.id == 3)) == "three_day"


@pytest.mark.parametrize("changes", [{"slot": "am"}, {"frequency": "daily"}, {"note": "not allowed"},
                                    {"is_abnormal": True}, {"category": "safety"}])
def test_three_day_executor_visits_keep_existing_restrictions(engine, v17, changes):
    upgrade_schema(engine)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(Inspection.__table__.insert().values(**_visit(**changes)))


def test_three_day_frequency_and_personal_limit_checks_remain_strict(engine, v17):
    upgrade_schema(engine)
    with engine.begin() as connection:
        for statement in (Point.__table__.update().where(Point.id == 2).values(pending_frequency="three_day"),
                          Point.__table__.update().where(Point.id == 2).values(
                              pending_frequency="bogus", frequency_effective_date=date(2026, 11, 10)),
                          PatrolExecution.__table__.insert().values(**_execution(slot="pm"))):
            with pytest.raises(IntegrityError), connection.begin_nested():
                connection.execute(statement)
        connection.execute(Inspection.__table__.insert().values(**_visit()))
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(Inspection.__table__.insert().values(**_visit(id=4, spot_request_id="other-click")))


def test_frequency_upgrade_preserves_immutable_link_and_legacy_triggers(engine, v17):
    upgrade_schema(engine)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(Inspection.__table__.update().where(Inspection.id == 1).values(execution_id=None))
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(Inspection.__table__.update().where(Inspection.id == 1).values(legacy_slot_repeat=True))


def test_failed_frequency_upgrade_rolls_back_checks_data_and_version(engine, v17, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, v17)
    signature = _signature(engine)
    original = migrations._validate_current
    def fail(connection):
        original(connection)
        raise RuntimeError("Injected frequency validation failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="Injected frequency"):
        upgrade_schema(engine)
    assert _signature(engine) == signature
    with engine.connect() as connection:
        assert snapshot(connection, v17) == before
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 17
