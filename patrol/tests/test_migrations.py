"""Migration regression tests use disposable databases, never production data."""
from datetime import date, datetime

import pytest
from sqlalchemy import (Boolean, CheckConstraint, Column, Date, DateTime, ForeignKey,
                        Index, Integer, MetaData, String, Table, Text, UniqueConstraint,
                        create_engine, event, inspect, select, text)
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateColumn, CreateTable

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import Inspection, InspectionPhoto, Point, PointSchedule, db


def legacy_metadata():
    """Frozen v1 schema; independent from the current ORM declarations."""
    metadata = MetaData()
    Table("patrol_users", metadata,
          Column("id", Integer, primary_key=True), Column("username", String(80), nullable=False, unique=True),
          Column("display_name", String(100), nullable=False), Column("password_hash", String(512), nullable=False),
          Column("role", String(20), nullable=False), Column("active", Boolean, nullable=False),
          Column("must_change_password", Boolean, nullable=False), Column("auth_version", Integer, nullable=False),
          Column("created_at", DateTime, nullable=False))
    Table("patrol_points", metadata,
          Column("id", Integer, primary_key=True), Column("code", String(30), nullable=False, unique=True),
          Column("name", String(100), nullable=False), Column("floor", Integer, nullable=False),
          Column("frequency", String(10), nullable=False), Column("active", Boolean, nullable=False),
          Column("qr_token", String(100), nullable=False, unique=True), Column("created_at", DateTime, nullable=False),
          Column("schedule_start", Date, nullable=False),
          CheckConstraint("floor >= 1 AND floor <= 5", name="patrol_point_floor"))
    Table("patrol_point_schedules", metadata,
          Column("id", Integer, primary_key=True),
          Column("point_id", Integer, ForeignKey("patrol_points.id"), nullable=False, index=True),
          Column("effective_date", Date, nullable=False), Column("frequency", String(10), nullable=False),
          Column("active", Boolean, nullable=False))
    Table("patrol_device_bindings", metadata,
          Column("id", Integer, primary_key=True),
          Column("user_id", Integer, ForeignKey("patrol_users.id"), nullable=False, index=True),
          Column("token_hash", String(64), nullable=False, unique=True), Column("label", String(100), nullable=False),
          Column("status", String(20), nullable=False, index=True), Column("created_at", DateTime, nullable=False),
          Column("approved_at", DateTime), Column("last_seen_at", DateTime),
          Index("patrol_one_approved_device", "user_id", unique=True,
                sqlite_where=text("status = 'approved'"), postgresql_where=text("status = 'approved'")))
    Table("patrol_inspections", metadata,
          Column("id", Integer, primary_key=True),
          Column("user_id", Integer, ForeignKey("patrol_users.id"), nullable=False, index=True),
          Column("point_id", Integer, ForeignKey("patrol_points.id"), nullable=False, index=True),
          Column("binding_id", Integer, ForeignKey("patrol_device_bindings.id")),
          Column("created_at", DateTime, nullable=False, index=True), Column("period_key", String(10), nullable=False),
          Column("frequency", String(10), nullable=False), Column("point_code", String(30), nullable=False),
          Column("point_name", String(100), nullable=False), Column("point_floor", Integer, nullable=False),
          Column("user_name", String(100), nullable=False),
          UniqueConstraint("point_id", "frequency", "period_key", name="patrol_one_inspection_per_period"))
    Table("patrol_audit_logs", metadata,
          Column("id", Integer, primary_key=True), Column("actor_id", Integer, ForeignKey("patrol_users.id")),
          Column("action", String(80), nullable=False), Column("target", String(120), nullable=False),
          Column("detail", Text, nullable=False), Column("created_at", DateTime, nullable=False))
    Table("patrol_login_attempts", metadata,
          Column("id", Integer, primary_key=True), Column("key", String(64), nullable=False, index=True),
          Column("created_at", DateTime, nullable=False, index=True))
    return metadata


@pytest.fixture
def engine(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'migration.sqlite3').as_posix()}")
    yield engine
    engine.dispose()


@pytest.fixture
def legacy(engine):
    metadata = legacy_metadata()
    metadata.create_all(engine)
    instant = datetime(2026, 11, 3, 1, 2, 3)
    with engine.begin() as connection:
        connection.execute(metadata.tables["patrol_users"].insert(), dict(
            id=17, username="admin", display_name="Existing administrator", password_hash="fixture-hash-preserved",
            role="admin", active=True, must_change_password=False, auth_version=9, created_at=instant))
        connection.execute(metadata.tables["patrol_points"].insert(), dict(
            id=23, code="1F-A01", name="Original point", floor=1, frequency="daily", active=True,
            qr_token="existing-qr-token-kept", created_at=instant, schedule_start=date(2026, 1, 1)))
        connection.execute(metadata.tables["patrol_point_schedules"].insert(), dict(
            id=31, point_id=23, effective_date=date(2026, 1, 1), frequency="daily", active=True))
        connection.execute(metadata.tables["patrol_device_bindings"].insert(), dict(
            id=41, user_id=17, token_hash="existing-browser-token-hash", label="Existing phone", status="approved",
            created_at=instant, approved_at=instant, last_seen_at=instant))
        connection.execute(metadata.tables["patrol_inspections"].insert(), dict(
            id=51, user_id=17, point_id=23, binding_id=41, created_at=instant, period_key="2026-11-03",
            frequency="daily", point_code="1F-A01", point_name="Original snapshot", point_floor=1,
            user_name="Original person snapshot"))
        connection.execute(metadata.tables["patrol_audit_logs"].insert(), dict(
            id=61, actor_id=17, action="checkin", target="1F-A01", detail="Original audit", created_at=instant))
        connection.execute(metadata.tables["patrol_login_attempts"].insert(), dict(
            id=71, key="existing-attempt-key", created_at=instant))
        connection.exec_driver_sql("CREATE TABLE unrelated_license (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.exec_driver_sql("INSERT INTO unrelated_license VALUES (1, 'untouched')")
        if engine.dialect.name == "postgresql":
            # Explicit fixture IDs must advance sequences as original ORM inserts
            # would have done; otherwise later imports collide with seeded IDs.
            for table in metadata.sorted_tables:
                connection.execute(text("SELECT setval(pg_get_serial_sequence(:table, 'id'), "
                                        f"(SELECT MAX(id) FROM {table.name}), true)"), {"table": table.name})
    return metadata


def snapshot(connection, metadata):
    return {table.name: connection.execute(select(table).order_by(table.c.id)).all()
            for table in metadata.sorted_tables}


def test_fresh_database_and_idempotent_upgrade(engine):
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        before = connection.exec_driver_sql("SELECT * FROM patrol_schema_versions").all()
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT * FROM patrol_schema_versions").all() == before
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    assert len(inspect(engine).get_table_names()) == 9


def test_v1_rows_ids_qr_credentials_and_unrelated_data_survive(engine, legacy):
    with engine.connect() as connection:
        before = snapshot(connection, legacy)
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert snapshot(connection, legacy) == before
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
        assert connection.exec_driver_sql("SELECT category FROM patrol_points").scalar_one() == "uncategorized"
        assert connection.exec_driver_sql("SELECT category FROM patrol_point_schedules").scalar_one() == "uncategorized"
        assert connection.exec_driver_sql("SELECT category, slot, note, is_abnormal FROM patrol_inspections").one() == ("uncategorized", "any", "", 0)
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert snapshot(connection, legacy) == before
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_schema_versions").scalar_one() == 1


def test_v1_indexes_unique_constraints_and_foreign_keys_survive(engine, legacy):
    before_inspector = inspect(engine)
    index_names = {name: {index["name"] for index in before_inspector.get_indexes(name)} for name in legacy.tables}
    foreign_keys = {name: {(tuple(key["constrained_columns"]), key["referred_table"], tuple(key["referred_columns"]))
                           for key in before_inspector.get_foreign_keys(name)} for name in legacy.tables}
    upgrade_schema(engine)
    after_inspector = inspect(engine)
    for name in legacy.tables:
        assert {index["name"] for index in after_inspector.get_indexes(name)} == index_names[name]
        assert {(tuple(key["constrained_columns"]), key["referred_table"], tuple(key["referred_columns"]))
                for key in after_inspector.get_foreign_keys(name)} == foreign_keys[name]
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_inspections SET user_id=99999 WHERE id=51")
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("INSERT INTO patrol_device_bindings (user_id,token_hash,label,status,created_at) "
                                   "VALUES (17,'another-token','Other','approved',CURRENT_TIMESTAMP)")
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("INSERT INTO patrol_points (code,name,floor,frequency,active,qr_token,created_at,schedule_start) "
                                   "VALUES ('1F-A01','Duplicate',1,'daily',1,'different-token',CURRENT_TIMESTAMP,'2026-01-01')")


def test_daily2_allows_am_and_pm_but_prevents_duplicate_slot(engine, legacy):
    upgrade_schema(engine)
    with engine.begin() as connection:
        values = dict(user_id=17, point_id=23, binding_id=41, created_at=datetime(2026, 11, 3, 2),
                      period_key="2026-11-03", frequency="daily2", category="safety", point_code="1F-A01",
                      point_name="Safety point", point_floor=1, user_name="Inspector")
        connection.execute(Inspection.__table__.insert().values(**values, slot="am"))
        connection.execute(Inspection.__table__.insert().values(**values, slot="pm"))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(Inspection.__table__.insert().values(**values, slot="am"))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        # Existing legacy daily check-in keeps its original one-per-period rule.
        connection.execute(Inspection.__table__.insert().values(**{**values, "frequency": "daily"}, slot="any"))
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT slot FROM patrol_inspections ORDER BY id").all() == [("any",), ("am",), ("pm",)]


@pytest.mark.parametrize("floor", [-2, -1, 1, 11, 2, 3, 4, 14, 5, 15])
def test_upgraded_floor_constraint_accepts_catalog_levels(engine, legacy, floor):
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_points SET floor=? WHERE id=23", (floor,))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_points SET floor=999 WHERE id=23")


def test_extra_sqlite_columns_indexes_and_triggers_are_preserved(engine, legacy):
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE patrol_points ADD COLUMN local_reference TEXT DEFAULT 'existing-extra' CHECK(length(local_reference)>0)")
        connection.exec_driver_sql("CREATE INDEX local_point_name_index ON patrol_points(name)")
        connection.exec_driver_sql("CREATE TRIGGER local_point_update AFTER UPDATE ON patrol_points BEGIN "
                                   "INSERT INTO unrelated_license(value) VALUES ('trigger fired'); END")
    upgrade_schema(engine)
    with engine.begin() as connection:
        assert connection.exec_driver_sql("SELECT local_reference FROM patrol_points").scalar_one() == "existing-extra"
        connection.exec_driver_sql("UPDATE patrol_points SET name='Updated' WHERE id=23")
        assert connection.exec_driver_sql("SELECT value FROM unrelated_license ORDER BY id").all() == [("untouched",), ("trigger fired",)]
    assert "local_point_name_index" in {index["name"] for index in inspect(engine).get_indexes("patrol_points")}
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_points SET local_reference='' WHERE id=23")


def test_failure_after_table_rebuild_rolls_back_schema_data_and_version(engine, legacy, monkeypatch):
    with engine.connect() as connection:
        before_rows = snapshot(connection, legacy)
        before_schema = connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name").all()

    def fail_validation(connection):
        raise RuntimeError("Injected failure before migration commit")

    monkeypatch.setattr(migrations, "_validate_current", fail_validation)
    with pytest.raises(RuntimeError, match="Injected failure"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, legacy) == before_rows
        assert connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name").all() == before_schema
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []


def test_failure_during_fresh_creation_is_transactional(engine, monkeypatch):
    monkeypatch.setattr(migrations, "_validate_current", lambda connection: (_ for _ in ()).throw(RuntimeError("Injected failure")))
    with pytest.raises(RuntimeError, match="Injected failure"):
        upgrade_schema(engine)
    assert inspect(engine).get_table_names() == []


def test_partial_schema_fails_without_creating_or_dropping_tables(engine):
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE patrol_users (id INTEGER PRIMARY KEY)")
    with pytest.raises(SchemaMigrationError, match="Incomplete patrol schema"):
        upgrade_schema(engine)
    assert inspect(engine).get_table_names() == ["patrol_users"]


def test_future_version_is_not_downgraded(engine):
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("INSERT INTO patrol_schema_versions(version) VALUES (999)")
    with pytest.raises(SchemaMigrationError, match="newer"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT MAX(version) FROM patrol_schema_versions").scalar_one() == 999


def test_photo_bytes_are_deferred_and_foreign_key_is_enforced(engine, legacy):
    upgrade_schema(engine)
    payload = b"fixture-photo-bytes"
    with Session(engine) as session:
        photo = InspectionPhoto(inspection_id=51, data=payload, size_bytes=len(payload), width=1, height=1)
        session.add(photo)
        session.commit()
        photo_id = photo.id
    statements = []
    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        with Session(engine) as session:
            photo = session.get(InspectionPhoto, photo_id)
            assert "data" in inspect(photo).unloaded
            assert "patrol_inspection_photos.data" not in statements[-1]
            assert photo.data == payload
            assert "patrol_inspection_photos.data" in statements[-1]
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_inspection_photos SET inspection_id=99999")


def test_postgres_schema_compiles_expected_defaults_binary_and_slot_key():
    """Compiler check only; does not claim a live PostgreSQL migration test."""
    dialect = postgresql.dialect()
    inspection_ddl = str(CreateTable(Inspection.__table__).compile(dialect=dialect))
    photo_ddl = str(CreateTable(InspectionPhoto.__table__).compile(dialect=dialect))
    assert "UNIQUE (point_id, frequency, period_key, slot)" in inspection_ddl
    assert "is_abnormal BOOLEAN DEFAULT false NOT NULL" in inspection_ddl
    assert "slot VARCHAR(8) DEFAULT 'any' NOT NULL" in inspection_ddl
    assert "data BYTEA NOT NULL" in photo_ddl
    assert "FOREIGN KEY(inspection_id) REFERENCES patrol_inspections (id)" in photo_ddl
    assert "DEFAULT 'uncategorized' NOT NULL" in str(CreateColumn(PointSchedule.__table__.c.category).compile(dialect=dialect))


def test_postgres_upgrade_uses_targeted_alter_and_preserves_unrelated_constraints(monkeypatch):
    """Offline verification of the actual ALTER branch; no PostgreSQL connection."""
    statements = []

    class RecordingConnection:
        dialect = postgresql.dialect()

        def exec_driver_sql(self, statement):
            statements.append(statement)

    class LegacyInspector:
        def get_columns(self, table_name):
            return [{"name": "id"}]

        def get_check_constraints(self, table_name):
            return [{"name": "patrol_point_floor", "sqltext": "floor >= 1 AND floor <= 5"},
                    {"name": "extra_point_check", "sqltext": "length(name)>0"}]

        def get_unique_constraints(self, table_name):
            return [{"name": "patrol_one_inspection_per_period", "column_names": ["point_id", "frequency", "period_key"]},
                    {"name": "extra_unique_check", "column_names": ["id", "created_at"]}]

    monkeypatch.setattr(migrations, "inspect", lambda connection: LegacyInspector())
    connection = RecordingConnection()
    migrations._add_missing_columns(connection, "patrol_inspections", [Inspection.__table__.c[name]
                                    for name in ("category", "slot", "note", "is_abnormal")])
    migrations._postgres_replace_constraints(connection)
    combined = "\n".join(statements)
    assert "ADD COLUMN is_abnormal BOOLEAN DEFAULT false NOT NULL" in combined
    assert "ADD COLUMN slot VARCHAR(8) DEFAULT 'any' NOT NULL" in combined
    assert "DROP CONSTRAINT patrol_one_inspection_per_period" in combined
    assert "ADD CONSTRAINT patrol_one_inspection_per_slot UNIQUE (point_id, frequency, period_key, slot)" in combined
    assert "ADD CONSTRAINT patrol_point_floor CHECK (floor IN (-2, -1, 1, 11, 2, 3, 4, 14, 5, 15))" in combined
    assert "DROP TABLE" not in combined
    assert "extra_point_check" not in combined and "extra_unique_check" not in combined
    assert all(statement.startswith("ALTER TABLE patrol_") for statement in statements)
