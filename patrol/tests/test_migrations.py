"""Migration regression tests use disposable databases, never production data."""
from datetime import date, datetime

import pytest
from sqlalchemy import (Boolean, CheckConstraint, Column, Date, DateTime, ForeignKey,
                        Index, Integer, LargeBinary, MetaData, String, Table, Text, UniqueConstraint,
                        create_engine, event, inspect, select, text)
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateColumn, CreateIndex, CreateTable

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import Inspection, InspectionIssue, InspectionPhoto, IssueEvent, Point, PointSchedule, User, db


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
    seed_legacy_rows(engine, metadata)
    return metadata


def seed_legacy_rows(engine, metadata):
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


def version_two_metadata():
    """Frozen v2 additions, independent of the current issue-workflow models."""
    metadata = legacy_metadata()
    points = metadata.tables["patrol_points"]
    points.append_column(Column("category", String(20), nullable=False, server_default="uncategorized"))
    for constraint in list(points.constraints):
        if isinstance(constraint, CheckConstraint) and constraint.name == "patrol_point_floor":
            points.constraints.remove(constraint)
    points.append_constraint(CheckConstraint("floor IN (-2, -1, 1, 11, 2, 3, 4, 14, 5, 15)", name="patrol_point_floor"))
    metadata.tables["patrol_point_schedules"].append_column(
        Column("category", String(20), nullable=False, server_default="uncategorized"))
    inspections = metadata.tables["patrol_inspections"]
    for column in (Column("category", String(20), nullable=False, server_default="uncategorized"),
                   Column("slot", String(8), nullable=False, server_default="any"),
                   Column("note", Text, nullable=False, server_default=""),
                   Column("is_abnormal", Boolean, nullable=False, server_default=text("false"))):
        inspections.append_column(column)
    for constraint in list(inspections.constraints):
        if isinstance(constraint, UniqueConstraint) and constraint.name == "patrol_one_inspection_per_period":
            inspections.constraints.remove(constraint)
    inspections.append_constraint(UniqueConstraint("point_id", "frequency", "period_key", "slot",
                                                  name="patrol_one_inspection_per_slot"))
    Table("patrol_inspection_photos", metadata,
          Column("id", Integer, primary_key=True),
          Column("inspection_id", Integer, ForeignKey("patrol_inspections.id"), nullable=False, index=True),
          Column("data", LargeBinary, nullable=False), Column("mime_type", String(40), nullable=False, server_default="image/jpeg"),
          Column("size_bytes", Integer, nullable=False), Column("width", Integer, nullable=False),
          Column("height", Integer, nullable=False), Column("created_at", DateTime, nullable=False))
    Table("patrol_schema_versions", metadata,
          Column("version", Integer, primary_key=True), Column("applied_at", DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP")))
    return metadata


@pytest.fixture
def version_two(engine):
    metadata = version_two_metadata()
    metadata.create_all(engine)
    seed_legacy_rows(engine, legacy_metadata())
    with engine.begin() as connection:
        connection.execute(metadata.tables["patrol_schema_versions"].insert().values(version=2))
        connection.execute(metadata.tables["patrol_inspections"].update().where(
            metadata.tables["patrol_inspections"].c.id == 51).values(is_abnormal=True, note="Original abnormal note"))
        connection.execute(metadata.tables["patrol_inspections"].insert(), dict(
            id=52, user_id=17, point_id=23, binding_id=41, created_at=datetime(2026, 11, 4, 1, 2, 3),
            period_key="2026-11-04", frequency="daily", point_code="1F-A01", point_name="Normal snapshot",
            point_floor=1, user_name="Original person snapshot", is_abnormal=False))
        connection.execute(metadata.tables["patrol_inspection_photos"].insert(), dict(
            id=81, inspection_id=51, data=b"existing-photo-fixture", size_bytes=22, width=2, height=1,
            created_at=datetime(2026, 11, 3, 1, 2, 3)))
    return metadata


@pytest.fixture
def version_three(engine, version_two):
    metadata = version_two
    issues = InspectionIssue.__table__.to_metadata(metadata)
    events = IssueEvent.__table__.to_metadata(metadata)
    with engine.begin() as connection:
        issues.create(connection)
        events.create(connection)
        connection.execute(metadata.tables["patrol_schema_versions"].insert().values(version=3))
        connection.execute(issues.insert().values(
            inspection_id=51, status="resolved", opened_at=datetime(2026, 11, 3, 1, 2, 3),
            resolved_at=datetime(2026, 11, 3, 5), resolved_by_id=17,
            resolved_by_name="Original manager", resolution_note="Existing repair"))
        connection.execute(events.insert().values(
            inspection_id=51, actor_id=17, actor_name="Original manager", action="resolved",
            note="Existing repair", created_at=datetime(2026, 11, 3, 5)))
        # The old record still says 1F; only the point's current location is known.
        connection.execute(metadata.tables["patrol_points"].update().values(floor=14, code="4M-A01"))
    return metadata


def snapshot(connection, metadata):
    return {table.name: connection.execute(select(table).order_by(*table.primary_key.columns)).all()
            for table in metadata.sorted_tables}


@pytest.fixture
def version_four(engine, version_three):
    """Frozen pre-v5 account/point layout with real prior inspection history."""
    schedules = version_three.tables["patrol_point_schedules"]
    with engine.begin() as connection:
        for name, column_type in (("floor", Integer()), ("point_code", String(30)), ("point_name", String(100))):
            column = Column(name, column_type, nullable=True)
            schedules.append_column(column)
            connection.exec_driver_sql("ALTER TABLE patrol_point_schedules ADD COLUMN "
                                       + str(CreateColumn(column).compile(dialect=connection.dialect)))
        connection.execute(schedules.update().values(floor=14, point_code="4M-A01", point_name="Original point"))
        connection.execute(version_three.tables["patrol_schema_versions"].insert().values(version=4))
        connection.execute(version_three.tables["patrol_users"].insert(), [dict(
            id=user_id, username=f"worker{user_id}", display_name=f"Fixture reporter {user_id}", password_hash="fixture-hash",
            role="inspector", active=True, must_change_password=False, auth_version=3, created_at=datetime(2026, 11, 3),
        ) for user_id in (18, 19)])
    return version_three


def test_fresh_database_and_idempotent_upgrade(engine):
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        before = connection.exec_driver_sql("SELECT * FROM patrol_schema_versions").all()
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT * FROM patrol_schema_versions").all() == before
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    assert len(inspect(engine).get_table_names()) == 16
    assert inspect(engine).has_table("patrol_executions")
    assert inspect(engine).has_table("patrol_revoked_sessions")
    assert inspect(engine).has_table("patrol_login_events")
    assert inspect(engine).has_table("patrol_offline_submissions")


def test_v1_rows_ids_qr_credentials_and_unrelated_data_survive(engine, legacy):
    with engine.connect() as connection:
        before = snapshot(connection, legacy)
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert snapshot(connection, legacy) == before
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
        assert connection.exec_driver_sql("SELECT category FROM patrol_points").scalar_one() == "uncategorized"
        assert connection.exec_driver_sql("SELECT category FROM patrol_point_schedules").scalar_one() == "uncategorized"
        assert connection.exec_driver_sql("SELECT floor,point_code,point_name FROM patrol_point_schedules").one() == (1, "1F-A01", "Original point")
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
        additions = ({"patrol_execution_reviews", "patrol_spot_request_once", "patrol_one_standard_per_slot",
                      "patrol_person_am_once", "patrol_person_pm_once"}
                     if name == "patrol_inspections" else set())
        assert {index["name"] for index in after_inspector.get_indexes(name)} == index_names[name] | additions
        assert {(tuple(key["constrained_columns"]), key["referred_table"], tuple(key["referred_columns"]))
                for key in after_inspector.get_foreign_keys(name) if key["name"] != "patrol_final_execution_slot"} == foreign_keys[name]
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
    slot_index = next(index for index in Inspection.__table__.indexes if index.name == "patrol_one_standard_per_slot")
    assert str(CreateIndex(slot_index).compile(dialect=dialect)) == (
        "CREATE UNIQUE INDEX patrol_one_standard_per_slot ON patrol_inspections "
        "(point_id, frequency, period_key, slot) WHERE workflow_mode = 'standard'")
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


def test_v2_upgrade_preserves_old_columns_and_backfills_abnormal_once(engine, version_two):
    with engine.connect() as connection:
        before = snapshot(connection, version_two)
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.upper())

    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert upgrade_schema(engine) == LATEST_VERSION
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    changing_statements = [statement for statement in statements
                           if statement.lstrip().startswith(("ALTER TABLE", "DROP TABLE", "UPDATE PATROL_"))]
    assert all(statement.lstrip().startswith(("ALTER TABLE PATROL_POINT_SCHEDULES ADD COLUMN FLOOR",
                                             "ALTER TABLE PATROL_USERS ADD COLUMN PATROL_CATEGORY",
                                             "ALTER TABLE PATROL_USERS ADD COLUMN GENERAL_MANAGER_TITLE",
                                             "ALTER TABLE PATROL_USERS ADD COLUMN ENGINEERING_INSPECTOR_TITLE",
                                             "ALTER TABLE PATROL_USERS ADD COLUMN UI_LANGUAGE",
                                             "ALTER TABLE PATROL_USERS ADD COLUMN SIMPLE_EXECUTOR_UI",
                                             "ALTER TABLE PATROL_POINTS ADD COLUMN DELETED_AT",
                                             "ALTER TABLE PATROL_POINTS ADD COLUMN INSPECTION_TEAM",
                                             "ALTER TABLE PATROL_POINTS ADD COLUMN PENDING_FREQUENCY",
                                             "ALTER TABLE PATROL_POINTS ADD COLUMN FREQUENCY_EFFECTIVE_DATE",
                                             "ALTER TABLE PATROL_POINT_SCHEDULES ADD COLUMN RETIRED_AT",
                                             "ALTER TABLE PATROL_POINT_SCHEDULES ADD COLUMN POINT_CODE",
                                             "ALTER TABLE PATROL_POINT_SCHEDULES ADD COLUMN POINT_NAME",
                                             "ALTER TABLE PATROL_POINTS ADD COLUMN WORKFLOW_MODE",
                                             "ALTER TABLE PATROL_POINT_SCHEDULES ADD COLUMN WORKFLOW_MODE",
                                             "ALTER TABLE PATROL_POINT_SCHEDULES ADD COLUMN WORKFLOW_CHANGED_AT",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN WORKFLOW_MODE",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN EXECUTION_ID",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN SPOT_REQUEST_ID",
                                             "ALTER TABLE PATROL_INSPECTIONS DROP CONSTRAINT PATROL_ONE_INSPECTION_PER_SLOT",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD CONSTRAINT PATROL_FINAL_EXECUTION_SLOT",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD CONSTRAINT PATROL_INSPECTION_WORKFLOW",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD CONSTRAINT PATROL_PERSONAL_DAY_REQUIRED",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN PERSONAL_DAY",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN LEGACY_SLOT_REPEAT",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN LEGACY_UNSCHEDULED",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN EXECUTOR_VISIT",
                                             "ALTER TABLE PATROL_INSPECTIONS ADD COLUMN CHECKLIST_DATA",
                                             "ALTER TABLE PATROL_EXECUTIONS ADD COLUMN CHECKLIST_DATA",
                                             "ALTER TABLE PATROL_POINT_SCHEDULES ADD COLUMN LEGACY_UNSCHEDULED",
                                             "ALTER TABLE PATROL_EXECUTIONS DROP CONSTRAINT PATROL_EXECUTION_VALID_SLOT",
                                             "ALTER TABLE PATROL_EXECUTIONS ADD CONSTRAINT PATROL_EXECUTION_VALID_SLOT",
                                             "DROP TABLE PATROL_EXECUTIONS",
                                             "ALTER TABLE _PATROL_MIGRATE_EXECUTIONS RENAME TO PATROL_EXECUTIONS",
                                             "UPDATE PATROL_INSPECTIONS SET PERSONAL_DAY=",
                                             "UPDATE PATROL_POINT_SCHEDULES SET LEGACY_UNSCHEDULED=",
                                             "UPDATE PATROL_POINTS SET FREQUENCY=",
                                             "DROP TABLE PATROL_INSPECTIONS",
                                             "ALTER TABLE _PATROL_MIGRATE_INSPECTIONS RENAME TO PATROL_INSPECTIONS",
                                             "UPDATE PATROL_POINTS SET WORKFLOW_MODE=",
                                             "UPDATE PATROL_POINT_SCHEDULES SET FLOOR=",
                                             "UPDATE PATROL_POINT_SCHEDULES SET POINT_CODE=",
                                             "UPDATE PATROL_POINT_SCHEDULES SET POINT_NAME=")) for statement in changing_statements)
    with engine.connect() as connection:
        after = snapshot(connection, version_two)
        for table_name in before:
            if table_name != "patrol_schema_versions":
                assert after[table_name] == before[table_name]
        assert after["patrol_schema_versions"][0] == before["patrol_schema_versions"][0]
        assert [row[0] for row in after["patrol_schema_versions"]] == [2, LATEST_VERSION]
        assert connection.execute(select(InspectionIssue.__table__)).one() == (
            51, "open", datetime(2026, 11, 3, 1, 2, 3), None, None, "", "")
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_issue_events").scalar_one() == 0
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
    # Version 3 does not periodically backfill flags changed behind the workflow.
    with engine.begin() as connection:
        connection.execute(Inspection.__table__.update().where(Inspection.id == 52).values(is_abnormal=True))
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_inspection_issues").scalar_one() == 1


def test_v2_backfill_never_overwrites_existing_resolved_case_or_events(engine, version_two):
    with engine.begin() as connection:
        InspectionIssue.__table__.create(connection)
        IssueEvent.__table__.create(connection)
        connection.execute(InspectionIssue.__table__.insert().values(
            inspection_id=51, status="resolved", opened_at=datetime(2026, 11, 3, 1, 2, 3),
            resolved_at=datetime(2026, 11, 3, 5), resolved_by_id=17,
            resolved_by_name="Original manager", resolution_note="Already repaired"))
        connection.execute(IssueEvent.__table__.insert().values(
            inspection_id=51, actor_id=17, actor_name="Original manager", action="resolved",
            note="Already repaired", created_at=datetime(2026, 11, 3, 5)))
        before_issue = connection.execute(select(InspectionIssue.__table__)).all()
        before_events = connection.execute(select(IssueEvent.__table__)).all()
    upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.execute(select(InspectionIssue.__table__)).all() == before_issue
        assert connection.execute(select(IssueEvent.__table__)).all() == before_events
        assert connection.execute(select(Inspection.is_abnormal).where(Inspection.id == 51)).scalar_one() is True


def test_v2_upgrade_failure_rolls_back_backfill_and_new_tables(engine, version_two, monkeypatch):
    with engine.connect() as connection:
        before_rows = snapshot(connection, version_two)
        before_schema = connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name").all()

    def fail_validation(connection):
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_inspection_issues").scalar_one() == 1
        raise RuntimeError("Injected v3 migration failure")

    monkeypatch.setattr(migrations, "_validate_current", fail_validation)
    with pytest.raises(RuntimeError, match="Injected v3"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, version_two) == before_rows
        assert connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name").all() == before_schema
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1


@pytest.mark.parametrize("changes", [
    {"status": "unexpected"},
    {"status": "resolved"},
    {"resolved_at": datetime(2026, 11, 3, 4), "resolved_by_id": 17, "resolved_by_name": "Manager"},
    {"resolution_note": "Open cases must keep closure notes in event history"},
])
def test_issue_status_and_closure_consistency_constraints(engine, version_two, changes):
    upgrade_schema(engine)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(InspectionIssue.__table__.update().where(InspectionIssue.inspection_id == 51).values(**changes))


def test_issue_relationships_events_order_and_history_flag_survive_resolution_and_reopen(engine, version_two):
    upgrade_schema(engine)
    instant = datetime(2026, 11, 3, 4)
    with Session(engine) as session:
        inspection = session.get(Inspection, 51)
        issue = inspection.issue
        assert issue.inspection is inspection
        issue.status = "resolved"
        issue.resolved_at = instant
        issue.resolved_by_id = 17
        issue.resolved_by_name = "Manager snapshot"
        issue.resolution_note = "Repaired"
        issue.events.append(IssueEvent(actor_id=17, actor_name="Manager snapshot", action="resolved", note="Repaired", created_at=instant))
        session.commit()
        issue.status = "open"
        issue.resolved_at = issue.resolved_by_id = None
        issue.resolved_by_name = issue.resolution_note = ""
        issue.events.append(IssueEvent(actor_id=17, actor_name="Manager snapshot", action="reopened", note="Needs another check", created_at=instant))
        session.commit()
    with Session(engine) as session:
        inspection = session.get(Inspection, 51)
        assert inspection.is_abnormal is True
        assert inspection.note == "Original abnormal note"
        assert inspection.issue.status == "open"
        assert [event.action for event in inspection.issue.events] == ["resolved", "reopened"]
        assert [event.note for event in inspection.issue.events] == ["Repaired", "Needs another check"]
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(InspectionIssue.__table__.insert().values(inspection_id=51, opened_at=instant))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(IssueEvent.__table__.insert().values(inspection_id=99999, actor_id=17, actor_name="Manager", action="resolved", created_at=instant))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(IssueEvent.__table__.insert().values(inspection_id=51, actor_id=17, actor_name="Manager", action="deleted", created_at=instant))


def test_existing_v3_rejects_missing_nullable_resolution_columns(engine):
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE patrol_inspection_issues")
        connection.exec_driver_sql(
            "CREATE TABLE patrol_inspection_issues (inspection_id INTEGER NOT NULL PRIMARY KEY, "
            "status VARCHAR(10) NOT NULL DEFAULT 'open', opened_at DATETIME NOT NULL, "
            "resolved_by_name VARCHAR(100) NOT NULL DEFAULT '', resolution_note TEXT NOT NULL DEFAULT '', "
            "CONSTRAINT patrol_issue_status CHECK(status IN ('open','resolved')), "
            "CONSTRAINT patrol_issue_resolution_fields CHECK(1=1))")
    with pytest.raises(SchemaMigrationError, match="resolution columns are missing"):
        upgrade_schema(engine)


def test_existing_v3_rejects_missing_event_action_constraint(engine):
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE patrol_issue_events")
        connection.exec_driver_sql(
            "CREATE TABLE patrol_issue_events (id INTEGER PRIMARY KEY, "
            "inspection_id INTEGER NOT NULL REFERENCES patrol_inspection_issues(inspection_id), "
            "actor_id INTEGER NOT NULL REFERENCES patrol_users(id), actor_name VARCHAR(100) NOT NULL, "
            "action VARCHAR(20) NOT NULL, note TEXT NOT NULL, created_at DATETIME NOT NULL)")
    with pytest.raises(SchemaMigrationError, match="event action validation is missing"):
        upgrade_schema(engine)


def test_v3_location_history_upgrade_preserves_records_photos_issues_and_events(engine, version_three):
    with engine.connect() as connection:
        before = snapshot(connection, version_three)
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        after = snapshot(connection, version_three)
        for table_name in before:
            if table_name != "patrol_schema_versions":
                assert after[table_name] == before[table_name]
        assert after["patrol_schema_versions"][:2] == before["patrol_schema_versions"]
        assert [row[0] for row in after["patrol_schema_versions"]] == [2, 3, LATEST_VERSION]
        assert connection.exec_driver_sql("SELECT floor,point_code,point_name FROM patrol_point_schedules").one() == (14, "4M-A01", "Original point")
        assert connection.exec_driver_sql("SELECT point_floor,point_code FROM patrol_inspections WHERE id=51").one() == (1, "1F-A01")
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
    # A restart must not rewrite the captured location to a later location.
    with engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_points SET floor=2,code='2F-A01',name='Later name'")
        # Simulate a previous worker finishing during rollout: these nullable
        # fields are omitted and the application handles the documented fallback.
        connection.execute(PointSchedule.__table__.insert().values(
            id=93, point_id=23, effective_date=date(2026, 11, 5), frequency="daily", active=True))
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT floor,point_code,point_name FROM patrol_point_schedules WHERE id=31").one() == (14, "4M-A01", "Original point")
        assert connection.exec_driver_sql("SELECT floor,point_code,point_name FROM patrol_point_schedules WHERE id=93").one() == (None, None, None)


def test_v3_upgrade_preserves_preexisting_nonnull_location_snapshot(engine, version_three):
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE patrol_point_schedules ADD COLUMN floor INTEGER")
        connection.exec_driver_sql("ALTER TABLE patrol_point_schedules ADD COLUMN point_code VARCHAR(30)")
        connection.exec_driver_sql("ALTER TABLE patrol_point_schedules ADD COLUMN point_name VARCHAR(100)")
        connection.exec_driver_sql("UPDATE patrol_point_schedules SET floor=1,point_code='1F-ORIGINAL',point_name='Original captured name'")
    upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT floor,point_code,point_name FROM patrol_point_schedules").one() == (1, "1F-ORIGINAL", "Original captured name")


def test_v3_location_upgrade_failure_rolls_back_columns_backfill_and_version(engine, version_three, monkeypatch):
    with engine.connect() as connection:
        before_rows = snapshot(connection, version_three)
        before_schema = connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name").all()

    def fail_validation(connection):
        assert connection.exec_driver_sql("SELECT floor,point_code,point_name FROM patrol_point_schedules").one() == (14, "4M-A01", "Original point")
        raise RuntimeError("Injected v4 location migration failure")

    monkeypatch.setattr(migrations, "_validate_current", fail_validation)
    with pytest.raises(RuntimeError, match="Injected v4"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, version_three) == before_rows
        assert connection.exec_driver_sql("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name").all() == before_schema
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1


def test_v4_upgrade_keeps_old_accounts_unassigned_and_all_archive_history_intact(engine, version_four):
    with engine.connect() as connection:
        before = snapshot(connection, version_four)
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        after = snapshot(connection, version_four)
        assert all(after[name] == values for name, values in before.items() if name != "patrol_schema_versions")
        assert after["patrol_schema_versions"][:-1] == before["patrol_schema_versions"]
        assert [row[0] for row in after["patrol_schema_versions"]] == [2, 3, 4, LATEST_VERSION]
        assert connection.execute(select(User.id, User.patrol_category).order_by(User.id)).all() == [(17, None), (18, None), (19, None)]
        assert connection.execute(select(Point.id, Point.deleted_at)).all() == [(23, None)]
        assert connection.execute(select(PointSchedule.id, PointSchedule.retired_at)).all() == [(31, None)]
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
    archived_at = datetime(2026, 11, 4, 8, 12, 34)
    with engine.begin() as connection:
        connection.execute(User.__table__.update().where(User.id == 18).values(patrol_category="general"))
        connection.execute(User.__table__.update().where(User.id == 19).values(patrol_category="safety"))
        connection.execute(Point.__table__.update().where(Point.id == 23).values(deleted_at=archived_at))
        # An older worker creating a row during deployment can omit both v5 fields.
        connection.execute(version_four.tables["patrol_users"].insert().values(
            id=20, username="rolling-worker", display_name="Older worker", password_hash="fixture-hash", role="inspector",
            active=True, must_change_password=False, auth_version=1, created_at=datetime(2026, 11, 4)))
        connection.execute(version_four.tables["patrol_points"].insert().values(
            id=24, code="1F-QR02", name="Older QR", floor=1, frequency="daily", active=True,
            qr_token="old-worker-qr", created_at=datetime(2026, 11, 4), schedule_start=date(2026, 11, 4)))
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert connection.execute(select(User.id, User.patrol_category).order_by(User.id)).all() == [
            (17, None), (18, "general"), (19, "safety"), (20, None)]
        assert connection.execute(select(Point.id, Point.deleted_at).order_by(Point.id)).all() == [(23, archived_at), (24, None)]
        preserved = snapshot(connection, version_four)
        for table in ("patrol_point_schedules", "patrol_device_bindings", "patrol_inspections", "patrol_inspection_photos",
                      "patrol_inspection_issues", "patrol_issue_events", "patrol_audit_logs"):
            assert preserved[table] == before[table]


@pytest.mark.parametrize("invalid", ["", "uncategorized", "all"])
def test_v5_never_accepts_ambiguous_or_unrestricted_inspector_scope(engine, version_four, invalid):
    upgrade_schema(engine)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(User.__table__.update().where(User.id == 18).values(patrol_category=invalid))
    with engine.connect() as connection:
        assert connection.execute(select(User.patrol_category).where(User.id == 18)).scalar_one() is None


def test_v4_upgrade_rollback_preserves_version_rows_and_unrelated_database(engine, version_four, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, version_four)
    def stop_after_alters(connection):
        assert "patrol_category" in {col["name"] for col in inspect(connection).get_columns("patrol_users")}
        assert "deleted_at" in {col["name"] for col in inspect(connection).get_columns("patrol_points")}
        assert "retired_at" in {col["name"] for col in inspect(connection).get_columns("patrol_point_schedules")}
        raise RuntimeError("Injected v5 migration failure")
    monkeypatch.setattr(migrations, "_validate_current", stop_after_alters)
    with pytest.raises(RuntimeError, match="Injected v5"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert "patrol_category" not in {col["name"] for col in inspect(connection).get_columns("patrol_users")}
        assert "deleted_at" not in {col["name"] for col in inspect(connection).get_columns("patrol_points")}
        assert "retired_at" not in {col["name"] for col in inspect(connection).get_columns("patrol_point_schedules")}
        assert snapshot(connection, version_four) == before
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]


def test_v4_partial_install_without_category_constraint_refuses_upgrade(engine, version_four):
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE patrol_users ADD COLUMN patrol_category VARCHAR(20)")
    with pytest.raises(SchemaMigrationError, match="category validation is missing"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT MAX(version) FROM patrol_schema_versions").scalar_one() == 4
        assert "deleted_at" not in {col["name"] for col in inspect(connection).get_columns("patrol_points")}


def test_v5_schedule_keeps_retirement_instant_after_restore_and_legacy_writes(engine, version_four):
    upgrade_schema(engine)
    instant = datetime(2026, 11, 4, 7, 30)
    with engine.begin() as connection:
        connection.execute(Point.__table__.update().where(Point.id == 23).values(active=False, deleted_at=instant))
        connection.execute(PointSchedule.__table__.insert().values(id=32, point_id=23, active=False, retired_at=instant,
                           effective_date=date(2026, 11, 4), frequency="daily2", category="safety"))
        connection.execute(Point.__table__.update().where(Point.id == 23).values(deleted_at=None))
        connection.execute(version_four.tables["patrol_point_schedules"].insert().values(id=33, point_id=23, active=False,
                           effective_date=date(2026, 11, 5), frequency="daily", category="safety"))
    upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.execute(select(Point.active, Point.deleted_at).where(Point.id == 23)).one() == (False, None)
        assert connection.execute(select(PointSchedule.id, PointSchedule.retired_at).order_by(PointSchedule.id)).all() == [
            (31, None), (32, instant), (33, None)]


def test_v4_preexisting_category_default_cannot_grant_access_to_legacy_accounts(engine, version_four):
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE patrol_users ADD COLUMN patrol_category VARCHAR(20) DEFAULT 'safety' "
                                   "CONSTRAINT patrol_user_category_allowed CHECK (patrol_category IN ('safety','general'))")
    with pytest.raises(SchemaMigrationError, match="without a default"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT MAX(version) FROM patrol_schema_versions").scalar_one() == 4
        assert "deleted_at" not in {col["name"] for col in inspect(connection).get_columns("patrol_points")}


@pytest.fixture
def version_five(engine, version_four):
    """Freeze the deployed v5 layout, including assigned users and a retired point."""
    with engine.begin() as connection:
        for table, column in (
            ("patrol_users", Column("patrol_category", String(20), CheckConstraint(
                "patrol_category IN ('safety', 'general')", name="patrol_user_category_allowed"))),
            ("patrol_points", Column("deleted_at", DateTime)),
            ("patrol_point_schedules", Column("retired_at", DateTime)),
        ):
            version_four.tables[table].append_column(column)
            definition = str(CreateColumn(column).compile(dialect=connection.dialect))
            connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {definition}")
        connection.execute(version_four.tables["patrol_users"].update().where(
            version_four.tables["patrol_users"].c.id == 18).values(patrol_category="safety"))
        retired_at = datetime(2026, 11, 4, 7, 30)
        connection.execute(version_four.tables["patrol_points"].update().values(active=False, deleted_at=retired_at))
        connection.execute(version_four.tables["patrol_point_schedules"].insert().values(
            id=32, point_id=23, active=False, retired_at=retired_at, effective_date=retired_at.date(),
            frequency="daily2", category="safety"))
        connection.execute(version_four.tables["patrol_schema_versions"].insert().values(version=5))
    return version_four


def test_v5_adds_empty_revocation_table_and_preserves_other_tables(engine, version_five):
    with engine.connect() as connection:
        before = snapshot(connection, version_five)
        old_tables = set(inspect(connection).get_table_names())

    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.begin() as connection:
        assert set(inspect(connection).get_table_names()) == old_tables | {
            "patrol_revoked_sessions", "patrol_executions", "patrol_login_events", "patrol_offline_submissions",
            "patrol_issue_event_photos"}
        after = snapshot(connection, version_five)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_revoked_sessions").scalar_one() == 0
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
        revoked = db.metadata.tables["patrol_revoked_sessions"]
        row = dict(token_hash="0" * 64, user_id=18, auth_version=3, revoked_at=datetime(2026, 11, 4, 8))
        connection.execute(revoked.insert().values(**row))

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(revoked.insert().values(**row))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(revoked.insert().values(**{**row, "token_hash": "1" * 64, "user_id": 99999}))

    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert connection.execute(select(revoked)).mappings().one() == row
        assert connection.exec_driver_sql("SELECT version FROM patrol_schema_versions ORDER BY version").scalars().all() == [2, 3, 4, 5, LATEST_VERSION]


def test_v5_failure_rolls_back_new_table_and_preserves_shared_database(engine, version_five, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, version_five)
    def fail_before_commit(connection):
        assert inspect(connection).has_table("patrol_revoked_sessions")
        raise RuntimeError("Injected v6 migration failure")
    monkeypatch.setattr(migrations, "_validate_current", fail_before_commit)
    with pytest.raises(RuntimeError, match="Injected v6"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert not inspect(connection).has_table("patrol_revoked_sessions")
        assert snapshot(connection, version_five) == before
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]


def test_v5_partial_revocation_table_without_unique_token_refuses_upgrade(engine, version_five):
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE patrol_revoked_sessions (token_hash VARCHAR(64) NOT NULL, "
                                   "user_id INTEGER NOT NULL REFERENCES patrol_users(id), "
                                   "auth_version INTEGER NOT NULL, revoked_at TIMESTAMP NOT NULL)")
    with pytest.raises(SchemaMigrationError, match="token primary key"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT MAX(version) FROM patrol_schema_versions").scalar_one() == 5
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
