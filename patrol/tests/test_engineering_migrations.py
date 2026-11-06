"""A title-only additive users column preserves all existing identity and data."""
from datetime import datetime

import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, event, func, inspect, select
from sqlalchemy.exc import IntegrityError

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import DeviceBinding, SchemaVersion, User, db
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store


@pytest.fixture
def v12(engine):
    metadata = MetaData()
    users = Table(User.__tablename__, metadata, *[column._copy() for column in User.__table__.columns
                                                 if column.name != "engineering_inspector_title"])
    with engine.begin() as connection:
        users.create(connection)
        db.metadata.create_all(connection, tables=[table for table in db.metadata.sorted_tables
            if table.name.startswith("patrol_") and table.name != User.__tablename__])
        now = datetime(2026, 11, 6, 6)
        choices = [(1, "admin", None, False), (2, "inspector", "general", False),
                   (3, "inspector", "general", True), (4, "executor", "general", False),
                   (5, "inspector", "safety", False), (6, "inspector", None, False)]
        for identifier, role, category, manager in choices:
            connection.execute(users.insert().values(id=identifier, username=f"before-{identifier}",
                display_name=f"Existing {identifier}", password_hash="preserved-password-hash", role=role,
                patrol_category=category, general_manager_title=manager, active=True, must_change_password=False,
                auth_version=7, created_at=now))
        connection.execute(DeviceBinding.__table__.insert().values(id=12, user_id=2, token_hash="a" * 64,
            label="Existing phone", status="approved", created_at=now))
        connection.execute(SchemaVersion.__table__.insert().values(version=12, applied_at=now))
        outside = Table("unrelated_staff", metadata, Column("id", Integer, primary_key=True),
                        Column("user_id", Integer, ForeignKey("patrol_users.id")), Column("note", String(30)))
        outside.create(connection)
        connection.execute(outside.insert().values(id=1, user_id=2, note="Leave unchanged"))
        result = MetaData()
        result.reflect(connection)
        return result


def test_v13_adds_only_false_title_and_preserves_old_rows_and_external_fk(engine, v12):
    with engine.connect() as connection:
        before = snapshot(connection, v12)
        tables = inspect(connection).get_table_names()
    statements = []
    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert upgrade_schema(engine) == LATEST_VERSION == 13
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not any(statement.lstrip().upper().startswith(("DROP TABLE", "DELETE ", "UPDATE ")) for statement in statements)
    assert sum("ADD COLUMN engineering_inspector_title" in statement for statement in statements) == 1
    with engine.begin() as connection:
        after = snapshot(connection, v12)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before and set(inspect(connection).get_table_names()) == set(tables)
        assert set(connection.scalars(select(User.engineering_inspector_title))) == {False}
        # An old worker can still insert users without knowing the new column.
        connection.execute(v12.tables["patrol_users"].insert().values(id=7, username="old-worker",
            display_name="Old worker", password_hash="unchanged", role="inspector", patrol_category="general",
            general_manager_title=False, active=True, must_change_password=False, auth_version=1,
            created_at=datetime(2026, 11, 6)))
        connection.execute(User.__table__.update().where(User.id == 2).values(engineering_inspector_title=True))
    assert upgrade_schema(engine) == 13
    with engine.connect() as connection:
        assert connection.execute(select(User.id, User.engineering_inspector_title).where(User.id.in_((2, 7)))
                                  .order_by(User.id)).all() == [(2, True), (7, False)]
        assert connection.scalar(select(func.count()).where(SchemaVersion.version == 13)) == 1


@pytest.mark.parametrize("identifier", [1, 3, 4, 5, 6])
def test_engineering_title_cannot_grant_scope_to_other_account_types(engine, v12, identifier):
    upgrade_schema(engine)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(User.__table__.update().where(User.id == identifier).values(engineering_inspector_title=True))
        assert not connection.scalar(select(User.engineering_inspector_title).where(User.id == identifier))


def test_v13_failure_rolls_back_column_constraint_version_and_shared_data(engine, v12, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, v12)
    original = migrations._validate_current
    def fail(connection):
        original(connection)
        raise RuntimeError("Injected engineering migration failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="Injected engineering"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert "engineering_inspector_title" not in {c["name"] for c in inspect(connection).get_columns(User.__tablename__)}
        assert snapshot(connection, v12) == before


@pytest.mark.parametrize("definition", ["BOOLEAN NOT NULL DEFAULT TRUE", "BOOLEAN NOT NULL DEFAULT FALSE", "BOOLEAN DEFAULT FALSE"])
def test_partial_unconstrained_or_unsafe_title_column_refuses_upgrade(engine, v12, definition):
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE patrol_users ADD COLUMN engineering_inspector_title " + definition)
    with pytest.raises(SchemaMigrationError):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 12
