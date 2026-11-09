"""Schema 14 is additive and safe for users still served by the previous release."""
from datetime import datetime

import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, String, Table, event, inspect, select
from sqlalchemy.exc import IntegrityError

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import DeviceBinding, SchemaVersion, User, db
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store


@pytest.fixture
def v13(engine):
    metadata = MetaData()
    users = Table(User.__tablename__, metadata, *[column._copy() for column in User.__table__.columns
                if column.name not in ("ui_language", "simple_executor_ui")])
    with engine.begin() as connection:
        users.create(connection)
        db.metadata.create_all(connection, tables=[table for table in db.metadata.sorted_tables
            if table.name.startswith("patrol_") and table.name != User.__tablename__])
        now = datetime(2026, 11, 6, 6)
        for identifier, role, category in ((1, "admin", None), (2, "executor", "general"), (3, "inspector", "safety")):
            connection.execute(users.insert().values(id=identifier, username=f"before-{identifier}",
                display_name=f"Existing {identifier}", password_hash="preserved-password-hash", role=role,
                patrol_category=category, active=True, must_change_password=False, auth_version=7, created_at=now))
        connection.execute(DeviceBinding.__table__.insert().values(id=12, user_id=2, token_hash="a" * 64,
            label="Existing phone", status="approved", created_at=now))
        connection.execute(SchemaVersion.__table__.insert().values(version=13, applied_at=now))
        outside = Table("unrelated_staff", metadata, Column("id", Integer, primary_key=True),
                        Column("user_id", Integer, ForeignKey("patrol_users.id")), Column("note", String(30)))
        outside.create(connection)
        connection.execute(outside.insert().values(id=1, user_id=2, note="Leave unchanged"))
        result = MetaData()
        result.reflect(connection)
        return result


def test_additive_preferences_preserve_all_existing_rows_and_old_worker_writes(engine, v13):
    with engine.connect() as connection:
        before = snapshot(connection, v13)
    statements = []
    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert upgrade_schema(engine) == LATEST_VERSION
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not any(statement.lstrip().upper().startswith(("DROP TABLE", "DELETE ", "UPDATE ")) for statement in statements)
    assert sum("ADD COLUMN ui_language" in statement for statement in statements) == 1
    assert sum("ADD COLUMN simple_executor_ui" in statement for statement in statements) == 1
    with engine.begin() as connection:
        after = snapshot(connection, v13)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert connection.execute(select(User.ui_language, User.simple_executor_ui)).all() == [("zh-Hant", False)] * 3
        connection.execute(v13.tables["patrol_users"].insert().values(id=4, username="old-worker",
            display_name="Old worker", password_hash="unchanged", role="executor", patrol_category="general",
            active=True, must_change_password=False, auth_version=1, created_at=datetime(2026, 11, 6)))
        connection.execute(User.__table__.update().where(User.id == 2).values(ui_language="id", simple_executor_ui=True))
        # An old worker can change a role; the presentation gate still requires an executor.
        old_users = v13.tables["patrol_users"]
        connection.execute(old_users.update().where(old_users.c.id == 2).values(role="inspector"))
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert connection.execute(select(User.id, User.ui_language, User.simple_executor_ui).where(User.id.in_((2, 4)))
                                  .order_by(User.id)).all() == [(2, "id", True), (4, "zh-Hant", False)]


def test_preferences_failure_rolls_back_both_columns_and_version(engine, v13, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, v13)
    original = migrations._validate_current
    def fail(connection):
        original(connection)
        raise RuntimeError("Injected UI migration failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="Injected UI"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert not {"ui_language", "simple_executor_ui"} & {c["name"] for c in inspect(connection).get_columns(User.__tablename__)}
        assert snapshot(connection, v13) == before


def test_only_supported_locale_values_are_accepted_by_database(engine, v13):
    upgrade_schema(engine)
    with engine.begin() as connection:
        for locale in ("id", "vi", "zh-Hant"):
            connection.execute(User.__table__.update().where(User.id == 2).values(ui_language=locale))
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(User.__table__.update().where(User.id == 2).values(ui_language="en"))
        assert connection.scalar(select(User.ui_language).where(User.id == 2)) == "zh-Hant"


@pytest.mark.parametrize("constraint", ["", " CONSTRAINT patrol_user_ui_language CHECK (ui_language <> '')"])
def test_partial_unconstrained_language_column_fails_closed(engine, v13, constraint):
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE patrol_users ADD COLUMN ui_language VARCHAR(10) NOT NULL DEFAULT 'zh-Hant'" + constraint)
    with pytest.raises(SchemaMigrationError, match="language"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(db.func.max(SchemaVersion.version))) == 13
