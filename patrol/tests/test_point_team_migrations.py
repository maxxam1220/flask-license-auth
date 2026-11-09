"""Schema 15 is an additive responsibility field, never a historical rewrite."""
from datetime import date, datetime

import pytest
from sqlalchemy import CheckConstraint, Column, ForeignKey, Integer, MetaData, String, Table, event, func, inspect, select
from sqlalchemy.exc import IntegrityError

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import Point, PointSchedule, SchemaVersion, db
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store


@pytest.fixture
def v14(engine):
    metadata = MetaData()
    points = Table(Point.__tablename__, metadata, *[column._copy() for column in Point.__table__.columns
                   if column.name not in ("inspection_team", "pending_frequency", "frequency_effective_date")],
                   CheckConstraint(migrations.FLOOR_CHECK, name="patrol_point_floor"))
    with engine.begin() as connection:
        points.create(connection)
        db.metadata.create_all(connection, tables=[table for table in db.metadata.sorted_tables
            if table.name.startswith("patrol_") and table.name != Point.__tablename__])
        for identifier, category, mode in ((1, "general", "two_stage"), (2, "safety", "standard"),
                                            (3, "uncategorized", "standard")):
            connection.execute(points.insert().values(id=identifier, code=f"1F-BEFORE{identifier}",
                name="Original point", floor=1, category=category, frequency="daily", workflow_mode=mode,
                active=True, qr_token=f"preserved-qr-{identifier}", schedule_start=date(2026, 1, 1),
                created_at=datetime(2026, 1, 1)))
        connection.execute(PointSchedule.__table__.insert().values(point_id=1, effective_date=date(2026, 1, 1),
            frequency="daily", category="general", workflow_mode="two_stage", active=True))
        connection.execute(SchemaVersion.__table__.insert().values(version=14))
        outside = Table("unrelated_equipment", metadata, Column("id", Integer, primary_key=True),
                        Column("point_id", Integer, ForeignKey("patrol_points.id")), Column("note", String(30)))
        outside.create(connection)
        connection.execute(outside.insert().values(id=1, point_id=1, note="Unchanged"))
        reflected = MetaData()
        reflected.reflect(connection)
        return reflected


def test_v15_only_adds_default_team_and_preserves_existing_rows(engine, v14):
    with engine.connect() as connection:
        before = snapshot(connection, v14)
    statements = []
    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert upgrade_schema(engine) == LATEST_VERSION == 15
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not any(s.lstrip().upper().startswith(("DROP TABLE", "DELETE ", "UPDATE ")) for s in statements)
    assert sum("ADD COLUMN inspection_team" in s for s in statements) == 1
    assert sum("ADD COLUMN pending_frequency" in s for s in statements) == 1
    assert sum("ADD COLUMN frequency_effective_date" in s for s in statements) == 1
    with engine.begin() as connection:
        after = snapshot(connection, v14)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert set(connection.scalars(select(Point.inspection_team))) == {"general"}
        assert connection.execute(select(Point.pending_frequency, Point.frequency_effective_date)).all() == [(None, None)] * 3
        connection.execute(v14.tables["patrol_points"].insert().values(id=4, code="OLD-WORKER", name="Old worker",
            floor=1, category="general", frequency="daily", workflow_mode="spot", active=True,
            qr_token="old-worker-qr", schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1)))
        connection.execute(Point.__table__.update().where(Point.id == 1).values(inspection_team="engineering"))
    assert upgrade_schema(engine) == 15
    with engine.connect() as connection:
        assert connection.execute(select(Point.id, Point.inspection_team).where(Point.id.in_((1, 4))).order_by(Point.id)).all() == [
            (1, "engineering"), (4, "general")]
        assert connection.scalar(select(func.count()).where(SchemaVersion.version == 15)) == 1


@pytest.mark.parametrize("identifier,team", [(2, "engineering"), (3, "engineering"), (1, "unknown"), (1, None)])
def test_v15_database_enforces_allowed_team_and_general_category(engine, v14, identifier, team):
    upgrade_schema(engine)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(Point.__table__.update().where(Point.id == identifier).values(inspection_team=team))
        assert connection.scalar(select(Point.inspection_team).where(Point.id == identifier)) == "general"


def test_v15_failure_rolls_back_column_constraint_version_and_data(engine, v14, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, v14)
    original = migrations._validate_current
    def fail(connection):
        original(connection)
        raise RuntimeError("Injected team migration failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="Injected team"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert "inspection_team" not in {c["name"] for c in inspect(connection).get_columns(Point.__tablename__)}
        assert not {"pending_frequency", "frequency_effective_date"} & {c["name"] for c in inspect(connection).get_columns(Point.__tablename__)}
        assert snapshot(connection, v14) == before


@pytest.mark.parametrize("definition", ["VARCHAR(20) NOT NULL DEFAULT 'general'", "VARCHAR(20) DEFAULT 'general'",
    "VARCHAR(21) NOT NULL DEFAULT 'general' CONSTRAINT patrol_point_inspection_team CHECK "
    "(inspection_team = 'general' OR (inspection_team = 'engineering' AND category = 'general'))"])
def test_v15_partial_or_invalid_column_refuses_upgrade(engine, v14, definition):
    with engine.begin() as connection:
        connection.exec_driver_sql("ALTER TABLE patrol_points ADD COLUMN inspection_team " + definition)
    with pytest.raises(SchemaMigrationError):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 14


@pytest.mark.parametrize("frequency,day", [("weekly", None), (None, date(2026, 11, 10)), ("bogus", date(2026, 11, 10))])
def test_v15_database_requires_a_valid_paired_scheduled_frequency(engine, v14, frequency, day):
    upgrade_schema(engine)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(Point.__table__.update().where(Point.id == 1).values(
                pending_frequency=frequency, frequency_effective_date=day))
        assert connection.execute(select(Point.pending_frequency, Point.frequency_effective_date).where(Point.id == 1)).one() == (None, None)
