"""Transactional patrol-only schema upgrades for SQLite and PostgreSQL.

Call ``upgrade_schema(engine)`` before serving requests; do not call create_all
first on an existing database. Version 1 is the original unversioned schema.
No credentials, application data, or connection URLs are logged here.
"""
from __future__ import annotations

import re

from sqlalchemy import Column, MetaData, Table, UniqueConstraint, CheckConstraint, exists, inspect, literal, select, text
from sqlalchemy.schema import CreateColumn, CreateTable

from models import Inspection, InspectionIssue, InspectionPhoto, IssueEvent, Point, PointSchedule, SchemaVersion, db


LATEST_VERSION = 4
MIGRATION_LOCK_ID = 714032610302
BASE_TABLES = frozenset({
    "patrol_users", "patrol_points", "patrol_point_schedules",
    "patrol_device_bindings", "patrol_inspections", "patrol_audit_logs",
    "patrol_login_attempts",
})
FLOOR_CHECK = "floor IN (-2, -1, 1, 11, 2, 3, 4, 14, 5, 15)"
OLD_INSPECTION_KEY = ("point_id", "frequency", "period_key")
NEW_INSPECTION_KEY = (*OLD_INSPECTION_KEY, "slot")
SLOT_CONSTRAINT = "patrol_one_inspection_per_slot"


class SchemaMigrationError(RuntimeError):
    """An unsupported or inconsistent schema was left unchanged."""


def upgrade_schema(engine) -> int:
    """Create or upgrade the patrol schema atomically and return its version.

    PostgreSQL serializes this application's migrations with an advisory lock.
    SQLite requires foreign keys disabled outside a transaction while rebuilding
    two parent tables. An explicit BEGIN IMMEDIATE also makes SQLite DDL rollback
    work with Python's legacy sqlite3 transaction mode. Foreign keys are checked
    before commit and the connection's original enforcement setting is restored.
    """
    dialect = engine.dialect.name
    if dialect not in ("sqlite", "postgresql"):
        raise SchemaMigrationError("Only SQLite and PostgreSQL are supported.")
    with engine.connect() as connection:
        if dialect == "postgresql":
            with connection.begin():
                connection.exec_driver_sql("SET LOCAL lock_timeout = '30s'")
                connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_ID})
                return _upgrade_locked(connection)

        original_foreign_keys = connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
        connection.commit()
        try:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
            if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one():
                raise SchemaMigrationError("Could not prepare SQLite foreign keys for migration.")
            connection.commit()
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            version = _upgrade_locked(connection)
            violations = connection.exec_driver_sql("PRAGMA foreign_key_check").all()
            if any(row[0].startswith("patrol_") for row in violations):
                raise SchemaMigrationError("Patrol foreign-key validation failed; migration rolled back.")
            connection.commit()
            return version
        except Exception:
            connection.rollback()
            raise
        finally:
            # Never return a pooled connection with foreign keys accidentally off.
            connection.rollback()
            connection.exec_driver_sql(f"PRAGMA foreign_keys={'ON' if original_foreign_keys else 'OFF'}")
            connection.commit()


def _upgrade_locked(connection) -> int:
    tables = set(inspect(connection).get_table_names())
    version_table = SchemaVersion.__table__
    current = 0
    if version_table.name in tables:
        current = connection.scalar(select(db.func.max(version_table.c.version))) or 0
        if current > LATEST_VERSION:
            raise SchemaMigrationError("Database schema is newer than this application; refusing to downgrade.")

    existing_base = BASE_TABLES & tables
    if existing_base and existing_base != BASE_TABLES:
        missing = ", ".join(sorted(BASE_TABLES - tables))
        raise SchemaMigrationError(f"Incomplete patrol schema; missing tables: {missing}.")
    if current and not existing_base:
        raise SchemaMigrationError("Schema history exists but patrol tables are missing.")

    if not existing_base:
        # Deliberately pass only this application's tables on a shared database.
        db.metadata.create_all(connection, tables=[table for table in db.metadata.sorted_tables
                                                   if table.name.startswith("patrol_")])
    else:
        if current < 2:
            _upgrade_v1_to_v2(connection)
        if current < 3:
            _upgrade_v2_to_v3(connection)
        if current < 4:
            _upgrade_v3_to_v4(connection)

    version_table.create(connection, checkfirst=True)
    _validate_current(connection)
    if current < LATEST_VERSION:
        connection.execute(version_table.insert().values(version=LATEST_VERSION))
    return LATEST_VERSION


def _upgrade_v1_to_v2(connection):
    if connection.dialect.name == "sqlite":
        point_columns = _column_names(connection, "patrol_points")
        floor_checks = inspect(connection).get_check_constraints("patrol_points")
        floor_is_current = any(check["name"] == "patrol_point_floor" and
                               _compact(check["sqltext"]) == _compact(FLOOR_CHECK)
                               for check in floor_checks)
        if "category" not in point_columns or not floor_is_current:
            _sqlite_rebuild(connection, "patrol_points", [Point.__table__.c.category], replace_floor=True)

        inspection_columns = _column_names(connection, "patrol_inspections")
        inspection_additions = [Inspection.__table__.c[name] for name in
                                ("category", "slot", "note", "is_abnormal")]
        keys = _unique_keys(connection, "patrol_inspections")
        if not {column.name for column in inspection_additions} <= inspection_columns or NEW_INSPECTION_KEY not in keys or OLD_INSPECTION_KEY in keys:
            _sqlite_rebuild(connection, "patrol_inspections", inspection_additions, replace_inspection_key=True)
    else:
        _add_missing_columns(connection, "patrol_points", [Point.__table__.c.category])
        _add_missing_columns(connection, "patrol_inspections", [Inspection.__table__.c[name] for name in
                             ("category", "slot", "note", "is_abnormal")])
        _postgres_replace_constraints(connection)

    _add_missing_columns(connection, "patrol_point_schedules", [PointSchedule.__table__.c.category])
    InspectionPhoto.__table__.create(connection, checkfirst=True)


def _upgrade_v2_to_v3(connection):
    """Add issue workflow without rewriting historical abnormal flags or notes.

    Existing cases are left intact, including resolved cases from an interrupted
    deployment prepared manually. Only missing cases are backfilled, and this
    step runs once when the recorded schema version is older than version 3.
    """
    issues = InspectionIssue.__table__
    inspections = Inspection.__table__
    issues.create(connection, checkfirst=True)
    IssueEvent.__table__.create(connection, checkfirst=True)
    missing_abnormal = select(inspections.c.id, literal("open"), inspections.c.created_at).where(
        inspections.c.is_abnormal.is_(True),
        ~exists(select(issues.c.inspection_id).where(issues.c.inspection_id == inspections.c.id)),
    )
    connection.execute(issues.insert().from_select(
        ["inspection_id", "status", "opened_at"], missing_abnormal, include_defaults=False))


def _upgrade_v3_to_v4(connection):
    """Begin location history without inventing values before they were recorded.

    Old schedules can only be initialized from the point's current location.
    Inspection snapshot floors, photos and issue/event history are untouched.
    Nullable values remain compatible with an older worker's schedule inserts;
    the application falls back to the current point values for those rows.
    """
    schedules = PointSchedule.__table__
    points = Point.__table__
    fields = (("floor", "floor"), ("point_code", "code"), ("point_name", "name"))
    _add_missing_columns(connection, schedules.name, [schedules.c[name] for name, _ in fields])
    for name, point_name in fields:
        current_value = select(points.c[point_name]).where(points.c.id == schedules.c.point_id).scalar_subquery()
        connection.execute(schedules.update().where(schedules.c[name].is_(None)).values({name: current_value}))


def _compact(expression):
    return re.sub(r"\s+", "", expression).strip("()").lower()


def _column_names(connection, table_name):
    return {column["name"] for column in inspect(connection).get_columns(table_name)}


def _unique_keys(connection, table_name):
    return {tuple(constraint["column_names"]) for constraint in
            inspect(connection).get_unique_constraints(table_name)}


def _add_missing_columns(connection, table_name, columns):
    existing = _column_names(connection, table_name)
    quote = connection.dialect.identifier_preparer.quote
    for column in columns:
        if column.name not in existing:
            definition = str(CreateColumn(column).compile(dialect=connection.dialect))
            connection.exec_driver_sql(f"ALTER TABLE {quote(table_name)} ADD COLUMN {definition}")


def _postgres_replace_constraints(connection):
    quote = connection.dialect.identifier_preparer.quote
    checks = inspect(connection).get_check_constraints("patrol_points")
    if any(check["name"] == "patrol_point_floor" for check in checks):
        connection.exec_driver_sql('ALTER TABLE patrol_points DROP CONSTRAINT patrol_point_floor')
    connection.exec_driver_sql(f"ALTER TABLE patrol_points ADD CONSTRAINT patrol_point_floor CHECK ({FLOOR_CHECK})")

    unique_constraints = inspect(connection).get_unique_constraints("patrol_inspections")
    for constraint in unique_constraints:
        if tuple(constraint["column_names"]) == OLD_INSPECTION_KEY:
            connection.exec_driver_sql(f"ALTER TABLE patrol_inspections DROP CONSTRAINT {quote(constraint['name'])}")
    if not any(tuple(constraint["column_names"]) == NEW_INSPECTION_KEY for constraint in unique_constraints):
        columns = ", ".join(NEW_INSPECTION_KEY)
        connection.exec_driver_sql(f"ALTER TABLE patrol_inspections ADD CONSTRAINT {SLOT_CONSTRAINT} UNIQUE ({columns})")


def _sqlite_rebuild(connection, table_name, new_columns, *, replace_floor=False, replace_inspection_key=False):
    """SQLite's documented create/copy/drop/rename sequence, within our transaction.

    Reflection preserves existing columns and non-target constraints. Explicit
    indexes and triggers are saved and recreated; autoindexes are recreated by
    their table constraints. The original table is never renamed first, which
    avoids rewriting child foreign-key references to a temporary table name.
    """
    quote = connection.dialect.identifier_preparer.quote
    temporary_name = f"_patrol_migrate_{table_name.removeprefix('patrol_')}"
    if inspect(connection).has_table(temporary_name):
        raise SchemaMigrationError("A migration staging table already exists; no tables were removed.")
    saved_objects = connection.execute(text(
        "SELECT type, name, sql FROM sqlite_schema WHERE tbl_name=:table "
        "AND type IN ('index', 'trigger') AND sql IS NOT NULL ORDER BY type, name"
    ), {"table": table_name}).all()
    metadata = MetaData()
    original = Table(table_name, metadata, autoload_with=connection)
    replacement = original.to_metadata(metadata, name=temporary_name)
    for column in new_columns:
        if column.name not in replacement.c:
            replacement.append_column(Column(column.name, column.type, nullable=column.nullable,
                                             server_default=column.server_default.arg))

    if replace_floor:
        for constraint in list(replacement.constraints):
            if isinstance(constraint, CheckConstraint) and constraint.name == "patrol_point_floor":
                replacement.constraints.remove(constraint)
        replacement.append_constraint(CheckConstraint(FLOOR_CHECK, name="patrol_point_floor"))
    if replace_inspection_key:
        for constraint in list(replacement.constraints):
            if isinstance(constraint, UniqueConstraint) and tuple(column.name for column in constraint.columns) in (OLD_INSPECTION_KEY, NEW_INSPECTION_KEY):
                replacement.constraints.remove(constraint)
        replacement.append_constraint(UniqueConstraint(*NEW_INSPECTION_KEY, name=SLOT_CONSTRAINT))

    # CreateTable, unlike Table.create(), does not create colliding index names.
    connection.execute(CreateTable(replacement))
    original_columns = ", ".join(quote(column.name) for column in original.columns)
    connection.exec_driver_sql(f"INSERT INTO {quote(temporary_name)} ({original_columns}) SELECT {original_columns} FROM {quote(table_name)}")
    connection.exec_driver_sql(f"DROP TABLE {quote(table_name)}")
    connection.exec_driver_sql(f"ALTER TABLE {quote(temporary_name)} RENAME TO {quote(table_name)}")
    for _, _, statement in saved_objects:
        connection.exec_driver_sql(statement)


def _validate_current(connection):
    inspector = inspect(connection)
    expected_tables = BASE_TABLES | {"patrol_inspection_photos", "patrol_schema_versions",
                                   "patrol_inspection_issues", "patrol_issue_events"}
    if not expected_tables <= set(inspector.get_table_names()):
        raise SchemaMigrationError("Required patrol tables are missing after migration.")
    for table_name, required in {
        "patrol_points": ("category",),
        "patrol_point_schedules": ("category",),
        "patrol_inspections": ("category", "slot", "note", "is_abnormal"),
        "patrol_inspection_photos": ("inspection_id", "data", "mime_type", "size_bytes", "width", "height", "created_at"),
        "patrol_inspection_issues": ("inspection_id", "status", "opened_at", "resolved_by_name", "resolution_note"),
        "patrol_issue_events": ("inspection_id", "actor_id", "actor_name", "action", "note", "created_at"),
    }.items():
        columns = {column["name"]: column for column in inspector.get_columns(table_name)}
        if any(name not in columns or columns[name]["nullable"] for name in required):
            raise SchemaMigrationError(f"Required non-null columns are missing in {table_name}.")
    keys = _unique_keys(connection, "patrol_inspections")
    if NEW_INSPECTION_KEY not in keys or OLD_INSPECTION_KEY in keys:
        raise SchemaMigrationError("Inspection uniqueness does not match the slot-based schema.")
    checks = inspector.get_check_constraints("patrol_points")
    if not any(check["name"] == "patrol_point_floor" for check in checks):
        raise SchemaMigrationError("Point floor validation is missing.")
    if not {"floor", "point_code", "point_name"} <= {column["name"] for column in inspector.get_columns("patrol_point_schedules")}:
        raise SchemaMigrationError("Point schedule location history is missing.")
    issue_checks = {check["name"] for check in inspector.get_check_constraints("patrol_inspection_issues")}
    issue_columns = {column["name"] for column in inspector.get_columns("patrol_inspection_issues")}
    if not {"resolved_at", "resolved_by_id"} <= issue_columns:
        raise SchemaMigrationError("Issue resolution columns are missing.")
    if not {"patrol_issue_status", "patrol_issue_resolution_fields"} <= issue_checks:
        raise SchemaMigrationError("Issue status or resolution validation is missing.")
    event_checks = {check["name"] for check in inspector.get_check_constraints("patrol_issue_events")}
    if "patrol_issue_event_action" not in event_checks:
        raise SchemaMigrationError("Issue event action validation is missing.")
