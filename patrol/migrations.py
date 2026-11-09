"""Transactional patrol-only schema upgrades for SQLite and PostgreSQL.

Call ``upgrade_schema(engine)`` before serving requests; do not call create_all
first on an existing database. Version 1 is the original unversioned schema.
No credentials, application data, or connection URLs are logged here.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import Column, MetaData, Table, UniqueConstraint, CheckConstraint, case, exists, inspect, literal, select, text
from sqlalchemy.schema import AddConstraint, CreateColumn, CreateTable

from models import (Inspection, InspectionIssue, InspectionPhoto, IssueEvent, IssueEventPhoto, LoginEvent, OfflineSubmission, PatrolExecution, Point, PointSchedule,
                    ENGINEERING_TITLE_RULE, POINT_INSPECTION_TEAM_RULE, POINT_PENDING_FREQUENCY_RULE, RevokedSession, SchemaVersion, User, db, protect_execution_link, protect_legacy_exemptions)


LATEST_VERSION = 16
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
        if current < 5:
            _upgrade_v4_to_v5(connection)
        if current < 6:
            RevokedSession.__table__.create(connection, checkfirst=True)
        if current < 7:
            _upgrade_v6_to_v7(connection)
        if current < 8:
            _upgrade_v7_to_v8(connection)
        if current < 9:
            _add_missing_columns(connection, Inspection.__tablename__, [Inspection.__table__.c.executor_visit])
        if current < 10:
            _add_missing_columns(connection, User.__tablename__, [User.__table__.c.general_manager_title])
        if current < 11:
            LoginEvent.__table__.create(connection, checkfirst=True)
        if current < 12:
            OfflineSubmission.__table__.create(connection, checkfirst=True)
        if current < 13:
            _add_missing_columns(connection, User.__tablename__, [User.__table__.c.engineering_inspector_title])
        if current < 14:
            _add_missing_columns(connection, User.__tablename__,
                                 [User.__table__.c.ui_language, User.__table__.c.simple_executor_ui])
        if current < 15:
            _add_missing_columns(connection, Point.__tablename__, [Point.__table__.c.inspection_team,
                Point.__table__.c.pending_frequency, Point.__table__.c.frequency_effective_date])
        if current < 16:
            IssueEventPhoto.__table__.create(connection, checkfirst=True)

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


def _upgrade_v4_to_v5(connection):
    """Add optional account scope and archive time without altering existing rows.

    A previous worker can still insert rows without these fields. Explicit
    administrative assignment is required before an inspector gains a scope.
    """
    _add_missing_columns(connection, User.__tablename__, [User.__table__.c.patrol_category])
    _add_missing_columns(connection, Point.__tablename__, [Point.__table__.c.deleted_at])
    _add_missing_columns(connection, PointSchedule.__tablename__, [PointSchedule.__table__.c.retired_at])


def _upgrade_v6_to_v7(connection):
    points, schedules, inspections = Point.__table__, PointSchedule.__table__, Inspection.__table__
    for table in (points, schedules):
        _add_missing_columns(connection, table.name, [table.c.workflow_mode])
    _add_missing_columns(connection, schedules.name, [schedules.c.workflow_changed_at])
    PatrolExecution.__table__.create(connection, checkfirst=True)
    additions = [inspections.c[name] for name in ("workflow_mode", "execution_id", "spot_request_id")]
    final_constraints = [constraint for constraint in inspections.constraints
                         if constraint.name in ("patrol_final_execution_slot", "patrol_inspection_workflow")]
    if connection.dialect.name == "sqlite":
        _sqlite_rebuild(connection, inspections.name, additions, new_constraints=final_constraints, remove_slot_key=True)
    else:
        _add_missing_columns(connection, inspections.name, additions)
        quote = connection.dialect.identifier_preparer.quote
        for constraint in inspect(connection).get_unique_constraints(inspections.name):
            if tuple(constraint["column_names"]) == NEW_INSPECTION_KEY:
                connection.exec_driver_sql(f"ALTER TABLE patrol_inspections DROP CONSTRAINT {quote(constraint['name'])}")
        for constraint in final_constraints:
            connection.execute(AddConstraint(constraint, isolate_from_table=False))
    # These are the historical v7 indexes, independent of later ORM policy.
    for definition in (
        "UNIQUE INDEX patrol_one_required_inspection_per_slot ON patrol_inspections(point_id,frequency,period_key,slot) WHERE workflow_mode <> 'spot'",
        "UNIQUE INDEX patrol_spot_request_once ON patrol_inspections(spot_request_id) WHERE spot_request_id IS NOT NULL",
        "UNIQUE INDEX patrol_execution_review_once ON patrol_inspections(execution_id) WHERE execution_id IS NOT NULL",
        "INDEX patrol_recent_spot_at_point ON patrol_inspections(point_id,created_at) WHERE workflow_mode = 'spot'",
    ):
        connection.exec_driver_sql("CREATE " + definition)
    protect_execution_link(connection)

    # A general point changes on the local rollout date. Its earlier daily/weekly
    # obligations and all existing final records retain their original meaning.
    changed_at = datetime.now(timezone.utc)
    today = changed_at.astimezone(ZoneInfo("Asia/Taipei")).date()
    start, cutoff = points.c.schedule_start, literal(today)
    fields = ["point_id", "effective_date", "frequency", "category", "floor", "point_code", "point_name",
              "active", "workflow_mode"]
    general = (points.c.category == "general") & (points.c.workflow_mode == "standard")

    def snapshot_at(effective, mode):
        return select(points.c.id, effective, points.c.frequency, points.c.category, points.c.floor,
                      points.c.code, points.c.name, points.c.active, literal(mode)).where(general)

    needs_baseline = ~exists(select(schedules.c.id).where(
        schedules.c.point_id == points.c.id, schedules.c.effective_date <= start))
    baseline = snapshot_at(start, "standard").where(start <= cutoff, needs_baseline)
    connection.execute(schedules.insert().from_select(fields, baseline, include_defaults=False))
    first_spot_day = case((start > cutoff, start), else_=cutoff)
    spot_rows = snapshot_at(first_spot_day, "spot").add_columns(literal(changed_at.replace(tzinfo=None)))
    connection.execute(schedules.insert().from_select([*fields, "workflow_changed_at"], spot_rows, include_defaults=False))
    connection.execute(points.update().where(general).values(workflow_mode="spot"))


def _upgrade_v7_to_v8(connection):
    inspections, executions = Inspection.__table__, PatrolExecution.__table__
    points, schedules = Point.__table__, PointSchedule.__table__
    _add_missing_columns(connection, inspections.name, [inspections.c[name] for name in
                         ("personal_day", "legacy_slot_repeat", "legacy_unscheduled")])
    _add_missing_columns(connection, schedules.name, [schedules.c.legacy_unscheduled])
    # The stored timestamp is UTC without tzinfo. SQLite rounds fractional seconds
    # during date conversion, so discard the fraction before adding the modern Taipei offset.
    postgres = connection.dialect.name == "postgresql"
    local_day = ("CAST((created_at AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Taipei' AS DATE)" if postgres
                 else "date(substr(created_at,1,19), '+8 hours')")
    connection.exec_driver_sql(f"UPDATE patrol_inspections SET personal_day={local_day}, "
                               "legacy_unscheduled=(workflow_mode='spot') WHERE workflow_mode IN ('spot','two_stage')")
    # For v7 history with several all-day/half-day entries, one 'any' covers both
    # halves. Otherwise retain the earliest entry per half as the uniqueness anchor.
    connection.exec_driver_sql("""
        WITH ranked AS (
            SELECT id,slot,
                max(CASE WHEN slot='any' THEN 1 ELSE 0 END)
                    OVER (PARTITION BY point_id,user_id,personal_day) AS has_all_day,
                row_number() OVER (PARTITION BY point_id,user_id,personal_day,slot ORDER BY created_at,id) AS ordinal
            FROM patrol_inspections WHERE personal_day IS NOT NULL
        )
        UPDATE patrol_inspections SET legacy_slot_repeat=true
        WHERE id IN (SELECT id FROM ranked WHERE ordinal>1 OR (has_all_day=1 AND slot<>'any'))
    """)

    old_indexes = ("patrol_one_required_inspection_per_slot", "patrol_execution_review_once", "patrol_recent_spot_at_point")
    if not set(old_indexes) <= {index["name"] for index in inspect(connection).get_indexes(inspections.name)}:
        raise SchemaMigrationError("Required v7 inspection indexes are missing; no shared indexes were changed.")
    for name in old_indexes:
        connection.exec_driver_sql(f"DROP INDEX {name}")
    valid_slot = next(check for check in executions.constraints if check.name == "patrol_execution_valid_slot")
    personal_day_required = next(check for check in inspections.constraints if check.name == "patrol_personal_day_required")
    if postgres:
        connection.exec_driver_sql("ALTER TABLE patrol_executions DROP CONSTRAINT patrol_execution_valid_slot")
        connection.execute(AddConstraint(valid_slot, isolate_from_table=False))
        connection.execute(AddConstraint(personal_day_required, isolate_from_table=False))
    else:
        _sqlite_rebuild(connection, executions.name, [], new_constraints=[valid_slot], replace_checks={valid_slot.name})
        _sqlite_rebuild(connection, inspections.name, [], new_constraints=[personal_day_required])
    for index in inspections.indexes:
        if index.name in ("patrol_one_standard_per_slot", "patrol_person_am_once", "patrol_person_pm_once", "patrol_execution_reviews"):
            index.create(connection)
    protect_legacy_exemptions(connection)

    # Preserve v7 spot checks as optional. New single-stage spot work is scheduled
    # by frequency. Old points start the new policy as irregular, including restored points.
    now = datetime.now(timezone.utc)
    today = literal(now.astimezone(ZoneInfo("Asia/Taipei")).date())
    spot = (points.c.category == "general") & (points.c.workflow_mode == "spot")
    fields = ["point_id", "effective_date", "frequency", "category", "floor", "point_code", "point_name", "active",
              "workflow_mode", "legacy_unscheduled"]
    needs_baseline = ~exists(select(schedules.c.id).where(
        schedules.c.point_id == points.c.id, schedules.c.effective_date <= points.c.schedule_start))
    def snapshot_at(day, frequency, legacy):
        return select(points.c.id, day, frequency, points.c.category, points.c.floor, points.c.code, points.c.name,
                      points.c.active, points.c.workflow_mode, literal(legacy)).where(spot)
    baseline = snapshot_at(points.c.schedule_start, points.c.frequency, True).where(needs_baseline, points.c.schedule_start <= today)
    connection.execute(schedules.insert().from_select(fields, baseline, include_defaults=False))
    connection.execute(schedules.update().where(schedules.c.workflow_mode == "spot").values(legacy_unscheduled=True))
    effective = case((points.c.schedule_start > today, points.c.schedule_start), else_=today)
    transition = snapshot_at(effective, literal("irregular"), False).add_columns(literal(now.replace(tzinfo=None)))
    connection.execute(schedules.insert().from_select([*fields, "workflow_changed_at"], transition, include_defaults=False))
    connection.execute(points.update().where(spot).values(frequency="irregular"))


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


def _sqlite_rebuild(connection, table_name, new_columns, *, replace_floor=False, replace_inspection_key=False,
                    new_constraints=(), remove_slot_key=False, replace_checks=()):
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
    for constraint in list(replacement.constraints):
        if isinstance(constraint, CheckConstraint) and constraint.name in replace_checks:
            replacement.constraints.remove(constraint)
    for column in new_columns:
        if column.name not in replacement.c:
            replacement.append_column(Column(column.name, column.type, nullable=column.nullable,
                                             server_default=column.server_default.arg if column.server_default is not None else None))

    for constraint in new_constraints:
        if isinstance(constraint, CheckConstraint):
            replacement.append_constraint(CheckConstraint(str(constraint.sqltext), name=constraint.name))
        else:
            Table(PatrolExecution.__tablename__, metadata, autoload_with=connection)
            replacement.append_constraint(db.ForeignKeyConstraint(
                [element.parent.name for element in constraint.elements],
                [element.target_fullname for element in constraint.elements], name=constraint.name))

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
    if remove_slot_key:
        for constraint in list(replacement.constraints):
            if isinstance(constraint, UniqueConstraint) and tuple(column.name for column in constraint.columns) == NEW_INSPECTION_KEY:
                replacement.constraints.remove(constraint)

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
    revoked = RevokedSession.__tablename__
    expected_tables = BASE_TABLES | {"patrol_inspection_photos", "patrol_schema_versions",
                                   "patrol_inspection_issues", "patrol_issue_events", PatrolExecution.__tablename__, revoked,
                                   LoginEvent.__tablename__, OfflineSubmission.__tablename__, IssueEventPhoto.__tablename__}
    if not expected_tables <= set(inspector.get_table_names()):
        raise SchemaMigrationError("Required patrol tables are missing after migration.")
    _validate_login_events(inspector)
    _validate_offline_submissions(inspector)
    _validate_issue_event_photos(inspector)
    for table_name, required in {
        User.__tablename__: ("general_manager_title", "engineering_inspector_title", "ui_language", "simple_executor_ui"),
        "patrol_points": ("category", "workflow_mode", "inspection_team"),
        "patrol_point_schedules": ("category", "workflow_mode", "legacy_unscheduled"),
        "patrol_inspections": ("category", "slot", "note", "is_abnormal", "workflow_mode", "legacy_slot_repeat", "legacy_unscheduled",
                               "executor_visit"),
        "patrol_executions": ("user_id", "binding_id", "point_id", "frequency", "period_key", "slot", "created_at",
                              "category", "point_code", "point_name", "point_floor", "user_name"),
        "patrol_inspection_photos": ("inspection_id", "data", "mime_type", "size_bytes", "width", "height", "created_at"),
        "patrol_inspection_issues": ("inspection_id", "status", "opened_at", "resolved_by_name", "resolution_note"),
        "patrol_issue_events": ("inspection_id", "actor_id", "actor_name", "action", "note", "created_at"),
        revoked: ("token_hash", "user_id", "auth_version", "revoked_at"),
    }.items():
        columns = {column["name"]: column for column in inspector.get_columns(table_name)}
        if any(name not in columns or columns[name]["nullable"] for name in required):
            raise SchemaMigrationError(f"Required non-null columns are missing in {table_name}.")
        for name in ("general_manager_title", "engineering_inspector_title", "simple_executor_ui", "executor_visit"):
            if name in required:
                column = columns[name]
                if not isinstance(column["type"], db.Boolean) or _compact(str(column["default"])) not in ("false", "0"):
                    raise SchemaMigrationError(f"Expected a boolean {table_name}.{name} with a false default.")
    title_checks = {check["name"]: check["sqltext"] for check in inspector.get_check_constraints(User.__tablename__)}
    language_column = next(column for column in inspector.get_columns(User.__tablename__) if column["name"] == "ui_language")
    language_check = re.sub(r"::(?:character varying|text)(?:\[\])?", "",
                            str(title_checks.get("patrol_user_ui_language", "")).lower())
    language_check = re.sub(r"[()\s]", "", language_check)
    if (not isinstance(language_column["type"], db.String) or getattr(language_column["type"], "length", None) != 10
            or str(language_column["default"]).replace("::character varying", "") != "'zh-Hant'"
            or language_check not in ("ui_languagein'zh-hant','id','vi'", "ui_language=anyarray['zh-hant','id','vi']")):
        raise SchemaMigrationError("The account language column or allowed-language constraint is invalid.")
    normalize_title = lambda value: re.sub(r"::text|[()\s]", "", str(value).lower())
    if normalize_title(title_checks.get("patrol_engineering_inspector_title", "")) != normalize_title(ENGINEERING_TITLE_RULE):
        raise SchemaMigrationError("The engineering inspector display title constraint is missing or invalid.")
    team_column = next(column for column in inspector.get_columns(Point.__tablename__) if column["name"] == "inspection_team")
    team_checks = {check["name"]: check["sqltext"] for check in inspector.get_check_constraints(Point.__tablename__)}
    if (not isinstance(team_column["type"], db.String) or getattr(team_column["type"], "length", None) != 20
            or str(team_column["default"]).replace("::character varying", "") != "'general'"
            or normalize_title(team_checks.get("patrol_point_inspection_team", "")) != normalize_title(POINT_INSPECTION_TEAM_RULE)):
        raise SchemaMigrationError("The point inspection_team column or responsibility constraint is invalid.")
    point_columns = {column["name"]: column for column in inspector.get_columns(Point.__tablename__)}
    for name, expected_type in (("pending_frequency", db.String), ("frequency_effective_date", db.Date)):
        column = point_columns.get(name)
        if (not column or not column["nullable"] or column["default"] is not None
                or not isinstance(column["type"], expected_type)
                or (name == "pending_frequency" and getattr(column["type"], "length", None) != 10)):
            raise SchemaMigrationError("The scheduled frequency columns are missing or invalid.")
    if normalize_title(team_checks.get("patrol_point_pending_frequency", "")) != normalize_title(POINT_PENDING_FREQUENCY_RULE):
        raise SchemaMigrationError("The scheduled frequency pairing constraint is missing or invalid.")
    revoked_columns = {column["name"]: column["type"] for column in inspector.get_columns(revoked)}
    if (inspector.get_pk_constraint(revoked)["constrained_columns"] != ["token_hash"]
            or getattr(revoked_columns["token_hash"], "length", None) != 64
            or not isinstance(revoked_columns["auth_version"], db.Integer)
            or not isinstance(revoked_columns["revoked_at"], db.DateTime)):
        raise SchemaMigrationError("Session revocation columns or token primary key are invalid.")
    if not any(fk["constrained_columns"] == ["user_id"] and fk["referred_table"] == User.__tablename__
               and fk["referred_columns"] == ["id"] for fk in inspector.get_foreign_keys(revoked)):
        raise SchemaMigrationError("Session revocation account foreign key is missing.")
    if not any(index["column_names"] == ["user_id"] for index in inspector.get_indexes(revoked)):
        raise SchemaMigrationError("Session revocation account index is missing.")
    keys = _unique_keys(connection, "patrol_inspections")
    final_indexes = {index["name"]: index for index in inspector.get_indexes("patrol_inspections")}
    if (NEW_INSPECTION_KEY in keys or OLD_INSPECTION_KEY in keys or
            "patrol_execution_review_once" in final_indexes or "patrol_one_required_inspection_per_slot" in final_indexes):
        raise SchemaMigrationError("Inspection uniqueness does not match the workflow schema.")
    for name, fields, unique, condition in (
        ("patrol_one_standard_per_slot", NEW_INSPECTION_KEY, True, "workflow_mode='standard'"),
        ("patrol_spot_request_once", ("spot_request_id",), True, "spot_request_idisnotnull"),
        ("patrol_execution_reviews", ("execution_id",), False, "execution_idisnotnull"),
        ("patrol_person_am_once", ("point_id", "user_id", "personal_day"), True, "personal_dayisnotnullandnotlegacy_slot_repeatandslot<>'pm'"),
        ("patrol_person_pm_once", ("point_id", "user_id", "personal_day"), True, "personal_dayisnotnullandnotlegacy_slot_repeatandslot<>'am'"),
    ):
        index = final_indexes.get(name, {})
        predicate = index.get("dialect_options", {}).get(f"{connection.dialect.name}_where")
        normalized = re.sub(r"::text|[()\s]", "", str(predicate).lower())
        if tuple(index.get("column_names", [])) != fields or bool(index.get("unique")) != unique or normalized != condition:
            raise SchemaMigrationError(f"Missing or invalid workflow index: {name}.")
    if not {"patrol_inspection_workflow", "patrol_personal_day_required", "patrol_executor_visit_fields"} <= {
            check["name"] for check in inspector.get_check_constraints(Inspection.__tablename__)}:
        raise SchemaMigrationError("Final inspection workflow validation is missing.")
    if NEW_INSPECTION_KEY not in _unique_keys(connection, PatrolExecution.__tablename__):
        raise SchemaMigrationError("First-stage slot uniqueness is missing.")
    if not any(fk["constrained_columns"] == ["execution_id", *NEW_INSPECTION_KEY]
               and fk["referred_table"] == PatrolExecution.__tablename__ and fk["referred_columns"] == ["id", *NEW_INSPECTION_KEY]
               for fk in inspector.get_foreign_keys(Inspection.__tablename__)):
        raise SchemaMigrationError("Final inspections must reference the same first-stage slot.")
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
    for table_name, name, expected_type in ((User.__tablename__, "patrol_category", db.String),
                                            (Point.__tablename__, "deleted_at", db.DateTime),
                                            (PointSchedule.__tablename__, "retired_at", db.DateTime),
                                            (PointSchedule.__tablename__, "workflow_changed_at", db.DateTime)):
        columns = {column["name"]: column for column in inspector.get_columns(table_name)}
        column = columns.get(name)
        if (not column or not column["nullable"] or column["default"] is not None
                or not isinstance(column["type"], expected_type)):
            raise SchemaMigrationError(f"Expected nullable {table_name}.{name} without a default.")
    user_checks = {check["name"] for check in inspector.get_check_constraints(User.__tablename__)}
    if "patrol_user_category_allowed" not in user_checks:
        raise SchemaMigrationError("Account patrol category validation is missing.")


def _validate_login_events(inspector):
    table = LoginEvent.__table__
    actual = {column["name"]: column for column in inspector.get_columns(table.name)}
    for expected in table.columns:
        column = actual.get(expected.name)
        if (not column or column["nullable"] or not isinstance(column["type"], type(expected.type))
                or getattr(column["type"], "length", None) != getattr(expected.type, "length", None)):
            raise SchemaMigrationError(f"Invalid login event column: {expected.name}.")
    if inspector.get_pk_constraint(table.name)["constrained_columns"] != ["id"]:
        raise SchemaMigrationError("Login event primary key is invalid.")
    if not any(fk["constrained_columns"] == ["user_id"] and fk["referred_table"] == User.__tablename__
               and fk["referred_columns"] == ["id"] for fk in inspector.get_foreign_keys(table.name)):
        raise SchemaMigrationError("Login event account foreign key is missing.")
    if "patrol_login_event_client_type" not in {check["name"] for check in inspector.get_check_constraints(table.name)}:
        raise SchemaMigrationError("Login event device type check is missing.")
    actual_indexes = {i["name"]: i for i in inspector.get_indexes(table.name)}
    for expected in table.indexes:
        index = actual_indexes.get(expected.name)
        if (not index or index["unique"] or index["column_names"] != list(expected.columns.keys())
                or any(key.endswith("_where") for key in index.get("dialect_options", {}))):
            raise SchemaMigrationError(f"Missing or invalid login event index: {expected.name}.")


def _validate_issue_event_photos(inspector):
    """A partial pre-created table must fail closed instead of losing evidence."""
    table = IssueEventPhoto.__table__
    actual = {column["name"]: column for column in inspector.get_columns(table.name)}
    for expected in table.columns:
        column = actual.get(expected.name)
        if (not column or bool(column["nullable"]) != bool(expected.nullable)
                or not isinstance(column["type"], type(expected.type))
                or getattr(column["type"], "length", None) != getattr(expected.type, "length", None)):
            raise SchemaMigrationError(f"Invalid issue event photo column: {expected.name}.")
    if (inspector.get_pk_constraint(table.name)["constrained_columns"] != ["id"]
            or str(actual["mime_type"]["default"]).replace("::character varying", "") != "'image/jpeg'"):
        raise SchemaMigrationError("Issue event photo primary key or image default is invalid.")
    if not any(fk["constrained_columns"] == ["event_id"] and fk["referred_table"] == IssueEvent.__tablename__
               and fk["referred_columns"] == ["id"] for fk in inspector.get_foreign_keys(table.name)):
        raise SchemaMigrationError("Issue event photo history foreign key is missing.")
    if not any(index["column_names"] == ["event_id"] and not index["unique"]
               and not any(key.endswith("_where") for key in index.get("dialect_options", {}))
               for index in inspector.get_indexes(table.name)):
        raise SchemaMigrationError("Issue event photo history index is missing.")


def _validate_offline_submissions(inspector):
    table = OfflineSubmission.__table__
    actual = {column["name"]: column for column in inspector.get_columns(table.name)}
    for expected in table.columns:
        column = actual.get(expected.name)
        if (not column or bool(column["nullable"]) != bool(expected.nullable)
                or not isinstance(column["type"], type(expected.type))
                or getattr(column["type"], "length", None) != getattr(expected.type, "length", None)):
            raise SchemaMigrationError(f"Invalid offline submission column: {expected.name}.")
    if inspector.get_pk_constraint(table.name)["constrained_columns"] != ["id"]:
        raise SchemaMigrationError("Offline submission primary key is invalid.")
    foreign_keys = inspector.get_foreign_keys(table.name)
    for field, target in (("user_id", "patrol_users"), ("binding_id", "patrol_device_bindings"),
                          ("inspection_id", "patrol_inspections"), ("execution_id", "patrol_executions")):
        if not any(fk["constrained_columns"] == [field] and fk["referred_table"] == target
                   and fk["referred_columns"] == ["id"] for fk in foreign_keys):
            raise SchemaMigrationError(f"Offline submission foreign key is missing: {field}.")
    unique = {item["name"]: item["column_names"] for item in inspector.get_unique_constraints(table.name)}
    checks = {item["name"]: item["sqltext"] for item in inspector.get_check_constraints(table.name)}
    for constraint in table.constraints:
        if isinstance(constraint, UniqueConstraint) and unique.get(constraint.name) != list(constraint.columns.keys()):
            raise SchemaMigrationError(f"Offline submission uniqueness is invalid: {constraint.name}.")
        if isinstance(constraint, CheckConstraint):
            # PostgreSQL reflection may wrap boolean terms in parentheses and
            # add a text cast. Ignore only those formatting differences.
            normalize = lambda value: re.sub(r"::text|[()\s]", "", str(value).lower())
            if normalize(checks.get(constraint.name, "")) != normalize(constraint.sqltext):
                raise SchemaMigrationError(f"Offline submission check is invalid: {constraint.name}.")
    indexes = {item["name"]: item for item in inspector.get_indexes(table.name)}
    for expected in table.indexes:
        index = indexes.get(expected.name)
        if (not index or index["unique"] or index["column_names"] != list(expected.columns.keys())
                or any(key.endswith("_where") for key in index.get("dialect_options", {}))):
            raise SchemaMigrationError(f"Missing or invalid offline submission index: {expected.name}.")
