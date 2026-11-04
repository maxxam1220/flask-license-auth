"""Opt-in integration tests against the disposable local PostgreSQL cluster.

Set PATROL_TEST_POSTGRES_URL to the local patrol_test database on port 55432.
Every test creates its own schema and drops only that schema on completion.
Remote hosts, other databases, and other ports are deliberately rejected.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os
import re
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import migrations
from migrations import LATEST_VERSION, upgrade_schema
from models import Inspection, InspectionPhoto
from test_migrations import (  # Imported isolated fixtures and cross-dialect cases.
    legacy, snapshot, version_two, version_three, version_four, version_five,
    test_v2_upgrade_preserves_old_columns_and_backfills_abnormal_once as _v2_backfill_case,
    test_v2_backfill_never_overwrites_existing_resolved_case_or_events as _v2_existing_case,
    test_issue_relationships_events_order_and_history_flag_survive_resolution_and_reopen as _issue_history_case,
    test_issue_status_and_closure_consistency_constraints as _issue_constraint_case,
    test_v3_location_history_upgrade_preserves_records_photos_issues_and_events as _v3_location_case,
    test_v3_upgrade_preserves_preexisting_nonnull_location_snapshot as _v3_existing_location_case,
    test_v4_upgrade_keeps_old_accounts_unassigned_and_all_archive_history_intact as _v4_preservation_case,
    test_v5_never_accepts_ambiguous_or_unrestricted_inspector_scope as _v5_constraint_case,
    test_v4_upgrade_rollback_preserves_version_rows_and_unrelated_database as _v4_rollback_case,
    test_v4_partial_install_without_category_constraint_refuses_upgrade as _v4_partial_case,
    test_v4_preexisting_category_default_cannot_grant_access_to_legacy_accounts as _v4_unsafe_default_case,
    test_v5_schedule_keeps_retirement_instant_after_restore_and_legacy_writes as _v5_retirement_case,
    test_v5_adds_empty_revocation_table_and_preserves_other_tables as _v6_preservation_case,
    test_v5_failure_rolls_back_new_table_and_preserves_shared_database as _v6_rollback_case,
    test_v5_partial_revocation_table_without_unique_token_refuses_upgrade as _v6_partial_case,
)


pytestmark = pytest.mark.skipif(not os.environ.get("PATROL_TEST_POSTGRES_URL"),
                                reason="Set PATROL_TEST_POSTGRES_URL for disposable local PostgreSQL tests.")


@pytest.fixture
def engine():
    url = make_url(os.environ["PATROL_TEST_POSTGRES_URL"])
    if (url.get_backend_name() != "postgresql" or url.host not in ("127.0.0.1", "localhost", "::1")
            or url.port != 55432 or url.database != "patrol_test"):
        pytest.fail("PostgreSQL tests require the isolated local patrol_test database on port 55432.")
    schema = f"patrol_test_{uuid4().hex}"
    assert re.fullmatch(r"patrol_test_[0-9a-f]{32}", schema)
    control = create_engine(url, connect_args={"connect_timeout": 5}, pool_pre_ping=True)
    isolated = None
    created = False
    try:
        with control.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        created = True
        isolated = create_engine(url, connect_args={"connect_timeout": 5, "options": f"-csearch_path={schema}"},
                                 pool_pre_ping=True)
        yield isolated
    finally:
        if isolated is not None:
            isolated.dispose()
        if created:
            # The identifier is generated above, checked, and scoped to this test.
            with control.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        control.dispose()


def schema_signature(engine):
    inspector = inspect(engine)
    names = inspector.get_table_names()
    return {
        "tables": names,
        "sequences": inspector.get_sequence_names(),
        "columns": {name: [(column["name"], str(column["type"]), column["nullable"], column["default"])
                            for column in inspector.get_columns(name)] for name in names},
        "checks": {name: inspector.get_check_constraints(name) for name in names},
        "uniques": {name: inspector.get_unique_constraints(name) for name in names},
        "foreign_keys": {name: inspector.get_foreign_keys(name) for name in names},
        "indexes": {name: inspector.get_indexes(name) for name in names},
    }


def test_postgres_fresh_creation_and_idempotency(engine):
    assert upgrade_schema(engine) == LATEST_VERSION
    assert inspect(engine).has_table("patrol_revoked_sessions")
    before = schema_signature(engine)
    with engine.connect() as connection:
        version_before = connection.exec_driver_sql("SELECT * FROM patrol_schema_versions").all()
    assert upgrade_schema(engine) == LATEST_VERSION
    assert schema_signature(engine) == before
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT * FROM patrol_schema_versions").all() == version_before


def test_postgres_v1_rows_defaults_sequences_and_cross_app_isolation(engine, legacy):
    with engine.begin() as connection:
        before_rows = snapshot(connection, legacy)
        for table in legacy.sorted_tables:
            connection.execute(text("SELECT setval(pg_get_serial_sequence(:table, 'id'), "
                                    f"(SELECT MAX(id) FROM {table.name}), true)"), {"table": table.name})
        connection.exec_driver_sql("ALTER TABLE patrol_points ADD CONSTRAINT custom_point_name CHECK (length(name)>0)")
        connection.exec_driver_sql("CREATE INDEX custom_point_name_index ON patrol_points(name)")
        connection.exec_driver_sql("CREATE INDEX unrelated_value_index ON unrelated_license(value)")
    before_inspector = inspect(engine)
    unrelated_columns = before_inspector.get_columns("unrelated_license")
    unrelated_indexes = before_inspector.get_indexes("unrelated_license")
    foreign_keys = {table: before_inspector.get_foreign_keys(table) for table in legacy.tables}
    upgrade_schema(engine)
    with engine.connect() as connection:
        assert snapshot(connection, legacy) == before_rows
        assert connection.exec_driver_sql("SELECT category,slot,note,is_abnormal FROM patrol_inspections").one() == ("uncategorized", "any", "", False)
        assert connection.exec_driver_sql("SELECT category FROM patrol_points").scalar_one() == "uncategorized"
        assert connection.exec_driver_sql("SELECT category FROM patrol_point_schedules").scalar_one() == "uncategorized"
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
        assert connection.exec_driver_sql("SELECT nextval(pg_get_serial_sequence('patrol_inspections','id'))").scalar_one() == 52
    after = inspect(engine)
    assert [(c["name"], str(c["type"]), c["nullable"], c["default"]) for c in after.get_columns("unrelated_license")] == [
        (c["name"], str(c["type"]), c["nullable"], c["default"]) for c in unrelated_columns]
    assert after.get_indexes("unrelated_license") == unrelated_indexes
    assert {table: [fk for fk in after.get_foreign_keys(table) if fk["name"] != "patrol_final_execution_slot"]
            for table in legacy.tables} == foreign_keys
    assert "custom_point_name_index" in {index["name"] for index in after.get_indexes("patrol_points")}
    assert "custom_point_name" in {check["name"] for check in after.get_check_constraints("patrol_points")}
    assert upgrade_schema(engine) == LATEST_VERSION
    with engine.connect() as connection:
        assert snapshot(connection, legacy) == before_rows


def test_postgres_am_pm_unique_photos_foreign_keys_and_floor_constraint(engine, legacy):
    upgrade_schema(engine)
    values = dict(user_id=17, point_id=23, binding_id=41, created_at=datetime(2026, 11, 3, 2),
                  period_key="2026-11-03", frequency="daily2", category="safety", point_code="1F-A01",
                  point_name="Safety point", point_floor=1, user_name="Inspector")
    with engine.begin() as connection:
        am_id = connection.execute(Inspection.__table__.insert().values(**values, slot="am").returning(Inspection.id)).scalar_one()
        connection.execute(Inspection.__table__.insert().values(**values, slot="pm"))
        connection.exec_driver_sql("UPDATE patrol_points SET floor=-2 WHERE id=23")
        connection.exec_driver_sql("UPDATE patrol_points SET floor=15 WHERE id=23")
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(Inspection.__table__.insert().values(**values, slot="am"))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_points SET floor=999 WHERE id=23")
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("INSERT INTO patrol_device_bindings(user_id,token_hash,label,status,created_at) "
                                   "VALUES (17,'second-approved','Second phone','approved',CURRENT_TIMESTAMP)")
    payload = b"photo-byte-fixture\x00\xff"
    with Session(engine) as session:
        photo = InspectionPhoto(inspection_id=am_id, data=payload, size_bytes=len(payload), width=2, height=1)
        session.add(photo)
        session.commit()
        photo_id = photo.id
    with Session(engine) as session:
        photo = session.get(InspectionPhoto, photo_id)
        assert "data" in inspect(photo).unloaded
        assert photo.data == payload and photo.mime_type == "image/jpeg"
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.exec_driver_sql("UPDATE patrol_inspection_photos SET inspection_id=999999")
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_inspections").scalar_one() == 3


def test_postgres_failed_upgrade_rolls_back_all_ddl_rows_and_version(engine, legacy, monkeypatch):
    before_schema = schema_signature(engine)
    with engine.connect() as connection:
        before_rows = snapshot(connection, legacy)

    def fail_before_commit(connection):
        raise RuntimeError("Injected PostgreSQL migration failure")

    monkeypatch.setattr(migrations, "_validate_current", fail_before_commit)
    with pytest.raises(RuntimeError, match="Injected PostgreSQL"):
        upgrade_schema(engine)
    assert schema_signature(engine) == before_schema
    with engine.connect() as connection:
        assert snapshot(connection, legacy) == before_rows
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]


def test_postgres_failed_fresh_creation_leaves_no_tables_or_sequences(engine, monkeypatch):
    def fail_before_commit(connection):
        raise RuntimeError("Injected PostgreSQL fresh failure")

    monkeypatch.setattr(migrations, "_validate_current", fail_before_commit)
    with pytest.raises(RuntimeError, match="Injected PostgreSQL"):
        upgrade_schema(engine)
    assert inspect(engine).get_table_names() == []
    assert inspect(engine).get_sequence_names() == []


def test_postgres_concurrent_startup_is_serialized(engine, legacy):
    ready = Barrier(2)

    def run_upgrade():
        ready.wait(timeout=10)
        return upgrade_schema(engine)

    with ThreadPoolExecutor(max_workers=2) as workers:
        jobs = [workers.submit(run_upgrade) for _ in range(2)]
        assert [job.result(timeout=45) for job in jobs] == [LATEST_VERSION, LATEST_VERSION]
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_schema_versions").scalar_one() == 1
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_inspections").scalar_one() == 1
        assert connection.exec_driver_sql("SELECT qr_token FROM patrol_points").scalar_one() == "existing-qr-token-kept"


def test_postgres_concurrent_catalog_import_is_atomic_and_preserves_later_edits(engine, legacy):
    from app import create_app
    from catalog import IMPORT_ACTION, import_safety_catalog
    from models import AuditLog, Point, PointSchedule, db

    upgrade_schema(engine)
    with engine.connect() as connection:
        schema = connection.exec_driver_sql("SELECT current_schema()").scalar_one()
    application = create_app({
        "TESTING": True, "SECRET_KEY": "isolated-postgres-test", "APP_ENV": "development",
        "SQLALCHEMY_DATABASE_URI": engine.url,
        "SQLALCHEMY_ENGINE_OPTIONS": {"connect_args": {"connect_timeout": 5, "options": f"-csearch_path={schema}"}},
    })
    ready = Barrier(2)

    def run_import():
        with application.app_context():
            ready.wait(timeout=10)
            return import_safety_catalog(apply=True)

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            jobs = [workers.submit(run_import) for _ in range(2)]
            results = [job.result(timeout=45) for job in jobs]
        assert sorted(result["created"] for result in results) == [0, 42]
        assert sum(result["already_imported"] for result in results) == 1
        with application.app_context():
            assert db.session.scalar(select(db.func.count(Point.id))) == 43
            assert db.session.scalar(select(db.func.count(Point.id)).where(Point.category == "safety")) == 42
            assert db.session.scalar(select(db.func.count(PointSchedule.id)).where(PointSchedule.category == "safety")) == 42
            assert db.session.scalar(select(db.func.count(AuditLog.id)).where(AuditLog.action == IMPORT_ACTION)) == 1
            assert db.session.get(Point, 23).qr_token == "existing-qr-token-kept"
            point = db.session.scalar(select(Point).where(Point.category == "safety").order_by(Point.id))
            point_id = point.id
            point.name = "Administrator changed this name"
            db.session.commit()
            assert import_safety_catalog(apply=True)["already_imported"] is True
            assert db.session.get(Point, point_id).name == "Administrator changed this name"
    finally:
        with application.app_context():
            db.session.remove()
            db.engine.dispose()


def test_postgres_v2_backfill_is_append_only_and_one_time(engine, version_two):
    _v2_backfill_case(engine, version_two)


def test_postgres_v2_backfill_preserves_resolved_cases_and_event_history(engine, version_two):
    _v2_existing_case(engine, version_two)


def test_postgres_issue_relationships_constraints_and_history(engine, version_two):
    _issue_history_case(engine, version_two)


@pytest.mark.parametrize("changes", [
    {"status": "unexpected"}, {"status": "resolved"},
    {"resolved_at": datetime(2026, 11, 3, 4), "resolved_by_id": 17, "resolved_by_name": "Manager"},
    {"resolution_note": "Not a closure while open"},
])
def test_postgres_issue_status_and_resolution_fields_consistent(engine, version_two, changes):
    _issue_constraint_case(engine, version_two, changes)


def test_postgres_v2_upgrade_failure_preserves_old_nine_tables_and_versions(engine, version_two, monkeypatch):
    before_schema = schema_signature(engine)
    with engine.connect() as connection:
        before_rows = snapshot(connection, version_two)

    def fail_before_commit(connection):
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_inspection_issues").scalar_one() == 1
        raise RuntimeError("Injected PostgreSQL v3 failure")

    monkeypatch.setattr(migrations, "_validate_current", fail_before_commit)
    with pytest.raises(RuntimeError, match="Injected PostgreSQL v3"):
        upgrade_schema(engine)
    assert schema_signature(engine) == before_schema
    with engine.connect() as connection:
        assert snapshot(connection, version_two) == before_rows
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]


def test_postgres_concurrent_v2_upgrade_backfills_exactly_one_issue(engine, version_two):
    ready = Barrier(2)

    def run_upgrade():
        ready.wait(timeout=10)
        return upgrade_schema(engine)

    with ThreadPoolExecutor(max_workers=2) as workers:
        jobs = [workers.submit(run_upgrade) for _ in range(2)]
        assert [job.result(timeout=45) for job in jobs] == [LATEST_VERSION, LATEST_VERSION]
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT version FROM patrol_schema_versions ORDER BY version").all() == [(2,), (LATEST_VERSION,)]
        assert connection.exec_driver_sql("SELECT inspection_id,status FROM patrol_inspection_issues").all() == [(51, "open")]
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_issue_events").scalar_one() == 0
        assert connection.exec_driver_sql("SELECT COUNT(*) FROM patrol_inspections").scalar_one() == 2


def test_postgres_v3_location_history_and_legacy_null_compatibility(engine, version_three):
    _v3_location_case(engine, version_three)


def test_postgres_v3_existing_location_history_is_never_overwritten(engine, version_three):
    _v3_existing_location_case(engine, version_three)


def test_postgres_v4_upgrade_preserves_history_and_leaves_accounts_unassigned(engine, version_four):
    _v4_preservation_case(engine, version_four)


@pytest.mark.parametrize("invalid", ["", "uncategorized", "all"])
def test_postgres_v5_invalid_assignment_blocked(engine, version_four, invalid):
    _v5_constraint_case(engine, version_four, invalid)


def test_postgres_v4_upgrade_rolls_back_new_columns_and_version(engine, version_four, monkeypatch):
    _v4_rollback_case(engine, version_four, monkeypatch)


def test_postgres_v4_inconsistent_partial_migration_refuses_upgrade(engine, version_four):
    _v4_partial_case(engine, version_four)


def test_postgres_v4_rejects_unsafe_default_category(engine, version_four):
    _v4_unsafe_default_case(engine, version_four)


def test_postgres_v5_schedule_keeps_retirement_instant_after_restore_and_legacy_writes(engine, version_four):
    _v5_retirement_case(engine, version_four)


def test_postgres_v5_adds_empty_revocation_table_and_preserves_other_tables(engine, version_five):
    _v6_preservation_case(engine, version_five)


def test_postgres_v5_failure_rolls_back_new_table_and_preserves_shared_database(engine, version_five, monkeypatch):
    _v6_rollback_case(engine, version_five, monkeypatch)


def test_postgres_v5_partial_revocation_table_without_unique_token_refuses_upgrade(engine, version_five):
    _v6_partial_case(engine, version_five)


def test_postgres_v3_location_upgrade_failure_restores_entire_schema(engine, version_three, monkeypatch):
    before_schema = schema_signature(engine)
    with engine.connect() as connection:
        before_rows = snapshot(connection, version_three)

    def fail_before_commit(connection):
        assert connection.exec_driver_sql("SELECT floor,point_code,point_name FROM patrol_point_schedules").one() == (14, "4M-A01", "Original point")
        raise RuntimeError("Injected PostgreSQL v4 failure")

    monkeypatch.setattr(migrations, "_validate_current", fail_before_commit)
    with pytest.raises(RuntimeError, match="Injected PostgreSQL v4"):
        upgrade_schema(engine)
    assert schema_signature(engine) == before_schema
    with engine.connect() as connection:
        assert snapshot(connection, version_three) == before_rows
        assert connection.exec_driver_sql("SELECT * FROM unrelated_license").all() == [(1, "untouched")]
