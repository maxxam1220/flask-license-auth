"""Synthetic register rows only. Production manifests are private configuration."""
import hashlib
import json
from datetime import datetime

import pytest
from sqlalchemy import create_engine, inspect

import catalog_general as catalog
from models import AuditLog, Point, PointSchedule, db
from test_catalog import catalogue_app


@pytest.fixture
def manifest(monkeypatch):
    frequencies = [key for key, count in catalog.EXPECTED_FREQUENCIES.items() for _ in range(count)]
    rows = [dict(floor=1, code=f"1F-QA{i:03d}", name=f"測試點位 {i}", category="general", frequency=freq,
                 workflow_mode="spot" if i < 20 or freq == "irregular" else "two_stage")
            for i, freq in enumerate(frequencies)]
    rows[10]["code"] = "Xq-Q999"
    monkeypatch.setattr(catalog, "AUTHORIZED_SHA256", hashlib.sha256(catalog.canonical_bytes(rows)).hexdigest())
    monkeypatch.setenv("GENERAL_PATROL_CATALOG_JSON", json.dumps(rows))
    return rows


def test_invalid_or_missing_register_cannot_write(catalogue_app, monkeypatch, manifest):
    monkeypatch.delenv("GENERAL_PATROL_CATALOG_JSON")
    assert catalog.catalogue_rows() == []
    with pytest.raises(ValueError, match="未提供"):
        catalog.import_general_catalog(apply=True)
    with pytest.raises(ValueError, match="授權"):
        catalog.import_general_catalog(apply=True, rows=manifest[::-1])
    manifest[10]["code"] = manifest[10]["code"].upper()
    with pytest.raises(ValueError, match="授權"):
        catalog.import_general_catalog(apply=True, rows=manifest)
    assert db.session.query(Point).count() == db.session.query(AuditLog).count() == 0


def test_preview_import_and_rerun_preserve_history(catalogue_app, manifest):
    old = Point(**manifest[0], active=False, deleted_at=datetime(2026, 1, 1), qr_token="preserved")
    db.session.add(old)
    db.session.commit()
    assert catalog.import_general_catalog() == {"created": 71, "existing": 1, "already_imported": False}
    assert db.session.query(Point).count() == 1
    assert catalog.import_general_catalog(apply=True)["created"] == 71
    assert old.deleted_at and not old.active and old.qr_token == "preserved"
    assert db.session.query(PointSchedule).count() == 71
    point = db.session.query(Point).filter_by(code=manifest[10]["code"]).one()
    assert point.schedules[0].point_code == "Xq-Q999"
    point.name = "管理員更名"
    db.session.commit()
    assert catalog.import_general_catalog(apply=True)["already_imported"] and point.name == "管理員更名"
    assert db.session.query(Point).count() == 72
    assert db.session.query(AuditLog).filter_by(action=catalog.IMPORT_ACTION).count() == 1


@pytest.mark.parametrize("change", [{"code":"XQ-Q999"}, {"code":"1F-OTHER"}, {"name":"另一個測試地點"}])
def test_conflict_leaves_no_partial_register(catalogue_app, manifest, change):
    db.session.add(Point(**(manifest[10] | change)))
    db.session.commit()
    with pytest.raises(ValueError, match="未匯入任何點位"):
        catalog.import_general_catalog(apply=True)
    assert db.session.query(Point).count() == 1
    assert db.session.query(AuditLog).count() == 0


def test_preflight_empty_or_incomplete_database(manifest):
    engine = create_engine("sqlite://")
    assert catalog.preflight_general_catalog(engine)["created"] == len(manifest)
    assert not inspect(engine).get_table_names()
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE patrol_schema_versions (version INTEGER)")
        connection.exec_driver_sql("INSERT INTO patrol_schema_versions VALUES(7)")
    with pytest.raises(ValueError, match="不完整"):
        catalog.preflight_general_catalog(engine)
    assert inspect(engine).get_table_names() == ["patrol_schema_versions"]


@pytest.mark.parametrize("version, stored_frequency, desired_index, conflict", [
    (7, "weekly", -1, False),       # A v7 spot will match an irregular row after upgrade.
    (7, "daily", 0, True),          # It looks like a daily match until v8 converts it.
    (8, "daily", 0, False),         # A native v8 single-stage daily point stays scheduled.
    (6, "weekly", -1, False),       # v6 general -> v7 spot -> v8 irregular.
])
def test_read_only_preflight_projects_only_the_pending_upgrade(manifest, version, stored_frequency, desired_index, conflict):
    engine = create_engine("sqlite://")
    row = manifest[desired_index]
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE patrol_schema_versions (version INTEGER)")
        connection.exec_driver_sql("INSERT INTO patrol_schema_versions VALUES(?)", (version,))
        connection.exec_driver_sql("CREATE TABLE patrol_audit_logs (id INTEGER, action TEXT)")
        extra = ", workflow_mode TEXT" if version >= 7 else ""
        connection.exec_driver_sql("CREATE TABLE patrol_points (code TEXT, floor INTEGER, name TEXT, "
                                   "frequency TEXT, category TEXT" + extra + ")")
        values = (row["code"], row["floor"], row["name"], stored_frequency, "general")
        if version >= 7:
            values += ("spot",)
        connection.exec_driver_sql("INSERT INTO patrol_points VALUES(" + ",".join("?" * len(values)) + ")", values)
        connection.exec_driver_sql("PRAGMA query_only=ON")
    if conflict:
        with pytest.raises(ValueError, match="未匯入"):
            catalog.preflight_general_catalog(engine)
    else:
        assert catalog.preflight_general_catalog(engine) == {"created": 71, "existing": 1, "already_imported": False}
    with engine.connect() as connection:
        assert connection.exec_driver_sql("SELECT frequency FROM patrol_points").scalar_one() == stored_frequency
        assert connection.exec_driver_sql("SELECT version FROM patrol_schema_versions").scalar_one() == version
        assert connection.exec_driver_sql("SELECT count(*) FROM patrol_audit_logs").scalar_one() == 0


def test_preflight_completed_marker_preserves_later_edits(catalogue_app, manifest):
    from models import SchemaVersion
    db.session.add(SchemaVersion(version=8))
    db.session.commit()
    catalog.import_general_catalog(apply=True)
    db.session.query(Point).filter_by(code=manifest[10]["code"]).update({"frequency": "weekly"})
    db.session.commit()
    assert catalog.preflight_general_catalog(db.engine) == catalog.import_general_catalog()
    assert catalog.preflight_general_catalog(db.engine)["already_imported"]
