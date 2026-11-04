"""Import the authorized private general-affairs manifest as a single transaction."""
import hashlib
import json
import os
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import inspect, literal, select

from models import AuditLog, Point, PointSchedule, SchemaVersion, db


IMPORT_ACTION = "general_catalog_20261104"
AUTHORIZED_SHA256 = "fdafc84eae5d294bd1fab190c6527d3632762bb836a75008ff3d4523526222a2"
EXPECTED_FREQUENCIES = {"daily": 54, "daily2": 4, "weekly": 6, "monthly": 1, "irregular": 7}
EXPECTED_MODES = {"spot": 27, "two_stage": 45}


def canonical_bytes(rows):
    """Preserve the published authorization's row order, field values and case."""
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def catalogue_rows(rows=None):
    """Return the verified private manifest. No configuration means no manifest."""
    if rows is None:
        document = os.environ.get("GENERAL_PATROL_CATALOG_JSON")
        if document is None:
            return []
        try:
            rows = json.loads(document)
        except (ValueError, RecursionError) as error:
            raise ValueError("無法讀取總務清冊 JSON。") from error
    if not isinstance(rows, list) or len(rows) != sum(EXPECTED_FREQUENCIES.values()):
        raise ValueError("總務清冊筆數與授權版本不符。")
    try:
        digest = hashlib.sha256(canonical_bytes(rows)).hexdigest()
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError("總務清冊格式無效。") from error
    if digest != AUTHORIZED_SHA256:
        raise ValueError("總務清冊與授權版本不符，未匯入任何點位。")
    if (Counter(row["frequency"] for row in rows) != EXPECTED_FREQUENCIES
            or Counter(row["workflow_mode"] for row in rows) != EXPECTED_MODES):
        raise ValueError("總務清冊的巡檢頻率或作業方式數量不符。")
    return rows


def _required_rows(rows):
    rows = catalogue_rows(rows)
    if not rows:
        raise ValueError("未提供已授權的總務巡檢清冊。")
    return rows


def _import_plan(connection, rows, *, version=8, has_category=True, lock=False):
    """Compare the same six fields before migration and in the final import transaction."""
    audit = AuditLog.__table__.c
    if connection.scalar(select(audit.id).where(audit.action == IMPORT_ACTION).limit(1)):
        return [], {"created": 0, "existing": len(rows), "already_imported": True}
    point = Point.__table__.c
    category = point.category if has_category else literal("uncategorized")
    mode = point.workflow_mode if version >= 7 else literal("standard")
    codes = {row["code"].lower() for row in rows}
    query = select(point.code, point.floor, point.name, point.frequency, category.label("category"),
                   mode.label("workflow_mode")).where(db.or_(category == "general", db.func.lower(point.code).in_(codes)))
    if lock:
        query = query.with_for_update()
    existing = [dict(p) for p in connection.execute(query).mappings()]
    for p in existing:
        # v6 general points become spots in v7. All general v7 spots become
        # irregular in v8, including inactive and previously deleted points.
        if version < 8 and p["category"] == "general" and (version < 7 or p["workflow_mode"] == "spot"):
            p.update(workflow_mode="spot", frequency="irregular")
    missing = []
    for row in rows:
        matches = [p for p in existing if p["code"].lower() == row["code"].lower()
                   or (p["category"] == "general" and p["floor"] == row["floor"] and p["name"] == row["name"])]
        if not matches:
            missing.append(row)
        elif len(matches) != 1 or any(matches[0][key] != value for key, value in row.items()):
            raise ValueError(f"總務點位 {row['code']} 的既有編號或設定與清冊不符，未匯入任何點位。")
    return missing, {"created": len(missing), "existing": len(rows) - len(missing), "already_imported": False}


def preflight_general_catalog(engine, rows=None):
    """Read-only projection of the import after upgrading an existing schema to v8."""
    rows = _required_rows(rows)
    with engine.connect() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        version_table = SchemaVersion.__table__
        version = (connection.scalar(select(db.func.max(version_table.c.version))) or 0) if version_table.name in tables else 0
        if version > 8:
            raise ValueError("資料庫版本較新，無法預檢總務清冊。")
        if Point.__tablename__ not in tables:
            if version or AuditLog.__tablename__ in tables:
                raise ValueError("巡檢資料表不完整，無法預檢總務清冊。")
            return {"created": len(rows), "existing": 0, "already_imported": False}
        columns = {c["name"] for c in inspector.get_columns(Point.__tablename__)}
        required = {"code", "floor", "name", "frequency"}
        if version >= 2:
            required.add("category")
        if version >= 7:
            required.add("workflow_mode")
        if AuditLog.__tablename__ not in tables or not required.issubset(columns):
            raise ValueError("巡檢資料表不完整，無法預檢總務清冊。")
        _, result = _import_plan(connection, rows, version=version, has_category="category" in columns)
        return result


def import_general_catalog(apply=False, rows=None):
    """Preview by default. The register and its completion marker commit atomically."""
    rows = _required_rows(rows)
    try:
        if apply:
            if db.engine.dialect.name == "postgresql":
                db.session.execute(db.text("SELECT pg_advisory_xact_lock(714032610305)"))
            elif db.engine.dialect.name == "sqlite":
                # Acquire a writer lock before reading the completion marker.
                db.session.execute(db.update(AuditLog).where(db.false()).values(action=IMPORT_ACTION))
        missing, result = _import_plan(db.session, rows, lock=apply)
        if result["already_imported"] or not apply:
            db.session.rollback()
            return result
        today = datetime.now(ZoneInfo("Asia/Taipei")).date()
        for row in missing:
            point = Point(**row, active=True, schedule_start=today)
            point.schedules.append(PointSchedule(effective_date=today, active=True, frequency=point.frequency,
                workflow_mode=point.workflow_mode, category=point.category, floor=point.floor,
                point_code=point.code, point_name=point.name))
            db.session.add(point)
        db.session.add(AuditLog(action=IMPORT_ACTION, target=f"{len(rows)} general points",
                                detail=f"Created {len(missing)}; matched {result['existing']}."))
        db.session.commit()
        return result
    except Exception:
        db.session.rollback()
        raise
