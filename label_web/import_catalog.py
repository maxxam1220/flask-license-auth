"""Import approved Excel reference data without creating desktop print layouts.

The CLI defaults to a read-only preview. Business files stay local; only selected
reference fields and their provenance are written to the app's catalog table.
"""
import argparse
import configparser
import hashlib
import json
from pathlib import Path

from sqlalchemy import create_engine, insert, select, text, update
import database as db


def prepare_rows(records, selected_codes):
    rows = []
    for record in records:
        code = str(record["CodeNo"]).strip()
        if code not in selected_codes:
            continue
        if not record.get("latest_source_since_20261008"):
            raise ValueError("Historical-only records cannot be imported as current")
        days = record.get("KeepDays")
        if days is not None and (isinstance(days, bool) or int(days) != days or not 0 <= days <= 3660):
            raise ValueError("Invalid shelf life")
        row = {"code": code, "name": str(record["CodeName"]).strip(),
               "barcode": str(record.get("Barcode") or "").strip(),
               "keep_days": int(days) if days is not None else None,
               "barcode_type": str(record.get("TypesOfBarcode") or "").strip(),
               "active": True,
               "provenance": {"file": record["source_file"], "sheet": record["source_sheet"],
                              "row": record["source_row"], "source_date": record["source_date"]}}
        if not row["name"] or not code or len(code) > 80:
            raise ValueError("Invalid catalog identity")
        row["revision"] = hashlib.sha256(json.dumps(row, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        rows.append(row)
    if len(rows) != len(selected_codes) or len({row["code"] for row in rows}) != len(rows):
        raise ValueError("Missing or duplicate current list records")
    return rows


def write_rows(connection, rows):
    """Idempotent updates of list identities; never mutate the barcode53 schema."""
    counts = {"inserted": 0, "updated": 0, "unchanged": 0}
    for row in rows:
        previous = connection.execute(select(db.catalog).where(db.catalog.c.code == row["code"]).with_for_update()).mappings().first()
        if previous and all(previous[key] == value for key, value in row.items()):
            counts["unchanged"] += 1
            continue
        values = dict(row, updated_at=db.now())
        if previous:
            connection.execute(update(db.catalog).where(db.catalog.c.code == row["code"]).values(**values))
            counts["updated"] += 1
        else:
            connection.execute(insert(db.catalog).values(**values))
            counts["inserted"] += 1
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    records = json.loads((root / "qa/list-latest-records.json").read_text(encoding="utf-8"))["records"]
    plan = json.loads((root / "qa/list-db-plan.json").read_text(encoding="utf-8"))
    codes = {str(item["list"]["CodeNo"]) for item in plan["new_rows_not_inserted"] if item["current_list"]}
    rows = prepare_rows(records, codes)
    assert len(rows) == 269, "Unexpected approved import scope"
    assert all(row["keep_days"] == 6 for row in rows if row["barcode"] == "26586342")
    settings = configparser.ConfigParser(interpolation=None)
    settings.read(root.parent / "config.ini", encoding="utf-8-sig")
    url = settings.get("postgres", "database_url").replace("postgresql://", "postgresql+psycopg2://", 1)
    engine = create_engine(url, connect_args={"sslmode": "require", "connect_timeout": 20,
        "options": "-c statement_timeout=30000 -c lock_timeout=5000"})
    stamp = db.now().replace(":", "").replace("-", "").replace("+", "_")
    backup = root / "qa" / f"catalog-before-{stamp}.json"
    report = root / "qa" / f"catalog-import-{stamp}.json"
    try:
        with engine.begin() as connection:
            if connection.execute(text("SELECT current_database()")).scalar().lower() != "db_0801":
                raise ValueError("Unexpected database")
            exists = connection.execute(text("SELECT to_regclass('public.labelcheck_catalog') IS NOT NULL")).scalar()
            previous = [dict(row) for row in connection.execute(select(db.catalog)).mappings()] if exists else []
            if not args.apply:
                print(json.dumps({"dry_run": True, "selected_rows": len(rows), "existing_catalog_rows": len(previous),
                    "grape_keep_days": [row["keep_days"] for row in rows if row["barcode"] == "26586342"]}))
                return
            backup.write_text(json.dumps({"table_existed": exists, "rows": previous}, ensure_ascii=False, indent=2), encoding="utf-8")
            db.catalog.create(connection, checkfirst=True)
            connection.execute(text("LOCK TABLE public.labelcheck_catalog IN SHARE ROW EXCLUSIVE MODE"))
            counts = write_rows(connection, rows)
            actual = {row["code"]: dict(row) for row in connection.execute(select(db.catalog)).mappings()}
            assert all(all(actual[row["code"]][key] == value for key, value in row.items()) for row in rows)
        result = {"committed": True, "table": "labelcheck_catalog", "counts": counts,
                  "backup": str(backup), "rows": rows, "desktop_tables_changed": False}
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"committed": True, "counts": counts, "report": str(report)}, ensure_ascii=False))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
