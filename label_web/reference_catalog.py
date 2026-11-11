"""Read-only access to imported lists, without manufacturing desktop layouts."""
from sqlalchemy import text


PREFIX = "list:"
PROJECTION = "code,name,barcode,keep_days,barcode_type,revision,provenance,updated_at"


def available(engine):
    if engine.dialect.name != "postgresql":
        return False
    with engine.connect() as conn:
        return bool(conn.execute(text("SELECT to_regclass('public.labelcheck_catalog') IS NOT NULL")).scalar())


def records(engine):
    if not available(engine):
        return []
    with engine.connect() as conn:
        return [dict(row) for row in conn.execute(text(
            f"SELECT {PROJECTION} FROM public.labelcheck_catalog WHERE active=TRUE ORDER BY code"
        )).mappings().all()]


def build_draft(row):
    barcode = str(row.get("barcode") or "").strip()
    name = str(row["name"])
    known = ["product"] + (["barcode"] if barcode else [])
    if row.get("keep_days") is not None:
        known.append("keep_days")
    limitations = ["此來源只有清單已知欄位，沒有標籤版面、其他印字或日期位移設定。",
                   "未列於清單的文字仍屬未核對，不代表整張標籤已確認正確。"]
    return {"code": PREFIX + str(row["code"]), "name": name, "revision": row["revision"],
            "source_kind": "catalog", "comparison_scope": "catalog_fields", "known_fields": known,
            "fields": {"product": name}, "lines": [{"id": "product", "text": "品名：" + name, "score": 1.}],
            "rules": {"dates": False, "arrival": False}, "date_settings": [],
            "keep_days": row.get("keep_days"), "keep_days_source": "labelcheck_catalog.keep_days",
            "barcode_values": [barcode] if barcode else [],
            # Only payload comparison uses this type. No composition settings are known.
            "barcode_config": {"kind": str(row.get("barcode_type") or "").strip()},
            "provenance": row.get("provenance") or {}, "limitations": limitations,
            "notice": " ".join(limitations)}


def draft(engine, code):
    if not str(code).startswith(PREFIX) or not available(engine):
        return None
    with engine.connect() as conn:
        rows = conn.execute(text(f"SELECT {PROJECTION} FROM public.labelcheck_catalog "
                                 "WHERE active=TRUE AND code=:code"),
                            {"code": str(code)[len(PREFIX):]}).mappings().all()
    return build_draft(dict(rows[0])) if rows else None


def equivalence_key(item):
    """Only known list content can be declared equivalent, never inferred layouts."""
    row = item.get("catalog_record")
    if not row:
        return None
    return (str(row["name"]).strip(), str(row.get("barcode") or "").strip(),
            row.get("keep_days"), str(row.get("barcode_type") or "").strip())
