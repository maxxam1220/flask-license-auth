"""Read-only adapter for the existing desktop label tables."""
import hashlib
import json
from sqlalchemy import text
from validation import extract_fields


def available(engine):
    if engine.dialect.name != "postgresql":
        return False
    with engine.connect() as conn:
        return bool(conn.execute(text("SELECT to_regclass('barcode53.\"BcMst\"') IS NOT NULL AND to_regclass('barcode53.\"BcDtl\"') IS NOT NULL")).scalar())


def search(engine, query):
    pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    with engine.connect() as conn:
        rows = conn.execute(text('SELECT "CodeNo" AS code, "CodeName" AS name FROM barcode53."BcMst" '
                                 'WHERE "CodeNo" ILIKE :q OR "CodeName" ILIKE :q ORDER BY "CodeNo" LIMIT 40'), {"q": pattern}).mappings()
        return [dict(row) for row in rows]


def draft(engine, code):
    with engine.connect() as conn:
        # A single statement gives a consistent source snapshot without locking desktop edits.
        rows = conn.execute(text('SELECT m."CodeNo", m."CodeName", m."KeepDays", d."Seq", d."Attr", '
            'd."ObjContent", d."ShiftDate", d."PosX", d."PosY" FROM barcode53."BcMst" m '
            'LEFT JOIN barcode53."BcDtl" d ON d."CodeNo"=m."CodeNo" '
            'WHERE m."CodeNo"=:code ORDER BY d."PosY",d."PosX",d."Seq"'), {"code": code}).mappings().all()
    if not rows:
        return None
    snapshot = [dict(r) for r in rows]
    lines, dates = [], []
    for row in snapshot:
        attr = str(row["Attr"] or "")[:1]
        value = str(row["ObjContent"] or "")
        if attr == "2":
            value += str(row["CodeName"] or "")
        elif attr != "3":
            if attr in "ABCDEFGHIJKL" and attr:
                dates.append({"content": value, "format": row["Attr"], "shift_days": row["ShiftDate"]})
            continue
        n = len(lines)
        lines.append({"id": n, "text": value, "score": 1., "box": [[0,n*60],[1200,n*60],[1200,n*60+30],[0,n*60+30]]})
    fields = extract_fields(lines)
    return {"code": code, "name": snapshot[0]["CodeName"],
            "revision": hashlib.sha256(json.dumps(snapshot, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest(),
            "fields": {k: fields.get(k, {}).get("value", "") for k in ("product", "address", "origin")},
            "lines": lines, "keep_days": snapshot[0]["KeepDays"], "date_settings": dates,
            "notice": "標籤系統資料尚未人工核准。請確認實際印字、產地及地址；原系統保存天數與日期位移僅供參考，不會自動套用。"}
