"""Read-only adapter for the existing desktop label tables."""
import hashlib
import json
import re
from sqlalchemy import text
from validation import extract_fields, TEXT_FIELDS


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
    return build_draft(snapshot, code)


def build_draft(snapshot, code):
    """Keep desktop layout positions; its PosX is top and PosY is left."""
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
        left, top = float(row["PosY"] or 0) * 4, float(row["PosX"] or 0) * 4
        for offset, part in enumerate(value.splitlines()):
            if not part.strip():
                continue
            y = top + offset * 30
            right = left + max(80, len(part) * 12)
            lines.append({"id": len(lines), "text": part, "score": 1.,
                          "box": [[left,y],[right,y],[right,y+24],[left,y+24]]})
    fields = extract_fields(lines)
    date_labels = " ".join(re.sub(r"\s+", "", item["content"]) for item in dates)
    return {"code": code, "name": snapshot[0]["CodeName"],
            "revision": hashlib.sha256(json.dumps(snapshot, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest(),
            "fields": {k: fields.get(k, {}).get("value", "") for k in TEXT_FIELDS},
            "rules": {"dates": bool(re.search(r"製造日|生產日|有效日|有效期|到期日", date_labels)),
                      "arrival": bool(re.search(r"到店日|到貨日", date_labels))},
            "lines": lines, "keep_days": snapshot[0]["KeepDays"], "date_settings": dates,
            "notice": "標籤系統資料尚未人工核准。請確認實際印字、產地及地址；原系統保存天數與日期位移僅供參考，不會自動套用。"}
