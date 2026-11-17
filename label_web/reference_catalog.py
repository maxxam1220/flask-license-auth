"""Read-only access to imported lists, without manufacturing desktop layouts."""
from copy import deepcopy
import hashlib
import json
import re
from sqlalchemy import text


PREFIX = "list:"
PROJECTION = "code,name,barcode,keep_days,barcode_type,revision,provenance,updated_at"


def barcode_structure(source):
    """Return an exact, bounded EAN13 structure, without choosing its date."""
    config=source.get("catalog_barcode_config")
    if not isinstance(config,dict) or type(config.get("version")) is not int or config["version"]!=1 or config.get("origin")!="excel_fields":
        raise ValueError("清單組碼來源格式不完整，請先確認清單設定。")
    if str(config.get("kind"))!="1" or str((source.get("barcode_config") or {}).get("kind"))!="1":
        raise ValueError("清單條碼種類不是 EAN13，不推算此公式。")
    core=config.get("barcode")
    if not isinstance(core,str) or not re.fullmatch(r"[0-9]{1,12}",core) or core not in source.get("barcode_values",[]):
        raise ValueError("清單組碼的商品前綴與目前來源不同，請先確認。")
    front,back=config.get("front"),config.get("back")
    if any(not isinstance(value,str) or re.fullmatch(r"[0-9]*",value) is None for value in (front,back)):
        raise ValueError("清單前後碼有非數字內容，無法安全建立 EAN13 公式。")
    if config.get("solar") not in ("2","3") or config.get("price_len")=="4":
        raise ValueError("清單未提供可直接核對的太陽日設定，或還含售價組碼；不推測其他欄位。")
    width=int(config["solar"]);position=config.get("solar_pos")
    raw=front+core+back
    if type(position) is not int or not 1<=position<=len(raw)+1 or len(raw)+width!=12:
        raise ValueError("清單組碼無法直接組成完整 12 位內容，不會自動補零、截字或更改插入位置。")
    prefix,suffix=raw[:position-1],raw[position-1:]
    if not prefix or len(prefix)>10:
        raise ValueError("太陽日插入位置不在目前可確認的固定前綴之後，請先確認設定。")
    return {"prefix":prefix,"day_width":width,"suffix":suffix}


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
    result={"code": PREFIX + str(row["code"]), "name": name, "revision": row["revision"],
            "source_kind": "catalog", "comparison_scope": "catalog_fields", "known_fields": known,
            "fields": {"product": name}, "lines": [{"id": "product", "text": "品名：" + name, "score": 1.}],
            "rules": {"dates": False, "arrival": False}, "date_settings": [],
            "keep_days": row.get("keep_days"), "keep_days_source": "labelcheck_catalog.keep_days",
            "barcode_values": [barcode] if barcode else [],
            # Only payload comparison uses this type. No composition settings are known.
            "barcode_config": {"kind": str(row.get("barcode_type") or "").strip()},
            "provenance": row.get("provenance") or {}, "limitations": limitations,
            "notice": " ".join(limitations)}
    config=(row.get("provenance") or {}).get("barcode_config")
    if config is not None:
        result["catalog_barcode_config"]=deepcopy(config)
        evidence={"config":config,"provenance":{key:(row.get("provenance") or {}).get(key) for key in ("file","sheet","row","source_date")}}
        result["catalog_barcode_reference_revision"]=hashlib.sha256(json.dumps(evidence,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return result


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
    if item.get("_web_text_approved") or item.get("_standard_revision"):
        return ("approved_text",item.get("_source_revision"),item.get("code"))
    return (str(row["name"]).strip(), str(row.get("barcode") or "").strip(),
            row.get("keep_days"), str(row.get("barcode_type") or "").strip(),
            json.dumps((row.get("provenance") or {}).get("barcode_config"),ensure_ascii=False,sort_keys=True,separators=(",",":")))
