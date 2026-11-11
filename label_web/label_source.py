"""Read-only adapter for the existing desktop label tables."""
import hashlib
import json
import re
import unicodedata
from difflib import SequenceMatcher
from sqlalchemy import text
from validation import extract_fields, TEXT_FIELDS, traditional_display
from source_validation import normalize_text
import reference_catalog


_SKU_LABEL = r"(?:貨號|货号|商品編號|商品编号|品號|品号)"
_BARCODE_LABEL = r"(?:條碼|条码|商品條碼|商品条码|Barcode)"
_IDENTIFIER = r"[A-Za-z0-9][A-Za-z0-9._/\-]*"


def _identity_text(value):
    """Normalization locates one source only; it never changes validation evidence."""
    value = unicodedata.normalize("NFKC", str(value or ""))
    return re.sub(r"\s+", "", traditional_display(value).replace("臺", "台")).casefold()


def _identifiers(value, label, normalize=_identity_text):
    value = unicodedata.normalize("NFKC", str(value or ""))
    return {normalize(match[1]) for match in re.finditer(label + r"\s*[:：]?\s*(" + _IDENTIFIER + r")", value, re.I)}


def _fixed_barcodes(value):
    """Only call for Attr3: Attr0/1 always use a composed runtime barcode."""
    values = set()
    for part in str(value or "").splitlines():
        part = part.strip()
        labelled = re.search(_BARCODE_LABEL + r"\s*[:：]\s*(.+)", part, re.I)
        if labelled:
            # Code128 punctuation, letter case and internal spaces are data. Taking
            # just an alphanumeric prefix would conflate AB:12 with AB:99.
            values.add(labelled[1].strip())
        elif re.fullmatch(r"(?:[0-9]{8}|[0-9]{12,14})", part):
            values.add(part)
    return values


def _desktop_available(engine):
    if engine.dialect.name != "postgresql":
        return False
    with engine.connect() as conn:
        return bool(conn.execute(text("SELECT to_regclass('barcode53.\"BcMst\"') IS NOT NULL AND to_regclass('barcode53.\"BcDtl\"') IS NOT NULL")).scalar())


def available(engine):
    return _desktop_available(engine) or reference_catalog.available(engine)


def search(engine, query):
    pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    items = []
    if _desktop_available(engine):
        with engine.connect() as conn:
            rows = conn.execute(text('SELECT "CodeNo" AS code, "CodeName" AS name FROM barcode53."BcMst" '
                                     'WHERE "CodeNo" ILIKE :q OR "CodeName" ILIKE :q ORDER BY "CodeNo" LIMIT 40'), {"q": pattern}).mappings().all()
            items.extend(dict(row, source_kind="desktop") for row in rows)
    wanted = _identity_text(query)
    items.extend({"code": reference_catalog.PREFIX + str(row["code"]), "name": row["name"], "source_kind": "catalog"}
                 for row in reference_catalog.records(engine)
                 if any(wanted in _identity_text(row.get(key)) for key in ("code", "name", "barcode")))
    return items[:80]


def draft(engine, code):
    if str(code).startswith(reference_catalog.PREFIX):
        return reference_catalog.draft(engine, code)
    with engine.connect() as conn:
        # A single statement gives a consistent source snapshot without locking desktop edits.
        rows = conn.execute(text('SELECT m."CodeNo", m."CodeName", m."KeepDays", '
            'm."Barcode", m."TypesOfBarcode", m."FrontCode", m."BehindCode", '
            'm."SunDay", m."SunPos", m."PriceLen", m."SalePrice", '
            'b."SaveDays" AS "SourceSaveDays", b."FirstCode" AS "SourceFirstCode", '
            'b."LastCode" AS "SourceLastCode", b."Price" AS "SourcePrice", '
            'b."Barcode" AS "SourceBarcode", b."ProdName" AS "SourceProdName", d."Seq", d."Attr", '
            'd."ObjContent", d."ShiftDate", d."PosX", d."PosY" FROM barcode53."BcMst" m '
            'LEFT JOIN LATERAL (SELECT "SaveDays", "FirstCode", "LastCode", "Price", "Barcode", "ProdName" '
            'FROM barcode53."Barcode" WHERE NULLIF(TRIM(m."Barcode"), \'\') IS NOT NULL '
            'AND TRIM("Barcode")=TRIM(m."Barcode") LIMIT 1) b ON TRUE '
            'LEFT JOIN barcode53."BcDtl" d ON d."CodeNo"=m."CodeNo" '
            'WHERE m."CodeNo"=:code ORDER BY d."PosY",d."PosX",d."Seq"'), {"code": code}).mappings().all()
    if not rows:
        return None
    snapshot = [dict(r) for r in rows]
    return build_draft(snapshot, code)


def build_draft(snapshot, code):
    """Keep desktop layout positions; its PosX is top and PosY is left."""
    lines, dates, barcode_values = [], [], set()
    for row in snapshot:
        attr = str(row["Attr"] or "")[:1]
        value = str(row["ObjContent"] or "")
        if attr == "2":
            value += str(row["CodeName"] or "")
        elif attr != "3":
            if attr in "ABCDEFGHIJKL" and attr:
                dates.append({"content": value, "format": row["Attr"], "shift_days": row["ShiftDate"]})
            continue
        if attr == "3":
            barcode_values.update(_fixed_barcodes(value))
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
    master = snapshot[0]
    savedays = master.get("SourceSaveDays")
    keep_days = savedays if savedays is not None else master["KeepDays"]
    clean = lambda value: str(value or "").strip()
    price = float(master.get("SalePrice") or 0)
    if price <= 0 and master.get("SourcePrice") is not None:
        price = float(master["SourcePrice"])
    barcode_config = {
        "kind": clean(master.get("TypesOfBarcode")),
        "barcode": clean(master.get("SourceBarcode")) or clean(master.get("Barcode")),
        "master_barcode": clean(master.get("Barcode")),
        "front": clean(master.get("SourceFirstCode")) or clean(master.get("FrontCode")),
        "back": clean(master.get("SourceLastCode")) or clean(master.get("BehindCode")),
        "solar": clean(master.get("SunDay")), "solar_pos": int(master.get("SunPos") or 1),
        "price_len": clean(master.get("PriceLen")), "sale_price": price,
    }
    return {"code": code, "name": snapshot[0]["CodeName"], "source_kind": "desktop", "comparison_scope": "desktop_label",
            "revision": hashlib.sha256(json.dumps(snapshot, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest(),
            "fields": {k: fields.get(k, {}).get("value", "") for k in TEXT_FIELDS},
            "rules": {"dates": bool(re.search(r"製造日|生產日|有效日|有效期|到期日", date_labels)),
                      "arrival": bool(re.search(r"到店日|到貨日", date_labels))},
            "lines": lines, "keep_days": keep_days, "date_settings": dates,
            "master_keep_days": master["KeepDays"], "source_savedays": savedays,
            "keep_days_source": "Barcode.SaveDays" if savedays is not None else "BcMst.KeepDays",
            "barcode_config": barcode_config,
            "barcode_source": {"barcode": clean(master.get("SourceBarcode")), "product_name": clean(master.get("SourceProdName"))},
            "barcode_values": sorted(barcode_values),
            "notice": "標籤系統資料尚未人工核准。請確認實際印字、產地及地址；原系統保存天數與日期位移僅供參考，不會自動套用。"}


def _catalog(engine):
    """Names and static printed text; list metadata remains explicitly incomplete."""
    masters, details = [], []
    if _desktop_available(engine):
        with engine.connect() as conn:
            masters = conn.execute(text('SELECT "CodeNo" AS code, "CodeName" AS name '
                                        'FROM barcode53."BcMst" ORDER BY "CodeNo"')).mappings().all()
            details = conn.execute(text('SELECT "CodeNo" AS code, "ObjContent" AS content '
                'FROM barcode53."BcDtl" WHERE LEFT("Attr", 1)=\'3\' AND "ObjContent" IS NOT NULL')).mappings().all()
    catalog = {str(row["code"]).strip(): {"code": str(row["code"]).strip(), "name": str(row["name"] or ""),
                "sku": set(), "barcode": set(), "spec": set(), "origin": set(), "text": set(),
                "source_kind": "desktop"} for row in masters}
    for row in details:
        item = catalog.get(str(row["code"]).strip())
        if item is None:
            continue
        content = str(row["content"] or "")
        item["sku"].update(_identifiers(content, _SKU_LABEL))
        item["barcode"].update(_fixed_barcodes(content))
        for part in content.splitlines():
            # A barcode's case, punctuation, and spaces are payload, not typography.
            if part.strip() and not _fixed_barcodes(part):
                item["text"].add(normalize_text(part))
        for key, label in (("spec", r"(?:規格|规格)"), ("origin", r"(?:原料[產産产]地|原[產産产]地|[產産产]地)")):
            for part in content.splitlines():
                match = re.search(label + r"\s*[:：]?\s*(.+)", part)
                if match:
                    # Stop at another printed heading rather than combine different fields.
                    value = re.split(r"品名|規格|规格|產地|産地|产地|保存|電話|电话|貨號|货号", match[1], 1)[0]
                    if value.strip():
                        item[key].add(_identity_text(value))
    for row in reference_catalog.records(engine):
        code = reference_catalog.PREFIX + str(row["code"])
        barcode = str(row.get("barcode") or "").strip()
        catalog[code] = {"code": code, "name": row["name"], "sku": set(),
                         "barcode": {barcode} if barcode else set(), "spec": set(), "origin": set(),
                         "text": set(), "source_kind": "catalog", "catalog_record": row}
    return catalog


def _resolution(status, reason, catalog=None, codes=(), source=None):
    catalog = catalog or {}
    candidates = [{"code": code, "name": catalog[code]["name"], "source_kind": catalog[code].get("source_kind", "desktop")}
                  for code in codes if code in catalog][:8]
    result = {"status": status, "code": source["code"] if source else "",
            "name": source["name"] if source else "", "reason": reason,
            "candidates": candidates, "source": source}
    if source:
        result.update({key: source[key] for key in ("source_kind", "comparison_scope", "known_fields", "limitations", "equivalent_sources") if key in source})
    return result


def resolve(engine, ocr_lines, source_code=""):
    """Resolve one current label; never merge fields from different database labels."""
    try:
        if not available(engine):
            return _resolution("unavailable", "目前無法讀取標籤系統資料，僅提供文字辨識。")
        explicit = str(source_code or "").strip()
        if explicit:
            source = draft(engine, explicit)
            if source is None:
                return _resolution("unmatched", "指定的標籤編號不存在，請重新選擇；未改用其他標籤。")
            return _resolution("matched", "使用指定標籤的最新資料核對。",
                               {explicit: source}, [explicit], source)
        catalog = _catalog(engine)
        if not catalog:
            return _resolution("unmatched", "標籤系統尚無可比對的商品資料。")
        normalized_names = {code: _identity_text(item["name"]) for code, item in catalog.items()}
        name_index = {}
        for code, name in normalized_names.items():
            name_index.setdefault(name, set()).add(code)
        # Low-confidence OCR can suggest candidates, but cannot silently select one.
        reliable = [line for line in ocr_lines if float(line.get("score", 0)) >= .65 and not line.get("ambiguous")]
        fields = extract_fields(reliable)
        product = fields.get("product", {})
        names = set()
        if product.get("value") and not product.get("ambiguous"):
            names.add(_identity_text(product["value"]))
        # An exact complete standalone name can still be found when the generic field
        # extractor picked another heading. No substring or fuzzy acceptance is used.
        for line in reliable:
            value = re.sub(r"^(?:產品名稱|商品名稱|產品品名|品名)\s*[:：]?\s*", "", line["text"])
            names.add(_identity_text(value))
        sku_values, barcode_values = set(), set()
        for line in reliable:
            sku_values.update(_identifiers(line["text"], _SKU_LABEL))
            barcode_values.update(_fixed_barcodes(line["text"]))
            # Human-readable Code128 text has no mandatory heading on the photo.
            # It can identify a source only by the complete known fixed value.
            barcode_values.add(str(line["text"]).strip())
        signals = []
        for name in names:
            matched = name_index.get(name, set())
            if matched:
                signals.append(matched)
        name_candidates = set.intersection(*signals) if signals else set()
        for key, values in (("sku", sku_values), ("barcode", barcode_values)):
            for value in values:
                matched = {code for code, item in catalog.items() if value in item[key]}
                if matched:
                    if key == "barcode" and matched & name_candidates:
                        # A same-name list with an unknown barcode is not proof of
                        # a different barcode. Barcode-only discovery still uses
                        # affirmative known matches, never all blank records.
                        matched |= {code for code in name_candidates if not catalog[code]["barcode"]}
                    signals.append(matched)
        if signals:
            candidates = set.intersection(*signals)
            if not candidates:
                return _resolution("ambiguous", "品名、貨號或固定條碼指向不同標籤，請人工選擇。",
                                   catalog, sorted(set.union(*signals)))
            original_candidates = candidates.copy()
            if len(candidates) > 1:
                observed_days = {int(match[1]) for line in reliable
                                 if (match := re.fullmatch(r"(?:保存期限|保存天數|保鮮期|賞味天數):?(\d+)天",
                                                          _identity_text(line["text"])))}
                if observed_days and any(catalog[code].get("source_kind") == "catalog" for code in candidates):
                    if len(observed_days) > 1:
                        return _resolution("ambiguous", "照片出現不同的保存天數，無法確認單一清單來源。",
                                           catalog, sorted(original_candidates))
                    observed_days = next(iter(observed_days))
                    candidates = {code for code in candidates
                                  if catalog[code].get("catalog_record", {}).get("keep_days") is None
                                  or catalog[code]["catalog_record"]["keep_days"] == observed_days}
                    if not candidates:
                        return _resolution("ambiguous", "照片保存天數與同名清單均不相符，無法確認單一來源。",
                                           catalog, sorted(original_candidates))
                for key in ("spec", "origin"):
                    field = fields.get(key, {})
                    if not field.get("value") or field.get("ambiguous"):
                        continue
                    observed = _identity_text(field["value"])
                    # Missing catalog metadata is unknown, not proof that a variant differs.
                    remaining = {code for code in candidates if not catalog[code][key] or observed in catalog[code][key]}
                    if not remaining:
                        return _resolution("ambiguous", "同名標籤的規格或產地無法一致對應，請人工選擇。",
                                           catalog, sorted(original_candidates))
                    candidates = remaining
                # Use other complete printed lines only after product identity is
                # established. Shared footers alone never select a product. Lists
                # have no layout evidence, so missing text cannot exclude them.
                for line in reliable:
                    if _fixed_barcodes(line["text"]):
                        continue
                    observed = normalize_text(line["text"])
                    matches = {code for code in original_candidates if observed in catalog[code]["text"]}
                    if not matches:
                        continue
                    supported = matches | {code for code in original_candidates if catalog[code].get("source_kind") == "catalog"}
                    # Explicit spec/origin already retain unknown competing values.
                    if any(observed == normalize_text(field.get("value", "")) for key, field in fields.items() if key in {"spec", "origin"}):
                        continue
                    candidates &= supported
                    if not candidates:
                        return _resolution("ambiguous", "同張照片的差異文字指向不同款式，無法確認單一來源。",
                                           catalog, sorted(original_candidates))
            equivalent = []
            if len(candidates) > 1:
                keys = {reference_catalog.equivalence_key(catalog[code]) for code in candidates}
                if None not in keys and len(keys) == 1:
                    equivalent = [{"code": code, "name": catalog[code]["name"], "source_kind": "catalog"}
                                  for code in sorted(candidates)]
                    candidates = {sorted(candidates)[0]}
            if len(candidates) != 1:
                return _resolution("ambiguous", "現有文字仍無法區分多款來源；請補拍可辨識的規格、條碼或其他差異文字。",
                                   catalog, sorted(candidates))
            code = next(iter(candidates))
            source = draft(engine, code)
            if source is None:
                return _resolution("unmatched", "該標籤已變更或移除，請重新選擇。")
            if equivalent:
                source["equivalent_sources"] = equivalent
            reason = ("多筆清單的品名、條碼與保存天數完全相同，使用等價清單資料核對。" if equivalent
                      else "依完整相符的品名、貨號、條碼及可用差異文字，對應同一款來源。")
            return _resolution("matched", reason,
                               catalog, [code], source)
        # Suggestions are deliberately separate from source selection and validation.
        extracted = extract_fields(ocr_lines)
        observed = extracted.get("product", {}).get("value", "")
        possible = [_identity_text(observed)] if observed else []
        ranked = sorted(((max((SequenceMatcher(None, name, normalized_names[code]).ratio()
                               for name in possible), default=0), code) for code, item in catalog.items()), reverse=True)
        suggestions = [code for score, code in ranked if score >= .55][:5]
        return _resolution("unmatched", "尚未找到完全一致的商品；相近品名僅供選擇，不會自動判定相符。",
                           catalog, suggestions)
    except Exception:
        # Connection and schema failures must never silently activate unrelated defaults.
        return _resolution("unavailable", "標籤系統資料暫時無法讀取，請稍後重試；目前僅提供文字辨識。")
