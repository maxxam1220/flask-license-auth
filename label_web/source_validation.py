"""Compare OCR with one selected database label, without global fixed-text rules."""
from datetime import date, timedelta
from difflib import SequenceMatcher
import re
import unicodedata

from validation import diff_parts, parse_date, traditional_display, product_row_candidates, line_is_uncertain
from label_geometry import analyze_label_scope, scope_review_result, date_evidence


RULE_VERSION = "1.9"
MIN_CONFIDENCE = .65
DATE_KEYS = ("manufacture", "expiry", "arrival")


def _field_uncertain(field):
    return field.get("ambiguous") or not field.get("confidence_ok", field.get("score", 0) >= MIN_CONFIDENCE)


FIELD_NAMES = {"product": "品名", "origin": "產地", "address": "地址", "company": "公司名稱",
               "phone": "電話", "spec": "規格", "storage": "保存條件", "item_code": "貨號",
               "pack_count": "入數", "barcode": "條碼", "manufacture": "製造日期",
               "expiry": "有效日期", "arrival": "到店日", "shelf_days": "保存天數"}
HEADINGS = {
    "product": r"(?:產品名稱|商品名稱|產品品名|品名)",
    "origin": r"(?:原料產地|原產地|原產國|產地)",
    "address": r"(?:負責廠商地址|製造商地址|製造廠地址|公司地址|製造廠址|地址|住址|廠址)",
    "company": r"(?:負責廠商名稱|製造廠商名稱|製造商名稱|公司名稱|廠商名稱|負責廠商|製造廠商|製造商)",
    "phone": r"(?:免付費(?:服務)?電話|客服電話|服務電話|聯絡電話|客服專線|服務專線|電話)",
    "spec": r"規格", "storage": r"(?:保存條件|保存方式|儲存條件|貯存條件|儲存方式)",
    "item_code": r"(?:貨號|商品編號|品號)", "pack_count": r"(?:入數|裝入數)",
    "manufacture": r"(?:製造日期|製造日|生產日期|生產日)",
    "expiry": r"(?:有效日期|有效期限|有效日|保存期限至|最佳賞味期|賞味期限|到期日)",
    "arrival": r"(?:到店日期|到店日|到貨日期|到貨日)",
    "shelf_days": r"(?:保存天數|保存期限|保鮮期|賞味天數)",
}
ALL_HEADINGS = "|".join(HEADINGS.values())


def _prepared(text):
    value = unicodedata.normalize("NFKC", str(text or ""))
    return re.sub(r"\s+", "", traditional_display(value).replace("臺", "台"))


def _heading(text):
    value = _prepared(text)
    matches = [(match.end(), key) for key, pattern in HEADINGS.items()
               if (match := re.match(pattern + r":?", value))]
    return max(matches)[1] if matches else None


def normalize_text(text):
    """Only approved presentation equivalences; never repair digits or arbitrary typos."""
    value = _prepared(text)
    # Only a leading heading may be omitted. A heading-like word inside a value
    # (including an extra suffix) remains significant evidence.
    if kind := _heading(value):
        value = re.sub(r"^" + HEADINGS[kind] + r":?", "", value, count=1)
    value = re.sub(r"(?<=\d)[kK][gG]", "kg", value)
    # A hyphen between two positive temperatures is a range separator, not a minus sign.
    # Negative endpoints (including a double hyphen) are deliberately untouched.
    value = re.sub(r"(?<![\d.+-])(\d+(?:\.\d+)?°C)[~～〜至到-](\d+(?:\.\d+)?°C)", r"\1~\2", value)
    return value


def _kind(text, source_fields=None):
    if heading := _heading(text):
        return heading
    value = _prepared(text)
    if re.fullmatch(r"\d{12,14}", value):
        return "barcode"
    if re.search(r"(?:公司|企業社|商行)$", value):
        return "company"
    if re.search(r"[市縣].{1,20}(?:[區鄉鎮市]|[路街])", value):
        return "address"
    if re.fullmatch(r"[()0-9+.#-]+", value) and value.startswith(("0", "(0")) and 7 <= len(re.sub(r"\D", "", value)) <= 11:
        return "phone"
    if source_fields:
        matched = [key for key, expected in source_fields.items() if expected and normalize_text(expected) == normalize_text(text)]
        if len(matched) == 1:
            return matched[0]
    return None


def _bounds(line):
    box = line.get("box") or []
    if not box:
        return None
    return min(p[0] for p in box), min(p[1] for p in box), max(p[0] for p in box), max(p[1] for p in box)


def _following(first, other):
    left, right = _bounds(first), _bounds(other)
    if left is None or right is None:
        return None
    x, y, r, b = left
    nx, ny, nr, nb = right
    height = max(b-y, nb-ny, 1)
    overlap = max(0, min(r, nr)-max(x, nx))
    row_overlap = max(0, min(b, nb)-max(y, ny))
    if (_heading(first["text"]) and not normalize_text(first["text"])
            and row_overlap >= min(b-y, nb-ny)*.5 and 0 <= nx-r <= height*4):
        return (0, nx-r)
    aligned = overlap >= min(r-x, nr-nx)*.5 and abs(nx-x) <= max((r-x)*.45, height*2)
    if aligned and ny >= b-height*.35 and ny-b <= max(height*2, 24):
        return (1, max(0, ny-b))
    return None


def _groups(lines, source_fields=None):
    groups = []
    for line in lines:
        chain = [line]
        for _ in range(6):
            text = "".join(item["text"] for item in chain)
            groups.append({"lines": chain.copy(), "ids": frozenset(item["id"] for item in chain),
                           "text": text, "normal": normalize_text(text),
                           "kind": chain[0].get("_kind") or _kind(chain[0]["text"], source_fields),
                           "barcode_kind": chain[0].get("_barcode_kind"),
                           "barcode_heading": chain[0].get("_barcode_heading", False),
                           "score": min(float(item.get("score", 0)) for item in chain),
                           "ambiguous": any(item.get("human_uncertain") or (item.get("ambiguous", False) and not item.get("human_verified")) for item in chain),
                           "confidence_ok": all(not line_is_uncertain(item, MIN_CONFIDENCE) for item in chain)})
            nearby = [(distance, item) for item in lines if item not in chain
                      and (distance := _following(chain[-1], item)) is not None]
            if not nearby:
                break
            chain.append(min(nearby, key=lambda pair: pair[0])[1])
    for row in product_row_candidates(lines):
        groups.append({"lines": row["lines"], "ids": frozenset(row["line_ids"]),
                       "text": row["raw_text"], "normal": normalize_text(row["raw_text"]), "kind": "product",
                       "barcode_kind": None, "barcode_heading": False,
                       "score": row["score"], "ambiguous": row["ambiguous"], "assembled_product": True,
                       "confidence_ok": all(not line_is_uncertain(item, MIN_CONFIDENCE) for item in row["lines"])})
    return groups


def _compared_text(expected, text):
    if expected["kind"] != "barcode":
        return normalize_text(text)
    kind = expected.get("barcode_kind")
    if expected.get("barcode_heading"):
        text = _strip_barcode_heading(text)
    numeric = kind in {"1", "2", "3"} or (kind is None and expected["text"].strip().isascii() and expected["text"].strip().isdigit())
    if numeric:
        # EAN/UPC human-readable digits may be visually spaced; no punctuation/digit repair.
        return re.sub(r"\s+", "", unicodedata.normalize("NFKC", str(text)))
    # Code128 punctuation, spaces and case are data, not label formatting.
    return str(text).strip()


def _strip_barcode_heading(text):
    return re.sub(r"^(?:條碼|条码|Barcode|BARCODE)\s*[：:]\s*", "", str(text).strip(), count=1)


def _equivalent(expected, actual):
    return _compared_text(expected, expected["text"]) == _compared_text(expected, actual["text"])


def _compatible(expected, actual):
    a, b = expected["kind"], actual["kind"]
    if a == "barcode":
        return True  # The explicit database barcode type owns its payload semantics.
    if a in DATE_KEYS or b in DATE_KEYS:
        return False
    if a and b and a != b:
        return False
    # Bare long numeric codes must not be mistaken for an almost-matching phone number.
    if a == "phone" and len(re.sub(r"\D", "", actual["text"])) > 11:
        return False
    return True


def _source_rows(source):
    rows, seen = [], set()
    for index, row in enumerate((source or {}).get("lines", [])):
        identifier = row.get("id", index)
        if identifier in seen or not str(row.get("text", "")).strip():
            continue
        seen.add(identifier)
        rows.append(dict(row, id=identifier, text=str(row["text"]), score=1.))
    for index, entry in enumerate((source or {}).get("barcode_values", []) or []):
        value = str(entry.get("value", "") if isinstance(entry, dict) else entry)
        if value:
            existing = next((row for row in rows if row["text"].strip() == value.strip()), None)
            heading = False
            if existing is None:
                existing = next((row for row in rows if _strip_barcode_heading(row["text"]) == value.strip()), None)
                heading = existing is not None
            kind = str((source or {}).get("barcode_config", {}).get("kind", "")).strip() or None
            if existing:
                existing.update(_kind="barcode", _barcode_kind=kind, _barcode_heading=heading)
            else:
                rows.append({"id": f"barcode_{index}", "text": value, "score": 1., "box": [],
                             "_kind": "barcode", "_barcode_kind": kind})
    return [row for row in rows if row.get("_kind") == "barcode" or _heading(row["text"]) not in DATE_KEYS]


def _text_checks(lines, source):
    source_rows = _source_rows(source)
    expected_groups = _groups(source_rows, (source or {}).get("fields"))
    actual_groups = _groups(lines)
    used_source, used_actual, checks, fields, keys = set(), set(), [], {}, set()

    def usable(expected, actual):
        if actual["ids"] & used_actual or not _compatible(expected, actual):
            return False
        # Once geometry establishes a complete observed product row, do not
        # accept a shorter subset and hide extra/mistyped adjacent characters.
        return expected["kind"] != "product" or not any(
            actual["ids"] < row["ids"] for row in actual_groups if row.get("assembled_product"))

    def record(expected, actual=None, ambiguous=False):
        kind = expected["kind"] if len(expected["lines"]) == 1 else None
        key = kind or f"source_text_{expected['lines'][0]['id']}"
        if key in keys:
            key += f"_{expected['lines'][0]['id']}"
        keys.add(key)
        if actual is None:
            status, reason, text, confidence, identifiers = "review", "未辨識到資料庫中的這段文字，請確認是否漏印或照片未拍完整。", "", None, []
        else:
            text, confidence, identifiers = actual["text"], actual["score"], [item["id"] for item in actual["lines"]]
            if ambiguous or _field_uncertain(actual):
                status, reason = "review", "文字辨識不清楚或有多個候選，請對照原圖確認。"
            elif _equivalent(expected, actual):
                status, reason = "pass", "與這份資料庫標籤的對應文字相符。"
            else:
                status, reason = "fail", "與這份資料庫標籤不同，請確認錯字、漏字、多字或數字差異。"
            used_actual.update(actual["ids"])
            if kind:
                fields[kind] = {"value": text, "score": confidence, "line_ids": identifiers, "ambiguous": ambiguous or actual["ambiguous"]}
        used_source.update(expected["ids"])
        same_normal = actual is not None and _equivalent(expected, actual)
        checks.append({"key": key, "label": FIELD_NAMES.get(kind, "資料庫文字"), "status": status, "reason": reason,
                       "expected": expected["text"], "actual": text, "raw_actual": text,
                       "line_ids": identifiers, "source_line_ids": [item["id"] for item in expected["lines"]],
                       "score": confidence, "diff": diff_parts(expected["text"], text), "source": "database",
                       "normalization_note": ("已容許繁簡／異體、全半形、空白／冒號、標題及單位大小寫等格式差異；辨識原文保留。"
                                              if same_normal and expected["text"] != text else "")})

    # Exact single database rows are resolved first. Joining is only for unmatched wrapping.
    for group_size in (1, 2):
        for expected in sorted(expected_groups, key=lambda group: len(group["lines"])):
            if expected["ids"] & used_source or (len(expected["lines"]) == 1) != (group_size == 1) or not expected["normal"]:
                continue
            candidates = [actual for actual in actual_groups if usable(expected, actual) and _equivalent(expected, actual)]
            if candidates:
                candidates.sort(key=lambda group: (len(group["lines"]), -group["score"]))
                best = candidates[0]
                ambiguous = any(not best["ids"] & other["ids"] for other in candidates[1:])
                record(expected, best, ambiguous)
    for expected in [group for group in expected_groups if len(group["lines"]) == 1]:
        if expected["ids"] & used_source:
            continue
        ranked = []
        for actual in actual_groups:
            if not usable(expected, actual):
                continue
            similarity = SequenceMatcher(None, _compared_text(expected, expected["text"]), _compared_text(expected, actual["text"]), autojunk=False).ratio()
            minimum = .4 if expected["kind"] and expected["kind"] == actual["kind"] else .55
            if similarity >= minimum:
                ranked.append((similarity, actual))
        ranked.sort(key=lambda item: (item[0], -len(item[1]["lines"])), reverse=True)
        if ranked:
            similarity, actual = ranked[0]
            ambiguous = any(similarity-other_score < .025 and not actual["ids"] & other["ids"] for other_score, other in ranked[1:])
            record(expected, actual, ambiguous)
        else:
            record(expected)
    return checks, fields, used_actual


def _raw_date_value(text):
    value = str(text).strip()
    if ":" in value or "：" in value:
        return re.split(r"[：:]", value, maxsplit=1)[1].strip()
    match = re.search(r"民國|[0-9０-９OoIl]{2,}", value)
    return value[match.start():].strip() if match else ""


def _date_fields(lines):
    found = {}
    for line in lines:
        key = _heading(line["text"])
        if key not in DATE_KEYS:
            continue
        observed = date_evidence(line, _raw_date_value(line["text"]), lines)
        value, evidence = observed["value"], observed["lines"]
        candidate = {"value": value, "line_ids": [item["id"] for item in evidence],
                     "score": min(float(item.get("score", 0)) for item in evidence),
                     "ambiguous": observed["ambiguous"] or any(item.get("human_uncertain") or (item.get("ambiguous", False) and not item.get("human_verified")) for item in evidence),
                     "confidence_ok": all(not line_is_uncertain(item, MIN_CONFIDENCE) for item in evidence)}
        if key in found:
            found[key]["ambiguous"] = True
        else:
            found[key] = candidate
    # A standalone number/date box must never fill two different date headings.
    for first, field in found.items():
        for second, other in found.items():
            if first != second and set(field["line_ids"]) & set(other["line_ids"]):
                field["ambiguous"] = other["ambiguous"] = True
    return found


def _formatted_date(value, code):
    pattern = ("%Y.%m.%d" if code in "AB" else "%Y/%m/%d" if code in "CD"
               else "%m.%d" if code in "EF" else "%m/%d" if code in "GH" else "%m%d")
    return value.strftime(pattern) + ("1700" if code == "K" else "2400" if code == "L" else "")


def _date_settings(source, base):
    settings = {}
    for item in (source or {}).get("date_settings", []):
        key = _heading(item.get("content", ""))
        if key not in DATE_KEYS:
            continue
        code = str(item.get("format", ""))[:1]
        entry = {"format": code, "expected_date": None, "expected_text": None}
        if base and code in "ABCDEFGHIJKL" and code:
            keep = (source or {}).get("keep_days")
            try:
                shift = int(item.get("shift_days") or 0)
                if code in "BDFHJL" and keep is None:
                    raise ValueError("missing keep days")
                offset = shift + (int(keep) if code in "BDFHJL" else 0)
                expected = base + timedelta(days=offset)
                entry.update(expected_date=expected, expected_text=_formatted_date(expected, code), offset=offset)
            except (TypeError, ValueError, OverflowError):
                entry["invalid"] = True
        if key in settings:
            settings[key]["ambiguous"] = True
        else:
            settings[key] = entry
    return settings


def _date_checks(lines, source, batch_date, arrival_date, base_date, literal_ids=None):
    fields, checks, notes, parsed, uncertain = _date_fields(lines), [], [], {}, set()
    base = date.fromisoformat(base_date) if base_date else None
    settings = _date_settings(source, base)
    for key, explicit in (("manufacture", batch_date), ("arrival", arrival_date)):
        if explicit:
            expected = date.fromisoformat(explicit)
            entry = settings.setdefault(key, {"format": "A"})
            code = entry.get("format") or "A"
            entry.update(expected_date=expected, expected_text=_formatted_date(expected, code), manual_override=True)
            entry.pop("invalid", None)
            entry.pop("ambiguous", None)
    expected_keys = set(fields) | set(settings)
    rules = (source or {}).get("rules", {})
    if not settings and rules.get("dates"):
        expected_keys.update(("manufacture", "expiry"))
    if rules.get("arrival") or arrival_date:
        expected_keys.add("arrival")
    if batch_date:
        expected_keys.add("manufacture")

    def add(key, label, status, reason, expected, actual, identifiers, score=None, **extra):
        checks.append(dict(key=key, label=label, status=status, reason=reason, expected=expected, actual=actual,
                           raw_actual=actual, line_ids=identifiers, score=score, source="date", **extra))

    for key in DATE_KEYS:
        if key not in expected_keys:
            continue
        field = fields.get(key, {})
        value, ids, confidence = field.get("value", ""), field.get("line_ids", []), field.get("score", 0)
        setting = settings.get(key, {})
        short = bool(setting.get("format")) and setting["format"] in "EFGHIJKL"
        status, reason = "pass", "完整年月日格式可辨識；格式正確不代表符合本批排程。"
        try:
            if short:
                normal = unicodedata.normalize("NFKC", re.sub(r"\s+", "", value))
                code = setting["format"]
                pattern = r"\d{2}\.\d{2}" if code in "EF" else r"\d{2}/\d{2}" if code in "GH" else r"\d{4}" if code in "IJ" else r"\d{8}"
                if not re.fullmatch(pattern, normal):
                    raise ValueError("short format mismatch")
                month, day = (int(normal[:2]), int(normal[3:5])) if code in "EFGH" else (int(normal[:2]), int(normal[2:4]))
                date((setting.get("expected_date") or base or date(2000, 1, 1)).year, month, day)
                if code in "KL" and normal[4:] != ("1700" if code == "K" else "2400"):
                    raise ValueError("short time mismatch")
                if setting.get("expected_text") == normal:
                    parsed[key] = {"date": setting["expected_date"], "hour": None, "minute": 0}
                reason = "依資料庫的短日期格式檢查；照片未印出的年份不會當成辨識結果。"
            else:
                parsed[key] = parse_date(value)
        except (ValueError, TypeError):
            status, reason = "fail", "日期不完整、不合法或格式不符，請確認印字與辨識原文。"
        if not value or _field_uncertain(field):
            status, reason = "review", "日期未看清楚或有多個候選，請對照原圖確認。"
        if status != "pass":
            uncertain.add(key)
        add(key, FIELD_NAMES[key] + "格式", status, reason, "資料庫指定的短日期格式" if short else "完整且合法的年月日", value, ids, confidence)
        if setting.get("expected_text"):
            same = (unicodedata.normalize("NFKC", re.sub(r"\s+", "", value)) == setting["expected_text"] if short
                    else key in parsed and parsed[key]["date"] == setting["expected_date"])
            checked_status = "review" if status == "review" or setting.get("ambiguous") else "pass" if same else "fail"
            schedule_reason = (f"應為 {setting['expected_text']}，辨識為 {value or '未辨識到'}，與本批排程不同。" if checked_status == "fail"
                               else "日期辨識不確定，請對照原圖及本批預期日期複核。" if checked_status == "review"
                               else "已依本次手動指定日期覆蓋原排程；保留資料庫的印字格式。" if setting.get("manual_override")
                               else "符合本批基準日及資料庫日期設定。")
            add(key + "_schedule", FIELD_NAMES[key] + "排程", checked_status,
                schedule_reason, setting["expected_text"], value, ids, confidence,
                base_date=base_date)
            if not same:
                uncertain.add(key)
        elif setting.get("invalid"):
            add(key + "_schedule", FIELD_NAMES[key] + "排程", "review", "資料庫日期設定不完整，無法計算本批預期日期。", "完整的日期設定", value, ids, confidence)
        elif base and not short and key in parsed:
            same_year = parsed[key]["date"].year == base.year
            add(key + "_year", FIELD_NAMES[key] + "年份", "review" if status == "review" else "pass" if same_year else "fail",
                "未取得可跨年的資料庫日期設定，先與本批基準年份核對。", str(base.year), str(parsed[key]["date"].year), ids, confidence)
    for key, expected, check_key, label in (("manufacture", batch_date, "batch", "本批製造日"),
                                            ("arrival", arrival_date, "arrival_expected", "本批到店日")):
        if not expected:
            continue
        field = fields.get(key, {})
        actual = parsed.get(key, {}).get("date")
        low = _field_uncertain(field) or not field.get("value")
        add(check_key, label, "review" if low else "pass" if actual == date.fromisoformat(expected) else "fail",
            "與本次指定的日期核對。", expected, field.get("value", ""), field.get("line_ids", []), field.get("score"))
    for first, second, key, label, expectation in (("manufacture", "expiry", "date_order", "日期先後", "有效日期 ≥ 製造日期"),
                                                   ("manufacture", "arrival", "arrival_manufacture", "到店與製造先後", "到店日 ≥ 製造日期"),
                                                   ("arrival", "expiry", "arrival_expiry", "到店與有效日期", "有效日期 ≥ 到店日")):
        if first not in parsed or second not in parsed:
            continue
        a, b = parsed[first], parsed[second]
        bad = b["date"] < a["date"] or (b["date"] == a["date"] and a.get("hour") is not None and b.get("hour") is not None
                                               and (b["hour"], b["minute"]) < (a["hour"], a["minute"]))
        low = any(_field_uncertain(fields.get(item, {})) for item in (first, second))
        bad_reason = {"date_order": "有效日期早於製造日期。", "arrival_manufacture": "到店日早於製造日期。", "arrival_expiry": "到店日晚於有效日期。"}[key]
        add(key, label, "review" if low else "fail" if bad else "pass", bad_reason if bad else "日期先後順序合理。",
            expectation, f"{a['date']} → {b['date']}", fields[first]["line_ids"] + fields[second]["line_ids"])
    if (source or {}).get("source_kind") == "manual" and source.get("keep_days") is not None and all(key in parsed for key in ("manufacture","expiry")):
        days = (parsed["expiry"]["date"]-parsed["manufacture"]["date"]).days
        low = any(_field_uncertain(fields[key]) for key in ("manufacture","expiry"))
        same = days == source["keep_days"]
        add("keep_days", "保存天數", "review" if low else "pass" if same else "fail",
            "製造與有效日期的間隔符合人工確認的保存天數。" if same else "製造與有效日期的間隔不符合人工確認的保存天數。",
            f"相差 {source['keep_days']} 天",f"相差 {days} 天",fields["manufacture"]["line_ids"]+fields["expiry"]["line_ids"])
    if base:
        if "expiry" in parsed:
            field = fields["expiry"]
            low = _field_uncertain(field)
            expired = parsed["expiry"]["date"] < base
            add("expired", "有效日期與基準日", "review" if low else "fail" if expired else "pass",
                "有效日期已早於本批基準日。" if expired else "有效日期未早於本批基準日。", f"有效日期 ≥ {base}", field["value"], field["line_ids"])
        if "manufacture" in parsed and parsed["manufacture"]["date"] > base:
            field, setting = fields["manufacture"], settings.get("manufacture", {})
            scheduled = setting.get("expected_date") == parsed["manufacture"]["date"]
            low = _field_uncertain(field)
            add("future_manufacture", "製造日期與基準日", "review" if low else "pass" if scheduled else "fail",
                ("此未來製造日符合本次手動指定的預定日期。" if setting.get("manual_override") else "此未來製造日符合資料庫設定的預定生產位移。") if scheduled else "製造日期晚於基準日，且無相符的資料庫預定生產設定。",
                setting.get("expected_text") or f"製造日期 ≤ {base}", field["value"], field["line_ids"])
    labelled_ids = {identifier for field in fields.values() for identifier in field["line_ids"]}
    for line in lines:
        if line["id"] in labelled_ids or line["id"] in (literal_ids or set()):
            continue
        for number, match in enumerate(re.finditer(r"(?:民國\s*)?[0-9０-９OoIl]{3,4}\s*[年./．-]\s*[0-9０-９OoIl]{1,2}\s*[月./．-]\s*[0-9０-９OoIl]{1,2}(?:\s*日)?", line["text"])):
            confidence = float(line.get("score", 0))
            value, status, actual_date = match[0], "pass", None
            try:
                actual_date = parse_date(value)["date"]
                reason = "年月日格式可辨識；尚未確認這個日期的業務用途。"
            except (ValueError, TypeError):
                status, reason = "fail", "日期不完整或不合法，請確認數字是否錯誤。"
            if line_is_uncertain(line, MIN_CONFIDENCE):
                status, reason = "review", "日期文字看不清楚，請對照原圖。"
            add(f"date_line_{line['id']}_{number}", "其他日期格式", status, reason, "完整且合法的年月日", value, [line["id"]], confidence)
            if base and actual_date:
                # Unlabelled dates cannot inherit a different field's cross-year allowance.
                add(f"date_year_{line['id']}_{number}", "其他日期年份", "review" if line_is_uncertain(line, MIN_CONFIDENCE) else "pass" if actual_date.year == base.year else "fail",
                    "沒有此日期的對應排程，先核對本批基準年份。", str(base.year), str(actual_date.year), [line["id"]], confidence)
    if not base:
        notes.append("尚未指定本批基準日，未核對資料庫日期排程、基準年份或是否過期。")
    if not settings and not batch_date and not arrival_date:
        notes.append("未取得對應資料庫日期設定；日期格式與順序可檢查，仍不能確認實際排程。")
    return checks, fields, notes


def _decorate(result, lines):
    index = {line["id"]: line for line in lines}
    covered = {identifier for check in result["checks"] for identifier in check.get("line_ids", [])}
    for line in lines:
        if line["id"] in covered:
            matching = [check for check in result["checks"] if line["id"] in check.get("line_ids", [])]
            if any(check.get("source") == "database" for check in matching):
                continue
            remainder = line["text"]
            for value in sorted({check.get("actual", "") for check in matching}, key=len, reverse=True):
                if value:
                    remainder = remainder.replace(value, "", 1)
            if not normalize_text(remainder):
                continue
        low = line_is_uncertain(line, MIN_CONFIDENCE)
        result["checks"].append({"key": f"text_line_{line['id']}", "label": "其他辨識文字", "status": "review" if low else "read",
                                  "expected": "", "actual": line["text"], "raw_actual": line["text"], "line_ids": [line["id"]],
                                  "score": line.get("score"), "source": "ocr", "diff": [],
                                  "reason": "文字看不清楚，請對照原圖。" if low else "這段文字未在所選標籤找到對應依據，僅供閱讀。"})
    for check in result["checks"]:
        actual = check.get("actual", "")
        check.setdefault("raw_actual", actual)
        check["display_actual"] = traditional_display(actual)
        check["display_expected"] = traditional_display(check.get("expected", ""))
        check["conversion_changed"] = actual != check["display_actual"]
        check["source_lines"] = [{"id": identifier, "text": index[identifier]["text"],
                                  "display_text": traditional_display(index[identifier]["text"]), "score": index[identifier].get("score"),
                                  "alternatives": index[identifier].get("alternatives", []),
                                  "conversion_changed": traditional_display(index[identifier]["text"]) != index[identifier]["text"]}
                                 for identifier in check.get("line_ids", []) if identifier in index]
    counts = {key: sum(check["status"] == key for check in result["checks"]) for key in ("pass", "fail", "review", "read")}
    result["counts"] = counts
    result["status"] = "fail" if counts["fail"] else "review" if not result["checks"] or counts["review"] or counts["read"] else "pass"
    result["coverage"] = {"total_lines": len(lines), "covered_lines": len({identifier for check in result["checks"] for identifier in check.get("line_ids", [])}.intersection(index))}
    return result


def evaluate_source(lines, source, batch_date="", arrival_date="", base_date="", ocr_capabilities=None):
    """A source is a single database label snapshot, or None when it is unknown."""
    scope = analyze_label_scope(lines)
    if scope["blocked"]:
        return scope_review_result(lines, scope, RULE_VERSION, traditional_display)
    # An explicit Code128 payload can look like a date, but it remains barcode data.
    barcode_groups = [group for group in _groups(_source_rows(source)) if group["kind"] == "barcode" and len(group["lines"]) == 1]
    literal_barcodes = {line["id"] for line in lines if any(_compared_text(group, line["text"]) == _compared_text(group, group["text"]) for group in barcode_groups)}
    date_lines = [line for line in lines if line["id"] not in literal_barcodes]
    identified_dates = _date_fields(date_lines)
    date_ids = {identifier for field in identified_dates.values() for identifier in field["line_ids"]}
    text_lines = [line for line in lines if line["id"] not in date_ids]
    checks, fields, literal_ids = _text_checks(text_lines, source) if source else ([], {}, set())
    date_checks, date_fields, notes = _date_checks(date_lines, source, batch_date, arrival_date, base_date, literal_ids)
    fields.update(date_fields)
    checks.extend(date_checks)
    unsupported = (ocr_capabilities or {}).get("unsupported_symbols", [])
    weak = (ocr_capabilities or {}).get("known_weak_symbols", [])
    for check in checks:
        if check["status"] != "fail" or check.get("source") != "database":
            continue
        if check.get("line_ids") and all(next((line.get("human_verified", False) for line in lines if line["id"] == identifier), False)
                                         for identifier in check["line_ids"]):
            continue
        missing = [symbol for symbol in dict.fromkeys([*unsupported, *weak])
                   if symbol and check.get("expected", "").count(symbol) > check.get("actual", "").count(symbol)]
        expected_without = check.get("expected", "")
        actual_without = check.get("actual", "")
        for symbol in missing:
            expected_without = expected_without.replace(symbol, "")
            actual_without = actual_without.replace(symbol, "")
        if missing and normalize_text(expected_without) == normalize_text(actual_without):
            reason = (f"目前辨識模型不支援 {'、'.join(missing)}；請對照照片確認符號有無漏印。"
                      if all(symbol in unsupported for symbol in missing)
                      else f"{'、'.join(missing)} 容易在整句辨識時漏讀；請對照照片確認符號有無漏印。")
            check.update(status="review", reason=reason,
                         unsupported_symbols=[symbol for symbol in missing if symbol in unsupported],
                         known_weak_symbols=[symbol for symbol in missing if symbol in weak])
    catalog_source = (source or {}).get("source_kind") == "catalog"
    if catalog_source:
        # A list provides a duration, not a print layout or a manufacturing schedule.
        # Check this only when the photo actually prints the duration in days.
        for line in text_lines:
            if _heading(line["text"]) != "shelf_days" or source.get("keep_days") is None:
                continue
            actual = _prepared(line["text"])
            match = re.fullmatch(HEADINGS["shelf_days"] + r"[:：]?(\d+)(?:天|日)", actual)
            confidence = float(line.get("score", 0))
            same = bool(match) and int(match[1]) == source["keep_days"]
            status = "review" if not match or line_is_uncertain(line, MIN_CONFIDENCE) else "pass" if same else "fail"
            checks.append({"key": f"shelf_days_{line['id']}", "label": "保存天數", "status": status,
                "reason": "保存天數與清單相符。" if status == "pass" else "印出的保存天數與清單不同。" if status == "fail" else "保存天數或單位未看清楚，請確認。",
                "expected": f"保存期限：{source['keep_days']}天", "actual": line["text"],
                "line_ids": [line["id"]], "score": confidence, "source": "database"})
    if (source or {}).get("standard_reference", {}).get("state") == "stale":
        checks.append({"key":"standard_reference_stale", "label":"比對標準", "status":"review", "actual":"來源已變更",
                       "expected":"", "line_ids":[], "score":None, "source":"standard",
                       "reason":"原始來源資料已變更，先前人工比對標準已停用；請重新確認標準後再核對。"})
    manual_source = (source or {}).get("source_kind") == "manual"
    notes.insert(0, ("依人工提供並確認的文字與日期規則核對；沒有完整印標版面，未提供的內容仍需確認。" if manual_source else
                    "依清單核對已知品名、條碼及印出的保存天數；清單沒有其他印字與日期位移，不能據此確認整張標籤。" if catalog_source else
                    f"依資料庫標籤 {source.get('code', '')} 的完整文字及日期設定核對；不使用其他產品的文字補足。" if source
                     else "尚未找到對應資料庫標籤；僅檢查日期，其他文字不判定正確。"))
    result = {"checks": checks, "fields": fields, "notes": notes, "rule_version": RULE_VERSION,
              "verified_scope": "manual_text" if manual_source else "catalog_fields" if catalog_source else "selected_database_label" if source else "dates_only", "mode": "recognition"}
    return _decorate(result, lines)
