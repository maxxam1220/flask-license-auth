"""Conservative field extraction and deterministic, versioned label checks."""
from datetime import date, datetime
from difflib import SequenceMatcher
from functools import lru_cache
import re
import unicodedata
from opencc import OpenCC

RULE_VERSION = "1.3"
TEXT_FIELDS = ("product", "address", "origin", "spec", "storage", "company", "phone")
FIELD_NAMES = {"product": "品名", "address": "地址", "origin": "產地", "spec": "規格",
               "storage": "保存條件", "company": "公司名稱", "phone": "電話",
               "manufacture": "製造日期", "expiry": "有效日期", "arrival": "到店日", "advisory": "果皮白點說明"}
BUILTIN_STANDARDS = [
    {"key": "company", "label": "公司名稱", "value": "福和生鮮農產股份有限公司"},
    {"key": "address", "label": "地址", "value": "新北市土城區中興路9號"},
    {"key": "phone", "label": "電話", "value": "0800-200-859"},
    {"key": "advisory", "label": "果皮白點說明", "value": "果皮上的白點為正常現象(保護果實避免曬傷的碳酸鈣粉)"},
]
BUILTIN_FIELDS = {item["key"]: item["value"] for item in BUILTIN_STANDARDS}
ALIASES = {
    "product": r"(?:產品名稱|商品名稱|產品品名|品名)",
    "address": r"(?:負責廠商地址|製造商地址|製造廠地址|公司地址|製造廠址|地址|住址|廠址)",
    "origin": r"(?:原料[產産产]地|原[產産产]地|原[產産产]國|[產産产]地)",
    "manufacture": r"(?:製造日期|製造日|生產日期|生產日)",
    "expiry": r"(?:有效日期|有效期限|有效日|保存期限至|最佳賞味期|賞味期限|到期日)",
    "spec": r"(?:[規规]格)",
    "storage": r"(?:保存條件|保存条件|保存方式|儲存條件|貯存條件|儲存方式)",
    "company": r"(?:負責廠商名稱|製造廠商名稱|製造商名稱|公司名稱|廠商名稱|負責廠商|製造廠商|製造商)",
    "phone": r"(?:免付費(?:服務)?[電电][話话]|客服[電电][話话]|服務[電电][話话]|聯絡[電电][話话]|客服專線|服務專線|[電电][話话])",
    "arrival": r"(?:到\s*店\s*日\s*期|到\s*店\s*日|到貨日期|到貨日)",
}
ALL_KEYS = "|".join(ALIASES.values()) + r"|內容物|成分|淨重|重量|營養標示|食品業者登錄字號|貨號|入[數数]"


def compact(text):
    # Do not fold 台/臺, Chinese variants, punctuation or confusable digits.
    return re.sub(r"\s+", "", unicodedata.normalize("NFC", str(text or "")))


@lru_cache(maxsize=1)
def _traditional_converter():
    return OpenCC("s2t")


def traditional_display(text):
    """Reading aid only. Comparisons and persisted OCR evidence remain unchanged."""
    return _traditional_converter().convert(str(text or "")).replace("臺灣", "台灣")


def parse_date(text):
    value = unicodedata.normalize("NFKC", str(text or "")).strip()
    roc = value.startswith("民國")
    value = re.sub(r"^民國\s*", "", value)
    match = re.fullmatch(r"(\d{3,4})\s*[./年-]\s*(\d{1,2})\s*[./月-]\s*(\d{1,2})\s*日?(?:\s*(\d{1,2})\s*(?:時|时|:)(?:(\d{1,2})\s*分?)?)?", value)
    if not match:
        raise ValueError("日期須包含完整年月日；無法判讀的字元不會自動修正。")
    year, month, day = (int(match[i]) for i in (1, 2, 3))
    if not roc and len(match[1]) == 3 and year >= 200:
        raise ValueError("三碼年份可能有漏字；較大的民國年份須明確標示民國，不自動推測。")
    if roc or len(match[1]) == 3:
        year += 1911
    if not 1900 <= year <= 2200:
        raise ValueError("年份超出可檢查範圍。")
    hour = int(match[4]) if match[4] is not None else None
    minute = int(match[5] or 0)
    if hour is not None and (hour > 23 or minute > 59):
        raise ValueError("日期的時間不合法。")
    return {"date": date(year, month, day), "hour": hour, "minute": minute}


def _candidate(value, lines, ambiguous=False):
    return {"value": value.strip(" ：:"), "score": min(float(x.get("score", 0)) for x in lines),
            "line_ids": [x["id"] for x in lines],
            "ambiguous": ambiguous or any(x.get("ambiguous", False) for x in lines)}


def _bounds(line):
    box = line["box"]
    return min(p[0] for p in box), min(p[1] for p in box), max(p[0] for p in box), max(p[1] for p in box)


def _below_in_column(line, other):
    x, y, right, bottom = _bounds(line)
    nx, ny, nr, nb = _bounds(other)
    height = max(bottom - y, nb - ny, 1)
    overlap = max(0, min(right, nr) - max(x, nx))
    aligned = overlap >= min(right - x, nr - nx) * .35 or abs(nx - x) < height * 1.5
    return aligned and ny >= bottom - height * .4 and ny - bottom <= max(height * 1.5, 20)


def product_row_candidates(lines):
    """Assemble observed horizontal product fragments without consulting a standard.

    Close boxes on the same baseline may be OCR pieces of one name. A price,
    another field heading, company, address or barcode is a stopping boundary.
    Returned lines are the original evidence; no missing character is supplied.
    """
    def fragment(line, anchor=False):
        value = compact(traditional_display(line.get("text", "")))
        heading = re.match(ALIASES["product"] + r"[：:]?", value)
        if heading:
            if not anchor:
                return False
            value = value[heading.end():]
            if not value:
                return True
        if re.search(ALL_KEYS, value):
            return False
        if re.search(r"價格|售價|單價|特價|促銷|公司|股份|有限|企業社|商行|食用|清洗|客服|熱量|蛋白質|脂肪|碳水", value):
            return False
        if re.search(r"[市縣].{1,20}(?:[區鄉鎮市]|[路街])", value):
            return False
        if re.search(r"(?:[$＄]|NT\$)|^[(（\[]?\d+(?:\.\d+)?元", value, re.I):
            return False
        if anchor and re.fullmatch(r"[（(\[【].*[）)\]】]", value):
            return False  # A detached parenthetical suffix cannot supply a missing head.
        return bool(re.search(r"[\u4e00-\u9fff]", value)) or (not anchor and bool(re.match(r"[（(\[【]", value)))

    usable = [line for line in lines if line.get("box")]
    groups = []
    for first in usable:
        if not fragment(first, anchor=True):
            continue
        chain, ambiguous = [first], False
        for _ in range(5):
            left = chain[-1]
            x, y, right, bottom = _bounds(left)
            nearby = []
            for other in usable:
                if other in chain:
                    continue
                nx, ny, nr, nb = _bounds(other)
                height, other_height = bottom-y, nb-ny
                if min(height, other_height) <= 0 or min(height, other_height) / max(height, other_height) < .6:
                    continue
                overlap = max(0, min(bottom, nb)-max(y, ny))
                if overlap < min(height, other_height)*.6 or abs((y+bottom)-(ny+nb))/2 > max(height, other_height)*.35:
                    continue
                gap = nx-right
                bracket = bool(re.match(r"\s*[（(\[【]", other["text"]))
                if 0 <= gap <= max(height, other_height) * (2. if bracket else 1.25):
                    nearby.append((gap, other))
            if not nearby:
                break
            nearby.sort(key=lambda pair: pair[0])
            gap, nxt = nearby[0]
            nx, ny, nr, nb = _bounds(nxt)
            band_top, band_bottom = max(y, ny), min(bottom, nb)
            # Font-size filtering chooses a plausible continuation, but must not
            # make an intervening visible price or small character disappear.
            blocked = False
            for middle in usable:
                if middle in chain or middle is nxt or not middle.get("text", "").strip():
                    continue
                mx, my, mr, mb = _bounds(middle)
                if mx < nx and mr > right and my < band_bottom and mb > band_top:
                    blocked = True
                    break
            if blocked:
                break
            if not fragment(nxt):
                break
            ambiguous |= len(nearby) > 1 and abs(nearby[1][0]-gap) < 2
            chain.append(nxt)
        if len(chain) > 1:
            raw = "".join(item["text"] for item in chain)
            value = re.sub(r"^\s*" + ALIASES["product"] + r"\s*[：:]?\s*", "", raw, count=1)
            groups.append(dict(_candidate(value, chain, ambiguous), lines=chain, raw_text=raw))
    return groups


def _next_value(line, ordered):
    """Use geometry, not OCR list order, so neighbouring columns stay separate."""
    x, y, right, bottom = _bounds(line)
    candidates = []
    for other in ordered:
        if other["id"] == line["id"] or re.search(ALL_KEYS, other["text"]):
            continue
        nx, ny, nr, nb = _bounds(other)
        height = max(bottom-y, nb-ny, 1)
        row_overlap = max(0, min(bottom, nb) - max(y, ny))
        if row_overlap >= min(bottom-y, nb-ny) * .5 and 0 <= nx-right <= max(height * 4, 40):
            candidates.append((0, nx-right, other))
        elif _below_in_column(line, other):
            candidates.append((1, max(0, ny-bottom), other))
    return min(candidates, key=lambda item: item[:2])[2] if candidates else None


def _join_address(value, evidence, ordered):
    # Only close, aligned address fragments qualify; never append a company/phone column.
    for _ in range(3):
        candidates = []
        for line in ordered:
            text = compact(line["text"])
            if line in evidence or re.search(ALL_KEYS, text) or not _below_in_column(evidence[-1], line):
                continue
            continuation = re.match(r"^[\d一二三四五六七八九十]+(?:段|巷|弄|號|樓)", text)
            if not re.search(r"[路街]", compact(value)):
                continuation = continuation or re.match(r"^[\u4e00-\u9fff]{1,15}[路街].*", text)
            if continuation:
                candidates.append(line)
        if not candidates:
            break
        nxt = min(candidates, key=lambda line: _bounds(line)[1])
        value += nxt["text"]
        evidence.append(nxt)
    return value, evidence


def _located_by_expected(ordered, expected, excluded):
    # Similarity locates evidence only; it never changes characters or accepts a match.
    ranked = sorted(((SequenceMatcher(None, compact(x["text"]), compact(expected)).ratio(), x)
                     for x in ordered if x["id"] not in excluded and not re.search(ALL_KEYS, x["text"])),
                    key=lambda item: item[0], reverse=True)
    if not ranked or ranked[0][0] < .55:
        return None
    score, line = ranked[0]
    return _candidate(line["text"], [line], len(ranked) > 1 and score - ranked[1][0] < .04)


def _advisory_candidate(ordered):
    """Locate a present statement, including wrapped fragments; never invent absent text."""
    expected = compact(BUILTIN_FIELDS["advisory"])
    anchor = r"果皮.{0,8}(?:白|點)|白點.{0,8}正常|保護果實|碳酸鈣"
    best = []
    for first in ordered:
        chain = [first]
        for _ in range(6):
            raw = "".join(item["text"] for item in chain)
            located = compact(traditional_display(raw))
            score = SequenceMatcher(None, located, expected).ratio()
            if re.search(anchor, located) and score >= .32:
                best.append((score, chain.copy()))
            next_lines = [item for item in ordered if item not in chain
                          and _below_in_column(chain[-1], item)
                          and not re.search(ALL_KEYS, item["text"])]
            if not next_lines:
                break
            # A close continuation must increase the match, rather than absorb an unrelated footer.
            ranked = sorted(((SequenceMatcher(None, compact(traditional_display(raw + item["text"])), expected).ratio(), item)
                             for item in next_lines), key=lambda item: item[0], reverse=True)
            if ranked[0][0] <= score:
                break
            chain.append(ranked[0][1])
    if not best:
        return None
    best.sort(key=lambda item: item[0], reverse=True)
    score, chain = best[0]
    # Competing disjoint statements require review; overlapping windows are the same evidence.
    ids = {item["id"] for item in chain}
    ambiguous = any(abs(score - other_score) < .04 and not ids.intersection(item["id"] for item in other)
                    for other_score, other in best[1:])
    return _candidate("".join(item["text"] for item in chain), chain, ambiguous)


def extract_fields(lines, expected=None):
    found = {}
    ordered = sorted(lines, key=lambda x: (min(p[1] for p in x["box"]), min(p[0] for p in x["box"])))
    product_rows = product_row_candidates(ordered)
    for key, alias in ALIASES.items():
        candidates = []
        for i, line in enumerate(ordered):
            match = re.search(alias + r"\s*[：:]?\s*", line["text"])
            if not match:
                continue
            # A shorter heading such as 製造商 must not consume 製造商地址.
            if any(other != key and (longer := re.search(pattern, line["text"]))
                   and longer.start() == match.start() and longer.end() > match.end()
                   for other, pattern in ALIASES.items()):
                continue
            value = re.split(ALL_KEYS, line["text"][match.end():], maxsplit=1)[0].strip(" ：:")
            evidence = [line]
            # A value may be detected as a separate box on the same row.
            if not value:
                nxt = _next_value(line, ordered)
                if nxt is not None:
                    value = nxt["text"]
                    evidence.append(nxt)
            # Join a wrapped address only where the continuation is close and address-like.
            if key == "address" and value:
                value, evidence = _join_address(value, evidence, ordered)
            if key == "product":
                row = next((row for row in product_rows if row["lines"][0]["id"] == line["id"]), None)
                if row:
                    candidates.append({key: row[key] for key in ("value", "score", "line_ids", "ambiguous")})
                    continue
            if value:
                candidates.append(_candidate(value, evidence))
        if candidates:
            found[key] = dict(candidates[0], ambiguous=len(candidates) > 1 or candidates[0]["ambiguous"])
    if "address" not in found:
        addresses = [x for x in ordered if not re.search(ALL_KEYS, x["text"])
                     and re.search(r"[市縣].{1,20}(?:[區鄉鎮市]|[路街])", compact(x["text"]))]
        if addresses:
            value, evidence = _join_address(addresses[0]["text"], [addresses[0]], ordered)
            found["address"] = _candidate(value, evidence, len(addresses) > 1)
    if "company" not in found:
        companies = [x for x in ordered if not re.search(ALL_KEYS, x["text"])
                     and re.search(r"(?:公司|企業社|商行)$", compact(x["text"]))]
        if companies:
            line = companies[0]
            evidence = [line]
            if re.fullmatch(r"(?:股份)?有限公司", compact(line["text"])):
                prefixes = [x for x in ordered if x["id"] != line["id"] and _below_in_column(x, line)
                            and not re.search(ALL_KEYS, x["text"]) and not re.search(r"[市縣區路街號\d]", x["text"])]
                if prefixes:
                    evidence.insert(0, max(prefixes, key=lambda x: _bounds(x)[1]))
            found["company"] = _candidate("".join(x["text"] for x in evidence), evidence, len(companies) > 1)
    if "phone" not in found:
        phones = [x for x in ordered if re.fullmatch(r"[（(]?0[\d()（）\-－–—. ]{6,20}(?:#\d+)?", x["text"].strip())
                  and 8 <= len(re.sub(r"\D", "", x["text"])) <= 11]
        if phones:
            found["phone"] = _candidate(phones[0]["text"], [phones[0]], len(phones) > 1)
    if expected:
        for key in ("company", "address", "phone"):
            if key not in found and expected.get(key):
                excluded = {identifier for field in found.values() for identifier in field["line_ids"]}
                eligible = ordered
                if key == "phone":
                    # An EAN barcode is not a telephone merely because some digits resemble it.
                    eligible = [item for item in ordered if re.fullmatch(r"[()（）\d\-－–—. +#]+", item["text"].strip())
                                and 7 <= len(re.sub(r"\D", "", item["text"])) <= 11]
                located = _located_by_expected(eligible, expected[key], excluded)
                if located:
                    found[key] = located
    advisory = _advisory_candidate(ordered)
    if advisory:
        found["advisory"] = advisory
    if "product" not in found:
        excluded = {identifier for field in found.values() for identifier in field["line_ids"]}
        candidates = [x for x in ordered if len(compact(x["text"])) >= 3 and not re.search(ALL_KEYS, x["text"])
                      and x["id"] not in excluded
                      and re.search(r"[\u4e00-\u9fff]", x["text"])
                      and not re.search(r"\d{4}\s*[年./-]|清晨|上午|下午|鮮食\s|營養|熱量|蛋白質|脂肪|碳水|毫克|公克|客服|公司|食用|清洗", x["text"])]
        # Replace members with the observed complete row, so a suffix a fraction
        # of a pixel higher cannot displace the name on its left.
        for row in product_rows:
            if any(identifier in excluded for identifier in row["line_ids"]):
                continue
            if not any(item["id"] in row["line_ids"] for item in candidates):
                continue
            positions = [index for index, item in enumerate(candidates) if item["id"] in row["line_ids"]]
            replacement = dict(row["lines"][0], text=row["value"], _product_evidence=row["lines"], ambiguous=row["ambiguous"])
            candidates = [item for item in candidates if item["id"] not in row["line_ids"]]
            candidates.insert(min(positions), replacement)
        if expected and expected.get("product") and candidates:
            # Similarity locates the line only. Acceptance always requires exact characters.
            ranked = sorted(candidates, key=lambda x: SequenceMatcher(None, compact(x["text"]), compact(expected["product"])).ratio(), reverse=True)
            best = ranked[0]
            if SequenceMatcher(None, compact(best["text"]), compact(expected["product"])).ratio() >= 0.35:
                score = SequenceMatcher(None, compact(best["text"]), compact(expected["product"])).ratio()
                ambiguous = len(ranked) > 1 and abs(score - SequenceMatcher(None, compact(ranked[1]["text"]), compact(expected["product"])).ratio()) < .04
                found["product"] = _candidate(best["text"], best.get("_product_evidence", [best]), ambiguous or best.get("ambiguous", False))
        elif candidates:
            best = candidates[0]
            found["product"] = _candidate(best["text"], best.get("_product_evidence", [best]), best.get("ambiguous", False))
    return found


def diff_parts(expected, actual):
    a, b = compact(expected), compact(actual)
    return [{"kind": kind, "expected": a[i:j], "actual": b[k:l]}
            for kind, i, j, k, l in SequenceMatcher(None, a, b, autojunk=False).get_opcodes()]


def _fixed_check(key, field):
    expected, actual = BUILTIN_FIELDS[key], field["value"]
    status, reason = "pass", "與已確認固定文字逐字相符（忽略空白與換行）。"
    if field.get("ambiguous"):
        status, reason = "review", "偵測到多個候選內容，請對照原圖確認。"
    elif field.get("score", 0) < .94:
        status, reason = "review", "文字辨識把握不足，請對照原圖；不自動更正。"
    elif compact(actual) != compact(expected):
        status, reason = "fail", "與已確認固定文字不同，請確認錯字、漏字或多字。"
    return {"key": key, "label": FIELD_NAMES[key], "status": status, "reason": reason,
            "expected": expected, "actual": actual, "diff": diff_parts(expected, actual),
            "line_ids": field.get("line_ids", []), "score": field.get("score"), "source": "builtin"}


def _finish_result(lines, result):
    """Cover all OCR evidence without claiming that unreferenced text is correct."""
    checks = result["checks"]
    checked_keys = {check["key"] for check in checks}
    fields = result["fields"]
    for key in BUILTIN_FIELDS:
        if key not in checked_keys and fields.get(key, {}).get("value"):
            checks.append(_fixed_check(key, fields[key]))
    covered = {identifier for check in checks for identifier in check.get("line_ids", [])}
    for line in lines:
        if line["id"] not in covered:
            continue
        remainder = line["text"]
        for check in checks:
            if line["id"] not in check.get("line_ids", []):
                continue
            actual = check.get("actual", "")
            if len(check.get("line_ids", [])) > 1 and compact(remainder) in compact(actual):
                remainder = ""
                break
            if actual and actual in remainder:
                remainder = remainder.replace(actual, "", 1)
        # Already-compared values carry their own raw/difference evidence. Only unchecked
        # text (including headings before removal) needs another source-line review.
        changed = traditional_display(remainder) != remainder
        remainder = re.sub(ALL_KEYS, "", remainder).strip(" ：:\t\r\n")
        # Checking a phone's digits does not verify a misread heading on the same OCR line.
        if remainder or changed:
            checks.append({"key": f"source_line_{line['id']}", "label": "來源行文字",
                           "status": "review" if changed or line.get("score", 0) < .94 else "read",
                           "expected": "", "actual": line["text"], "diff": [], "line_ids": [line["id"]],
                           "score": line.get("score"), "source": "ocr",
                           "reason": ("來源行含繁簡轉換字形，繁體顯示僅供閱讀；請對照原圖確認。" if changed
                                      else "此行仍有未核對的文字，請對照原圖；已核對的欄位不代表整行都正確。")})
    date_pattern = r"(?:民國\s*)?[0-9０-９OoIl]{3,4}\s*[年./．-]\s*[0-9０-９OoIl]{1,2}\s*[月./．-]\s*[0-9０-９OoIl]{1,2}(?:\s*日)?"
    for line in lines:
        if line["id"] in covered or not line["text"].strip():
            continue
        # Other printed dates can be checked for validity, not for their business meaning.
        for number, match in enumerate(re.finditer(date_pattern, line["text"])):
            status, reason = "pass", "年月日格式可辨識；未核對這個日期的業務用途。"
            try:
                parse_date(match[0])
            except (ValueError, TypeError):
                status, reason = "review", "日期不完整或不合法，請確認數字是否漏印或辨識錯誤。"
            if line.get("score", 0) < .94:
                status, reason = "review", "日期辨識把握不足，請對照原圖確認。"
            checks.append({"key": f"date_line_{line['id']}_{number}", "label": "其他日期格式", "status": status,
                           "expected": "完整且合法的年月日", "actual": match[0], "reason": reason,
                           "line_ids": [line["id"]], "score": line.get("score"), "source": "date"})
        changed = traditional_display(line["text"]) != line["text"]
        checks.append({"key": f"text_line_{line['id']}", "label": "其他辨識文字",
                       "status": "read" if line.get("score", 0) >= .94 and not changed else "review", "expected": "",
                       "actual": line["text"], "diff": [], "line_ids": [line["id"]], "score": line.get("score"),
                       "source": "ocr", "reason": ("來源行含繁簡轉換字形，繁體顯示僅供閱讀；請對照原圖確認。" if changed
                                                    else "已讀取文字，尚無核對依據，未判定內容正確。" if line.get("score", 0) >= .94
                                                    else "文字辨識把握不足，請對照原圖確認；尚無核對依據。")})
    indexed = {line["id"]: line for line in lines}
    for check in checks:
        actual, expected = check.get("actual", ""), check.get("expected", "")
        check["raw_actual"] = actual
        check["display_actual"] = traditional_display(actual)
        check["display_expected"] = traditional_display(expected)
        check["conversion_changed"] = check["display_actual"] != actual
        check.setdefault("source", "template" if check["key"] in TEXT_FIELDS else "date")
        # A script conversion is a reading aid, never evidence of an exact printed match.
        if (check["status"] == "fail" and check.get("diff") and compact(actual) != compact(expected)
                and _traditional_converter().convert(actual) != actual
                and compact(_traditional_converter().convert(actual)) == compact(_traditional_converter().convert(expected))):
            check.update(status="review", reason="辨識原文有繁簡字形差異；顯示為繁體僅方便閱讀，仍需對照原圖確認，未判定相符。")
        check["source_lines"] = [{"id": identifier, "text": indexed[identifier]["text"],
                                  "display_text": traditional_display(indexed[identifier]["text"]),
                                  "conversion_changed": traditional_display(indexed[identifier]["text"]) != indexed[identifier]["text"],
                                  "score": indexed[identifier].get("score")}
                                 for identifier in check.get("line_ids", []) if identifier in indexed]
    covered = {identifier for check in checks for identifier in check.get("line_ids", [])}
    result["coverage"] = {"total_lines": len(lines), "covered_lines": len(covered.intersection(indexed))}
    result["counts"] = {key: sum(check["status"] == key for check in checks) for key in ("pass", "fail", "review", "read")}
    result["status"] = ("fail" if result["counts"]["fail"] else "review" if not checks or result["counts"]["review"] or result["counts"]["read"] else "pass")
    result["verified_scope"] = "configured_checks"
    if result["counts"]["read"] or any(check.get("source") == "ocr" for check in checks):
        result["notes"].append("其他辨識文字沒有核對依據，僅提供閱讀；未判定整張標籤所有內容正確。")
    return result


def evaluate(lines, template, batch_date="", arrival_date=""):
    fields = extract_fields(lines, {**BUILTIN_FIELDS, **template["fields"]})
    checks = []
    threshold = .94
    for key in TEXT_FIELDS:
        expected = template["fields"].get(key, "")
        if key not in ("product", "address", "origin") and not expected:
            continue
        field = fields.get(key, {})
        actual = field.get("value", "")
        status, reason = "pass", "逐字相符（忽略空白與換行）。"
        if not actual:
            status, reason = "review", "未辨識到這個欄位，請重拍或人工複核。"
        elif field.get("ambiguous"):
            status, reason = "review", "辨識到多個候選內容，需要確認。"
        elif field["score"] < threshold:
            status, reason = "review", "文字辨識把握不足，請對照原圖；不自動更正。"
        elif compact(expected) != compact(actual):
            status, reason = "fail", "與標準文字不同，請確認是否有錯字、漏字或多字。"
        checks.append({"key": key, "label": FIELD_NAMES[key], "status": status, "reason": reason,
                       "expected": expected, "actual": actual, "diff": diff_parts(expected, actual),
                       "line_ids": field.get("line_ids", []), "score": field.get("score")})
    notes = []
    parsed = {}
    uncertain_dates = set()
    if template["rules"].get("dates", True):
        for key in ("manufacture", "expiry"):
            field = fields.get(key, {})
            value = field.get("value", "")
            status, reason = "pass", "年月日格式可辨識。"
            try:
                parsed[key] = parse_date(value)
            except (ValueError, TypeError):
                status, reason = "review", "日期未讀完整或日期不合法，請查看原圖。"
            if field.get("ambiguous") or field.get("score", 0) < threshold:
                status, reason = "review", "日期辨識不確定，請查看原圖；不推測數字。"
            if status != "pass":
                uncertain_dates.add(key)
            checks.append({"key": key, "label": FIELD_NAMES[key], "status": status, "reason": reason,
                           "expected": "完整且合法的年月日", "actual": value, "line_ids": field.get("line_ids", []), "score": field.get("score")})
        if len(parsed) == 2:
            m, e = parsed["manufacture"], parsed["expiry"]
            days = (e["date"] - m["date"]).days
            reversed_time = days == 0 and m["hour"] is not None and e["hour"] is not None and (e["hour"], e["minute"]) < (m["hour"], m["minute"])
            bad = days < 0 or reversed_time
            order_status = "review" if uncertain_dates else "fail" if bad else "pass"
            reason = "有效日期早於製造日期。" if bad else "有效日期未早於製造日期。"
            if uncertain_dates:
                reason = ("辨識結果疑似有效日期早於製造日期，請優先複核原圖。" if bad else "日期文字辨識不確定，無法確認日期順序。")
            checks.append({"key": "date_order", "label": "日期先後", "status": order_status,
                           "reason": reason,
                           "expected": "有效日期 ≥ 製造日期", "actual": f"{m['date']} → {e['date']}",
                           "line_ids": fields["manufacture"]["line_ids"] + fields["expiry"]["line_ids"]})
            keep = template["rules"].get("keep_days")
            if keep is not None:
                checks.append({"key": "keep_days", "label": "保存天數", "status": "review" if uncertain_dates else "pass" if days == keep else "fail",
                               "reason": "依標準設定的日期相差天數核對。", "expected": f"相差 {keep} 天", "actual": f"相差 {days} 天", "line_ids": []})
            else:
                notes.append("此標準尚未設定保存天數，未核對有效期限長度。")
        if batch_date:
            expected_date = date.fromisoformat(batch_date)
            actual_date = parsed.get("manufacture", {}).get("date")
            checks.append({"key": "batch", "label": "本批製造日", "status": "review" if "manufacture" in uncertain_dates else "pass" if actual_date == expected_date else "fail",
                           "reason": "與本次指定的製造日核對。", "expected": batch_date,
                           "actual": str(actual_date) if actual_date else fields.get("manufacture", {}).get("value", ""),
                           "line_ids": fields.get("manufacture", {}).get("line_ids", [])})
        elif len(parsed) == 2:
            notes.append("未指定本批製造日，未驗證兩個日期是否一起印錯。")
    else:
        notes.append("此標準未啟用製造／有效日期檢查。")
    if template["rules"].get("arrival", False) or arrival_date:
        field = fields.get("arrival", {})
        value = field.get("value", "")
        status, reason = "pass", "年月日格式可辨識。"
        try:
            parsed["arrival"] = parse_date(value)
        except (ValueError, TypeError):
            status, reason = "review", "到店日未讀完整或日期不合法，請查看原圖。"
        if field.get("ambiguous") or field.get("score", 0) < threshold:
            status, reason = "review", "到店日辨識不確定，請查看原圖；不推測數字。"
        if status != "pass":
            uncertain_dates.add("arrival")
        checks.append({"key": "arrival", "label": FIELD_NAMES["arrival"], "status": status, "reason": reason,
                       "expected": "完整且合法的年月日", "actual": value,
                       "line_ids": field.get("line_ids", []), "score": field.get("score")})
        if arrival_date:
            actual = str(parsed["arrival"]["date"]) if "arrival" in parsed else value
            checks.append({"key": "arrival_expected", "label": "本批到店日",
                           "status": "review" if "arrival" in uncertain_dates else "pass" if actual == arrival_date else "fail",
                           "reason": "與本次指定的到店日核對；不沿用標準照片的日期。",
                           "expected": arrival_date, "actual": actual, "line_ids": field.get("line_ids", [])})
        else:
            notes.append("未指定本批到店日，僅檢查日期格式與可辨識的日期先後，尚未確認到店日符合本批排程。")
        if "arrival" in parsed:
            for key, label, expected_order in (("manufacture", "到店與製造先後", "到店日 ≥ 製造日期"),
                                                ("expiry", "到店與有效日期", "到店日 ≤ 有效日期")):
                other = fields.get(key, {})
                if not other.get("value"):
                    continue
                try:
                    other_date = parse_date(other["value"])["date"]
                except (ValueError, TypeError):
                    continue
                uncertain = ("arrival" in uncertain_dates or other.get("ambiguous")
                             or other.get("score", 0) < threshold)
                actual_date = parsed["arrival"]["date"]
                bad = actual_date < other_date if key == "manufacture" else actual_date > other_date
                reason = ("到店日早於製造日期。" if key == "manufacture" else "到店日晚於有效日期。") if bad else "日期先後符合設定。"
                if uncertain:
                    reason = ("辨識結果疑似" + reason + "請優先複核原圖。") if bad else "日期文字辨識不確定，請複核原圖。"
                checks.append({"key": "arrival_" + key, "label": label,
                               "status": "review" if uncertain else "fail" if bad else "pass", "reason": reason,
                               "expected": expected_order, "actual": f"到店 {actual_date} / {FIELD_NAMES[key]} {other_date}",
                               "line_ids": field.get("line_ids", []) + other.get("line_ids", [])})
    status = "fail" if any(x["status"] == "fail" for x in checks) else "review" if any(x["status"] == "review" for x in checks) else "pass"
    return _finish_result(lines, {"status": status, "checks": checks, "fields": fields, "notes": notes, "rule_version": RULE_VERSION})


def recognize_only(lines, batch_date="", arrival_date=""):
    """Date consistency is useful without a baseline; text correctness is unverified."""
    extracted = extract_fields(lines, BUILTIN_FIELDS)
    result = evaluate(lines, {"fields": {k: "" for k in TEXT_FIELDS},
                              "rules": {"dates": bool(batch_date or "manufacture" in extracted or "expiry" in extracted),
                                        "arrival": bool(arrival_date or "arrival" in extracted), "keep_days": None}},
                      batch_date, arrival_date)
    # Remove mandatory template placeholders and the first pass of whole-line rendering.
    result["checks"] = [check for check in result["checks"]
                        if check["key"] not in TEXT_FIELDS and not check["key"].startswith(("text_line_", "date_line_", "source_line_"))
                        and (check.get("actual") or check["key"] in {"batch", "arrival_expected"})]
    result["fields"] = extracted
    result["notes"] = [note for note in result["notes"] if note != "此標準未啟用製造／有效日期檢查。"]
    result["mode"] = "recognition"
    result["notes"] = [note for note in result["notes"] if not note.startswith("其他辨識文字")]
    result["notes"].insert(0, "掃描時核對已確認的固定文字及日期；固定字句未出現時不報缺漏，其他文字僅供閱讀。")
    return _finish_result(lines, result)
