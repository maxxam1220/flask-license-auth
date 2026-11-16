"""Conservative arithmetic checks of observed nutrition rows, not legal certification.

No standard/database text is read or used to fill missing labels or quantities.
Positive printed amounts use inclusive half-last-digit rounding intervals, covering
round-half-up and CNS tie handling. Zero declarations have special rules, so their
unknown underlying amounts are never treated as mathematical zero.

Background: MOHW nutrition-label Q&A (2022-06-23), linked from
https://www.mohw.gov.tw/cp-2704-70142-1.html . This is deliberately not a complete
implementation of nutrition labeling law, measurement tolerance, or food analysis.
"""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import re
import unicodedata

from validation import line_is_uncertain, traditional_display


LABELS = {"energy": "熱量", "protein": "蛋白質", "fat": "脂肪", "saturated": "飽和脂肪",
          "trans": "反式脂肪", "carbohydrate": "碳水化合物", "sugar": "糖", "sodium": "鈉",
          "fiber": "膳食纖維"}
ALIASES = {label: key for key, label in LABELS.items()}
ALIASES.update({"飽和脂肪酸": "saturated", "反式脂肪酸": "trans",
                "飽和脂肪(酸)": "saturated", "反式脂肪(酸)": "trans"})
UNITS = {"公克": "g", "克": "g", "g": "g", "毫克": "mg", "mg": "mg",
         "大卡": "kcal", "kcal": "kcal", "毫升": "ml", "ml": "ml"}
DISPLAY_UNIT = {"g": "公克", "mg": "毫克", "kcal": "大卡", "ml": "毫升"}
NUMBER = r"[+-]?\d{1,9}(?:\.\d{1,6})?"
AMOUNT = re.compile(rf"({NUMBER})(公克|毫克|大卡|毫升|kcal|mg|ml|克|g)", re.I)
HEADER = re.compile(r"每(?:一)?份(?!量)|每100(公克|毫升|ml|克|g)", re.I)
PUNCTUATION = " ：:()（）,，;；|／/"


def _compact(text):
    return re.sub(r"\s+", "", traditional_display(unicodedata.normalize("NFKC", str(text or ""))))


def _ids(rows):
    return list(dict.fromkeys(identifier for row in rows for identifier in
        row.get("source_line_ids", [row.get("id")]) if identifier is not None))


def _uncertain(row):
    evidence = row.get("source_lines") or [row]
    return bool(row.get("ambiguous") or row.get("confidence_ok") is False or any(
        line_is_uncertain(line, .65) or (line.get("suspected_typo") and not line.get("human_verified"))
        for line in evidence))


def _check(key, label, status, rows, reason, expected="", actual=None):
    return {"key": "nutrition_" + key, "label": label, "status": status, "source": "logic",
            "line_ids": _ids(rows), "reason": reason, "expected": expected,
            "actual": actual if actual is not None else "；".join(row.get("text", "") for row in rows)}


def _bounds(row):
    box = row.get("box") or []
    if len(box) < 3:
        return None
    return min(p[0] for p in box), min(p[1] for p in box), max(p[0] for p in box), max(p[1] for p in box)


def _same_row(first, second):
    a, b = _bounds(first), _bounds(second)
    return bool(a and b and abs((a[1]+a[3]-b[1]-b[3])/2) <= max(a[3]-a[1], b[3]-b[1])*.45)


def _near_table(row, table_rows):
    box = _bounds(row)
    boxes = [item_box for item in table_rows if (item_box := _bounds(item))]
    if not box or not boxes:
        return False
    left, top, right = min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes)
    height = max(box[3]-box[1], min(b[3]-b[1] for b in boxes), 1)
    return box[3] >= top-max(400, height*12) and box[1] <= top+height and min(right, box[2]) > max(left, box[0])


@dataclass(frozen=True)
class Quantity:
    printed: str
    value: Decimal
    unit: str
    lower: Decimal
    upper: Decimal


def _quantity(number, unit):
    value = Decimal(number)
    half = Decimal(1).scaleb(value.as_tuple().exponent)/2
    return Quantity(number, value, UNITS[unit.lower()], max(Decimal(0), value-half), value+half)


def _nutrient(row):
    text = _compact(row.get("text"))
    for label in sorted(ALIASES, key=len, reverse=True):
        if text.startswith(label):
            rest = text[len(label):].lstrip("：:")
            if not rest or re.match(r"[-+\d<(]", rest):
                return ALIASES[label], rest
    return None, ""


def _parse_amounts(text):
    # Whole suffix must be recognized: no ignoring a third column, percent,
    # a missing unit, a less-than sign, or an OCR letter embedded in a number.
    matches = list(AMOUNT.finditer(text))
    remainder = AMOUNT.sub("", text).strip(PUNCTUATION)
    if remainder or len(matches) != 2:
        return None
    try:
        return [_quantity(match[1], match[2]) for match in matches]
    except (InvalidOperation, KeyError):
        return None


def _table_context(rows, nutrient_rows, text_only=False):
    headers, servings = [], []
    for row in rows:
        text = _compact(row.get("text"))
        if not text_only and not _near_table(row, nutrient_rows):
            continue
        tokens = list(HEADER.finditer(text))
        if tokens and not HEADER.sub("", text).strip(PUNCTUATION):
            headers.append((row, tokens))
        serving = re.fullmatch(rf"每(?:一)?份量[:：]?({NUMBER})(公克|克|g|毫升|ml)", text, re.I)
        if serving:
            servings.append((row, _quantity(serving[1], serving[2])))
    evidence = [row for row, _ in headers] + [row for row, _ in servings]
    if len(servings) != 1:
        return None, evidence, "每份量未完整辨識或有多個候選，不能推算每份與每100公克／毫升。"
    serving_row, size = servings[0]
    if size.value <= 0:
        return None, evidence, "每份量必須為正數，請確認原照的數字。"
    header_tokens = [(row, token) for row, tokens in headers for token in tokens]
    if (len(header_tokens) != 2 or (text_only and len(headers) != 1)
            or (len(headers) == 2 and not _same_row(headers[0][0], headers[1][0]))):
        return None, evidence, "每份／每100公克或毫升的欄名未完整辨識，不能猜測數字欄位。"
    # Two separate header boxes are ordered by their real x coordinates.
    header_tokens.sort(key=lambda item: ((_bounds(item[0]) or [0])[0], item[1].start()))
    kinds = ["hundred" if token[1] else "serving" for _, token in header_tokens]
    if sorted(kinds) != ["hundred", "serving"]:
        return None, evidence, "營養表欄名重複或不完整，請確認每份與每100公克／毫升。"
    hundred_unit = UNITS[next(token[1].lower() for _, token in header_tokens if token[1])]
    if hundred_unit != size.unit:
        return None, evidence, "每份量與每100欄的公克／毫升單位不同，不能直接換算或假定密度。"
    if any(_uncertain(row) for row in evidence):
        return None, evidence, "份量或營養欄名辨識不確定，請先對照照片確認。"
    return {"size": size, "serving": kinds.index("serving"), "hundred": kinds.index("hundred"),
            "rows": evidence, "column_labels": ["每份" if kind == "serving" else "每100"+DISPLAY_UNIT[size.unit] for kind in kinds]}, evidence, ""


def _intersection(a, b):
    return min(a[1], b[1])-max(a[0], b[0])


def _ratio_check(kind, row, amounts, context):
    serving, hundred = amounts[context["serving"]], amounts[context["hundred"]]
    size = context["size"]
    evidence = [row, *context["rows"]]
    expected = f"每份 = 每100{DISPLAY_UNIT[size.unit]} × {size.printed} ÷ 100（考慮顯示位數修整）"
    if serving.value == 0 and hundred.value == 0:
        # Two printed zeroes provide no useful arithmetic evidence. The normal
        # literal-standard comparison still checks what is printed on the row.
        return None
    if _uncertain(row):
        return _check("ratio_"+kind, LABELS[kind]+"份量換算", "review", evidence,
                      "本列辨識不確定，不能以模糊數字判定換算正確。", expected, row["text"])
    if serving.value == 0 or hundred.value == 0:
        return _check("ratio_"+kind, LABELS[kind]+"份量換算", "review", evidence,
                      "標示 0 可能適用特殊門檻，不能當作實際含量等於零；請確認原始營養計算資料。", expected, row["text"])
    observed = (serving.lower, serving.upper)
    fixed = (hundred.lower*size.value/100, hundred.upper*size.value/100)
    loose = (hundred.lower*size.lower/100, hundred.upper*size.upper/100)
    nominal = hundred.value*size.value/100
    if _intersection(observed, fixed) > 0:
        status, reason = "pass", "兩欄數值在顯示位數的修整區間內相容；此項只檢查換算，不代表成分已驗證。"
    elif _intersection(observed, loose) >= 0:
        status, reason = "review", (f"以標示份量換算為 {nominal.normalize():f}{DISPLAY_UNIT[hundred.unit]}；"
            "目前兩欄只在份量本身也經修整、或修整邊界時可能相容，請確認原始計算資料。")
    else:
        status, reason = "fail", (f"以標示份量換算為 {nominal.normalize():f}{DISPLAY_UNIT[hundred.unit]}；"
            "即使考慮數值與份量的顯示位數修整，兩欄仍不相容，請核對數字或單位。")
    return _check("ratio_"+kind, LABELS[kind]+"份量換算", status, evidence, reason, expected, row["text"])


def _relation_checks(parsed, observed, context, parts, total, stem, label):
    required = [*parts, total]
    if not any(kind in observed for kind in required):
        return []
    evidence = [observed[kind] for kind in required if kind in observed]
    expected = "＋".join(LABELS[kind] for kind in parts)+" ≤ "+LABELS[total]
    if not context or any(kind not in parsed for kind in required):
        return [_check(stem, label, "review", evidence, "所需營養項目、數值、單位或欄名不完整，不能補值計算。", expected)]
    checks = []
    for index, column in enumerate(context["column_labels"]):
        quantities = [parsed[kind][index] for kind in required]
        if any(value.value == 0 for value in quantities):
            # Unknown nonnegative zero-declared parts cannot erase a provable
            # contradiction from the positive parts. Otherwise skip this
            # inapplicable calculation instead of generating routine warnings.
            positive_lower = sum(value.lower for value in quantities[:-1] if value.value > 0)
            if quantities[-1].value <= 0 or positive_lower <= quantities[-1].upper:
                continue
            if any(_uncertain(observed[kind]) for kind in required):
                status, reason = "review", "已辨識的非零子項可能超過總項，但相關數字仍不確定，請對照原照確認。"
            else:
                status, reason = "fail", "即使不把標示 0 當成實際零含量，已知非零子項本身已超過總項的修整區間。"
        elif any(_uncertain(observed[kind]) for kind in required):
            status, reason = "review", "相關營養數字辨識不確定，請先對照原照確認。"
        else:
            smallest_sum = sum(value.lower for value in quantities[:-1])
            max_total = quantities[-1].upper
            if smallest_sum > max_total:
                status, reason = "fail", "即使考慮顯示位數修整，子項數值仍超過總項，請確認數字。"
            elif smallest_sum == max_total:
                status, reason = "review", "只有在修整邊界才可能相容，請確認原始數值。"
            else:
                status, reason = "pass", "在顯示位數修整範圍內未見子項超過總項的矛盾；不代表成分已驗證。"
        checks.append(_check(f"{stem}_{index}", column+"／"+label, status, evidence, reason, expected))
    return checks


def checks_for(ocr):
    """Return bounded nutrition_* check dictionaries; never mutate OCR evidence."""
    from text_rows import group_observed_rows
    lines = ocr.get("lines", [])
    if not isinstance(lines, list) or len(lines) > 500:
        return [_check("scope", "營養表範圍", "review", [], "文字範圍過多或格式不完整，請裁切單張營養表。")]
    rows = group_observed_rows(lines)
    observed, duplicates, orphans = {}, [], []
    for row in rows:
        kind, rest = _nutrient(row)
        if kind:
            if kind in observed:
                duplicates.extend([observed[kind], row])
            else:
                observed[kind] = row
        elif row.get("row_type") == "nutrition_values":
            orphans.append(row)
    titles = [row for row in rows if _compact(row.get("text")) in {"營養標示", "營養標籤"}]
    has_header = any("每100" in _compact(row.get("text")) and HEADER.search(_compact(row.get("text"))) for row in rows)
    amount_evidence = any(AMOUNT.search(_nutrient(row)[1]) for row in observed.values())
    if not titles and not has_header and not (len(observed) >= 2 and amount_evidence):
        # An ingredient named sugar or protein is not itself a nutrition table.
        return []
    if len(titles) > 1 or duplicates or ocr.get("label_scope", {}).get("status") == "multiple":
        return [_check("scope", "營養表範圍", "review", duplicates or list(observed.values()),
                       "有重複營養項目或多張貼紙，請裁切單張營養表，不能跨表借用數字。")]
    checks = [_check(f"unlabelled_{index}", "營養項目待確認", "review", [row],
                     "這列只有數字，未辨識到營養名稱；不推定為鈉或其他項目。") for index, row in enumerate(orphans)]
    # Only an explicitly identified approved-standard draft may lack geometry.
    # OCR rows with absent/mixed boxes never gain this text-only shortcut.
    text_only = (ocr.get("context") == "standard_draft" and len(titles) == 1
                 and not any(_bounds(row) for row in rows))
    context, context_rows, error = _table_context(rows, list(observed.values()), text_only=text_only)
    if error:
        checks.append(_check("columns", "營養表份量與欄名", "review", context_rows, error))
    parsed = {}
    for kind, row in observed.items():
        amounts = _parse_amounts(_nutrient(row)[1])
        unit = "kcal" if kind == "energy" else "mg" if kind == "sodium" else "g"
        if not amounts:
            checks.append(_check("values_"+kind, LABELS[kind]+"數值", "review", [row],
                                 "需要同列完整的兩欄數字與單位；目前有缺字、額外欄位或不支援的格式，請確認原照。"))
            continue
        problem = "營養數值不可為負數。" if any(value.value < 0 for value in amounts) else (
            f"這個營養項目預期使用{DISPLAY_UNIT[unit]}，目前辨識到其他單位，請確認欄名及單位。"
            if any(value.unit != unit for value in amounts) else "")
        if problem:
            checks.append(_check("values_"+kind, LABELS[kind]+"數值與單位", "review" if _uncertain(row) else "fail", [row], problem))
            continue
        parsed[kind] = amounts
        if context:
            ratio = _ratio_check(kind, row, amounts, context)
            if ratio is not None:
                checks.append(ratio)
    checks.extend(_relation_checks(parsed, observed, context, ["sugar"], "carbohydrate", "sugar_total", "糖與碳水化合物"))
    checks.extend(_relation_checks(parsed, observed, context, ["saturated", "trans"], "fat", "fat_total", "脂肪子項與總脂肪"))
    return checks
