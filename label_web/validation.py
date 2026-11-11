"""Conservative field extraction and deterministic, versioned label checks."""
from datetime import date, datetime
from difflib import SequenceMatcher
import re
import unicodedata

RULE_VERSION = "1.1"
FIELD_NAMES = {"product": "品名", "address": "地址", "origin": "產地", "manufacture": "製造日期", "expiry": "有效日期"}
ALIASES = {
    "product": r"(?:產品名稱|商品名稱|產品品名|品名)",
    "address": r"(?:負責廠商地址|製造商地址|製造廠地址|公司地址|製造廠址|地址|住址|廠址)",
    "origin": r"(?:原料[產産产]地|原[產産产]地|原[產産产]國|[產産产]地)",
    "manufacture": r"(?:製造日期|製造日|生產日期|生產日)",
    "expiry": r"(?:有效日期|有效期限|有效日|保存期限至|最佳賞味期|賞味期限|到期日)",
}
ALL_KEYS = "|".join(ALIASES.values()) + r"|內容物|成分|淨重|重量|電話|負責廠商|保存方式|營養標示|食品業者登錄字號"


def compact(text):
    # Do not fold 台/臺, Chinese variants, punctuation or confusable digits.
    return re.sub(r"\s+", "", unicodedata.normalize("NFC", str(text or "")))


def parse_date(text):
    value = unicodedata.normalize("NFKC", str(text or "")).strip()
    roc = value.startswith("民國")
    value = re.sub(r"^民國\s*", "", value)
    match = re.fullmatch(r"(\d{3,4})\s*[./年-]\s*(\d{1,2})\s*[./月-]\s*(\d{1,2})\s*日?(?:\s*(\d{1,2})\s*(?:時|时|:)(?:(\d{1,2})\s*分?)?)?", value)
    if not match:
        raise ValueError("日期須包含完整年月日；無法判讀的字元不會自動修正。")
    year, month, day = (int(match[i]) for i in (1, 2, 3))
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
            "line_ids": [x["id"] for x in lines], "ambiguous": ambiguous}


def extract_fields(lines, expected=None):
    found = {}
    ordered = sorted(lines, key=lambda x: (min(p[1] for p in x["box"]), min(p[0] for p in x["box"])))
    for key, alias in ALIASES.items():
        candidates = []
        for i, line in enumerate(ordered):
            match = re.search(alias + r"\s*[：:]?\s*", line["text"])
            if not match:
                continue
            value = re.split(ALL_KEYS, line["text"][match.end():], maxsplit=1)[0].strip(" ：:")
            evidence = [line]
            # A value may be detected as a separate box on the same row.
            if not value and i + 1 < len(ordered):
                nxt = ordered[i + 1]
                h = max(p[1] for p in line["box"]) - min(p[1] for p in line["box"])
                gap = min(p[1] for p in nxt["box"]) - max(p[1] for p in line["box"])
                if gap <= max(h, 15) and not re.search(ALL_KEYS, nxt["text"]):
                    value = nxt["text"]
                    evidence.append(nxt)
            # Join a wrapped address only where the continuation is close and address-like.
            if key == "address" and value and i + 1 < len(ordered):
                nxt = ordered[i + 1]
                gap = min(p[1] for p in nxt["box"]) - max(p[1] for p in evidence[-1]["box"])
                if nxt not in evidence and 0 <= gap < 30 and re.match(r"^[\d一二三四五六七八九十]+(?:段|巷|弄|號|樓)", nxt["text"]) and not re.search(ALL_KEYS, nxt["text"]):
                    value += nxt["text"]
                    evidence.append(nxt)
            if value:
                candidates.append(_candidate(value, evidence))
        if candidates:
            found[key] = dict(candidates[0], ambiguous=len(candidates) > 1)
    if "address" not in found:
        addresses = [x for x in ordered if re.search(r"[市縣].{1,20}[區鄉鎮市].{1,35}[路街].{0,20}號", compact(x["text"]))]
        if addresses:
            found["address"] = _candidate(addresses[0]["text"], [addresses[0]], len(addresses) > 1)
    if "product" not in found:
        candidates = [x for x in ordered if len(compact(x["text"])) >= 3 and not re.search(ALL_KEYS, x["text"])
                      and re.search(r"[\u4e00-\u9fff]", x["text"])
                      and not re.search(r"\d{4}\s*[年./-]|清晨|上午|下午|鮮食\s|營養|熱量|蛋白質|脂肪|碳水|毫克|公克|客服", x["text"])]
        if expected and expected.get("product") and candidates:
            # Similarity locates the line only. Acceptance always requires exact characters.
            ranked = sorted(candidates, key=lambda x: SequenceMatcher(None, compact(x["text"]), compact(expected["product"])).ratio(), reverse=True)
            best = ranked[0]
            if SequenceMatcher(None, compact(best["text"]), compact(expected["product"])).ratio() >= 0.35:
                score = SequenceMatcher(None, compact(best["text"]), compact(expected["product"])).ratio()
                ambiguous = len(ranked) > 1 and abs(score - SequenceMatcher(None, compact(ranked[1]["text"]), compact(expected["product"])).ratio()) < .04
                found["product"] = _candidate(best["text"], [best], ambiguous)
        elif candidates:
            found["product"] = _candidate(candidates[0]["text"], [candidates[0]])
    return found


def diff_parts(expected, actual):
    a, b = compact(expected), compact(actual)
    return [{"kind": kind, "expected": a[i:j], "actual": b[k:l]}
            for kind, i, j, k, l in SequenceMatcher(None, a, b, autojunk=False).get_opcodes()]


def evaluate(lines, template, batch_date=""):
    fields = extract_fields(lines, template["fields"])
    checks = []
    threshold = .94
    for key in ("product", "address", "origin"):
        expected = template["fields"][key]
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
    if template["rules"].get("dates", True):
        parsed = {}
        uncertain_dates = set()
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
                checks.append({"key": "batch", "label": "本批製造日", "status": "review" if "manufacture" in uncertain_dates else "pass" if m["date"] == expected_date else "fail",
                               "reason": "與本次指定的製造日核對。", "expected": batch_date, "actual": str(m["date"]), "line_ids": fields["manufacture"]["line_ids"]})
            else:
                notes.append("未指定本批製造日，未驗證兩個日期是否一起印錯。")
    else:
        notes.append("此標準未啟用日期檢查。")
    status = "fail" if any(x["status"] == "fail" for x in checks) else "review" if any(x["status"] == "review" for x in checks) else "pass"
    return {"status": status, "checks": checks, "fields": fields, "notes": notes, "rule_version": RULE_VERSION,
            "counts": {k: sum(x["status"] == k for x in checks) for k in ("pass", "fail", "review")}}


def recognize_only(lines, batch_date=""):
    """Date consistency is useful without a baseline; text correctness is unverified."""
    result = evaluate(lines, {"fields": {k: "" for k in ("product", "address", "origin")},
                              "rules": {"dates": True, "keep_days": None}}, batch_date)
    for check in result["checks"]:
        if check["key"] in {"product", "address", "origin"}:
            check.update(status="review", expected="尚無已確認標準", diff=[],
                         reason="僅辨識文字，尚未核對正確性。請對照原圖及正確資料確認。")
    result["mode"] = "recognition"
    result["status"] = "fail" if any(c["status"] == "fail" for c in result["checks"]) else "review"
    result["counts"] = {k: sum(c["status"] == k for c in result["checks"]) for k in ("pass", "fail", "review")}
    result["notes"].insert(0, "目前為先辨識模式：日期格式與先後可檢查；品名、地址、產地及保存期限是否正確，仍需已確認標準。")
    return result
