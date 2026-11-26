"""Conservative photo scope and date-neighbour rules using observed OCR boxes only."""
import math
import re
from statistics import median
import unicodedata


ANCHORS = {
    "product": ("品名", r"^(?:產品名稱|商品名稱|產品品名|品名)"),
    "manufacture": ("製造日期", r"^(?:製造日期|製造日|生產日期|生產日|生产日期|生产日)"),
    "expiry": ("有效日期", r"^(?:有效日期|有效期限|有效日|保存期限至|最佳賞味期|賞味期限|到期日)"),
    "arrival": ("到店日", r"^(?:到店日期|到店日|到貨日期|到貨日|到货日期|到货日)"),
    "address": ("地址", r"^(?:負責廠商地址|製造商地址|製造廠地址|公司地址|製造廠址|地址|住址|廠址)"),
    "company": ("公司名稱", r"^(?:負責廠商名稱|製造廠商名稱|製造商名稱|公司名稱|廠商名稱|負責廠商|製造廠商|製造商)"),
    "phone": ("電話", r"^(?:免付費(?:服務)?[電电][話话]|客服[電电][話话]|服務[電电][話话]|聯絡[電电][話话]|客服專線|服務專線|[電电][話话])"),
}
DATE_KINDS = {"manufacture", "expiry", "arrival"}
DIGIT = r"[0-9０-９]"
DATE_PREFIX = re.compile(rf"(?:民國\s*)?{DIGIT}{{3,4}}\s*[年./．／－-]\s*{DIGIT}{{1,2}}\s*[月./．／－-]\s*{DIGIT}{{1,2}}(?:\s*日)?")
CLOCK_PREFIX = re.compile(rf"\s*(?P<hour>{DIGIT}{{1,2}})\s*(?:[時时](?:\s*(?P<cjk_min>{DIGIT}{{1,2}})\s*分?)?|[:：]\s*(?P<colon_min>{DIGIT}{{1,2}}))")
DATE_CANDIDATE = re.compile(DATE_PREFIX.pattern.replace(DIGIT, r"[0-9０-９OoIl]"))
SHORT_DIGIT = r"[0-9０-９OoIl□�]"
SHORT_DATE_START = re.compile(rf"{SHORT_DIGIT}{{2}}\s*(?:([.．/／])|{SHORT_DIGIT}{{2}})")
MONTH_LENGTHS = (0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def barcode_number(text):
    """Recognize a complete retail-code length, including grouped printed digits."""
    digits = re.sub(r"[\s－-]+", "", str(text))
    return len(digits) in (8, 12, 13, 14) and re.fullmatch(DIGIT + "+", digits) is not None


def date_barcode_boundary(value):
    """Keep a product number on the same OCR line outside the date's evidence."""
    date = DATE_PREFIX.match(value)
    if not date:
        return None
    start = date.end()
    hour = re.match(rf"\s*{DIGIT}{{1,2}}\s*[時时]", value[start:])
    clock = CLOCK_PREFIX.match(value, start)
    ends = [start]
    if hour:
        ends.append(start + hour.end())
    if clock:
        ends.append(clock.end())
    return next((end for end in ends if barcode_number(value[end:])), None)


def is_date_annotation(text):
    """Printed digits, punctuation and symbols following a complete date."""
    value = str(text or "").strip()
    return bool(value and not DATE_PREFIX.search(value) and not barcode_number(value) and all(
        char.isspace() or unicodedata.category(char)[0] in "NPS" for char in value))


def split_date_annotation(text, short_format=""):
    """Read the calendar and clock first; symbols can never supply missing digits."""
    value = str(text or "").strip()
    if short_format:
        value = re.sub(r"\s+", "", value)
        pattern = (rf"{DIGIT}{{2}}[.．]{DIGIT}{{2}}" if short_format in "EF" else
                   rf"{DIGIT}{{2}}[/／]{DIGIT}{{2}}" if short_format in "GH" else
                   DIGIT + ("{8}" if short_format in "KL" else "{4}"))
        match = re.match(pattern, value)
    else:
        match = DATE_PREFIX.match(value)
    if not match:
        raise ValueError("日期須包含完整數字。")
    end = match.end()
    annotation_start = end
    if not short_format or short_format in "EFGHIJ":
        clock = CLOCK_PREFIX.match(value, end)
        if clock:
            hour, minute = int(clock["hour"]), int(clock["cjk_min"] or clock["colon_min"] or 0)
            extra = value[clock.end():]
            if (hour > 24 or minute > 59 or (hour == 24 and minute) or
                    (extra[:1].isdecimal() and value[clock.end()-1].isdecimal()) or re.match(r"\s*[:：]\s*\d", extra)):
                raise ValueError("日期的時間不合法。")
            annotation_start = clock.end()
        else:
            hour = re.match(r"\s*([^：:\s]+)\s*[:：]", value[end:])
            if hour and hour[1].isnumeric():
                raise ValueError("時間須有完整的時與分。")
    tail = value[annotation_start:].strip()
    if tail and not is_date_annotation(tail):
        raise ValueError("日期後方含無法辨識的文字。")
    return value[:end if short_format else annotation_start].rstrip(), tail


def short_date_format_hint(value):
    """Identify a possible printed form for localization, without guessing its source settings."""
    start = SHORT_DATE_START.match(value)
    if not start:
        return None
    if start[1]:
        return "E" if start[1] in ".．" else "G"
    return "K" if re.match(rf"{SHORT_DIGIT}{{8}}", value) else "I"


def short_date_ink(value):
    """Read a complete MM/DD, MM.DD, MMDD, or MMDD1700/2400 without adding a year."""
    hint = short_date_format_hint(value)
    if not hint:
        return None
    try:
        core, annotation = split_date_annotation(value, hint)
    except ValueError:
        return None
    digits = "".join(str(int(c)) for c in core if c.isdecimal())
    month, day = int(digits[:2]), int(digits[2:4])
    if not 1 <= month <= 12 or not 1 <= day <= MONTH_LENGTHS[month]:
        return None
    if hint == "K" and digits[4:] not in {"1700", "2400"}:
        return None
    # An uninterrupted extra digit is part of the core or an explicit clock.
    # Never reinterpret part of a damaged eight-digit field as an annotation.
    match = re.match(r"\s*".join(re.escape(char) for char in core), value)
    if not match:
        return None
    suffix = value[match.end():]
    if suffix[:1].isdecimal() and (hint == "K" or not CLOCK_PREFIX.match(suffix)):
        return None
    if any(barcode_number(run[0]) for run in re.finditer(rf"{DIGIT}(?:[\s－-]*{DIGIT})*", suffix)):
        return None
    return core, annotation


def unlabelled_dates(text):
    """Include the observed time and annotation when they finish a date line."""
    for match in DATE_CANDIDATE.finditer(text):
        value = text[match.start():].strip()
        boundary = date_barcode_boundary(value)
        if boundary is not None:
            value = value[:boundary]
        try:
            split_date_annotation(value)
        except ValueError:
            # Keep a malformed clock visible to the validator, while treating
            # unrelated prose or a second date on the line as separate evidence.
            tail = text[match.end():].strip()
            clock_like = tail and all(char.isspace() or char in "時时分" or
                                      unicodedata.category(char)[0] in "NPS" for char in tail)
            if not clock_like or DATE_CANDIDATE.search(tail):
                clock = CLOCK_PREFIX.match(text, match.end())
                value = text[match.start():clock.end()] if clock else match[0]
        yield value


def date_segments(line):
    """Locate date headings and their raw, non-overlapping character ranges.

    OCR can put several printed date fields in one box. Character positions,
    unlike inferred sub-boxes or expected dates, identify their actual values.
    """
    text = str(line.get("text", ""))
    headings = []
    for kind in sorted(DATE_KINDS):
        pattern = re.sub(r"[\u4e00-\u9fff]", lambda match: match[0] + r"\s*", ANCHORS[kind][1][1:])
        headings.extend((match.start(), match.end(), kind) for match in re.finditer(pattern, text))
    headings.sort()
    segments = []
    for position, (start, heading_end, kind) in enumerate(headings):
        end = headings[position + 1][0] if position + 1 < len(headings) else len(text)
        # A second, explicitly delimited field remains independent evidence.
        # In particular, a circled arrival annotation must not swallow storage
        # text when OCR emits both fields in one box.
        nondate = re.search(r"(?:保存條件|保存条件|保存方式|儲存條件|貯存條件|儲存方式|品名|規格|规格|產地|产地|地址|電話|电话|內容物|内容物)\s*[：:]",
                            text[heading_end:end])
        if nondate:
            end = heading_end + nondate.start()
        value_start, value_end = heading_end, end
        while value_start < value_end and (text[value_start].isspace() or text[value_start] in ":："):
            value_start += 1
        while value_end > value_start and text[value_end - 1].isspace():
            value_end -= 1
        boundary = date_barcode_boundary(text[value_start:value_end])
        if boundary is not None:
            value_end = end = value_start + boundary
        segments.append({"kind": kind, "value": text[value_start:value_end], "start": start, "end": end,
                         "value_start": value_start, "value_end": value_end})
    return segments


def date_observations(lines):
    """Share raw date evidence between both validators, without modifying OCR."""
    observations = []
    for line in lines:
        segments = date_segments(line)
        # Two headings with only one value cannot be assigned confidently from
        # one shared box. Do not borrow a nearby value for either sub-heading.
        shared_empty = len(segments) > 1 and any(not segment["value"] for segment in segments)
        for segment in segments:
            observed = (date_evidence(line, segment["value"], lines, kind=segment["kind"])
                        if len(segments) == 1 and not line["text"][segment["end"]:].strip()
                        else {"value": segment["value"], "lines": [line], "ambiguous": shared_empty})
            observed["kind"] = segment["kind"]
            observed["evidence_spans"] = [{"line_id": line["id"], "start": segment["start"], "end": segment["end"]}]
            observed["evidence_spans"].extend({"line_id": other["id"], "start": 0,
                                               "end": observed.get("end_offsets", {}).get(other["id"], len(other["text"]))}
                                               for other in observed["lines"] if other["id"] != line["id"])
            observations.append(observed)
    return observations


def date_evidence_overlaps(first, second):
    """The same OCR line is safe only when its date character spans are disjoint."""
    common = set(first["line_ids"]) & set(second["line_ids"])
    for identifier in common:
        left = [span for span in first.get("evidence_spans", []) if span["line_id"] == identifier]
        right = [span for span in second.get("evidence_spans", []) if span["line_id"] == identifier]
        if not left or not right or any(max(a["start"], b["start"]) < min(a["end"], b["end"]) for a in left for b in right):
            return True
    return False


def without_date_evidence(line, fields):
    """Remove checked date spans only; unrelated prefix text stays unverified."""
    spans = [span for key, field in fields.items() if key in DATE_KINDS
             for span in field.get("evidence_spans", []) if span["line_id"] == line["id"]]
    text = line["text"]
    # Union spans before slicing so overlapping/conflicting observations cannot
    # shift offsets and accidentally consume unrelated text.
    merged = []
    for span in sorted(spans, key=lambda item: item["start"]):
        start, end = span["start"], span["end"]
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        text = text[:start] + text[end:]
    return text


def compact(text):
    return re.sub(r"\s+", "", unicodedata.normalize("NFKC", str(text or "")))


def bounds(line):
    try:
        box = line.get("box") or []
        if len(box) < 4 or any(len(point) != 2 or not all(math.isfinite(float(v)) for v in point) for point in box):
            return None
        xs, ys = [float(p[0]) for p in box], [float(p[1]) for p in box]
        result = min(xs), min(ys), max(xs), max(ys)
        return result if result[2] > result[0] and result[3] > result[1] else None
    except (TypeError, ValueError, OverflowError):
        return None


def anchor_kind(text):
    text = compact(text)
    for key, (_, pattern) in ANCHORS.items():
        if re.search(pattern, text):
            return key
    # A visibly truncated/extra company suffix still identifies a footer block;
    # this is only a scope hint, never a spelling correction or accepted value.
    if re.search(r"(?:股份有限.{0,4}|公司.{0,2}|企業社.{0,2}|商行.{0,2})$", text):
        return "company"
    if re.search(r"[市縣县].{1,20}(?:[區区鄉乡鎮镇市]|[路街])", text):
        return "address"
    if re.fullmatch(r"[()0-9+.#-]+", text) and text.startswith(("0", "(0")) and 7 <= len(re.sub(r"\D", "", text)) <= 11:
        return "phone"
    return None


def _same_observation(a, b):
    if a.get("_date_span") != b.get("_date_span"):
        return False
    if compact(a["text"]) != compact(b["text"]):
        return False
    aa, bb = bounds(a), bounds(b)
    if not aa or not bb:
        return False
    x,y,r,bottom = aa;nx,ny,nr,nb = bb
    intersection = max(0,min(r,nr)-max(x,nx))*max(0,min(bottom,nb)-max(y,ny))
    return intersection / min((r-x)*(bottom-y),(nr-nx)*(nb-ny)) >= .8


def _heading_only(key, line):
    text=compact(line.get("text",""))
    match=re.search(ANCHORS[key][1],text)
    return bool(match and not text[match.end():].strip(":"))


def _near_value(first, other, lines):
    left,right=bounds(first),bounds(other)
    if not left or not right:
        return False
    x,y,r,b=left;nx,ny,nr,nb=right
    height=max(b-y,nb-ny,1)
    row_overlap=max(0,min(b,nb)-max(y,ny))
    horizontal=row_overlap>=min(b-y,nb-ny)*.6 and 0<=nx-r<=height*3
    overlap=max(0,min(r,nr)-max(x,nx))
    vertical=overlap>=min(r-x,nr-nx)*.55 and abs(nx-x)<=height*1.5 and ny>=b-height*.2 and ny-b<=height*1.5
    return bool((horizontal or vertical) and not _blocked_between(first,other,lines,horizontal))


def _footer_observations(key, observed, lines):
    """An empty footer heading and its unique adjacent bare value are one anchor."""
    if key not in {"company","address","phone"}:
        return observed
    associations=[]
    for first in observed:
        if not _heading_only(key,first):
            continue
        candidates=[other for other in observed if other["id"]!=first["id"]
                    and not re.search(ANCHORS[key][1],compact(other["text"])) and _near_value(first,other,lines)]
        if len(candidates)==1:
            associations.append((first["id"],candidates[0]["id"]))
    remove={heading for heading,value in associations if sum(other==value for _,other in associations)==1}
    return [line for line in observed if line["id"] not in remove]


def analyze_label_scope(lines):
    """Repeated identity/date/footer anchors prevent mixing two physical labels.

    This is a conservative ambiguity gate, not an assertion that all undetected
    layouts contain exactly one label. It never selects a region using expected
    text and never joins different regions to complete a reference.
    """
    anchors = {}
    for line in lines:
        key = anchor_kind(line.get("text", ""))
        if key and key not in DATE_KINDS and not any(_same_observation(line, other) for other in anchors.get(key, [])):
            anchors.setdefault(key, []).append(line)
        for segment in date_segments(line):
            key = segment["kind"]
            observed = dict(line, _date_span=(segment["start"], segment["end"]))
            if not any(_same_observation(observed, other) for other in anchors.get(key, [])):
                anchors.setdefault(key, []).append(observed)
    issues = []
    for key, observed in anchors.items():
        observed=_footer_observations(key,observed,lines)
        if len(observed) < 2:
            continue
        # One complete address may wrap onto an address-like second line.
        # Only independent city/county starts count as duplicate bare addresses.
        if key == "address":
            observed = [line for line in observed if re.search(ANCHORS[key][1], compact(line["text"]))
                        or re.match(r"[^路街號]{1,6}[市縣县]", compact(line["text"]))]
            if len(observed) < 2:
                continue
        issues.append({"kind":key, "label":ANCHORS[key][0], "line_ids":[line["id"] for line in observed]})
    spatial = [(line,bounds(line)) for line in lines if bounds(line)]
    if not issues and len(spatial) >= 4:
        height = median(area[3]-area[1] for _,area in spatial)
        # A broad empty strip separating two independently structured blocks is
        # unresolved scope even if each partial label has different field names.
        # Normal close text columns and footer wraps do not satisfy this rule.
        for axis in (0,1):
            ordered = sorted(spatial,key=lambda pair:pair[1][axis])
            far = ordered[0][1][axis+2]
            for position,(_,area) in enumerate(ordered[1:],1):
                if area[axis]-far > height*5:
                    left,right = ordered[:position],ordered[position:]
                    kinds = [{anchor_kind(item["text"]) for item,_ in group}-{None} for group in (left,right)]
                    if all(len(group)>=2 for group in (left,right)) and all(len(found)>=2 for found in kinds):
                        issues.append({"kind":"separated_blocks", "label":"分離的標籤區塊",
                                       "line_ids":[item["id"] for item,_ in ordered]})
                        break
                far=max(far,area[axis+2])
            if issues:
                break
    blocked = bool(issues)
    return {"blocked":blocked, "status":"review" if blocked else "clear", "issues":issues,
            "line_ids":list(dict.fromkeys(identifier for issue in issues for identifier in issue["line_ids"])),
            "reason":"照片中有多張標籤或重複欄位，無法確認文字及日期屬於同一張；請裁切單張標籤後重新辨識。" if blocked else ""}


def scope_review_result(lines, scope, rule_version, display=str):
    """Return raw per-line evidence without evaluating a mixed label snapshot."""
    checks = [{"key":"label_scope", "label":"標籤範圍", "status":"review", "expected":"一次核對單張標籤",
               "actual":"偵測到重複欄位", "line_ids":[], "reason":scope["reason"], "source":"scope", "diff":[]}]
    checks.extend({"key":issue["kind"], "label":issue["label"], "status":"review", "expected":"同一張標籤的唯一欄位",
                   "actual":"", "line_ids":issue["line_ids"], "reason":scope["reason"], "source":"scope", "diff":[]}
                  for issue in scope["issues"])
    index = {line["id"]:line for line in lines}
    for line in lines:
        uncertain = line.get("human_uncertain") or (not line.get("human_verified") and
                    (float(line.get("score",0)) < .65 or line.get("ambiguous")))
        checks.append({"key":f"text_line_{line['id']}", "label":"辨識原文", "status":"review" if uncertain else "read",
                       "expected":"", "actual":line["text"], "line_ids":[line["id"]], "score":line.get("score"),
                       "reason":"保留原文供對照；尚未確定單張標籤範圍，不判定內容正確。", "source":"ocr", "diff":[]})
    for check in checks:
        check.update(raw_actual=check["actual"], display_actual=display(check["actual"]), display_expected=display(check["expected"]))
        check["source_lines"] = [{"id":identifier, "text":index[identifier]["text"], "display_text":display(index[identifier]["text"]),
                                  "score":index[identifier].get("score")} for identifier in check["line_ids"] if identifier in index]
    return {"status":"review", "checks":checks, "fields":{}, "notes":[scope["reason"]], "rule_version":rule_version,
            "mode":"recognition", "label_scope":scope, "verified_scope":"unresolved_label_scope",
            "coverage":{"total_lines":len(lines),"covered_lines":len(lines)},
            "counts":{key:sum(check["status"]==key for check in checks) for key in ("pass","fail","review","read")}}


def _blocked_between(first, candidate, lines, horizontal):
    x,y,r,b = bounds(first);nx,ny,nr,nb = bounds(candidate)
    for other in lines:
        if other["id"] in {first["id"],candidate["id"]} or not str(other.get("text","")).strip() or not bounds(other):
            continue
        ox,oy,orr,ob = bounds(other)
        if horizontal:
            if ox < nx and orr > r and oy < min(b,nb) and ob > max(y,ny):
                return True
        elif oy < ny and ob > b and ox < min(r,nr) and orr > max(x,nx):
            return True
    return False


def date_evidence(heading, value, lines, kind=None):
    """Find one close, unobstructed date value/continuation; never use expected data."""
    evidence, conflicts, ambiguous = [heading], [], False
    end_offsets = {}
    for _ in range(3):
        complete = DATE_PREFIX.match(value.strip())
        if complete:
            try:
                core, tail = split_date_annotation(value)
            except ValueError:
                break
            if tail:
                break
            has_clock = not DATE_PREFIX.fullmatch(core)
        elif value.strip() and not re.fullmatch(rf"(?:民國)?{DIGIT}{{3,4}}[./年．／－-](?:{DIGIT}{{1,2}}[./月．／－-]?)?", re.sub(r"\s+", "", value)):
            break
        first = evidence[-1]
        area = bounds(first)
        if not area:
            break
        x,y,r,b = area
        candidates = []
        for other in lines:
            if other["id"] in {item["id"] for item in evidence} or anchor_kind(other.get("text","")) or not bounds(other):
                continue
            raw = str(other["text"]).strip()
            if kind in DATE_KINDS and not value.strip() and barcode_number(raw) and not short_date_ink(raw):
                continue
            is_marker = False
            if complete:
                clock = CLOCK_PREFIX.match(raw)
                if clock and not has_clock:
                    suffix = raw[clock.end():].strip()
                    if suffix and not is_date_annotation(suffix):
                        continue
                elif is_date_annotation(raw) and not clock:
                    is_marker = True
                else:
                    continue
            elif not DATE_PREFIX.match((value + raw).strip()) and not re.fullmatch(
                    r"(?:民國)?[0-9０-９OoIl][0-9０-９OoIl年月日./．／－:時时分-]{0,23}", re.sub(r"\s+", "", raw)):
                # A separate date heading may be followed by a short printed
                # date, an optional time, and a symbol. Existing geometric
                # and competing-candidate guards still apply to the whole row.
                short = short_date_ink(raw) if kind in DATE_KINDS and not value.strip() else None
                if not short or not short[1]:
                    continue
            nx,ny,nr,nb = bounds(other);height=max(b-y,nb-ny,1)
            row_overlap=max(0,min(b,nb)-max(y,ny))
            horizontal=row_overlap>=min(b-y,nb-ny)*.6 and 0<=nx-r<=height*3
            overlap=max(0,min(r,nr)-max(x,nx))
            vertical=(overlap>=min(r-x,nr-nx)*.55 and abs(nx-x)<=height*1.5 and
                      ny>=b-height*.2 and ny-b<=height*1.5)
            if is_marker and not (horizontal and nx-r <= height*1.5):
                continue
            if not (horizontal or vertical) or _blocked_between(first,other,lines,horizontal):
                continue
            candidates.append(((0,nx-r) if horizontal else (1,max(0,ny-b)),other))
        if not candidates:
            break
        candidates.sort(key=lambda pair:pair[0])
        # Two geometrically plausible values are an ambiguity, even if one matches a reference.
        ambiguous |= len(candidates)>1
        if len(candidates)>1:
            conflicts.extend(item for _,item in candidates[1:])
        chosen=candidates[0][1]
        if complete and value[-1:].isdecimal() and chosen["text"][:1].isdecimal():
            value += " "  # Separate digit groups observed in different OCR boxes.
        previous_length = len(value)
        value += chosen["text"]
        evidence.append(chosen)
        boundary = date_barcode_boundary(value.lstrip())
        if boundary is not None:
            boundary += len(value) - len(value.lstrip())
            end_offsets[chosen["id"]] = max(0, boundary - previous_length)
            value = value[:boundary].rstrip()
            break
    for item in conflicts:
        if item["id"] not in {line["id"] for line in evidence}:
            evidence.append(item)
    return {"value":value,"lines":evidence,"ambiguous":ambiguous,"end_offsets":end_offsets}
