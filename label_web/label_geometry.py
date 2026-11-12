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
        if key and not any(_same_observation(line, other) for other in anchors.get(key, [])):
            anchors.setdefault(key, []).append(line)
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


def date_evidence(heading, value, lines):
    """Find one close, unobstructed date value/continuation; never use expected data."""
    evidence, conflicts, ambiguous = [heading], [], False
    for _ in range(3):
        normalized = compact(value)
        time_only = bool(re.fullmatch(r"(?:民國)?[0-9]{3,4}[./年-][0-9]{1,2}[./月-][0-9]{1,2}日?",normalized))
        if normalized and not time_only and not re.fullmatch(r"(?:民國)?[0-9０-９OoIl]{3,4}[./年-](?:[0-9０-９OoIl]{1,2}[./月-]?)?", normalized):
            break  # A complete/invalid observed value is never replaced with another date.
        first = evidence[-1]
        area = bounds(first)
        if not area:
            break
        x,y,r,b = area
        candidates = []
        for other in lines:
            if other["id"] in {item["id"] for item in evidence} or anchor_kind(other.get("text","")) or not bounds(other):
                continue
            text = compact(other["text"])
            if time_only and not re.fullmatch(r"[0-9]{1,2}(?:[時时](?:[0-9]{1,2}分?)?|:[0-9]{2})",text):
                continue
            if not re.fullmatch(r"(?:民國)?[0-9OoIl][0-9OoIl年年月日./:時时分-]{0,23}", text):
                continue
            nx,ny,nr,nb = bounds(other);height=max(b-y,nb-ny,1)
            row_overlap=max(0,min(b,nb)-max(y,ny))
            horizontal=row_overlap>=min(b-y,nb-ny)*.6 and 0<=nx-r<=height*3
            overlap=max(0,min(r,nr)-max(x,nx))
            vertical=(overlap>=min(r-x,nr-nx)*.55 and abs(nx-x)<=height*1.5 and
                      ny>=b-height*.2 and ny-b<=height*1.5)
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
        value += chosen["text"]
        evidence.append(chosen)
    for item in conflicts:
        if item["id"] not in {line["id"] for line in evidence}:
            evidence.append(item)
    return {"value":value,"lines":evidence,"ambiguous":ambiguous}
