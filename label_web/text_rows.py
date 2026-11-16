"""Observed nutrition rows, assembled only from photo geometry and literal cells."""
from copy import deepcopy
import math
import re
from statistics import median
import unicodedata

from validation import traditional_display, line_is_uncertain


NUTRIENTS = ("飽和脂肪酸", "反式脂肪酸", "飽和脂肪", "反式脂肪", "碳水化合物", "膳食纖維", "總碳水化合物", "蛋白質", "膽固醇",
             "熱量", "脂肪", "糖", "鈉", "鉀", "鈣", "鐵")
UNIT = r"(?:大卡|千卡|公克|毫克|微克|千焦|kcal|mg|μg|µg|kj|克|g|%)"
NUMBER_CELL = re.compile(r"[<>≤≥~約+\-]?\d+(?:[.,]\d+)?" + UNIT, re.I)
OTHER_FIELD = re.compile(r"^(?:品名|商品名稱|產品名稱|製造|有效|到店|到貨|地址|電話|保存|產地|原產地|淨重|內容物|成分|貨號)")


def _normal(text):
    return re.sub(r"\s+", "", traditional_display(unicodedata.normalize("NFKC", str(text or ""))))


def nutrition_label(text):
    value = _normal(text)
    for key in sorted(NUTRIENTS, key=len, reverse=True):
        if value.startswith(key) and (len(value)==len(key) or re.match(r"[:：0-9<>≤≥~約+.\-]", value[len(key):])):
            return key
    return None


def _numeric_cell(text):
    return bool(NUMBER_CELL.fullmatch(_normal(text)))


def _bounds(line):
    box = line.get("box") or []
    if len(box) != 4:
        return None
    try:
        values = [float(v) for point in box for v in point]
        if len(values)!=8 or not all(math.isfinite(v) for v in values):
            return None
        x,y,r,b = min(p[0] for p in box),min(p[1] for p in box),max(p[0] for p in box),max(p[1] for p in box)
        return (x,y,r,b) if r>x and b>y else None
    except (TypeError, ValueError, IndexError):
        return None


def _row(cells, row_type=None, ambiguous=False, table_id=None):
    cells = sorted(cells, key=lambda line: (_bounds(line) or (0,0,0,0))[0])
    bounds = [_bounds(line) for line in cells if _bounds(line)]
    box = []
    if bounds:
        x,y,r,b=min(v[0] for v in bounds),min(v[1] for v in bounds),max(v[2] for v in bounds),max(v[3] for v in bounds)
        box=[[x,y],[r,y],[r,b],[x,b]]
    text = " ".join(str(line["text"]).strip() for line in cells)
    uncertain = ambiguous or any(line.get("human_uncertain") or (line.get("ambiguous") and not line.get("human_verified")) for line in cells)
    return {"id":cells[0]["id"], "text":text, "source_line_ids":[line["id"] for line in cells],
            "source_lines":deepcopy(cells), "cell_texts":[line["text"] for line in cells], "box":box,
            "score":min(float(line.get("score",0)) for line in cells), "ambiguous":bool(uncertain),
            "confidence_ok":not uncertain and all(not line_is_uncertain(line,.65) for line in cells),
            "human_verified":all(line.get("human_verified",False) for line in cells),
            "human_uncertain":any(line.get("human_uncertain",False) for line in cells),
            "row_type":row_type or ("nutrition" if nutrition_label(text) else "text"), "table_id":table_id}


def group_observed_rows(lines):
    """Preserve all observed cells and duplicates; never fill an absent label/value.

    Multiple tables or missing geometry remain separate. A single nutrition title
    and its printed per-100g column bound the horizontal table region; date and
    product columns outside it never participate in an assembled nutrition row.
    """
    originals = [line for line in lines if str(line.get("text", "")).strip()]
    positioned = [line for line in originals if _bounds(line)]
    titles = [line for line in positioned if _normal(line["text"]) in ("營養標示", "營養標籤")]
    if len(titles)!=1:
        return [_row([line]) for line in originals]
    title=titles[0]; tx,ty,tr,tb=_bounds(title)
    title_h=tb-ty
    headers=[line for line in positioned if re.search(r"每(?:100|一百)(?:公克|毫升|克|g|ml)",_normal(line["text"]),re.I)
             and ty <= _bounds(line)[1] <= tb+title_h*4
             and _bounds(line)[0] <= tr+title_h*3 and _bounds(line)[2] >= tx-title_h]
    if not headers:
        return [_row([line]) for line in originals]
    header=max(headers,key=lambda line:_bounds(line)[2])
    hx,hy,hr,hb=_bounds(header)
    height=median([_bounds(line)[3]-_bounds(line)[1] for line in positioned
                   if _numeric_cell(line["text"])]) if any(_numeric_cell(line["text"]) for line in positioned) else title_h
    right=max(tr,hr)+height*.45
    anchors=[line for line in positioned if nutrition_label(line["text"])
             and _bounds(line)[0]<right-height and _bounds(line)[1]>=hy
             and _bounds(line)[1]<=hb+height*20]
    if len(anchors)<2:
        return [_row([line]) for line in originals]
    left=min(_bounds(line)[0] for line in anchors)-height*.5
    label_right=min(_bounds(line)[0] for line in anchors)+height*2.5
    bottom=max(_bounds(line)[3] for line in anchors)+height*1.8
    eligible=[line for line in positioned if left<=(_bounds(line)[0]+_bounds(line)[2])/2<=right
              and hy<=(_bounds(line)[1]+_bounds(line)[3])/2<=bottom
              and not OTHER_FIELD.match(_normal(line["text"]))]
    # Estimate the table's small camera skew from the observed quadrilaterals,
    # not an expected row or standard answer. Reject severe rotation here.
    slopes=[]
    for line in [*headers,*[line for line in eligible if _numeric_cell(line["text"])]]:
        box=line["box"]; dx=(box[1][0]+box[2][0]-box[0][0]-box[3][0])/2
        if abs(dx)>1:
            slopes.append((box[1][1]+box[2][1]-box[0][1]-box[3][1])/2/dx)
    slope=median(slopes) if slopes else 0.
    if abs(slope)>.25:
        return [_row([line]) for line in originals]
    baseline=lambda line:(_bounds(line)[1]+_bounds(line)[3])/2-slope*(_bounds(line)[0]+_bounds(line)[2])/2
    labels=[line for line in eligible if nutrition_label(line["text"]) or
            (_bounds(line)[0]<=label_right and re.search(r"[\u4e00-\u9fff]",line["text"])
             and not _numeric_cell(line["text"]) and not re.search(r"營養|每|份量|包裝|包装",line["text"]))]
    rows={line["id"]:[line] for line in labels}; conflicts=set(); orphans=[]
    for cell in [line for line in eligible if _numeric_cell(line["text"])]:
        choices=[label for label in labels if _bounds(cell)[0]>=_bounds(label)[0]
                 and abs(baseline(cell)-baseline(label))<=height*.36]
        if len(choices)==1:
            rows[choices[0]["id"]].append(cell)
        else:
            orphans.append(cell)
            conflicts.update(label["id"] for label in choices)
    grouped=[]; used=set()
    for label in labels:
        cells=rows[label["id"]]
        # Two labels on the same baseline are ambiguous, never one fused row.
        conflict=label["id"] in conflicts or any(other["id"]!=label["id"] and
            abs(baseline(other)-baseline(label))<=height*.36 for other in labels)
        grouped.append(_row(cells,"nutrition",conflict,title["id"]))
        used.update(cell["id"] for cell in cells)
    # An OCR omission of e.g. 鈉 leaves a numeric row, never a guessed nutrient.
    while orphans:
        first=orphans.pop(0)
        same=[cell for cell in orphans if abs(baseline(cell)-baseline(first))<=height*.25]
        orphans=[cell for cell in orphans if cell not in same]
        cells=[first,*same]
        grouped.append(_row(cells,"nutrition_values",False,title["id"]))
        used.update(cell["id"] for cell in cells)
    result=[_row([line]) for line in originals if line["id"] not in used]+grouped
    order={line["id"]:index for index,line in enumerate(originals)}
    return sorted(result,key=lambda row:min(order[identifier] for identifier in row["source_line_ids"]))
