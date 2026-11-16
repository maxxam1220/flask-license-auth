"""Decode printed bars independently; checksum validity is not product identity."""
import re

from PIL import Image
from validation import line_is_uncertain


def decode_barcodes(path):
    try:
        import zxingcpp
    except ImportError:
        return {"state":"unavailable", "items":[]}
    try:
        with Image.open(path) as photo:
            decoded = zxingcpp.read_barcodes(photo.convert("RGB"))
        items=[]
        for code in decoded[:12]:
            if not code.valid:
                continue
            p=code.position
            items.append({"text":code.text, "format":str(code.format),
                          "box":[[v.x,v.y] for v in (p.top_left,p.top_right,p.bottom_right,p.bottom_left)]})
        return {"state":"decoded" if items else "not_read", "items":items}
    except Exception:
        return {"state":"unavailable", "items":[]}


def gtin_valid(value):
    if not isinstance(value,str) or not value.isascii() or not value.isdigit() or len(value) not in (8,12,13,14):
        return None
    total=sum(int(c)*(3 if i%2==0 else 1) for i,c in enumerate(reversed(value[:-1])))
    return (10-total%10)%10 == int(value[-1])


def checks_for(ocr):
    checks=[]
    decoded=ocr.get("barcodes",{}).get("items",[])
    if len(decoded)>1:
        checks.append({"key":"barcode_multiple", "label":"條碼範圍", "status":"review", "actual":"偵測到多個條碼",
                       "reason":"請確認只核對同一張標籤，不能把不同商品的條碼混用。", "line_ids":[]})
    for index,code in enumerate(decoded):
        value=code["text"]
        checks.append({"key":f"barcode_decode_{index}", "label":"條碼圖形", "status":"pass", "actual":value,
                       "reason":"黑白條紋可解碼；只確認可讀取，不代表商品資料正確。", "line_ids":[], "box":code["box"]})
    # Only complete standalone numeric rows or explicit headings are possible HRI.
    candidates=[]
    for line in ocr.get("lines",[]):
        raw=str(line.get("text",""))
        match=re.fullmatch(r"\s*(?:(?:條碼|条码|EAN|GTIN)\s*[:：]?\s*)?([0-9][0-9 \t]{6,24}[0-9])\s*",raw)
        if match:
            value=re.sub(r"\s","",match[1])
            if len(value) in (8,12,13,14):
                candidates.append((line,value))
    for index,(line,value) in enumerate(candidates):
        ambiguous=line_is_uncertain(line,.65)
        known_non_gtin=any(c["text"]==value and not any(f in c["format"] for f in ("EAN","UPC")) for c in decoded)
        if known_non_gtin:
            continue  # Code128 identifiers need not carry a GS1 check digit.
        # A length alone does not establish symbology. Unlabelled 8-digit rows may be SKU/date.
        established=any(c["text"]==value and c["format"].replace("-","") in ("EAN13","EAN8","UPCA") for c in decoded)
        explicit=bool(re.match(r"\s*(?:EAN|GTIN)\s*[:：]?",line["text"],re.I))
        if established or explicit:
            valid=gtin_valid(value)
            checks.append({"key":f"barcode_checksum_{index}", "label":"條碼檢查碼", "status":"review" if ambiguous else "pass" if valid else "fail",
                "actual":value,"reason":"EAN／GTIN 檢查碼符合計算規則。" if valid and not ambiguous else "請確認條碼數字與檢查碼；辨識不確定。" if ambiguous else "EAN／GTIN 檢查碼不符合計算規則。", "line_ids":[line.get("id")]})
    paired=[(line,value) for line,value in candidates if len(decoded)==1 and _near_bars(line,decoded[0])]
    if len(decoded)==1 and len(paired)==1:
        line,value=paired[0]
        uncertain=line_is_uncertain(line,.65)
        same=value==decoded[0]["text"]
        checks.append({"key":"barcode_hri", "label":"條碼與印字", "status":"review" if uncertain else "pass" if same else "fail" if line.get("human_verified") else "review",
            "actual":value,"expected":decoded[0]["text"],"reason":"條紋解碼與印出的數字一致。" if same and not uncertain else "條紋解碼與文字讀取不同或不確定，請查看原圖。", "line_ids":[line.get("id")]})
    elif candidates and not decoded:
        checks.append({"key":"barcode_unread", "label":"條碼圖形", "status":"review", "actual":candidates[0][1],
            "reason":"只讀到疑似條碼數字，尚未成功解碼條紋，不能確認可掃描或檢查碼。", "line_ids":[x[0].get("id") for x in candidates]})
    return checks


def _near_bars(line, barcode):
    box=line.get("box")
    bars=barcode.get("box")
    if not box or not bars:
        return False
    bx0,bx1=min(p[0] for p in bars),max(p[0] for p in bars)
    by0,by1=min(p[1] for p in bars),max(p[1] for p in bars)
    cx=sum(p[0] for p in box)/len(box)
    cy=sum(p[1] for p in box)/len(box)
    return bx0-max(25,(bx1-bx0)*.12)<=cx<=bx1+max(25,(bx1-bx0)*.12) and by0-max(20,(by1-by0)*.25)<=cy<=by1+max(150,(by1-by0)*1.5)
