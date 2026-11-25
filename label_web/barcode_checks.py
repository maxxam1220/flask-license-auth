"""Decode printed bars independently; checksum validity is not product identity."""
import re
from contextlib import nullcontext
from urllib.parse import urlsplit

from PIL import Image
from validation import line_is_uncertain


def decode_barcodes(path):
    try:
        import zxingcpp
    except ImportError:
        return {"state":"unavailable", "items":[]}
    try:
        with (nullcontext(path) if isinstance(path, Image.Image) else Image.open(path)) as photo:
            if photo.mode == "RGB":
                decoded = zxingcpp.read_barcodes(photo)
            else:
                with photo.convert("RGB") as rgb:
                    decoded = zxingcpp.read_barcodes(rgb)
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


def matches_decoded_gtin(digits, code):
    """UPC-A bars may be reported as EAN-13 with one leading zero."""
    format_name = str(code.get("format", "")).replace("-", "").upper()
    kind = {"EAN13": "1", "UPCA": "2"}.get(format_name)
    return digits == code.get("text") or typed_gtin_digits(digits, kind) == code.get("text")


def typed_gtin_digits(digits, kind):
    """Compare valid UPC-A / zero-prefixed EAN-13 in the declared source format."""
    if kind == "2" and len(digits) == 13 and digits.startswith("0") and gtin_valid(digits) is True:
        return digits[1:]
    if kind == "1" and len(digits) == 12 and gtin_valid(digits) is True:
        return "0" + digits
    return digits


def is_traceability_qr(code):
    """Classify a decoded web link without opening it or changing its payload."""
    format_name = re.sub(r"[\s_-]", "", str(code.get("format", ""))).casefold()
    if format_name not in {"qrcode", "qr", "microqrcode", "rmqrcode"}:
        return False
    value = str(code.get("text") or "").strip()
    if not value or any(char.isspace() or not char.isprintable() for char in value):
        return False
    try:
        url = urlsplit(value)
        # Accessing port also validates malformed and out-of-range ports.
        _ = url.port
        return url.scheme in {"http", "https"} and bool(url.hostname) and "\\" not in url.netloc
    except ValueError:
        return False


def checks_for(ocr):
    checks=[]
    decoded=[]
    for index, code in enumerate(ocr.get("barcodes",{}).get("items",[])):
        if is_traceability_qr(code):
            checks.append({"key":f"barcode_traceability_{index}", "label":"履歷 QR Code", "status":"pass",
                           "actual":code["text"], "reason":"已讀取履歷查詢網址。", "line_ids":[], "box":code.get("box",[])})
        else:
            decoded.append(code)
    if len(decoded)>1:
        checks.append({"key":"barcode_multiple", "label":"條碼範圍", "status":"review", "actual":"偵測到多個條碼",
                       "reason":"請確認只核對同一張標籤，不能把不同商品的條碼混用。", "line_ids":[]})
    for index,code in enumerate(decoded):
        value=code["text"]
        checks.append({"key":f"barcode_decode_{index}", "label":"條碼圖形", "status":"pass", "actual":value,
                       "reason":"黑白條紋可解碼；只確認可讀取，不代表商品資料正確。", "line_ids":[], "box":code["box"]})
    # Without decoded bars, only existing full-length numeric candidates are
    # strong enough to suggest barcode/checksum evidence rather than a SKU.
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
        established=any(matches_decoded_gtin(value,c) and c["format"].replace("-","") in ("EAN13","EAN8","UPCA") for c in decoded)
        explicit=bool(re.match(r"\s*(?:EAN|GTIN)\s*[:：]?",line["text"],re.I))
        if established or explicit:
            valid=gtin_valid(value)
            checks.append({"key":f"barcode_checksum_{index}", "label":"條碼檢查碼", "status":"review" if ambiguous else "pass" if valid else "fail",
                "actual":value,"reason":"EAN／GTIN 檢查碼符合計算規則。" if valid and not ambiguous else "請確認條碼數字與檢查碼；辨識不確定。" if ambiguous else "EAN／GTIN 檢查碼不符合計算規則。", "line_ids":[line.get("id")]})
    paired=[]
    if len(decoded)==1:
        # A successful spatially adjacent decode is independent evidence that
        # even a short digit row may be a partially read HRI. Do not require a
        # GTIN length here or silently leave missing digits unchecked.
        for line in ocr.get("lines",[]):
            match=re.fullmatch(r"\s*(?:(?:條碼|条码|EAN|GTIN)\s*[:：]?\s*)?([0-9][0-9 \t]*)\s*",
                               str(line.get("text","")),re.I)
            if match and _near_bars(line,decoded[0]):
                paired.append((line,re.sub(r"\s","",match[1])))
    if len(decoded)==1 and len(paired)==1:
        line,value=paired[0]
        uncertain=line_is_uncertain(line,.65)
        same=matches_decoded_gtin(value, decoded[0])
        partial=decoded[0]["text"].isascii() and decoded[0]["text"].isdigit() and len(value)<len(decoded[0]["text"])
        reason=("UPC-A 與前置零的 EAN-13 表示相同商品碼，檢查碼相符。" if same and value!=decoded[0]["text"] and not uncertain else
                "條紋解碼與印出的數字一致。" if same and not uncertain else
                "條碼圖形已解碼，但下方數字可能只辨識到一部分，請對照原圖確認完整印字。" if partial and not line.get("human_verified") else
                "條紋解碼與文字讀取不同或不確定，請查看原圖。")
        checks.append({"key":"barcode_hri", "label":"條碼與印字", "status":"review" if uncertain else "pass" if same else "fail" if line.get("human_verified") else "review",
            "actual":value,"expected":decoded[0]["text"],"reason":reason, "line_ids":[line.get("id")]})
    elif len(decoded)==1 and len(paired)>1:
        checks.append({"key":"barcode_hri", "label":"條碼與印字", "status":"review",
            "actual":"；".join(value for _,value in paired), "expected":decoded[0]["text"],
            "reason":"條碼附近讀到多段數字，無法唯一配對；請對照原圖確認完整印字，未自動拼接或補字。",
            "line_ids":[line.get("id") for line,_ in paired]})
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
