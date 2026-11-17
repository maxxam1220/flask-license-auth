"""Explicitly confirmed barcode hypotheses; never infer printer configuration."""
from copy import deepcopy
from datetime import date
import hashlib
import json
import re
import unicodedata

from flask import abort
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError, OperationalError

import corrections
import database as db
import history_cleanup
import standard_library
import standard_reference as standards
from barcode_checks import gtin_valid, _near_bars
from label_geometry import analyze_label_scope
from validation import line_is_uncertain, parse_date


DAY_LABELS={"base_date":"本批基準日","manufacture":"製造日期","expiry":"有效日期","arrival":"到店日"}
RULE_KEYS={"version","symbology","prefix","day_source","day_width","suffix"}
CHOICE_KEYS={"base_revision","source_revision","manual_revision","candidate_id","fill_keep_days"}
MANUAL_KEYS={"manual_rule","confirmed_ean13"}


def _digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()


def validate_rule(rule):
    if not isinstance(rule,dict) or set(rule)!=RULE_KEYS or type(rule.get("version")) is not int or rule["version"]!=1:
        raise ValueError("不支援的條碼規則版本。")
    if rule.get("symbology")!="EAN13" or not isinstance(rule.get("day_source"),str) or rule["day_source"] not in DAY_LABELS or type(rule.get("day_width")) is not int or rule["day_width"] not in (2,3):
        raise ValueError("條碼種類或日期來源不正確。")
    if not isinstance(rule.get("prefix"),str) or not re.fullmatch(r"[0-9]{1,10}",rule["prefix"]):
        raise ValueError("固定前綴須為已知的半形數字。")
    if not isinstance(rule.get("suffix"),str) or not re.fullmatch(r"[0-9]*",rule["suffix"]):
        raise ValueError("尾碼須為半形數字。")
    if len(rule["prefix"])+rule["day_width"]+len(rule["suffix"])!=12:
        raise ValueError("EAN13 的規則內容須剛好 12 位，另計檢查碼。")
    return deepcopy(rule)


def compose(rule, value):
    rule=validate_rule(rule)
    day=value.timetuple().tm_yday
    day_text=f"{day%100:02d}" if rule["day_width"]==2 else f"{day:03d}"
    payload=rule["prefix"]+day_text+rule["suffix"]
    check=(10-sum(int(c)*(3 if i%2==0 else 1) for i,c in enumerate(reversed(payload)))%10)%10
    return payload+str(check)


def literal_value(text):
    text=unicodedata.normalize("NFKC",str(text)).strip()
    match=re.fullmatch(r"(?:(?:條碼|条码|Barcode|EAN|GTIN)\s*[:：]?\s*)?([0-9][0-9 \t]*)",text,re.I)
    return re.sub(r"\s+","",match[1]) if match else ""


def dynamic_literal(rule,text):
    """Only stand-alone numeric barcode evidence can leave static comparison."""
    try:rule=validate_rule(rule)
    except ValueError:return False
    value=literal_value(text)
    return value==rule["prefix"] or (len(value)==13 and value.startswith(rule["prefix"]) and gtin_valid(value) is True)


def _observed(original,current):
    ocr=deepcopy(original.get("ocr") or {})
    patches={row["line_id"]:row for row in (current or {}).get("patches",[])}
    for line in ocr.get("lines",[]):
        patch=patches.get(line.get("id"))
        if patch and patch["kind"]=="ocr_misread":
            line.update(text=patch["text"],human_verified=True,human_uncertain=False)
        elif patch:
            line["human_uncertain"]=True
    return ocr


def read_observations(ocr,base_date):
    from source_validation import _date_fields
    lines=ocr.get("lines") or []
    decoded=[{key:item.get(key) for key in ("text","format","box")} for item in (ocr.get("barcodes") or {}).get("items",[])]
    readings=[]
    for line in lines:
        value=literal_value(line.get("text",""))
        if value and (len(value)==13 or any(_near_bars(line,code) for code in decoded if code.get("box"))):
            readings.append({"text":line["text"],"value":value,"line_ids":[line["id"]],
                "uncertain":line_is_uncertain(line,.65),"valid_ean13":len(value)==13 and gtin_valid(value) is True})
    values={row["value"] for row in readings}
    decoded_values={str(item.get("text") or "") for item in decoded}
    reason=""
    if len(decoded)>1 or len(readings)>1:
        reason="同張照片有多個條碼或數字候選，請先裁切單張並確認唯一條碼。"
    elif any(str(item.get("format") or "").replace("-","").upper()!="EAN13" or gtin_valid(str(item.get("text") or "")) is not True or len(str(item.get("text") or ""))!=13 for item in decoded):
        reason="目前只提供完整 EAN13 條碼公式候選，其他條碼種類不推算。"
    elif any(row["uncertain"] or not row["valid_ean13"] for row in readings):
        reason="條碼印字不完整、不確定或檢查碼不符，請先確認實際條碼。"
    elif values and decoded_values and values!=decoded_values:
        reason="條紋解碼與辨識印字不同，請先確認，不能用衝突資料建立規則。"
    found=values|decoded_values
    if not reason and len(found)!=1:
        reason="尚未取得唯一清楚且檢查碼有效的完整 EAN13 條碼。"
    fields=_date_fields(lines)
    dates=[];parsed={}
    for key,field in fields.items():
        uncertain=bool(field.get("ambiguous") or not field.get("confidence_ok",field.get("score",0)>=.65))
        try:value=parse_date(field["value"],kind=key)["date"]
        except (ValueError,TypeError,KeyError):value=None;uncertain=True
        dates.append({"kind":key,"label":DAY_LABELS[key],"value":field.get("value",""),
            "iso":value.isoformat() if value else None,"day_of_year":value.timetuple().tm_yday if value else None,
            "line_ids":field.get("line_ids",[]),"uncertain":uncertain})
        if value and not uncertain:parsed[key]=value
    try:base=date.fromisoformat(base_date)
    except (ValueError,TypeError):base=None
    if base:parsed["base_date"]=base
    scope=analyze_label_scope(lines)
    if scope["blocked"] or (ocr.get("label_scope") or {}).get("status")=="multiple" or ocr.get("image_status")=="multiple_labels":
        reason="照片包含多張或無法可靠區分的標籤，請先裁切單張。"
    return {"ocr":readings,"decoded":decoded,"dates":dates,"base_date":base_date},parsed,next(iter(found),"") if not reason else "",reason


def evaluate_rule(lines,rule,base_date):
    """Apply an approved rule to observed text; date business checks stay separate."""
    check={"key":"web_barcode_rule","label":"已核准條碼公式","source":"database","status":"review",
        "expected":"","actual":"","line_ids":[],"score":None,"diff":[],"reason":"條碼公式不完整，請管理員重新確認。"}
    try:rule=validate_rule(rule)
    except ValueError:return check
    observed,dates,value,reason=read_observations({"lines":lines},base_date)
    check.update(actual=" / ".join(item["text"] for item in observed["ocr"]),
        line_ids=[identifier for item in observed["ocr"] for identifier in item["line_ids"]],
        rule=rule,date_source=rule["day_source"])
    if reason:
        check["reason"]=reason if observed["ocr"] else "尚未取得唯一清楚的完整條碼印字，請確認條碼印字；僅條紋解碼不會讓公式自動通過。"
        return check
    chosen=dates.get(rule["day_source"])
    if chosen is None:
        check["reason"]=f"缺少唯一清楚且完整的{DAY_LABELS[rule['day_source']]}，無法核對條碼公式。"
        return check
    expected=compose(rule,chosen)
    check.update(expected=expected,status="pass" if value==expected else "fail",date_value=chosen.isoformat(),
        reason=f"依已核准規則，以{DAY_LABELS[rule['day_source']]} {chosen.isoformat()} 計算，條碼相符。" if value==expected else
               f"依已核准規則應為 {expected}，辨識為 {value}，條碼不同。")
    return check


def _known_prefixes(base,effective):
    if str((base.get("barcode_config") or {}).get("kind","")) not in {"","1"}:return []
    values=list(base.get("barcode_values") or [])
    config=base.get("barcode_config") or {}
    values.extend(config.get(key) for key in ("master_barcode","barcode") if config.get(key))
    if effective.get("web_barcode_rule"):
        values.append(effective["web_barcode_rule"].get("prefix"))
    return sorted({str(value) for value in values if re.fullmatch(r"[0-9]{1,10}",str(value or ""))})


def auto_hypotheses(entry,current_rule=None,known_candidates=()):
    """Bounded observed-date splits; a match is a proposal, never approval."""
    value=entry.get("observed_value","")
    if not entry.get("available") or not isinstance(value,str) or not re.fullmatch(r"[0-9]{13}",value) or gtin_valid(value) is not True:
        return [],None
    dates={}
    for kind in ("manufacture","expiry","arrival"):
        found=[item for item in entry.get("dates",[]) if item.get("kind")==kind]
        if len(found)!=1 or found[0].get("uncertain"):continue
        try:dates[kind]=date.fromisoformat(found[0].get("iso"))
        except (ValueError,TypeError):continue
    try:dates["base_date"]=date.fromisoformat(entry.get("base_date"))
    except (ValueError,TypeError):pass
    try:approved=validate_rule(current_rule)
    except ValueError:approved=None
    candidates=[];seen=set();payload=value[:12]
    for width in (3,2):
        for kind,day in dates.items():
            token=f"{day.timetuple().tm_yday:03d}" if width==3 else f"{day.timetuple().tm_yday%100:02d}"
            # At least one observed digit precedes the date. Never pad, repair
            # or silently omit a digit; every candidate reproduces all 13.
            for position in range(1,len(payload)-width+1):
                if payload[position:position+width]!=token:continue
                rule={"version":1,"symbology":"EAN13","prefix":payload[:position],"day_source":kind,
                    "day_width":width,"suffix":payload[position+width:]}
                if compose(rule,day)!=value:continue
                marker=_digest(rule)
                if marker in seen:continue
                seen.add(marker)
                evidence={"kind":"observed_hypothesis","method":"date_token_match","date_value":day.isoformat(),
                    "day_token":token,"insertion_position":position+1,"components_inferred":True}
                known=next((item for item in known_candidates if item.get("rule")==rule and
                    (item.get("evidence") or {}).get("kind")=="catalog_structure"),None)
                if known:evidence={**deepcopy(known["evidence"]),"date_value":day.isoformat(),"day_token":token,"insertion_position":position+1}
                if rule==approved:evidence={"kind":"approved_rule","method":"current_approved_rule",
                    "date_value":day.isoformat(),"day_token":token,"insertion_position":position+1,"components_inferred":False}
                warnings=["依本張完整條碼與日期找到的分段試算；前綴與尾碼尚未證實是商品碼或固定資料。",
                    "同一條碼可能同時符合三位、兩位太陽日或其他公式；試算相符不代表唯一或已核准。"]
                if evidence["kind"]=="approved_rule":warnings=["沿用目前已核准的公式，並以本張日期試算；原日期檢查仍分開保留。"]
                elif known:warnings=deepcopy(known["warnings"])
                if entry.get("fixed_barcode_reference") and evidence["kind"]!="approved_rule":
                    warnings.append("此標準已有相同的固定完整條碼，日期數字可能只是巧合；不自動推薦改為動態公式。")
                candidates.append({"id":_digest({"rule":rule,"observed_value":value,"evidence":evidence}),"rule":rule,
                    "summary":f"前綴{rule['prefix']}＋{DAY_LABELS[kind]}{width}位太陽日＋尾碼{rule['suffix'] or '無'}＋檢查碼",
                    "parts":[{"label":"待核准固定前綴","value":rule["prefix"]},{"label":DAY_LABELS[kind],"value":day.isoformat()},
                        {"label":f"{width}位太陽日","value":token},{"label":"待核准固定尾碼","value":rule["suffix"]},
                        {"label":"EAN13檢查碼","value":value[-1]}],"composed_value":value,"evidence":evidence,"warnings":warnings})
    preferred=[item for item in candidates if item["evidence"]["kind"]=="approved_rule"]
    # An existing approved formula may be exposing a real printing error.
    # Keep alternatives visible, but never recommend replacing it just to fit.
    if not preferred and approved is None and not entry.get("fixed_barcode_reference"):
        known=[item for item in candidates if item["evidence"]["kind"]=="catalog_structure"]
        preferred=known if known else [item for item in candidates if item["rule"]["day_width"]==3]
    return candidates,preferred[0]["id"] if len(preferred)==1 else None


def _load(engine,identifier,conn=None):
    original=standards._inspection(engine,identifier)
    if conn is None:
        with engine.connect() as connection:
            history_cleanup.ensure_active(connection,identifier)
            current=corrections.latest(connection,identifier)
    else:
        history_cleanup.ensure_active(conn,identifier);current=corrections.latest(conn,identifier)
    inputs=original.get("result",{}).get("inputs") or {}
    ocr=_observed(original,current)
    observation,dates,value,reason=read_observations(ocr,inputs.get("base_date",""))
    observation_reason=reason
    base,unsupported=standards._context(engine,original)
    if base and base.get("catalog_barcode_line_ids"):
        # _context supplies synthetic editor rows for catalog literals. This
        # operation changes only a rule, so do not persist those as new text.
        base=deepcopy(base)
        editor_ids=set(base.pop("catalog_barcode_line_ids"))
        base["lines"]=[row for row in base.get("lines",[]) if row.get("id") not in editor_ids]
    effective=deepcopy((original.get("template_snapshot") or {}).get("source") or {})
    version=None
    if base:
        version=standards._current(engine,str(base["code"]))
        effective=standards.apply_current(engine,base,version or {})
    if original.get("template_id"):
        reason="照片標準目前不支援儲存條碼公式，原照片與核對內容保持不變。"
    elif unsupported or not base:
        reason=(unsupported or {}).get("notice") or "請先選定或建立唯一的比對標準，再設定條碼規則。"
    current_days=effective.get("keep_days")
    suggested=None;days_reason="已有保存天數，不會用照片覆寫。" if current_days is not None else "需有唯一清楚且前後合理的製造與有效日期。"
    if current_days is None and all(key in dates for key in ("manufacture","expiry")):
        delta=(dates["expiry"]-dates["manufacture"]).days
        from source_validation import _date_checks
        checks,_,_=_date_checks(ocr.get("lines",[]),effective,inputs.get("batch_date",""),inputs.get("arrival_date",""),inputs.get("base_date",""))
        if 0<=delta<=3660 and not any(check["status"] in {"fail","review"} for check in checks):
            suggested=delta;days_reason="依本張製造與有效日期相差天數提供候選，確認前不寫入。"
    structure=None;structure_evidence=None
    if base and "catalog_barcode_config" in base:
        from reference_catalog import barcode_structure
        try:
            structure=barcode_structure(base)
            structure_evidence={"kind":"catalog_structure","revision":base["catalog_barcode_reference_revision"],
                "config":deepcopy(base["catalog_barcode_config"]),
                "provenance":{key:(base.get("provenance") or {}).get(key) for key in ("file","sheet","row","source_date")},
                "date_source_confirmed":False}
        except (ValueError,KeyError) as error:
            if not reason:reason=str(error) if isinstance(error,ValueError) else "清單組碼證據缺少版本，請重新載入清單。"
    prefixes=[structure["prefix"]] if structure else _known_prefixes(base or {},effective)
    kind=str(((base or {}).get("barcode_config") or {}).get("kind","")).strip()
    manual_reason=observation_reason
    if not base or unsupported or original.get("template_id") or effective.get("source_kind")!="manual" or not str(effective.get("code","")).startswith("manual:"):
        manual_reason="手動補上組碼目前只適用仍有效的人工文字標準。"
    elif kind not in {"","1"}:
        manual_reason="此來源已指定其他條碼種類，不能以手動確認覆蓋為 EAN13。"
    elif not manual_reason and not dates:
        manual_reason="尚未取得可信的完整日期或本批基準日，無法試算日期條碼。"
    decoded=observation["decoded"]
    decoded_ean13=(len(decoded)==1 and str(decoded[0].get("format") or "").replace("-","").upper()=="EAN13"
        and str(decoded[0].get("text") or "")==value and len(value)==13 and gtin_valid(value) is True)
    type_verification="source_config" if kind=="1" else "decoded" if decoded_ean13 else "assumed"
    manual_entry={"available":not bool(manual_reason),"reason":manual_reason,"observed_value":value,
        "dates":deepcopy(observation["dates"]),"base_date":observation["base_date"],
        "type_verification":type_verification,"requires_ean13_confirmation":type_verification=="assumed"}
    fixed_values=[]
    # Explicit fixed barcode fields are declarations. Text-only historical HRI
    # (including spaced print) remains evidence, not a permanent-code promise.
    for stored in (base or {},effective):
        fixed_values.extend(stored.get("barcode_values") or [])
        config=stored.get("barcode_config") or {}
        if str(config.get("solar","")) not in {"2","3"} and not any(config.get(key) for key in ("front","back")) and str(config.get("price_len",""))!="4":
            fixed_values.append(config.get("barcode",""))
    manual_entry["fixed_barcode_reference"]=bool(value) and any(literal_value(item.get("value","") if isinstance(item,dict) else item)==value for item in fixed_values)
    if not reason and not kind and not observation["decoded"]:
        reason="來源尚未確認條碼種類，只有數字印字不足以認定 EAN13；請取得明確 EAN13 條紋解碼後再建立候選。"
    if not reason and not prefixes:reason="這份來源沒有已知數字前綴，不能只從完整條碼猜商品前綴。"
    candidates=[]
    if not reason:
        for prefix in prefixes:
            if not value.startswith(prefix):continue
            for day_source,day in dates.items():
                for width in (structure["day_width"],) if structure else (2,3):
                    if len(prefix)+width>12:continue
                    rule={"version":1,"symbology":"EAN13","prefix":prefix,"day_source":day_source,
                        "day_width":width,"suffix":structure["suffix"] if structure else value[len(prefix)+width:12]}
                    if compose(rule,day)!=value:continue
                    day_text=f"{day.timetuple().tm_yday%100:02d}" if width==2 else f"{day.timetuple().tm_yday:03d}"
                    warnings=["候選只是本次試算相符，尚未核准；同一條碼可能有不同組成方式。",
                        "尾碼僅是本次觀察的固定值假設，沒有推定它代表時刻、價格或其他資料。"]
                    if structure:
                        warnings=["組碼位置、位數與前後碼來自清單；採用哪個日期仍需管理員明確核准，不能由清單假定。",
                            "本次條碼試算相符尚不代表日期排程正確；原日期檢查仍分開保留。"]
                    candidate={"id":_digest({"rule":rule,"evidence":structure_evidence}) if structure else _digest(rule),"summary":f"前綴{prefix}＋{DAY_LABELS[day_source]}{width}位太陽日＋尾碼{rule['suffix'] or '無'}＋檢查碼",
                        "parts":[{"label":"固定前綴","value":prefix},{"label":DAY_LABELS[day_source],"value":day.isoformat()},
                            {"label":f"清單{width}位太陽日" if structure else f"{width}位太陽日","value":day_text},
                            {"label":"清單固定尾碼" if structure else "尾碼（本次觀察假設）","value":rule["suffix"]},
                            {"label":"EAN13檢查碼","value":value[-1]}],
                        "rule":rule,"keep_days_suggestion":suggested,"warnings":warnings}
                    if structure_evidence:candidate["evidence"]=deepcopy(structure_evidence)
                    candidates.append(candidate)
    if not reason and not candidates:reason="已知前綴與本次可信日期無法組成相同條碼；未猜補日期或尾碼。"
    manual_entry["auto_candidates"],manual_entry["recommended_id"]=auto_hypotheses(manual_entry,effective.get("web_barcode_rule"),candidates)
    payload={"source":{key:effective.get(key) for key in ("code","name","source_kind")},
        "base_revision":version["revision"] if version else 0,"source_revision":str((base or {}).get("revision","")),
        "manual_revision":current["revision"] if current else 0,"current_rule":effective.get("web_barcode_rule"),
        "can_write":bool(candidates) and not bool(reason),"reason":reason,"observed":observation,
        "manual_entry":manual_entry,
        "keep_days":{"current":current_days,"suggested":suggested,"can_fill":current_days is None and suggested is not None,"reason":days_reason},
        "candidates":candidates,"warnings":["只變更網站核對規則，不會改列印程式、原始文字、照片或日期排程。"]}
    return original,base,effective,payload


def suggest(engine,inspection_id):
    return _load(engine,inspection_id)[3]


def _manual_candidate(payload,body):
    entry=payload["manual_entry"]
    if not entry["available"]:abort(409,description=entry["reason"])
    acknowledgement=body.get("confirmed_ean13")
    if type(acknowledgement) is not bool or (entry["requires_ean13_confirmation"] and not acknowledgement):
        abort(400,description="請先同意採用 EAN13 日期組碼方式試算，正式採用仍須確認。")
    try:rule=validate_rule(body.get("manual_rule"))
    except ValueError as error:abort(400,description=str(error))
    if rule["day_source"]=="base_date":
        date_value=entry["base_date"]
    else:
        row=next((item for item in entry["dates"] if item["kind"]==rule["day_source"] and not item["uncertain"]),None)
        date_value=row.get("iso") if row else None
    try:chosen=date.fromisoformat(date_value)
    except (ValueError,TypeError):abort(400,description="所選日期尚未唯一、清楚且完整辨識，不能用其他日期代替。")
    expected=compose(rule,chosen)
    if expected!=entry["observed_value"]:
        abort(400,description=f"這份公式試算為 {expected}，與本張完整條碼 {entry['observed_value']} 不同，請確認各段與日期來源。")
    width=rule["day_width"];day=chosen.timetuple().tm_yday
    hypothesis=next((item for item in entry.get("auto_candidates",[]) if item["rule"]==rule),None)
    evidence={"kind":"manual_entry","ean13_assumption_accepted":acknowledgement if entry["type_verification"]=="assumed" else False,
        "type_verification":entry["type_verification"],
        "observed_value":entry["observed_value"],"submitted_rule":deepcopy(rule)}
    if hypothesis:
        evidence["photo_date_hypothesis" if hypothesis["evidence"]["kind"]=="observed_hypothesis" else "reference_evidence"]=deepcopy(hypothesis["evidence"])
    return {"id":"manual","rule":rule,"summary":f"前綴{rule['prefix']}＋{DAY_LABELS[rule['day_source']]}{width}位太陽日＋尾碼{rule['suffix'] or '無'}＋檢查碼",
        "parts":[{"label":"待核准固定前綴","value":rule["prefix"]},
            {"label":DAY_LABELS[rule["day_source"]],"value":chosen.isoformat()},
            {"label":f"{width}位太陽日","value":f"{day%100:02d}" if width==2 else f"{day:03d}"},
            {"label":"待核准固定尾碼","value":rule["suffix"]},{"label":"EAN13檢查碼","value":expected[-1]}],
        "keep_days_suggestion":payload["keep_days"]["suggested"],
        "warnings":["前綴、太陽日位數及尾碼可能來自本張日期的分段試算，尚不代表已證實的商品組碼設定。",
            "本次試算相符仍可能有其他組成方式；確認後此規則將用於這份人工標準的後續標籤，日期排程仍獨立檢查。"]+
            (hypothesis["warnings"] if hypothesis else []),"evidence":evidence}


def _selection(payload,body):
    for key in ("base_revision","manual_revision"):
        if standards._integer(body.get(key),"版本",0,2**31-2)!=payload[key]:
            abort(409,description="標準或人工訂正已變更，請重新取得條碼候選。")
    if body.get("source_revision")!=payload["source_revision"]:
        abort(409,description="來源已變更，請重新取得條碼候選。")
    if body.get("candidate_id")=="manual":
        candidate=_manual_candidate(payload,body)
    else:
        if not payload["can_write"]:abort(409,description=payload["reason"])
        candidate=next((item for item in payload["candidates"] if item["id"]==body.get("candidate_id")),None)
    if candidate is None:abort(409,description="候選不存在或已變更，請重新預覽。")
    fill=body.get("fill_keep_days")
    if type(fill) is not bool:abort(400,description="請明確選擇是否填入缺少的保存天數。")
    if fill and not payload["keep_days"]["can_fill"]:abort(409,description="保存天數已有設定或缺少可信日期，不會自動覆寫。")
    return candidate,payload["keep_days"]["suggested"] if fill else payload["keep_days"]["current"]


def _preview(payload,body,inspection_id):
    candidate,days=_selection(payload,body)
    before={"rule":payload["current_rule"],"keep_days":payload["keep_days"]["current"]}
    after={"rule":candidate["rule"],"keep_days":days}
    keys=CHOICE_KEYS|MANUAL_KEYS if body.get("candidate_id")=="manual" else CHOICE_KEYS
    signature={"inspection_id":inspection_id,"choice":{key:body[key] for key in keys},
        "observed":payload["observed"],"before":before,"after":after,"candidate_evidence":candidate.get("evidence")}
    return {**{key:payload[key] for key in ("base_revision","source_revision","manual_revision")},
        "preview_hash":_digest(signature),"candidate":candidate,"before":before,"after":after,
        "warnings":candidate["warnings"]+payload["warnings"]}


def preview(engine,inspection_id,body):
    if not isinstance(body,dict) or set(body)!=(CHOICE_KEYS|MANUAL_KEYS if body.get("candidate_id")=="manual" else CHOICE_KEYS):
        abort(400,description="請選擇條碼候選或填寫完整公式，並提供目前版本。")
    return _preview(suggest(engine,inspection_id),body,inspection_id)


def save(engine,inspection_id,body):
    if not isinstance(body,dict) or set(body)!=(CHOICE_KEYS|(MANUAL_KEYS if body.get("candidate_id")=="manual" else set())|{"preview_hash","reviewer","note","confirmed"}) or body.get("confirmed") is not True:
        abort(400,description="請預覽並明確確認此規則將用於之後同款標籤。")
    reviewer=standards._text(body["reviewer"],"確認人員",100);note=standards._text(body["note"],"確認原因",2000)
    try:
        with engine.begin() as conn:
            standards._lock_active_inspection(conn,inspection_id)
            original,base,effective,payload=_load(engine,inspection_id,conn)
            if not base:abort(409,description=payload["reason"])
            code=str(base["code"])
            standard_library.ensure_selectable(conn,code=code)
            # Re-read after the shared standard lock; a second administrator's
            # save must not be replaced by a preview from an older revision.
            original,base,effective,payload=_load(engine,inspection_id,conn)
            reviewed=_preview(payload,body,inspection_id)
            if body.get("preview_hash")!=reviewed["preview_hash"]:abort(409,description="預覽內容已變更或尚未預覽，請重新確認。")
            if conn.dialect.name=="postgresql":from sqlalchemy.dialects.postgresql import insert as upsert
            else:from sqlalchemy.dialects.sqlite import insert as upsert
            conn.execute(upsert(standards.heads).values(code=code,revision=0).on_conflict_do_nothing(index_elements=["code"]))
            revision=conn.execute(select(standards.heads.c.revision).where(standards.heads.c.code==code).with_for_update()).scalar_one()
            if revision!=body["base_revision"]:abort(409,description="另一位使用者已更新標準，請重新預覽。")
            snapshot=deepcopy(effective);snapshot.pop("standard_reference",None);snapshot.pop("base_date",None)
            snapshot["revision"]=str(base["revision"])
            snapshot["web_barcode_rule"]=reviewed["after"]["rule"]
            if body["fill_keep_days"]:
                snapshot.update(keep_days=reviewed["after"]["keep_days"],keep_days_source="confirmed_date_difference")
            evidence={"inspection_id":inspection_id,"manual_revision":payload["manual_revision"],
                "candidate_id":body["candidate_id"],"preview_hash":body["preview_hash"],"observed":payload["observed"]}
            if reviewed["candidate"].get("evidence"):
                evidence["manual_entry" if body["candidate_id"]=="manual" else "catalog_structure"]=deepcopy(reviewed["candidate"]["evidence"])
            snapshot["web_barcode_rule_evidence"]=evidence
            new_revision=revision+1;created=db.now()
            conn.execute(insert(standards.versions).values(id=db.uid(),code=code,revision=new_revision,
                source_revision=str(base["revision"]),operation="barcode_rule",snapshot=snapshot,
                changes={"web_barcode_rule":snapshot["web_barcode_rule"],"fill_keep_days":body["fill_keep_days"],"evidence":evidence},
                inspection_id=inspection_id,reviewer=reviewer,note=note,created_at=created))
            changed=conn.execute(update(standards.heads).where(standards.heads.c.code==code,standards.heads.c.revision==revision).values(revision=new_revision))
            if changed.rowcount!=1:abort(409,description="標準版本已變更，請重新預覽。")
            kind="manual" if code.startswith("manual:") else "source"
            state=standard_library._state(conn,kind,code,lock=True)
            item_revision=standard_library._write_state(conn,state)
            standard_library._audit(conn,kind,code,"barcode_rule",reviewer,note,{"item_revision":item_revision,"base_revision":new_revision,**evidence})
    except IntegrityError:abort(409,description="標準版本已變更，請重新預覽。")
    except OperationalError as error:
        if getattr(error.orig,"sqlite_errorcode",None) in {5,6,517}:abort(409,description="標準正在更新，請重新預覽。")
        raise
    return {"source_code":code,"base_revision":new_revision,"source_revision":str(base["revision"]),
        "rule":snapshot["web_barcode_rule"],"keep_days":snapshot.get("keep_days"),"recheck_required":True,"replayed":False}
