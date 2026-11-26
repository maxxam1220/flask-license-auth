"""Explicitly approved website text references, independent of printer layouts."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import unicodedata
from urllib.parse import quote

from flask import abort, jsonify, request
from sqlalchemy import inspect, select, insert, func, or_, cast, Text
from sqlalchemy.exc import IntegrityError

import database as db
from validation import extract_fields, TEXT_FIELDS
from source_validation import HEADINGS, _kind, normalize_text
from standard_draft_quality import eligibility as draft_eligibility


PREFIX = "manual:"
DATE_LABELS = {"manufacture": "製造日期", "expiry": "有效日期", "arrival": "到店日"}
LIMITATIONS = ["只核對人員已確認並列入的文字與日期規則；沒有建立印標版面。",
               "未列入標準的文字仍屬未核對，不代表整張標籤已確認正確。"]
DEFINITION_KEYS = {"name", "sku", "lines", "keep_days", "date_settings"}


def _fixed_manual_text(value):
    from standard_reference import _fixed_text
    value = _fixed_text(value)
    if re.fullmatch(r"\s*\d{1,2}\s*[./-]\s*\d{1,2}(?:\s+\d{1,2}[:：]\d{2})?\s*", unicodedata.normalize("NFKC", value)):
        abort(400, description="像日期的獨立月日不能存成永久標準；請使用日期位移規則。")
    return value


def fixed_line_text(value):
    """The same fixed-text contract applies to creation and later revisions."""
    from standard_reference import _text
    value = _fixed_manual_text(_text(value, "標準文字", 2000))
    if "\n" in value or "\r" in value:
        abort(400, description="請將標準文字逐行分開，不要合併成一段。")
    if _kind(value) in DATE_LABELS:
        abort(400, description="製造日、有效日與到店日請填日期規則，不要存成固定文字。")
    return value


def _stored(engine):
    inspector = inspect(engine, raiseerr=False)
    return inspector is not None and inspector.has_table(db.manual_sources.name)


def available(engine):
    if not _stored(engine):
        return False
    with engine.connect() as conn:
        return conn.execute(select(db.manual_sources.c.code).where(db.manual_sources.c.active.is_(True)).limit(1)).first() is not None


def records(engine):
    if not _stored(engine):
        return []
    with engine.connect() as conn:
        return [dict(row) for row in conn.execute(select(db.manual_sources).where(db.manual_sources.c.active.is_(True))
            .order_by(db.manual_sources.c.created_at, db.manual_sources.c.code)).mappings()]


def draft(engine, code):
    if not str(code).startswith(PREFIX) or not _stored(engine):
        return None
    with engine.connect() as conn:
        row = conn.execute(select(db.manual_sources.c.snapshot).where(
            (db.manual_sources.c.code == str(code)) & db.manual_sources.c.active.is_(True))).first()
    return deepcopy(row.snapshot) if row else None


def listing(engine, query="", page=1, limit=24):
    """Return only current list metadata; snapshots stay in the database."""
    import standard_reference as standards
    if not isinstance(query, str) or len(query) > 100:
        abort(400, description="搜尋文字最多 100 字。")
    page = standards._integer(page, "頁碼", 1, 1_000_000)
    limit = standards._integer(limit, "每頁筆數", 1, 100)
    sources, heads, versions = db.manual_sources, standards.heads, standards.versions
    joined = sources.outerjoin(heads, heads.c.code == sources.c.code).outerjoin(versions,
        (versions.c.code == heads.c.code) & (versions.c.revision == heads.c.revision))
    current_name = func.coalesce(versions.c.snapshot["name"].as_string(), sources.c.name)
    clauses = [sources.c.active.is_(True)]
    query = query.strip()
    if query:
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        # SKU is an explicitly approved static line. Query its current JSON text
        # in SQL so pagination never loads every standard's snapshot into memory.
        current_lines = func.coalesce(cast(versions.c.snapshot["lines"], Text), cast(sources.c.snapshot["lines"], Text))
        clauses.append(or_(current_name.ilike(pattern, escape="\\"), sources.c.code.ilike(pattern, escape="\\"),
                           current_lines.ilike(pattern, escape="\\")))
    statement = select(sources.c.code, current_name.label("name"),
        func.coalesce(heads.c.revision, 1).label("revision"),
        func.coalesce(versions.c.reviewer, sources.c.reviewer).label("reviewer"),
        func.coalesce(versions.c.created_at, sources.c.created_at).label("created_at"),
        sources.c.inspection_id).select_from(joined).where(*clauses).order_by(sources.c.created_at.desc(), sources.c.code)
    with engine.connect() as conn:
        total = conn.execute(select(func.count()).select_from(joined).where(*clauses)).scalar_one()
        rows = conn.execute(statement.offset((page-1)*limit).limit(limit)).mappings().all()
    return {"items": [dict(row, source_kind="manual") for row in rows], "total": total,
            "has_more": page*limit < total, "page": page}


def _pending_today_bounds(now=None):
    taiwan=timezone(timedelta(hours=8))
    current=(now or datetime.now(timezone.utc)).astimezone(taiwan)
    start=datetime.combine(current.date(),datetime.min.time(),tzinfo=taiwan)
    return start.astimezone(timezone.utc).isoformat(),(start+timedelta(days=1)).astimezone(timezone.utc).isoformat()


def _pending_name(stored, lines):
    if isinstance(stored,str) and stored.strip():
        return stored.strip()[:200]
    from validation import ALIASES
    try:
        candidate=extract_fields(lines or []).get("product",{})
        ids=set(candidate.get("line_ids",[])); value=candidate.get("value","")
        headed=any(line.get("id") in ids and re.match(r"^\s*"+ALIASES["product"],line.get("text","")) for line in lines or [])
        numeric=re.fullmatch(r"(?:民國)?[()（）\d\s:：./\-年月日時时分]+",value)
        return value[:200] if headed and not candidate.get("ambiguous") and not numeric else ""
    except (KeyError,TypeError,ValueError,IndexError,AttributeError):
        return ""


def _pending_query(period="today", state="active"):
    import history_cleanup
    import pending_drafts
    import reference_photos
    if period not in {"today","all"}:
        abort(400,description="請選擇今日或全部待建立紀錄。")
    if state not in {"active","removed"}:
        abort(400,description="請選擇待建立或已移除草稿。")
    inspection=db.inspections
    ranked=select(inspection.c.id,func.row_number().over(partition_by=inspection.c.image_id,
        order_by=(inspection.c.created_at.desc(),inspection.c.id.desc())).label("position"))
    ranked=ranked.where(history_cleanup.active_filter()).subquery("latest_active_image")
    manual_origin=inspection.alias("manual_origin")
    manual_exists=select(db.manual_sources.c.code).join(manual_origin,
        db.manual_sources.c.inspection_id==manual_origin.c.id).where(
        manual_origin.c.image_id==inspection.c.image_id).correlate(inspection).exists()
    attached=select(reference_photos.photos.c.id).where(
        reference_photos.photos.c.image_id==inspection.c.image_id).correlate(inspection).exists()
    # An older successful match of this image must not reappear as a new
    # standard merely because a later raw recheck omitted its source selection.
    handled=inspection.alias("handled_image")
    known_source=select(handled.c.id).where(handled.c.image_id==inspection.c.image_id,
        history_cleanup.active_filter(handled),or_(func.trim(func.coalesce(handled.c.template_id,""))!="",
            func.trim(func.coalesce(handled.c.template_snapshot["source"]["code"].as_string(),""))!=""))
    decisions=pending_drafts.current_states()
    clauses=[ranked.c.position==1]
    if state=="active":
        clauses.extend((~manual_exists,~attached,~known_source.correlate(inspection).exists(),
            func.coalesce(decisions.c.removed,False).is_(False)))
    else:
        clauses.append(decisions.c.removed.is_(True))
    if period=="today":
        start,end=_pending_today_bounds()
        timestamp=decisions.c.created_at if state=="removed" else inspection.c.created_at
        clauses.extend((timestamp>=start,timestamp<end))
    joined=inspection.join(ranked,ranked.c.id==inspection.c.id).outerjoin(decisions,decisions.c.image_id==inspection.c.image_id)
    latest_patches=select(db.corrections.c.patches).where(db.corrections.c.inspection_id==inspection.c.id).order_by(
        db.corrections.c.revision.desc()).limit(1).correlate(inspection).scalar_subquery()
    query=select(inspection.c.id,inspection.c.image_id,inspection.c.created_at,
        inspection.c.result["fields"]["product"]["value"].as_string().label("product"),
        inspection.c.ocr["lines"].label("ocr_lines"),
        inspection.c.ocr["image_status"].as_string().label("image_status"),
        inspection.c.ocr["recognition_engine"].as_string().label("recognition_engine"),
        inspection.c.ocr["label_scope"].label("observed_scope"),
        inspection.c.result["label_scope"].label("evaluated_scope"),
        inspection.c.result["source_match"]["status"].as_string().label("source_status"),
        func.coalesce(decisions.c.revision,0).label("pending_revision"),
        func.coalesce(decisions.c.removed,False).label("pending_removed"),
        decisions.c.created_at.label("pending_updated_at"), decisions.c.note.label("pending_note"),
        latest_patches.label("patches")).select_from(joined).where(*clauses)
    return query


def _pending_ocr(row):
    return {"lines":row["ocr_lines"],"image_status":row["image_status"],
            "recognition_engine":row["recognition_engine"],"label_scope":row["observed_scope"]}


def _pending_result(row):
    return {"label_scope":row["evaluated_scope"],"source_match":{"status":row["source_status"]}}


def pending_listing(engine, period="today", page=1, limit=24, state="active"):
    """A read-only queue of existing inspections, not unapproved database standards."""
    from standard_reference import _integer
    page=_integer(page,"頁碼",1,1_000_000)
    limit=_integer(limit,"每頁筆數",1,24)
    query=_pending_query(period,state)
    inspection=db.inspections
    items,total=[],0
    start=(page-1)*limit
    with engine.connect() as conn:
        # One shared Python rule avoids SQLite/PostgreSQL JSON-rule drift. The
        # SQL filters run first; a server cursor retains at most 50 candidate
        # summaries and the requested page, never the entire OCR history.
        order_time=query.selected_columns.pending_updated_at if state=="removed" else inspection.c.created_at
        result=conn.execute(query.order_by(order_time.desc(),inspection.c.id.desc())
            .execution_options(stream_results=True,yield_per=50))
        try:
            for batch in result.mappings().partitions(50):
                for row in batch:
                    quality=draft_eligibility(_pending_ocr(row),row["patches"],_pending_result(row))
                    if state=="active" and not quality["eligible"]:
                        continue
                    if start<=total<start+limit:
                        items.append({"inspection_id":row["id"],"image_id":row["image_id"],"created_at":row["created_at"],
                            "name":_pending_name(row["product"],row["ocr_lines"]),
                            "thumbnail":f"/media/{quote(str(row['image_id']),safe='')}/thumb.jpg",
                            **{key:row[key] for key in ("pending_revision","pending_removed","pending_updated_at","pending_note")}})
                    total+=1
        finally:
            result.close()
    return {"items":items,
        "page":page,"total":total,"has_more":page*limit<total,"range":period,"state":state}


def fields_from_lines(lines, name):
    """Text-only references have no invented geometry or neighbouring columns."""
    candidates = {key: set() for key in TEXT_FIELDS}
    for line in lines:
        value = line["text"]
        key = _kind(value)
        if key not in candidates:
            continue
        heading = HEADINGS.get(key)
        content = re.sub(r"^\s*" + heading + r"\s*[：:]?\s*", "", value, count=1) if heading else value
        if content.strip():
            candidates[key].add(content.strip())
    fields = {key: next(iter(values)) if len(values) == 1 else "" for key, values in candidates.items()}
    fields["product"] = name
    return fields


def validate_date_rules(source,include_external=False):
    """Reject contradictory explicitly supplied rules, without inventing missing ones."""
    manual=source.get("source_kind")=="manual"
    if not manual and not include_external:
        return
    # Restore/reset also pass here: a historical fixed batch date must not
    # bypass today's creation/edit validation just because it was saved before.
    if manual:
        for row in source.get("lines", []):
            fixed_line_text(row["text"])
    def offset(setting):
        raw=setting.get("shift_days")
        if raw is None:
            shift=0
        elif isinstance(raw,bool) or not isinstance(raw,(int,str)) or not re.fullmatch(r"[+-]?\d+",str(raw).strip()):
            abort(400,description="來源的日期位移格式不正確，請先確認原日期規則。")
        else:
            shift=int(raw)
        code=str(setting.get("format") or "A")[:1]
        if code not in "ABCDEFGHIJKL":
            abort(400,description="來源的日期格式不支援，請先確認原日期規則。")
        return shift+(int(source.get("keep_days") or 0) if not manual and code in "BDFHJL" else 0)
    offsets = {_kind(setting.get("content", "")): offset(setting)
               for setting in source.get("date_settings", []) if _kind(setting.get("content", "")) in DATE_LABELS}
    for first, second, message in (
        ("manufacture", "expiry", "有效日位移不可早於製造日位移，請確認日期規則。"),
        ("manufacture", "arrival", "到店日位移不可早於製造日位移，請確認日期規則。"),
        ("arrival", "expiry", "到店日位移不可晚於有效日位移，請確認日期規則。"),
    ):
        if first in offsets and second in offsets and offsets[second] < offsets[first]:
            abort(400, description=message)
    if manual and source.get("keep_days") is not None and all(key in offsets for key in ("manufacture", "expiry")):
        if offsets["expiry"] - offsets["manufacture"] != source["keep_days"]:
            abort(400, description="製造日與有效日位移的間隔不等於保存天數，請修正後再預覽。")


def _context(engine, inspection):
    with engine.connect() as conn:
        prior = conn.execute(select(db.manual_sources.c.code).where(
            db.manual_sources.c.inspection_id == inspection["id"])).first()
    existing = prior.code if prior else ""
    source = (inspection.get("template_snapshot") or {}).get("source")
    has_source = bool(inspection.get("template_id") or (source and source.get("code")))
    if has_source:
        return False, existing, "這筆檢查已有比對來源，請使用「修正比對標準」建立新版。"
    if existing:
        return False, existing, "這張照片已建立人工文字標準，請選用既有標準重新核對。"
    quality=draft_eligibility(inspection.get("ocr"),result=inspection.get("result"))
    if quality["reason_code"]=="multiple_labels":
        return False, existing, quality["reason"]
    return True, "", "辨識文字只是草稿，請逐字修正後核准；日期請另填相對基準日規則。"


def _near_date_fragments(lines, excluded):
    """Do not freeze the final day of an observed split '到店日 11/ 19'."""
    def bounds(line):
        box=line.get("box") or []
        return (min(p[0] for p in box),min(p[1] for p in box),max(p[0] for p in box),max(p[1] for p in box)) if len(box)==4 else None
    excluded=set(excluded)
    for _ in range(3):
        added=set()
        for line in lines:
            first=bounds(line)
            if line.get("id") not in excluded or first is None or not re.search(r"\d\s*[./\-年月:：]\s*$",line.get("text","")):
                continue
            x,y,r,b=first; height=max(b-y,1)
            for following in lines:
                second=bounds(following)
                if following.get("id") in excluded or second is None or not re.fullmatch(r"\s*\d{1,2}\s*[./年月日]?\s*",following.get("text","")):
                    continue
                nx,ny,nr,nb=second
                if (0<=nx-r<=height*1.5 and min(b,nb)-max(y,ny)>=min(height,nb-ny)*.6
                        and not any(other.get("id") not in (line.get("id"),following.get("id"))
                            and (middle:=bounds(other)) is not None and middle[0]>=r and middle[2]<=nx
                            and min(b,middle[3])>max(y,middle[1]) for other in lines)):
                    added.add(following["id"])
        if not added-excluded:
            break
        excluded.update(added)
    return excluded


def payload(engine, inspection):
    from label_source import _identifiers, _SKU_LABEL
    import corrections
    can_create, existing, notice = _context(engine, inspection)
    original_lines = deepcopy(inspection.get("ocr", {}).get("lines", []))
    lines = deepcopy(original_lines)
    with engine.connect() as conn:
        correction = corrections.latest(conn, inspection["id"])
    quality = draft_eligibility(inspection.get("ocr"), (correction or {}).get("patches"), inspection.get("result"))
    patches = {patch["line_id"]: patch for patch in (correction or {}).get("patches", [])}
    excluded_unconfirmed, applied = [], []
    for line in lines:
        patch = patches.get(line.get("id"))
        if not patch:
            continue
        if patch["kind"] in {"confirmed_text", "ocr_misread"}:
            # A confirmed reading is draft input, never an approved standard or
            # a replacement of the original OCR stored with the inspection.
            line.update(text=patch["text"], human_verified=True, human_uncertain=False)
            applied.append(line["id"])
        else:
            line["human_uncertain"] = True
            excluded_unconfirmed.append({"id": line["id"], "text": patch["text"], "kind": patch["kind"],
                "reason": "此行已確認標籤印錯，不能直接作為正確標準。" if patch["kind"] == "label_misprint"
                          else "此行已標記看不清楚，請確認正確文字後另外填入。"})
    excluded_ids = {line["id"] for line in excluded_unconfirmed}
    from observed_text import is_unreadable_placeholder_only
    for line in lines:
        if line.get("id") not in excluded_ids and is_unreadable_placeholder_only(line):
            excluded_unconfirmed.append({"id":line["id"],"text":line["text"],"kind":"unreadable_placeholder",
                "reason":"此段只有無法讀取的佔位符，沒有可帶入的文字；請查看原照片確認。"})
            excluded_ids.add(line["id"])
    try:
        fields = extract_fields(lines)
    except (KeyError, ValueError, TypeError):
        fields = {}
    dynamic = {identifier for key in DATE_LABELS for identifier in fields.get(key, {}).get("line_ids", [])}
    draft_lines, excluded = [], []
    from werkzeug.exceptions import HTTPException
    for line in lines:
        if line.get("id") in excluded_ids:
            continue
        value = str(line.get("text", "")).strip()
        if not value:
            continue
        try:
            _fixed_manual_text(value)
            safe = line.get("id") not in dynamic and _kind(value) not in DATE_LABELS
        except HTTPException:
            safe = False
        (draft_lines if safe else excluded).append({"id": line.get("id"), "text": value})
    date_ids=_near_date_fragments(lines,{row["id"] for row in excluded})
    for row in draft_lines:
        if row["id"] in date_ids:
            excluded.append(row)
    draft_lines=[row for row in draft_lines if row["id"] not in date_ids]
    # A cloud OCR box can contain both a variable date and fixed storage or
    # product text. Only observed character spans identify what to omit. Keep
    # the other printed text in the editable draft instead of dropping the
    # entire box, and never fill it from the currently selected standard.
    from label_geometry import without_date_evidence
    for line in lines:
        if line.get("id") not in date_ids or line.get("id") in excluded_ids:
            continue
        remaining=without_date_evidence(line,fields).strip()
        if not remaining or remaining==str(line.get("text","" )).strip():
            continue
        try:
            _fixed_manual_text(remaining)
            if _kind(remaining) not in DATE_LABELS:
                draft_lines.append({"id":line.get("id"),"text":remaining})
        except HTTPException:
            pass  # Unknown date fragments remain excluded for human review.
    from text_rows import group_observed_rows
    safe_text = {row["id"]:row["text"] for row in draft_lines}
    draft_lines = group_observed_rows([dict(line,text=safe_text[line["id"]])
        for line in lines if line.get("id") in safe_text])
    skus = {value for line in lines if line.get("id") not in excluded_ids
            for value in _identifiers(line.get("text", ""), _SKU_LABEL, normalize=lambda v:v)}
    product = fields.get("product", {})
    suggested_name = "" if excluded_ids.intersection(product.get("line_ids", [])) else product.get("value", "")
    equivalents = []
    if suggested_name and draft_lines and not excluded_unconfirmed:
        try:
            proposed, digest = definition({"name": suggested_name,
                "sku": next(iter(skus)) if len(skus) == 1 else "",
                "lines": [{"text": row["text"]} for row in draft_lines]})
            equivalents = equivalent_references(engine, proposed, digest)
        except HTTPException:
            pass  # Incomplete OCR remains an editable draft, never approval.
    return {"can_create": can_create, "existing_code": existing, "notice": notice,
            "manual_standard_eligibility": quality,
            "suggested_name": suggested_name,
            "suggested_sku": next(iter(skus)) if len(skus) == 1 else "",
            "ocr_lines": original_lines, "draft_lines": draft_lines, "excluded_date_lines": excluded,
            "manual_revision": correction["revision"] if correction else 0,
            "draft_basis": "manual_correction" if applied else "original_ocr",
            "excluded_unconfirmed_lines": excluded_unconfirmed,
            "equivalent_references": equivalents,
            "suggested_source": equivalents[0] if len(equivalents) == 1 else None,
            "warning": (f"草稿已套用第 {correction['revision']} 版中確認的辨識訂正，仍未核准為標準；請逐字確認後再儲存。" if applied
                        else "這是辨識原文，尚未核准；請逐字修正後，確認要作為之後同款標籤的比對標準。")}


def definition(body):
    from standard_reference import _text, _integer, _fixed_text
    from label_source import _fixed_barcodes, _identifiers, _SKU_LABEL, with_printed_upca
    if not isinstance(body, dict):
        abort(400, description="請填寫人工標準內容。")
    name = _fixed_text(_text(body.get("name"), "品名", 200))
    sku = body.get("sku", "")
    if not isinstance(sku, str) or len(sku) > 100:
        abort(400, description="貨號最多 100 字。")
    sku = unicodedata.normalize("NFKC", sku.strip())
    if sku and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/\-]*", sku):
        abort(400, description="貨號請填完整英數字，可包含 . _ / -，不要填標題或日期。")
    supplied = body.get("lines")
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= 150:
        abort(400, description="請逐字確認 1 至 150 段標準文字。")
    texts = []
    for item in supplied:
        if not isinstance(item, dict) or set(item) != {"text"}:
            abort(400, description="每段標準文字只能提供 text。")
        text = fixed_line_text(item["text"])
        if _kind(text) == "product" and normalize_text(text) != normalize_text(name):
            abort(400, description="品名與標準文字中的品名不同，請逐字修正後再預覽。")
        # Repeated values are separate evidence (e.g. two nutrition columns).
        # Deduplicating them would silently delete a printed value.
        texts.append(text)
    if not any(normalize_text(text) == normalize_text(name) for text in texts):
        texts.insert(0, "品名：" + name)
    listed_skus = {value for text in texts for value in _identifiers(text, _SKU_LABEL, normalize=lambda v:v)}
    if sku and listed_skus and listed_skus != {sku}:
        abort(400, description="貨號與標準文字中的貨號不同，請確認。")
    if sku and not listed_skus:
        texts.insert(1, "貨號：" + sku)
    keep_days = body.get("keep_days")
    if keep_days is not None:
        keep_days = _integer(keep_days, "保存天數", 0, 3650)
    settings, kinds = [], set()
    supplied_dates = body.get("date_settings", [])
    if not isinstance(supplied_dates, list) or len(supplied_dates) > 3:
        abort(400, description="日期規則最多包含製造日、有效日與到店日。")
    for item in supplied_dates:
        if (not isinstance(item, dict) or set(item) != {"kind", "shift_days"}
                or not isinstance(item.get("kind"), str) or item["kind"] not in DATE_LABELS or item["kind"] in kinds):
            abort(400, description="每種日期只能設定一次，並填寫相對本批基準日的位移天數。")
        kinds.add(item["kind"])
        settings.append({"content": DATE_LABELS[item["kind"]], "format": "A",
                         "shift_days": _integer(item["shift_days"], "日期位移", -3650, 3650)})
    lines = [{"id": index, "text": fixed_line_text(value), "score": 1., "box": []} for index, value in enumerate(texts)]
    fields = fields_from_lines(lines, name)
    source = {"name": name, "source_kind": "manual", "comparison_scope": "manual_text",
              "fields": fields, "lines": lines, "rules": {"dates": bool(kinds & {"manufacture", "expiry"}), "arrival": "arrival" in kinds},
              "keep_days": keep_days, "keep_days_source": "manual_confirmation", "date_settings": settings,
              "barcode_config": {}, "barcode_values": sorted({value for text in texts for value in _fixed_barcodes(text)}),
              "known_fields": [key for key, value in fields.items() if value], "limitations": LIMITATIONS,
              "notice": "人工確認的獨立文字標準；只核對已列入的內容，不代表具有完整印標版面。"}
    source=with_printed_upca(source)
    validate_date_rules(source)
    digest = hashlib.sha256(json.dumps(source, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    source.update(revision=digest)
    return source, digest


def equivalent_references(engine, proposed, digest):
    """Exact current definitions only; similar photos/names are not evidence."""
    import standard_reference as standards
    from reference_photos import source_info
    from werkzeug.exceptions import HTTPException
    sources, heads, versions = db.manual_sources, standards.heads, standards.versions
    joined = sources.outerjoin(heads, heads.c.code == sources.c.code).outerjoin(versions,
        (versions.c.code == heads.c.code) & (versions.c.revision == heads.c.revision))
    current_name = func.coalesce(versions.c.snapshot["name"].as_string(), sources.c.name)
    with engine.connect() as conn:
        candidates = conn.execute(select(sources.c.snapshot,
            versions.c.revision.label("standard_revision"), versions.c.source_revision.label("approved_source_revision"),
            versions.c.operation, versions.c.snapshot.label("approved_snapshot"), versions.c.reviewer, versions.c.created_at)
            .select_from(joined).where(sources.c.active.is_(True),
            current_name == proposed["name"]).order_by(sources.c.code).limit(81)).mappings().all()
    # Keep bounded previews. Never suggest an arbitrary subset as a unique match.
    if len(candidates) > 80:
        return []
    result = []
    for candidate in candidates:
        version = {"revision": candidate["standard_revision"], "source_revision": candidate["approved_source_revision"],
            "operation": candidate["operation"], "snapshot": candidate["approved_snapshot"],
            "reviewer": candidate["reviewer"], "created_at": candidate["created_at"]} if candidate["standard_revision"] is not None else {}
        effective = standards.apply_current(engine, candidate["snapshot"], version)
        if effective.get("standard_reference", {}).get("state") == "stale":
            continue
        try:
            _, current_digest = definition({"name": effective["name"],
                "lines": [{"text": row["text"]} for row in effective.get("lines", [])],
                "keep_days": effective.get("keep_days"),
                "date_settings": [{"kind": _kind(row["content"]), "shift_days": row["shift_days"]}
                                  for row in effective.get("date_settings", [])]})
        except (HTTPException, KeyError, TypeError):
            continue
        if current_digest == digest:
            result.append(dict(source_info(effective), match_basis="exact_definition"))
    return result


def preview(engine, inspection, body):
    allowed = DEFINITION_KEYS
    if not isinstance(body, dict) or set(body) - allowed:
        abort(400, description="預覽只接受品名、貨號、標準文字、保存天數及日期規則。")
    can_create, _, notice = _context(engine, inspection)
    if not can_create:
        abort(409, description=notice)
    source, digest = definition(body)
    equivalents = equivalent_references(engine, source, digest)
    return {"source": source, "preview_hash": digest, "equivalent_references": equivalents,
            "suggested_source": equivalents[0] if len(equivalents) == 1 else None,
            "nutrition_checks": [],
            "warnings": LIMITATIONS + ["日期位移直接相對本批基準日；不會自動加上保存天數。"]}


def save(engine, inspection, body):
    import standard_reference as standards
    if not isinstance(body, dict) or set(body) - (DEFINITION_KEYS | {"preview_hash", "reviewer", "note", "confirmed"}):
        abort(400, description="人工標準內容格式不正確。")
    if body.get("confirmed") is not True:
        abort(400, description="請確認已逐字核對，並將套用到之後同款標籤。")
    can_create, _, notice = _context(engine, inspection)
    if not can_create:
        abort(409, description=notice)
    reviewer = standards._text(body.get("reviewer"), "確認人員", 100)
    note = standards._text(body.get("note"), "確認原因", 2000)
    source, digest = definition(body)
    if body.get("preview_hash") != digest:
        abort(409, description="內容尚未預覽或已變更，請重新預覽並確認後儲存。")
    code, created = PREFIX + db.uid(), db.now()
    source.update(code=code, provenance={"inspection_id": inspection["id"], "reviewer": reviewer, "created_at": created})
    try:
        with engine.begin() as conn:
            standards._lock_active_inspection(conn, inspection["id"])
            conn.execute(insert(db.manual_sources).values(code=code, name=source["name"], inspection_id=inspection["id"],
                reference_hash=digest, snapshot=source, active=True, reviewer=reviewer, note=note, created_at=created))
            conn.execute(insert(standards.heads).values(code=code, revision=1))
            conn.execute(insert(standards.versions).values(id=db.uid(), code=code, revision=1,
                source_revision=digest, operation="create", snapshot=source, changes={},
                inspection_id=inspection["id"], reviewer=reviewer, note=note, created_at=created))
    except IntegrityError:
        abort(409, description="這張照片或相同標準內容已建立，請搜尋並選用既有標準，不會重複新增。")
    return {"code": code, "name": source["name"], "source_kind": "manual", "comparison_scope": "manual_text",
            "source": source, "revision": 1}


def register_routes(app, engine):
    from standard_reference import _inspection
    @app.get("/api/manual-standards")
    def list_manual_references():
        try:
            page, limit = int(request.args.get("page", 1)), int(request.args.get("limit", 24))
        except ValueError:
            abort(400, description="頁碼與每頁筆數須為整數。")
        return jsonify(listing(engine, request.args.get("q", ""), page, limit))

    @app.get("/api/manual-standards/pending")
    def list_pending_manual_references():
        try:
            page,limit=int(request.args.get("page",1)),int(request.args.get("limit",24))
        except ValueError:
            abort(400,description="頁碼與每頁筆數須為整數。")
        return jsonify(pending_listing(engine,request.args.get("range","today"),page,limit,request.args.get("state","active")))

    @app.get("/api/inspections/<identifier>/manual-standard")
    def get_manual_reference(identifier):
        return jsonify(payload(engine, _inspection(engine, identifier)))

    @app.post("/api/inspections/<identifier>/manual-standard/preview")
    def preview_manual_reference(identifier):
        return jsonify(preview(engine, _inspection(engine, identifier), request.get_json(silent=True)))

    @app.post("/api/inspections/<identifier>/manual-standard")
    def create_manual_reference(identifier):
        return jsonify(save(engine, _inspection(engine, identifier), request.get_json(silent=True))), 201
