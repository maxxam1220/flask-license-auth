"""Direct, versioned standard-library management, independent of inspections."""
from copy import deepcopy
import hashlib
import json
import re
import secrets
import unicodedata

from flask import abort, jsonify, request, session
from sqlalchemy import (Table, Column, String, Integer, Boolean, Text, JSON, UniqueConstraint,
                        select, insert, update, func, literal, union_all, and_, or_, cast)
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.exceptions import HTTPException

import database as db
import standard_reference as standards
from validation import TEXT_FIELDS, parse_date


categories=Table("labelcheck_standard_categories",db.metadata,
    Column("id",String(32),primary_key=True),Column("name",String(60),nullable=False),
    Column("name_key",String(240),unique=True),Column("revision",Integer,nullable=False),
    Column("removed",Boolean,nullable=False),Column("updated_at",String(40),nullable=False))
items=Table("labelcheck_standard_library_items",db.metadata,
    Column("kind",String(12),primary_key=True),Column("key",String(80),primary_key=True),
    Column("revision",Integer,nullable=False),Column("category_id",String(32),index=True),
    Column("removed",Boolean,nullable=False),Column("updated_at",String(40),nullable=False))
audit=Table("labelcheck_standard_library_audit",db.metadata,
    Column("id",String(32),primary_key=True),Column("kind",String(12),nullable=False),
    Column("key",String(80),nullable=False,index=True),Column("operation",String(20),nullable=False),
    Column("actor",String(100),nullable=False),Column("note",Text,nullable=False),
    Column("details",JSON,nullable=False),Column("created_at",String(40),nullable=False))


def _conflict():
    abort(409,description="標準、分類或版本已變更，請重新載入後再操作。")


def _key(kind,key):
    if kind not in {"manual","photo"} or not isinstance(key,str) or not key or len(key)>80 or any(ord(c)<32 for c in key):
        abort(400,description="標準識別格式不正確。")
    if kind=="manual" and not key.startswith("manual:"):
        abort(400,description="請選擇人工文字標準代碼。")
    return kind,key


def _state(conn,kind,key,lock=False):
    query=select(items).where(items.c.kind==kind,items.c.key==key)
    row=conn.execute(query.with_for_update() if lock else query).mappings().first()
    return dict(row) if row else {"kind":kind,"key":key,"revision":0,"category_id":None,"removed":False,"updated_at":None}


def _photo_family(conn,family_id,lock=False):
    if lock:
        # The first version is an immutable lock anchor even when superseded.
        anchor=conn.execute(select(db.templates.c.id).where(db.templates.c.family_id==family_id)
            .order_by(db.templates.c.version,db.templates.c.id).limit(1).with_for_update()).first()
        if not anchor:
            return None
    row=conn.execute(select(db.templates).where(db.templates.c.family_id==family_id)
        .order_by(db.templates.c.version.desc(),db.templates.c.id).limit(1)).mappings().first()
    return dict(row) if row else None


def ensure_selectable(conn, *, code=None, template_id=None, allow_superseded=False, family_id=None):
    """Lock through a scan's commit; deleted standards cannot revive via snapshots.

    Manual: source row -> standard head (writers) -> library item.
    Photo: oldest family template row -> library item. Legacy orphan snapshots
    remain readable only with allow_superseded=True; library removal never
    deletes template rows, so a managed removed family always remains findable.
    """
    if code and str(code).startswith("manual:"):
        row=conn.execute(select(db.manual_sources).where(db.manual_sources.c.code==str(code)).with_for_update()).mappings().first()
        if not row or not row["active"] or _state(conn,"manual",str(code))["removed"]:
            abort(409,description="這份文字標準已移除，請先還原或重新選擇標準。")
        return dict(row)
    if template_id:
        row=conn.execute(select(db.templates).where(db.templates.c.id==template_id)).mappings().first()
        if row:
            family_id=row["family_id"]
        elif not allow_superseded:
            abort(404,description="找不到這份照片標準。")
        if not family_id:
            return None
        current=_photo_family(conn,family_id,lock=True)
        if _state(conn,"photo",family_id)["removed"] or (current is not None and not current["active"]):
            abort(409,description="這份照片標準已移除，請先還原或重新選擇標準。")
        if row and not allow_superseded and current and current["id"]!=template_id:
            abort(409,description="照片標準已有新版，請重新選擇。")
        return current
    return None


def _load(conn,kind,key,lock=False):
    _key(kind,key)
    if kind=="manual":
        query=select(db.manual_sources).where(db.manual_sources.c.code==key)
        row=conn.execute(query.with_for_update() if lock else query).mappings().first()
        if not row:
            abort(404,description="找不到這份文字標準。")
        head_query=select(standards.heads.c.revision).where(standards.heads.c.code==key)
        revision=conn.execute(head_query.with_for_update() if lock else head_query).scalar_one_or_none() or 0
        prior=conn.execute(select(standards.versions).where(standards.versions.c.code==key,
            standards.versions.c.revision==revision)).mappings().first() if revision else None
        base=deepcopy(row["snapshot"])
        effective=standards.apply_current(None,base,dict(prior) if prior else {})
        return {"master":dict(row),"base":base,"source":effective,"base_revision":revision,
                "source_revision":str(base["revision"]),"state":_state(conn,kind,key,lock)}
    row=_photo_family(conn,key,lock)
    if not row:
        abort(404,description="找不到這份照片標準。")
    return {"master":row,"template":deepcopy(row),"base_revision":row["version"],
            "source_revision":row["id"],"state":_state(conn,kind,key,lock)}


def _removed(context):
    return bool(context["state"]["removed"] or not context["master"]["active"])


def _expect(context,body,content=True):
    if standards._integer(body.get("item_revision"),"標準庫版本",0,2**31-2)!=context["state"]["revision"]:
        _conflict()
    if content and (standards._integer(body.get("base_revision"),"標準版本",0,2**31-2)!=context["base_revision"]
            or body.get("source_revision")!=context["source_revision"]):
        _conflict()


def _write_state(conn,state,**changes):
    values={"category_id":state["category_id"],"removed":state["removed"],"updated_at":db.now(),
            "revision":state["revision"]+1,**changes}
    if state["revision"]:
        result=conn.execute(update(items).where(items.c.kind==state["kind"],items.c.key==state["key"],
            items.c.revision==state["revision"]).values(**values))
        if result.rowcount!=1:
            _conflict()
    else:
        conn.execute(insert(items).values(kind=state["kind"],key=state["key"],**values))
    return values["revision"]


def _audit(conn,kind,key,operation,actor,note,details):
    conn.execute(insert(audit).values(id=db.uid(),kind=kind,key=key,operation=operation,actor=str(actor)[:100],
        note=note,details=details,created_at=db.now()))


def _safe_image(image_payload,identifier):
    if not identifier:
        return None
    try:
        return image_payload(identifier)
    except HTTPException as error:
        if error.code==404:
            return None
        raise


def detail(engine,kind,key,image_payload,summary=False):
    import reference_photos
    with engine.connect() as conn:
        context=_load(conn,kind,key);state=context["state"]
        category=conn.execute(select(categories.c.name).where(categories.c.id==state["category_id"],
            categories.c.removed.is_(False))).scalar_one_or_none() if state["category_id"] else None
        if kind=="manual":
            source=context["source"]
            origin=conn.execute(select(db.inspections.c.image_id).where(db.inspections.c.id==context["master"]["inspection_id"])).scalar_one_or_none()
            attached=conn.execute(select(reference_photos.photos.c.image_id).where(reference_photos.photos.c.source_code==key)
                .order_by(reference_photos.photos.c.created_at.desc()).limit(1 if summary else 50)).scalars().all()
            selected=source.get("reference_image_id")
            image_ids=list(dict.fromkeys([*([selected] if selected else []),*([origin] if origin else []),*attached]))
            photo_ids=union_all(select(db.inspections.c.image_id).where(db.inspections.c.id==context["master"]["inspection_id"]),
                select(reference_photos.photos.c.image_id).where(reference_photos.photos.c.source_code==key)).subquery()
            photo_count=conn.scalar(select(func.count(func.distinct(photo_ids.c.image_id))).where(photo_ids.c.image_id!=""))
            history=conn.execute(select(standards.versions.c.revision,standards.versions.c.operation,standards.versions.c.reviewer,
                standards.versions.c.note,standards.versions.c.created_at).where(standards.versions.c.code==key)
                .order_by(standards.versions.c.revision.desc()).limit(1 if summary else 30)).mappings().all()
            fields=source.get("fields") or {}; name=source["name"]
            display_spec=fields.get("spec","") or next((match[1].strip() for row in source.get("lines",[])
                if (match:=re.match(r"^\s*(?:淨重|净重|重量)\s*[:：]?\s*(.+)$",row["text"]))),"")
            barcode=", ".join(str(value) for value in source.get("barcode_values",[]))
            sku=next((re.sub(r"^(?:貨號|品號|商品編號)\s*[:：]?\s*","",row["text"]) for row in source.get("lines",[])
                      if re.match(r"^(?:貨號|品號|商品編號)",row["text"])),"")
        else:
            template=context["template"];fields=template.get("fields") or {};name=template["name"];barcode=sku=""
            display_spec=fields.get("spec","")
            versions=conn.execute(select(db.templates).where(db.templates.c.family_id==key)
                .order_by(db.templates.c.version.desc()).limit(1 if summary else 50)).mappings().all()
            image_ids=list(dict.fromkeys(row["image_id"] for row in versions if row["image_id"]))
            photo_count=conn.scalar(select(func.count(func.distinct(db.templates.c.image_id))).where(
                db.templates.c.family_id==key,db.templates.c.image_id!=""))
            history=[{"revision":row["version"],"operation":"photo_version","reviewer":row["approved_by"],
                      "note":"照片標準版本","created_at":row["created_at"]} for row in versions[:30]]
    photos=[image for identifier in image_ids[:1] if (image:=_safe_image(image_payload,identifier)) is not None] if summary else [
        image for identifier in image_ids if (image:=_safe_image(image_payload,identifier)) is not None]
    result={"kind":kind,"key":key,"name":name,"item_revision":state["revision"],"base_revision":context["base_revision"],
        "source_revision":context["source_revision"],"removed":_removed(context),"editable":not _removed(context),
        "category_id":state["category_id"] if category else None,"category_name":category or "未分類",
        "image":photos[0] if photos else None,"current_image":photos[0] if photos else None,"photos":photos,"photo_count":photo_count,
        "updated_at":state["updated_at"] or (history[0]["created_at"] if history else context["master"]["created_at"]),
        "history":[dict(row) for row in history],"identity":{"spec":display_spec,"barcode":barcode,"sku":sku},
        "notice":"修改另存新版，只影響之後的比對；照片、舊版及既有檢查紀錄都會保留。"}
    result["source" if kind=="manual" else "template"]=context["source" if kind=="manual" else "template"]
    result["supports_line_replacement"]=kind=="manual"
    return result


def listing(engine,image_payload,*,kind="all",state="active",category_id="all",query="",page=1,limit=24):
    if kind not in {"all","manual","photo"} or state not in {"active","removed"}:
        abort(400,description="標準類型或狀態不正確。")
    if not isinstance(query,str) or len(query)>100 or not isinstance(category_id,str) or len(category_id)>32:
        abort(400,description="搜尋或分類格式不正確。")
    page=standards._integer(page,"頁碼",1,1_000_000);limit=standards._integer(limit,"每頁筆數",1,24)
    m,h,v=db.manual_sources,standards.heads,standards.versions
    joined=m.outerjoin(h,h.c.code==m.c.code).outerjoin(v,and_(v.c.code==h.c.code,v.c.revision==h.c.revision))
    manual=select(literal("manual").label("kind"),m.c.code.label("key"),func.coalesce(v.c.snapshot["name"].as_string(),m.c.name).label("name"),
        m.c.active.label("master_active"),func.coalesce(v.c.created_at,m.c.created_at).label("updated_at"),
        func.coalesce(cast(v.c.snapshot["lines"],Text),cast(m.c.snapshot["lines"],Text)).label("search_text")).select_from(joined)
    latest=select(db.templates.c.family_id,func.max(db.templates.c.version).label("version")).group_by(db.templates.c.family_id).subquery()
    photo=select(literal("photo").label("kind"),db.templates.c.family_id.label("key"),db.templates.c.name,
        db.templates.c.active.label("master_active"),db.templates.c.created_at.label("updated_at"),cast(db.templates.c.fields,Text).label("search_text"))
    photo=photo.join(latest,and_(db.templates.c.family_id==latest.c.family_id,db.templates.c.version==latest.c.version))
    all_rows=union_all(manual,photo).subquery("library_rows")
    relation=all_rows.outerjoin(items,and_(items.c.kind==all_rows.c.kind,items.c.key==all_rows.c.key))
    removed=func.coalesce(items.c.removed,False).is_(True)
    clauses=[removed] if state=="removed" else [~removed,all_rows.c.master_active.is_(True)]
    if kind!="all":clauses.append(all_rows.c.kind==kind)
    if category_id=="uncategorized":clauses.append(items.c.category_id.is_(None))
    elif category_id!="all":clauses.append(items.c.category_id==category_id)
    if query.strip():
        pattern="%"+query.strip().replace("\\","\\\\").replace("%","\\%").replace("_","\\_")+"%"
        search_terms=[all_rows.c.name.ilike(pattern,escape="\\"),all_rows.c.key.ilike(pattern,escape="\\"),all_rows.c.search_text.ilike(pattern,escape="\\")]
        # SQLAlchemy JSON serialization may preserve unicode escapes when cast
        # to SQL text. Search both encodings without changing stored content.
        encoded=json.dumps(query.strip(),ensure_ascii=True)[1:-1]
        if encoded!=query.strip():
            encoded_pattern="%"+encoded.replace("\\","\\\\").replace("%","\\%").replace("_","\\_")+"%"
            search_terms.append(all_rows.c.search_text.ilike(encoded_pattern,escape="\\"))
        short=re.fullmatch(r"([MP])-([0-9a-f]{4,32})",query.strip(),re.I)
        if short:
            source_kind="manual" if short[1].upper()=="M" else "photo"
            prefix=("manual:" if source_kind=="manual" else "")+short[2].lower()
            search_terms.append(and_(all_rows.c.kind==source_kind,all_rows.c.key.like(prefix+"%")))
        clauses.append(or_(*search_terms))
    with engine.connect() as conn:
        total=conn.scalar(select(func.count()).select_from(relation).where(*clauses))
        rows=conn.execute(select(all_rows.c.kind,all_rows.c.key).select_from(relation).where(*clauses)
            .order_by(func.coalesce(items.c.updated_at,all_rows.c.updated_at).desc(),all_rows.c.kind,all_rows.c.key)
            .offset((page-1)*limit).limit(limit)).mappings().all()
    summaries=[]
    for row in rows:
        entry=detail(engine,row["kind"],row["key"],image_payload,summary=True)
        summaries.append({key:value for key,value in entry.items() if key not in {"source","template","history","photos","notice"}})
    return {"items":summaries,"total":total,"page":page,"has_more":page*limit<total,"kind":kind,"state":state,"category_id":category_id}


def _photo_changes(current,changes):
    if not isinstance(changes,dict) or set(changes)-{"name","fields","rules","reference_dates"}:
        abort(400,description="照片標準只可修改名稱、欄位及日期設定。")
    result=deepcopy(current)
    if "name" in changes:result["name"]=standards._text(changes["name"],"標準名稱",200)
    if "fields" in changes:
        fields=changes["fields"]
        if not isinstance(fields,dict) or set(fields)-set(TEXT_FIELDS):abort(400,description="標準欄位格式不正確。")
        result["fields"].update(fields)
    for key in TEXT_FIELDS:
        value=result["fields"].get(key,"")
        if not isinstance(value,str) or len(value)>500 or "\x00" in value:abort(400,description="標準欄位最多 500 字。")
        if key in {"product","address","origin"} and not value.strip():abort(400,description="請完整確認品名、地址及產地。")
        result["fields"][key]=value.strip()
    if "rules" in changes:
        rules=changes["rules"]
        if not isinstance(rules,dict) or set(rules)-{"dates","arrival","keep_days"}:abort(400,description="日期規則格式不正確。")
        result["rules"].update(rules)
    rules=result["rules"]
    if type(rules.get("dates")) is not bool or type(rules.get("arrival",False)) is not bool:abort(400,description="請確認日期檢查設定。")
    keep=rules.get("keep_days")
    if keep is not None:standards._integer(keep,"保存天數",0,3650)
    if "reference_dates" in changes:
        dates=changes["reference_dates"]
        if not isinstance(dates,dict) or set(dates)-{"manufacture","expiry","arrival"}:abort(400,description="照片參考日期格式不正確。")
        result["reference_dates"].update(dates)
    for value in result["reference_dates"].values():
        if not isinstance(value,str) or len(value)>80 or "\x00" in value:abort(400,description="照片參考日期格式不正確。")
    try:
        if rules.get("dates") and not rules.get("source"):
            manufacture=parse_date(result["reference_dates"].get("manufacture",""));expiry=parse_date(result["reference_dates"].get("expiry",""))
            if expiry["date"]<manufacture["date"] or (keep is not None and (expiry["date"]-manufacture["date"]).days!=keep):raise ValueError()
            if expiry["date"]==manufacture["date"] and manufacture["hour"] is not None and expiry["hour"] is not None and (expiry["hour"],expiry["minute"])<(manufacture["hour"],manufacture["minute"]):raise ValueError()
        if rules.get("arrival") and not rules.get("source"):
            arrival=parse_date(result["reference_dates"].get("arrival",""))
            if rules.get("dates") and not manufacture["date"]<=arrival["date"]<=expiry["date"]:raise ValueError()
    except (ValueError,TypeError):abort(400,description="照片參考日期不合法、前後矛盾或不符合保存天數。")
    return result


def _changed(context,kind,changes):
    if kind=="photo":return _photo_changes(context["template"],changes)
    from manual_reference import validate_date_rules
    source=standards.changed_snapshot(context["base"],context["source"],changes)
    validate_date_rules(source)
    return source


def _digest(kind,key,body,changed):
    value={"kind":kind,"key":key,**{field:body[field] for field in ("item_revision","base_revision","source_revision","changes")},"snapshot":changed}
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()


def preview(engine,kind,key,body):
    if not isinstance(body,dict) or set(body)!={"item_revision","base_revision","source_revision","changes"}:
        abort(400,description="請提供目前標準版本與待預覽內容。")
    with engine.connect() as conn:
        context=_load(conn,kind,key);_expect(context,body)
        if _removed(context):abort(409,description="請先還原標準再編輯。")
        changed=_changed(context,kind,body["changes"])
    from nutrition_checks import checks_for
    return {"kind":kind,"key":key,"source" if kind=="manual" else "template":changed,
        "preview_hash":_digest(kind,key,body,changed),"nutrition_checks":checks_for({"lines":changed.get("lines",[]),"context":"standard_draft"}) if kind=="manual" else []}


def save(engine,kind,key,body,actor,image_payload):
    if not isinstance(body,dict) or set(body)!={"item_revision","base_revision","source_revision","changes","preview_hash","reviewer","note","confirmed"} or body.get("confirmed") is not True:
        abort(400,description="請預覽並明確確認標準內容。")
    reviewer=standards._text(body["reviewer"],"確認人員",100);note=standards._text(body["note"],"修改原因",2000)
    with engine.begin() as conn:
        context=_load(conn,kind,key,lock=True);_expect(context,body)
        if _removed(context):abort(409,description="標準已移除，請先還原再編輯。")
        changed=_changed(context,kind,body["changes"])
        if body.get("preview_hash")!=_digest(kind,key,body,changed):abort(409,description="內容尚未預覽或已修改，請重新預覽。")
        revision=context["base_revision"]+1
        if kind=="manual":
            conn.execute(insert(standards.versions).values(id=db.uid(),code=key,revision=revision,source_revision=context["source_revision"],
                operation="update",snapshot=changed,changes=body["changes"],inspection_id="",reviewer=reviewer,note=note,created_at=db.now()))
            if context["base_revision"]:
                result=conn.execute(update(standards.heads).where(standards.heads.c.code==key,standards.heads.c.revision==context["base_revision"]).values(revision=revision))
                if result.rowcount!=1:_conflict()
            else:conn.execute(insert(standards.heads).values(code=key,revision=revision))
        else:
            conn.execute(update(db.templates).where(db.templates.c.family_id==key,db.templates.c.active.is_(True)).values(active=False))
            changed.update(id=db.uid(),family_id=key,version=revision,active=True,approved_by=reviewer,created_at=db.now())
            conn.execute(insert(db.templates).values(**changed))
        new_item=_write_state(conn,context["state"])
        _audit(conn,kind,key,"save",actor,note,{"item_revision":new_item,"base_revision":revision,"reviewer":reviewer})
    return detail(engine,kind,key,image_payload)


def change_state(engine,kind,key,body,actor,image_payload):
    if not isinstance(body,dict) or set(body)-{"item_revision","base_revision","operation","note"} or body.get("operation") not in ("remove","restore"):
        abort(400,description="請選擇移除或還原標準。")
    note=body.get("note") or ("從標準庫移除。" if body["operation"]=="remove" else "還原標準庫項目。")
    note=standards._text(note,"操作原因",500)
    with engine.begin() as conn:
        context=_load(conn,kind,key,lock=True);_expect(context,body,content=False)
        if standards._integer(body.get("base_revision"),"標準版本",0,2**31-2)!=context["base_revision"]:_conflict()
        removed=body["operation"]=="remove"
        if removed==_removed(context):_conflict()
        if kind=="manual":conn.execute(update(db.manual_sources).where(db.manual_sources.c.code==key).values(active=not removed))
        else:
            conn.execute(update(db.templates).where(db.templates.c.family_id==key,db.templates.c.active.is_(True)).values(active=False))
            if not removed:conn.execute(update(db.templates).where(db.templates.c.id==context["master"]["id"]).values(active=True))
        revision=_write_state(conn,context["state"],removed=removed)
        _audit(conn,kind,key,body["operation"],actor,note,{"item_revision":revision,"base_revision":context["base_revision"]})
    return detail(engine,kind,key,image_payload)


def assign_category(engine,kind,key,body,actor,image_payload):
    if not isinstance(body,dict) or set(body)-{"item_revision","category_id","category_revision"} or "category_id" not in body:
        abort(400,description="請提供分類與標準庫版本。")
    category_id=body["category_id"]
    if category_id is not None and (not isinstance(category_id,str) or not category_id or len(category_id)>32):abort(400,description="分類識別不正確。")
    with engine.begin() as conn:
        # Category -> source/family -> item; category deletion only locks items.
        if category_id:
            category_revision=standards._integer(body.get("category_revision"),"分類版本",1,2**31-2)
            category=conn.execute(select(categories).where(categories.c.id==category_id).with_for_update()).mappings().first()
            if not category or category["removed"] or category["revision"]!=category_revision:_conflict()
        context=_load(conn,kind,key,lock=True);_expect(context,body,content=False)
        revision=_write_state(conn,context["state"],category_id=category_id)
        _audit(conn,kind,key,"category",actor,"變更標準分類。",{"item_revision":revision,"category_id":category_id})
    return detail(engine,kind,key,image_payload)


def category_listing(engine):
    with engine.connect() as conn:
        rows=conn.execute(select(categories.c.id,categories.c.name,categories.c.revision).where(categories.c.removed.is_(False))
            .order_by(categories.c.name,categories.c.id)).mappings().all()
    return {"items":[dict(row) for row in rows]}


def change_category(engine,identifier,body,actor):
    if not isinstance(body,dict):abort(400,description="分類資料格式不正確。")
    if identifier is None:
        if set(body)!={"name"}:abort(400,description="請填寫分類名稱。")
        operation="create"
    else:
        if set(body)-{"base_revision","operation","name"} or body.get("operation") not in ("rename","remove"):abort(400,description="分類操作不正確。")
        operation=body["operation"]
    name=standards._text(body.get("name"),"分類名稱",60) if operation!="remove" else None
    if name and any(ord(c)<32 for c in name):abort(400,description="分類名稱不能包含控制字元。")
    name_key=unicodedata.normalize("NFKC",name).casefold() if name else None
    with engine.begin() as conn:
        if identifier is None:
            identifier=db.uid();revision=1
            conn.execute(insert(categories).values(id=identifier,name=name,name_key=name_key,revision=revision,removed=False,updated_at=db.now()))
        else:
            row=conn.execute(select(categories).where(categories.c.id==identifier).with_for_update()).mappings().first()
            if not row or row["removed"] or row["revision"]!=standards._integer(body.get("base_revision"),"分類版本",1,2**31-2):_conflict()
            revision=row["revision"]+1
            changes={"revision":revision,"updated_at":db.now()}
            if operation=="rename":changes.update(name=name,name_key=name_key)
            else:
                name=row["name"];changes.update(removed=True,name_key=None)
                affected=conn.execute(select(items.c.kind,items.c.key).where(items.c.category_id==identifier)
                    .order_by(items.c.kind,items.c.key).with_for_update()).all()
                conn.execute(update(items).where(items.c.category_id==identifier).values(category_id=None,revision=items.c.revision+1,updated_at=db.now()))
            result=conn.execute(update(categories).where(categories.c.id==identifier,categories.c.revision==row["revision"]).values(**changes))
            if result.rowcount!=1:_conflict()
        _audit(conn,"category",identifier,operation,actor,"管理標準分類。",{"revision":revision,"name":name})
    return {"id":identifier,"name":name,"revision":revision,"removed":operation=="remove"}


def register_routes(app,engine,require_admin,image_payload):
    def guard(write=False):
        identity=require_admin()
        if write:
            token,expected=request.headers.get("X-CSRF-Token",""),session.get("csrf","")
            if request.headers.get("Sec-Fetch-Site")=="cross-site" or not isinstance(expected,str) or not expected or not secrets.compare_digest(token.encode(),expected.encode()):abort(403,description="請從本站重新整理後操作。")
        return identity if isinstance(identity,str) else session.get("username") or session.get("admin_username") or "管理員共用帳號"

    def execute(operation):
        try:return operation()
        except IntegrityError:_conflict()
        except OperationalError as error:
            if getattr(error.orig,"sqlite_errorcode",None) in {5,6,517}:_conflict()
            raise

    @app.get("/api/standard-library")
    def list_standard_library():
        guard()
        try:page,limit=int(request.args.get("page",1)),int(request.args.get("limit",24))
        except ValueError:abort(400,description="頁碼及每頁筆數須為整數。")
        return jsonify(listing(engine,image_payload,kind=request.args.get("kind","all"),state=request.args.get("state","active"),
            category_id=request.args.get("category_id","all"),query=request.args.get("q",""),page=page,limit=limit))

    @app.get("/api/standard-library/categories")
    def list_standard_categories():
        guard();return jsonify(category_listing(engine))

    @app.post("/api/standard-library/categories")
    def create_standard_category():
        actor=guard(True)
        return jsonify(execute(lambda:change_category(engine,None,request.get_json(silent=True),actor))),201

    @app.post("/api/standard-library/categories/<identifier>")
    def update_standard_category(identifier):
        actor=guard(True)
        return jsonify(execute(lambda:change_category(engine,identifier,request.get_json(silent=True),actor)))

    @app.get("/api/standard-library/<kind>/<path:key>")
    def get_library_standard(kind,key):
        guard();return jsonify(detail(engine,kind,key,image_payload))

    @app.post("/api/standard-library/<kind>/<path:key>/preview")
    def preview_library_standard(kind,key):
        guard(True);return jsonify(preview(engine,kind,key,request.get_json(silent=True)))

    @app.post("/api/standard-library/<kind>/<path:key>/save")
    def save_library_standard(kind,key):
        actor=guard(True)
        return jsonify(execute(lambda:save(engine,kind,key,request.get_json(silent=True),actor,image_payload))),201

    @app.post("/api/standard-library/<kind>/<path:key>/state")
    def state_library_standard(kind,key):
        actor=guard(True)
        return jsonify(execute(lambda:change_state(engine,kind,key,request.get_json(silent=True),actor,image_payload)))

    @app.post("/api/standard-library/<kind>/<path:key>/category")
    def category_library_standard(kind,key):
        actor=guard(True)
        return jsonify(execute(lambda:assign_category(engine,kind,key,request.get_json(silent=True),actor,image_payload)))
