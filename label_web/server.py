from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import io
import json
import os
import re
import secrets
import threading
import time
import warnings

from flask import Flask, jsonify, request, session, send_from_directory, abort
from PIL import Image, ImageOps, UnidentifiedImageError
from pillow_heif import register_heif_opener
from sqlalchemy import select, insert, update, func
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

import database as db
from ocr_worker import IsolatedOCR, OCRMemoryLimitError
from memory_cleanup import release_unused_memory
from validation import extract_fields, evaluate, parse_date, TEXT_FIELDS
from source_validation import evaluate_source, RULE_VERSION
from source_rules import prepare_source
from label_geometry import analyze_label_scope
import label_source
import corrections
import standard_reference
import barcode_rule_authoring
import history_cleanup
import history_status
import photo_regions
import recognition_samples
import reference_photos
import pending_drafts
import standard_library
import cloud_budget
from sticker_scope import recognize_scoped
from inspection_evidence import augment
from access_control import AccessControl
from standard_draft_quality import eligibility as draft_eligibility

register_heif_opener()
Image.MAX_IMAGE_PIXELS = 32_000_000
ROOT = Path(__file__).resolve().parent


def create_app(config=None, ocr=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    data_dir = Path(os.environ.get("LABELCHECK_DATA_DIR", ROOT / "data"))
    app.config.update(DATA_DIR=data_dir, DATABASE_URL=os.environ.get("LABELCHECK_DATABASE_URL", ""),
        APP_PASSWORD=os.environ.get("LABELCHECK_PASSWORD", ""),
        ADMIN_PASSWORD=os.environ.get("LABELCHECK_ADMIN_PASSWORD", ""),
        CLOUD_TRIAL_LIMIT=cloud_budget.configured_limit(os.environ.get("LABELCHECK_CLOUD_TRIAL_LIMIT","20")),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024, MAX_FORM_MEMORY_SIZE=128 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("LABELCHECK_HTTPS", "") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8))
    if config:
        app.config.update(config)
    app.config["CLOUD_TRIAL_LIMIT"] = cloud_budget.configured_limit(app.config["CLOUD_TRIAL_LIMIT"])
    data_dir = Path(app.config["DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    key_file = data_dir / ".session-key"
    if not key_file.exists():
        try:
            with key_file.open("x", encoding="ascii") as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    app.secret_key = os.environ.get("LABELCHECK_SECRET", "") or key_file.read_text().strip()
    access = AccessControl(app)
    app.extensions["label_access"] = access
    engine = db.open_database(app.config["DATABASE_URL"], data_dir)
    cloud_budget.initialize(engine)
    worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="label-ocr")
    slots = threading.BoundedSemaphore(12)
    image_lock = threading.Lock()
    retry_lock = threading.Lock()
    correction_lock = threading.Lock()
    recognizer = ocr or IsolatedOCR(ROOT / "models")
    app.extensions.update(label_engine=engine, label_worker=worker)
    last_memory_cleanup = None
    with engine.begin() as conn:
        conn.execute(update(db.jobs).where(db.jobs.c.state.in_(["pending", "running"])).values(
            state="failed", error="服務重新啟動中斷了辨識，請重新上傳。"))

    def get_one(table, identifier):
        with engine.connect() as conn:
            if table is db.inspections:
                history_cleanup.ensure_active(conn, identifier)
            row = conn.execute(select(table).where(table.c.id == identifier)).mappings().first()
        if row is None:
            abort(404, description="找不到這筆資料。")
        return dict(row)

    def image_payload(identifier):
        if not identifier:
            return None
        image = get_one(db.images, identifier)
        image.update(url=f"/media/{identifier}/image.jpg", thumbnail=f"/media/{identifier}/thumb.jpg")
        return image

    def template_payload(row):
        result = dict(row)
        result["image"] = image_payload(result["image_id"])
        return result

    def taiwan_today():
        return datetime.now(timezone(timedelta(hours=8))).date().isoformat()

    def scan_inputs(body):
        values = {}
        for key, label in (("base_date", "本批基準日"), ("batch_date", "本批製造日"), ("arrival_date", "本批到店日")):
            value = body.get(key, "") or (taiwan_today() if key == "base_date" else "")
            if not isinstance(value, str):
                abort(400, description=f"{label}格式不正確。")
            if value:
                try:
                    if date.fromisoformat(value).isoformat() != value:
                        raise ValueError()
                except ValueError:
                    abort(400, description=f"{label}格式不正確。")
            values[key] = value
        source_code = body.get("source_code", "")
        if not isinstance(source_code, str) or len(source_code) > 100 or any(ord(char) < 32 for char in source_code):
            abort(400, description="系統標籤代碼不正確。")
        values["source_code"] = source_code.strip()
        return values

    def ensure_explicit_source(code, conn):
        """A stale selection must stop before OCR instead of becoming a new match."""
        if not code:
            return
        standard_library.ensure_selectable(conn, code=code)

    def ensure_job_standard(conn, job):
        saved = job.get("result") or {}
        if job["kind"] == "inspection":
            standard_library.ensure_selectable(conn, template_id=job["template_id"],
                allow_superseded=bool(saved.get("recognition_standard")),
                family_id=(saved.get("recognition_standard") or {}).get("family_id"))
        elif job["kind"] == "recognition":
            ensure_explicit_source((saved.get("request") or {}).get("source_code", ""), conn)

    def ensure_result_standard(conn, standard):
        source = standard.get("source") or {}
        if source.get("code"):
            standard_library.ensure_selectable(conn, code=source["code"])

    def check_source(lines, inputs, ocr_info=None, match_lines=None):
        scope = analyze_label_scope(lines)
        match = ({"status": "scope_review", "reason": scope["reason"], "candidates": []}
                 if scope["blocked"] else
                 label_source.resolve(engine, lines if match_lines is None else match_lines, inputs["source_code"]))
        source = prepare_source(None if match.get("status") == "source_conflict" else match.get("source"), inputs["base_date"])
        prefix = {"catalog": "清單比對", "manual": "人工文字標準"}.get((source or {}).get("source_kind"), "系統標籤")
        standard = {"id": "", "name": f"{prefix} {source['code']} · {source['name']}" if source else "直接掃描・文字與日期檢查",
                    "version": 0, "image_id": "", "mode": "system_label", "source": source}
        result = evaluate_source(lines, source, inputs["batch_date"], inputs["arrival_date"], base_date=inputs["base_date"],
                                 ocr_capabilities=(ocr_info or {}).get("capabilities"))
        result["source_match"] = {key: value for key, value in match.items() if key != "source"}
        result["inputs"] = inputs
        augment(result, {**(ocr_info or {}),"lines":lines})
        return standard, result

    def recognition_options(body, fallback=None, check_available=True):
        prior=fallback or {}
        selected=body.get("recognition_engine",prior.get("recognition_engine","local"))
        scope=body.get("label_scope",prior.get("label_scope","sticker"))
        if selected not in ("local","cloud") or scope not in ("sticker","full"):
            abort(400,description="辨識方式或照片範圍不正確。")
        if selected=="cloud" and check_available:
            if not os.environ.get("OPENAI_API_KEY", "").strip() and not app.config.get("CLOUD_OCR"):
                abort(409,description="尚未設定雲端辨識金鑰，請使用本機辨識。")
            remaining=cloud_budget.remaining(engine,app.config["CLOUD_TRIAL_LIMIT"])
            if remaining is not None and remaining<=0:
                abort(429,description="雲端試用次數已用完，請改用本機辨識。")
        return {"recognition_engine":selected,"label_scope":scope}

    @app.before_request
    def protect():
        if request.path == "/healthz":
            return None
        if not app.config["APP_PASSWORD"] and not app.testing:
            if request.remote_addr not in {"127.0.0.1", "::1"} or request.host.split(":")[0] not in {"127.0.0.1", "localhost", "["}:
                abort(403, description="遠端使用前請設定網頁登入密碼。")
        if request.path.startswith(("/api/", "/media/")) and request.path not in {"/api/session", "/api/login"}:
            if app.config["APP_PASSWORD"] and not session.get("authenticated"):
                abort(401, description="請先登入。")
        if request.method == "POST":
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                abort(403, description="請從本站操作。")
            token, expected = request.headers.get("X-CSRF-Token", ""), session.get("csrf", "")
            if not isinstance(expected, str) or not expected or not secrets.compare_digest(token.encode(), expected.encode()):
                abort(403, description="頁面已過期，請重新整理後再試。")
        if request.endpoint in {"list_templates", "save_template", "source_label", "list_manual_references", "list_pending_manual_references",
                "get_manual_reference", "preview_manual_reference", "create_manual_reference",
                "get_comparison_standard", "preview_comparison_standard", "update_comparison_standard"}:
            access.require_admin()

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(self), microphone=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"
        if request.path.startswith(("/api/", "/media/")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=("照片超過 15 MB，請縮小後重新上傳。" if error.code == 413 else error.description)), error.code

    @app.errorhandler(Exception)
    def unhandled(error):
        app.logger.exception("Label check request failed")
        return jsonify(error="處理失敗，資料未完成儲存。請稍後再試。"), 500

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/healthz")
    def health():
        with engine.connect() as conn:
            conn.execute(select(func.count()).select_from(db.templates))
        return jsonify(status="ok")

    @app.get("/api/session")
    def current_session():
        return jsonify(access.payload())

    @app.post("/api/login")
    def login():
        return access.login()

    @app.post("/api/admin/unlock")
    def unlock_admin():
        return access.unlock()

    @app.post("/api/admin/lock")
    def lock_admin():
        return access.lock_admin()

    @app.post("/api/logout")
    def logout():
        access.revoke()
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/templates")
    def list_templates():
        with engine.connect() as conn:
            rows = conn.execute(select(db.templates).where(db.templates.c.active.is_(True)).order_by(db.templates.c.created_at.desc())).mappings().all()
        return jsonify(items=[template_payload(x) for x in rows])

    @app.get("/api/inspection-options")
    def inspection_options():
        with engine.connect() as conn:
            rows = conn.execute(select(db.templates.c.id, db.templates.c.name, db.templates.c.version)
                .where(db.templates.c.active.is_(True)).order_by(db.templates.c.created_at.desc())).mappings()
            return jsonify(items=[dict(row) for row in rows])

    @app.get("/api/scan-config")
    def scan_config():
        remaining=cloud_budget.remaining(engine,app.config["CLOUD_TRIAL_LIMIT"])
        unlimited=app.config["CLOUD_TRIAL_LIMIT"] == -1
        cloud_available=bool(os.environ.get("OPENAI_API_KEY", "").strip() or app.config.get("CLOUD_OCR")) and (unlimited or remaining>0)
        return jsonify(standards=[], version=RULE_VERSION, mode="system_label", today=taiwan_today(),recognition={
            "cloud_available":cloud_available,
            "default_engine":"cloud" if cloud_available else "local", "cloud_model":os.environ.get("LABELCHECK_CLOUD_MODEL","gpt-6.1-sol"),
            "cloud_unlimited":unlimited,"cloud_limit":None if unlimited else app.config["CLOUD_TRIAL_LIMIT"],"cloud_remaining":remaining})

    def active_jobs():
        with engine.connect() as conn:
            return conn.execute(select(func.count()).select_from(db.jobs).where(
                db.jobs.c.state.in_(["pending", "running"]))).scalar_one()

    @app.get("/api/memory")
    def memory_status():
        if not hasattr(recognizer, "read_memory_status"):
            return jsonify(status="unavailable", busy=False, notice="此辨識服務不提供記憶體管理。")
        report = recognizer.read_memory_status()
        report["queued_jobs"] = active_jobs()
        report["busy"] = bool(report.get("busy") or report["queued_jobs"] or image_lock.locked())
        return jsonify(report)

    @app.post("/api/memory/cleanup")
    def cleanup_memory():
        nonlocal last_memory_cleanup
        if not hasattr(recognizer, "cleanup_memory"):
            abort(503, description="此辨識服務不提供記憶體管理。")
        if not image_lock.acquire(blocking=False):
            abort(409, description="目前正在處理照片，請等辨識完成後再清理。")
        try:
            if active_jobs():
                abort(409, description="還有辨識工作等待處理，完成後才能清理。")
            now = time.monotonic()
            if last_memory_cleanup is not None and now - last_memory_cleanup < 30:
                abort(429, description="剛完成記憶體清理，請至少間隔 30 秒再操作。")
            report = recognizer.cleanup_memory()
            if report.get("status") == "busy":
                abort(409, description="目前正在辨識，請等辨識完成後再清理。")
            last_memory_cleanup = time.monotonic()
            return jsonify(report)
        finally:
            image_lock.release()

    @app.get("/api/source-labels")
    def source_labels():
        if not label_source.available(engine):
            return jsonify(available=False, items=[])
        query = request.args.get("q", "").strip()[:100]
        return jsonify(available=True, items=label_source.search(engine, query) if query else [])

    @app.get("/api/source-labels/<code>")
    def source_label(code):
        if not label_source.available(engine):
            abort(404, description="目前尚未連接標籤系統資料庫。")
        source = label_source.draft(engine, code)
        if not source:
            abort(404, description="找不到這份系統標籤。")
        return jsonify(source)

    @app.post("/api/templates")
    def save_template():
        body = request.get_json(silent=True) or {}
        if body.get("confirmed") is not True:
            abort(400, description="請先逐欄確認標準文字。")
        source = None
        if body.get("source_code"):
            with engine.begin() as conn:
                ensure_explicit_source(str(body["source_code"]), conn)
            if not label_source.available(engine):
                abort(400, description="目前尚未連接標籤系統資料庫。")
            source = label_source.draft(engine, str(body["source_code"]))
            if not source or source["revision"] != body.get("source_revision"):
                abort(409, description="系統標籤已變更，請重新匯入並確認。")
            image_id = ""
        else:
            job = get_one(db.jobs, str(body.get("job_id", "")))
            if job["kind"] != "reference" or job["state"] != "done":
                abort(400, description="請先上傳並完成標準照片辨識。")
            image_id = job["image_id"]
        fields = body.get("fields", {})
        if not isinstance(fields, dict) or any(not isinstance(fields.get(k), str) or not fields[k].strip() or len(fields[k]) > 500 for k in ("product", "address", "origin")):
            abort(400, description="請完整確認品名、地址與產地，每欄最多 500 字。")
        if any(not isinstance(fields.get(k, ""), str) or len(fields.get(k, "")) > 500 for k in TEXT_FIELDS):
            abort(400, description="標準文字每欄最多 500 字。")
        fields = {k: fields.get(k, "").strip() for k in TEXT_FIELDS}
        name = body.get("name", "").strip()
        approver = body.get("approved_by", "").strip()
        if not name or len(name) > 200 or not approver or len(approver) > 100:
            abort(400, description="請填寫標準名稱與確認人員。")
        rules = body.get("rules", {})
        if not isinstance(rules, dict) or not isinstance(rules.get("dates"), bool) or not isinstance(rules.get("arrival", False), bool):
            abort(400, description="請確認日期檢查設定。")
        keep_days = rules.get("keep_days")
        if keep_days is not None and (type(keep_days) is not int or not 0 <= keep_days <= 3650):
            abort(400, description="保存天數請填 0 到 3650 的整數。")
        reference_dates = body.get("reference_dates", {})
        if not isinstance(reference_dates, dict):
            abort(400, description="請確認標準照片日期。")
        if rules["dates"] and not source:
            try:
                m = parse_date(reference_dates.get("manufacture", ""))
                e = parse_date(reference_dates.get("expiry", ""))
                if e["date"] < m["date"]:
                    raise ValueError()
                if e["date"] == m["date"] and m["hour"] is not None and e["hour"] is not None and (e["hour"], e["minute"]) < (m["hour"], m["minute"]):
                    raise ValueError()
                if keep_days is not None and (e["date"] - m["date"]).days != keep_days:
                    raise ValueError()
            except ValueError:
                abort(400, description="標準照片的日期不完整、前後矛盾或不符合保存天數，請核對。")
        if rules.get("arrival", False) and not source:
            try:
                arrival = parse_date(reference_dates.get("arrival", ""),kind="arrival")
                if rules["dates"] and not m["date"] <= arrival["date"] <= e["date"]:
                    raise ValueError()
            except (ValueError, TypeError):
                abort(400, description="標準照片的到店日不完整、不合法或與製造／有效日期矛盾，請核對。")
        row = dict(id=db.uid(), family_id=db.uid(), version=1, active=True, name=name,
                   image_id=image_id, fields=fields, rules={"dates": rules["dates"], "keep_days": keep_days, "arrival": rules.get("arrival", False)},
                   reference_dates={k: str(reference_dates.get(k, ""))[:80] for k in ("manufacture", "expiry", "arrival")},
                   approved_by=approver, created_at=db.now())
        if source:
            row["rules"]["source"] = {k: source[k] for k in ("code", "name", "revision", "keep_days", "date_settings")}
        try:
            with engine.begin() as conn:
                if source:
                    standard_library.ensure_selectable(conn, code=source["code"])
                if body.get("supersedes_id"):
                    standard_library.ensure_selectable(conn, template_id=body["supersedes_id"])
                    old = conn.execute(select(db.templates).where(db.templates.c.id == body["supersedes_id"]).with_for_update()).mappings().first()
                    if not old or not old["active"]:
                        abort(409, description="標準已更新，請重新載入再建立新版。")
                    row.update(family_id=old["family_id"], version=old["version"] + 1)
                    conn.execute(update(db.templates).where(db.templates.c.id == old["id"]).values(active=False))
                conn.execute(insert(db.templates).values(**row))
        except IntegrityError:
            abort(409, description="另一位使用者已建立新版，請重新載入。")
        return jsonify(template_payload(row)), 201

    def store_image(upload):
        raw = upload.read(15 * 1024 * 1024 + 1)
        if len(raw) > 15 * 1024 * 1024:
            abort(413)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(raw)) as original:
                    if original.format not in {"JPEG", "PNG", "WEBP", "HEIF", "HEIC"}:
                        raise ValueError()
                    if original.width * original.height > 32_000_000 or min(original.size) < 100:
                        raise ValueError()
                    original.draft("RGB", (2400, 2400))
                    ImageOps.exif_transpose(original, in_place=True)
                    original.thumbnail((2400, 2400))
                    normalized = original.convert("RGB")
        except (ValueError, OSError, UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning):
            abort(400, description="無法讀取照片。請使用清楚的 JPG、PNG、WebP 或 HEIC，圖片至少 100 像素且不超過 3,200 萬像素。")
        identifier = db.uid()
        folder = data_dir / "images" / identifier
        folder.mkdir(parents=True)
        (folder / "original").write_bytes(raw)
        try:
            normalized.thumbnail((2400, 2400))
            normalized.save(folder / "image.jpg", quality=95)
            with normalized.copy() as thumbnail:
                thumbnail.thumbnail((420, 420))
                thumbnail.save(folder / "thumb.jpg", quality=85)
            row = dict(id=identifier, created_at=db.now(), filename=(upload.filename or "photo")[:255],
                       sha256=hashlib.sha256(raw).hexdigest(), width=normalized.width, height=normalized.height)
        finally:
            normalized.close()
        with engine.begin() as conn:
            conn.execute(insert(db.images).values(**row))
        return row

    def process_job(job):
        cloud_reserved=False
        cloud_usage=None
        active_recognizer=recognizer
        try:
            with engine.begin() as conn:
                conn.execute(update(db.jobs).where(db.jobs.c.id == job["id"]).values(state="running"))
            saved_request = (job.get("result") or {}).get("request", {})
            selected=saved_request.get("recognition_engine","local")
            with image_lock:
                # A queued selection may have been removed after upload. Check
                # immediately before any paid call, then recheck at commit.
                with engine.begin() as conn:
                    ensure_job_standard(conn, job)
                if selected=="cloud":
                    from cloud_vision import CloudVisionEngine
                    def reserve_date_retry():
                        with engine.begin() as conn:
                            ensure_job_standard(conn, job)
                        return cloud_budget.reserve_date_retry(engine, job["id"], app.config["CLOUD_TRIAL_LIMIT"])
                    active_recognizer=app.config.get("CLOUD_OCR") or CloudVisionEngine(reserve_date_retry=reserve_date_retry)
                    cloud_budget.reserve(engine,job["id"],os.environ.get("LABELCHECK_CLOUD_MODEL","gpt-6.1-sol"),app.config["CLOUD_TRIAL_LIMIT"])
                    cloud_reserved=True
                ocr_result=recognize_scoped(data_dir / "images" / job["image_id"] / "image.jpg",active_recognizer,saved_request.get("label_scope","sticker"))
                ocr_result["recognition_engine"]=selected
                if cloud_reserved:
                    cloud_usage=cloud_budget.usage_record(ocr_result)
                    cloud_budget.finish(engine,job["id"],"done",cloud_usage)
            inputs = {"batch_date": job["batch_date"], "arrival_date": saved_request.get("arrival_date", ""),
                      "source_code": saved_request.get("source_code", ""),
                      "base_date": saved_request.get("base_date") or taiwan_today(),
                      "recognition_engine":selected,"label_scope":saved_request.get("label_scope","sticker")}
            result = {"ocr": ocr_result, "fields": extract_fields(ocr_result["lines"]), "request": inputs}
            for key in ("retry_of", "retry_root", "recognition_of", "recognition_request_id", "recognition_spec", "upload_request_id", "upload_spec"):
                if (job.get("result") or {}).get(key):
                    result[key] = job["result"][key]
            source_evaluation = None
            if job["kind"] == "recognition":
                source_evaluation = check_source(ocr_result["lines"], inputs, ocr_result)
            with engine.begin() as conn:
                if job["kind"] in {"inspection", "recognition"}:
                    ensure_job_standard(conn, job)
                    if job["kind"] == "inspection":
                        standard = (job.get("result") or {}).get("recognition_standard") or dict(conn.execute(
                            select(db.templates).where(db.templates.c.id == job["template_id"])).mappings().one())
                        evaluation = evaluate(ocr_result["lines"], standard, inputs["batch_date"], inputs["arrival_date"],
                                              base_date=inputs["base_date"])
                        augment(evaluation,ocr_result)
                    else:
                        standard, evaluation = source_evaluation
                        # Automatic matching can race with a library removal
                        # during OCR. The shared source lock covers this write.
                        ensure_result_standard(conn, standard)
                    evaluation["inputs"] = inputs
                    if result.get("recognition_of"):
                        evaluation["recognition_of"] = result["recognition_of"]
                    inspection_id = db.uid()
                    conn.execute(insert(db.inspections).values(id=inspection_id, image_id=job["image_id"],
                        template_id=standard["id"], template_snapshot=standard, status=evaluation["status"],
                        result=evaluation, ocr=ocr_result, created_at=db.now()))
                    result["inspection_id"] = inspection_id
                conn.execute(update(db.jobs).where(db.jobs.c.id == job["id"]).values(state="done", result=result))
        except Exception as error:
            app.logger.exception("OCR job failed")
            if isinstance(error, OCRMemoryLimitError) and error.memory_guard:
                app.logger.warning("OCR memory guard sample: %s", error.memory_guard)
            message = ("這次辨識的可用記憶體仍不足，照片已保留。可按「重新辨識這張照片」再試一次；若持續發生，請拍近單張標籤。"
                       if isinstance(error, OCRMemoryLimitError)
                       else "照片辨識失敗。請稍後重新上傳，或改用更清楚的照片。")
            if isinstance(error, OCRMemoryLimitError) and error.kind == "monitor_unavailable":
                message = "目前暫時無法安全啟動辨識，請稍後再試。照片已保留。"
            if cloud_reserved:
                # Validation or persistence can fail after a paid response. Keep
                # its known token usage instead of replacing it with an empty error.
                failed_usage=cloud_usage if cloud_usage is not None else getattr(error,"usage",None)
                receipts=getattr(active_recognizer,"cloud_calls",None)
                if cloud_usage is None and isinstance(receipts,list) and receipts:
                    from cloud_vision import usage_summary
                    failed_usage=cloud_budget.usage_record({**usage_summary(receipts),"cloud_calls":receipts})
                cloud_budget.finish(engine,job["id"],"failed",failed_usage,getattr(error,"code","processing_failed"))
                message=getattr(error,"safe_message","雲端辨識未完成，照片已保留。重試會再使用一次雲端額度。")
            if isinstance(error, HTTPException) and error.code in {404, 409}:
                message = str(error.description)
            failed_result = dict(job.get("result") or {})
            if isinstance(error, OCRMemoryLimitError):
                failed_result["memory_guard"] = error.memory_guard
                failed_result["recovery"] = getattr(error, "recovery", None)
            with engine.begin() as conn:
                conn.execute(update(db.jobs).where(db.jobs.c.id == job["id"]).values(state="failed", error=message, result=failed_result))
        finally:
            try:
                with image_lock:
                    release_unused_memory()
            finally:
                slots.release()

    @app.post("/api/jobs")
    def create_job():
        with retry_lock:
            return create_job_locked()

    def create_job_locked():
        kind = request.form.get("kind")
        if kind == "reference":
            access.require_admin()
        if kind not in {"reference", "inspection", "recognition"} or "photo" not in request.files:
            abort(400, description="請選擇照片。")
        template_id = request.form.get("template_id", "")
        inputs = scan_inputs(request.form)
        inputs.update(recognition_options(request.form,check_available=False))
        source_code = inputs["source_code"]
        if source_code and (kind != "recognition" or template_id):
            abort(400, description="請選擇系統標籤或照片標準其中一種。")
        request_id=request.form.get("request_id","")
        upload_spec=None
        if request_id:
            if not re.fullmatch(r"[0-9a-f]{32}",request_id):
                abort(400,description="上傳請求編號不正確，請重新選擇照片。")
            upload=request.files["photo"]
            raw=upload.read(15*1024*1024+1)
            if len(raw)>15*1024*1024:
                abort(413)
            photo_hash=hashlib.sha256(raw).hexdigest()
            upload.stream.seek(0)
            del raw
            upload_spec=hashlib.sha256(json.dumps({"photo":photo_hash,"kind":kind,"template_id":template_id,"inputs":inputs},
                sort_keys=True,ensure_ascii=False).encode()).hexdigest()
            with engine.connect() as conn:
                existing=conn.execute(select(db.jobs).where(db.jobs.c.result["upload_request_id"].as_string()==request_id).limit(1)).mappings().first()
            if existing:
                if existing["result"].get("upload_spec")!=upload_spec:
                    abort(409,description="這個請求已用於不同照片或設定，請重新確認後送出。")
                original_inspection=existing["result"].get("inspection_id")
                if original_inspection:
                    get_one(db.inspections,original_inspection)
                return jsonify(id=existing["id"],image=image_payload(existing["image_id"])),202
        recognition_options(request.form)
        with engine.begin() as conn:
            if kind == "inspection":
                standard_library.ensure_selectable(conn, template_id=template_id)
            elif kind == "recognition":
                ensure_explicit_source(source_code, conn)
        batch = inputs["batch_date"]
        if not slots.acquire(blocking=False):
            abort(429, description="目前等待辨識的照片較多，請稍後再試。")
        try:
            if not image_lock.acquire(timeout=0.1):
                abort(429, description="正在處理上一張照片，請稍後再上傳。")
            try:
                image = store_image(request.files["photo"])
            finally:
                image_lock.release()
            row = dict(id=db.uid(), image_id=image["id"], kind=kind, template_id=template_id or None,
                       batch_date=batch, state="pending", created_at=db.now(),
                       result={"request": inputs})
            if request_id:
                row["result"].update(upload_request_id=request_id,upload_spec=upload_spec)
            with engine.begin() as conn:
                conn.execute(insert(db.jobs).values(**row))
            worker.submit(process_job, row)
        except Exception:
            slots.release()
            raise
        return jsonify(id=row["id"], image=image_payload(image["id"])), 202

    @app.post("/api/inspections/<identifier>/recognize")
    def recognize_inspection(identifier):
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("request_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", body["request_id"]):
            abort(400, description="重新辨識的請求編號不正確，請重新開啟裁切視窗。")
        # Same browser submission is idempotent, including after a lost response.
        # This service intentionally has one instance; retry_lock serializes writers.
        with retry_lock:
            original = get_one(db.inspections, identifier)
            image = get_one(db.images, original["image_id"])
            try:
                region = photo_regions.validate_region(body.get("crop"), image["width"], image["height"])
            except ValueError as error:
                abort(400, description=str(error))
            options=recognition_options(body,check_available=False)
            spec = {"inspection_id":identifier, "image_id":image["id"], "crop":region, **options}
            with engine.connect() as conn:
                existing = conn.execute(select(db.jobs).where(
                    db.jobs.c.result["recognition_request_id"].as_string() == body["request_id"])
                    .order_by(db.jobs.c.created_at).limit(1)).mappings().first()
            if existing:
                if existing["result"].get("recognition_spec") != spec:
                    abort(409, description="這個請求已用於不同裁切範圍，請重新確認後送出。")
                return jsonify(id=existing["id"], image=image_payload(existing["image_id"])), 202
            recognition_options(body)
            if not (data_dir / "images" / image["id"] / "image.jpg").is_file():
                abort(404, description="原照片已不存在，請重新上傳。")
            old_inputs = original["result"].get("inputs") or {}
            inputs = scan_inputs({**old_inputs, "base_date":old_inputs.get("base_date") or
                datetime.fromisoformat(original["created_at"]).astimezone(timezone(timedelta(hours=8))).date().isoformat(),
                "source_code":""})
            inputs.update(options)
            # Explicit manual crop is the user's selected scope; don't crop it again.
            if region:
                inputs["label_scope"]="full"
            snapshot = original["template_snapshot"]
            kind = "recognition" if snapshot.get("mode") == "system_label" or "source" in snapshot else "inspection"
            if kind == "inspection":
                with engine.begin() as conn:
                    standard_library.ensure_selectable(conn, template_id=original["template_id"], allow_superseded=True,
                        family_id=snapshot.get("family_id"))
            if not slots.acquire(blocking=False):
                abort(429, description="目前等待辨識的照片較多，請稍後再試。")
            derivative = None
            committed = False
            try:
                if not image_lock.acquire(timeout=0.1):
                    abort(429, description="正在處理上一張照片，請稍後再試。")
                try:
                    if region:
                        derivative = photo_regions.save_region(data_dir, image, region)
                except ValueError as error:
                    abort(409, description=str(error))
                finally:
                    image_lock.release()
                saved = {"request":inputs, "recognition_of":spec, "recognition_spec":spec,
                         "recognition_request_id":body["request_id"]}
                if kind == "inspection":
                    saved["recognition_standard"] = snapshot
                row = dict(id=db.uid(), image_id=(derivative or image)["id"], kind=kind,
                           template_id=original["template_id"] or None, batch_date=inputs["batch_date"],
                           state="pending", created_at=db.now(), result=saved)
                with engine.begin() as conn:
                    ensure_job_standard(conn, row)
                    conn.execute(select(db.inspections.c.id).where(db.inspections.c.id == identifier).with_for_update()).first()
                    history_cleanup.ensure_active(conn, identifier)
                    if derivative:
                        conn.execute(insert(db.images).values(**derivative))
                    conn.execute(insert(db.jobs).values(**row))
                committed = True
                worker.submit(process_job, row)
            except Exception:
                slots.release()
                if derivative and not committed:
                    photo_regions.remove_uncommitted_region(data_dir / "images" / derivative["id"])
                if committed:
                    with engine.begin() as conn:
                        conn.execute(update(db.jobs).where(db.jobs.c.id == row["id"]).values(
                            state="failed", error="工作未能啟動，照片已保留，請稍後重新辨識。"))
                raise
            return jsonify(id=row["id"], image=image_payload(row["image_id"])), 202

    @app.get("/api/jobs/failed")
    def failed_jobs():
        # Shared workspace, like inspection history. Show only the newest failed
        # attempt in each retry chain, and hide chains already resumed/completed.
        limit = request.args.get("limit", 5, type=int)
        limit = min(10, max(1, limit or 5))
        with engine.connect() as conn:
            candidates = [dict(row) for row in conn.execute(select(db.jobs).where(
                db.jobs.c.state == "failed", db.jobs.c.kind.in_(["recognition", "inspection"])
            ).order_by(db.jobs.c.created_at.desc()).limit(100)).mappings()]
            resumed = set(conn.execute(select(db.jobs.c.result["retry_root"].as_string()).where(
                db.jobs.c.state.in_(["pending", "running", "done"]),
                db.jobs.c.result["retry_root"].as_string().is_not(None))).scalars())
        items, seen = [], set()
        for row in candidates:
            root = (row.get("result") or {}).get("retry_root") or row["id"]
            if root in resumed or root in seen:
                continue
            seen.add(root)
            if not (data_dir / "images" / row["image_id"] / "image.jpg").is_file():
                continue
            items.append({key: row[key] for key in ("id", "kind", "created_at", "error")})
            items[-1].update(image=image_payload(row["image_id"]), request=(row.get("result") or {}).get("request", {}))
            if len(items) >= limit:
                break
        return jsonify(items=items)

    @app.post("/api/jobs/<identifier>/retry")
    def retry_job(identifier):
        with retry_lock:
            original = get_one(db.jobs, identifier)
            if original["kind"] == "reference":
                access.require_admin()
            if original["state"] != "failed":
                abort(409, description="這張照片並非失敗狀態，請查看原本辨識結果。")
            body = request.get_json(silent=True) if request.get_data() else {}
            if not isinstance(body, dict) or set(body) - {"recognition_engine"}:
                abort(400, description="重試只可指定辨識方式，其他設定沿用原工作。")
            inputs = dict((original.get("result") or {}).get("request") or {})
            original_engine = inputs.get("recognition_engine", "local")
            selected_engine = body.get("recognition_engine", original_engine)
            if selected_engine not in ("local", original_engine):
                abort(400, description="重試只可沿用原辨識方式或明確改用一般辨識。")
            # Validate before replay, but only check cloud credentials/budget
            # when a new job is needed. A local retry must not need either.
            inputs.update(recognition_options(body, inputs, check_available=False))
            root = (original.get("result") or {}).get("retry_root") or original["id"]
            with engine.connect() as conn:
                # One parent permits one retry child, even if that child failed
                # before the browser received the response. A deliberate next
                # attempt targets the newest failed child, not the old parent.
                existing = conn.execute(select(db.jobs).where(
                    db.jobs.c.result["retry_of"].as_string() == identifier
                ).order_by(db.jobs.c.created_at).limit(1)).mappings().first()
                if existing is None:
                    existing = conn.execute(select(db.jobs).where(
                        db.jobs.c.result["retry_root"].as_string() == root,
                        db.jobs.c.state.in_(["pending", "running", "done"])
                    ).order_by(db.jobs.c.created_at.desc()).limit(1)).mappings().first()
            if existing:
                existing_engine = ((existing.get("result") or {}).get("request") or {}).get("recognition_engine", "local")
                if existing_engine != selected_engine:
                    abort(409, description="這張照片已有不同辨識方式的重試工作，請開啟最新工作後再改選辨識方式。")
                return jsonify(id=existing["id"], image=image_payload(existing["image_id"])), 202
            if not (data_dir / "images" / original["image_id"] / "image.jpg").is_file():
                abort(404, description="原照片已不存在，請重新上傳。")
            with engine.begin() as conn:
                ensure_job_standard(conn, original)
            inputs.update(recognition_options({},inputs))
            if not inputs.get("base_date"):
                inputs["base_date"] = datetime.fromisoformat(original["created_at"]).astimezone(
                    timezone(timedelta(hours=8))).date().isoformat()
            if not slots.acquire(blocking=False):
                abort(429, description="目前等待辨識的照片較多，請稍後再試。")
            try:
                if not image_lock.acquire(timeout=0.1):
                    abort(429, description="正在處理上一張照片，請稍後再試。")
                image_lock.release()
                row = dict(id=db.uid(), image_id=original["image_id"], kind=original["kind"],
                    template_id=original["template_id"], batch_date=original["batch_date"], state="pending",
                    created_at=db.now(), result={"request":inputs, "retry_of":identifier, "retry_root":root})
                for key in ("recognition_of", "recognition_spec", "recognition_request_id", "recognition_standard"):
                    if key in (original.get("result") or {}):
                        row["result"][key] = original["result"][key]
                with engine.begin() as conn:
                    ensure_job_standard(conn, row)
                    conn.execute(insert(db.jobs).values(**row))
                worker.submit(process_job, row)
            except Exception:
                slots.release()
                raise
            return jsonify(id=row["id"], image=image_payload(row["image_id"])), 202

    @app.get("/api/jobs/<identifier>")
    def job_status(identifier):
        if request.args.get("include") == "inspection":
            job = db.jobs.c
            with engine.connect() as conn:
                progress = conn.execute(select(job.kind, job.state, job.result["inspection_id"].as_string().label("inspection_id"))
                                        .where(job.id == identifier)).mappings().first()
            if progress is None:
                abort(404, description="找不到這筆資料。")
            if progress["kind"] in {"inspection", "recognition"}:
                summary = dict(id=identifier, kind=progress["kind"], state=progress["state"])
                if progress["state"] in {"pending", "running"}:
                    return jsonify(summary)
                if progress["state"] == "done" and progress["inspection_id"]:
                    inspection_id = progress["inspection_id"]
                    details = inspection_payload(get_one(db.inspections, inspection_id))
                    return jsonify(**summary, result={"inspection_id":inspection_id}, inspection=details)
        row = get_one(db.jobs, identifier)
        if row["kind"] == "reference":
            access.require_admin()
        inspection_id = (row.get("result") or {}).get("inspection_id")
        if inspection_id:
            with engine.connect() as conn:
                history_cleanup.ensure_active(conn, inspection_id)
        if (row.get("result") or {}).get("ocr"):
            row["manual_standard_eligibility"] = draft_eligibility(row["result"]["ocr"])
        row["image"] = image_payload(row["image_id"])
        return jsonify(row)

    @app.get("/media/<identifier>/<variant>")
    def media(identifier, variant):
        if variant not in {"image.jpg", "thumb.jpg"}:
            abort(404)
        get_one(db.images, identifier)
        return send_from_directory(data_dir / "images" / identifier, variant)

    @app.get("/api/inspections")
    def history():
        def product_name(row):
            field = (row["result"].get("fields") or {}).get("product") or {}
            current = field.get("value", "") if isinstance(field, dict) else ""
            if isinstance(current, str) and current.strip():
                return current
            # Display-only fallback from this inspection's original evidence.
            # Do not substitute a standard's answer or write a historical result.
            from validation import ALIASES
            lines = (row.get("ocr") or {}).get("lines", [])
            try:
                candidate = extract_fields(lines).get("product", {})
                value = candidate.get("value", "")
                ids = set(candidate.get("line_ids", []))
                headed = any(line.get("id") in ids and re.match(r"^\s*"+ALIASES["product"], line.get("text", "")) for line in lines)
                numeric_date_or_phone = re.fullmatch(r"(?:民國)?[()（）\d\s:：./\-年月日時时分]+", value)
                return value if headed and not candidate.get("ambiguous") and not numeric_date_or_phone else ""
            except (KeyError, TypeError, ValueError, IndexError):
                return ""  # One incomplete old OCR row must not break history.
        try:
            page = max(1, int(request.args.get("page", 1)))
        except ValueError:
            abort(400, description="頁碼不正確。")
        history_status.ensure_index(engine)
        verdict = history_status.status_column(db.inspections)
        query = select(db.inspections.c.id, db.inspections.c.image_id, verdict.label("status"),
                       history_status.summary_column(db.inspections).label("display_summary"),
                       db.inspections.c.template_snapshot, db.inspections.c.created_at, db.inspections.c.result,
                       db.inspections.c.ocr).where(history_cleanup.active_filter())
        status = request.args.get("status")
        status = status if status in {"pass", "fail", "review"} else None
        if status:
            query = query.where(verdict == status)
        with engine.connect() as conn:
            rows = conn.execute(query.order_by(db.inspections.c.created_at.desc(), db.inspections.c.id).offset((page - 1) * 24).limit(25)).mappings().all()
            manual = corrections.latest_summaries(conn, [x["id"] for x in rows[:24]])
            item_days, day_counts, today = history_cleanup.day_summary(conn, rows[:24], status)
        return jsonify(items=[dict(id=x["id"], status=x["status"], name=x["template_snapshot"]["name"],
            version=x["template_snapshot"]["version"], created_at=x["created_at"], day=item_days[x["id"]], image=image_payload(x["image_id"]),
            **(x["display_summary"] or history_status.result_summary(x["result"])),
            base_date=x["result"].get("inputs",{}).get("base_date",""),
            product=product_name(x),
            manual_revision=manual.get(x["id"], {}).get("revision", 0),
            manual_status=manual.get(x["id"], {}).get("status"),
            manual_counts=manual.get(x["id"], {}).get("counts"),
            manual_issue_reasons=manual.get(x["id"], {}).get("issue_reasons", [])) for x in rows[:24]],
            has_more=len(rows) > 24, page=page, day_counts=day_counts, today=today)

    def inspection_payload(original):
        row = dict(original)
        identifier = row["id"]
        row["result"] = history_status.project(row["result"], row["ocr"], row["template_snapshot"])
        row["status"] = row["result"].get("status", row["status"])
        row["image"] = image_payload(row["image_id"])
        row["reference_image"] = image_payload(row["template_snapshot"]["image_id"])
        with engine.connect() as conn:
            row["reviews"] = [dict(x) for x in conn.execute(select(db.reviews).where(db.reviews.c.inspection_id == identifier).order_by(db.reviews.c.created_at)).mappings()]
            latest_revision = corrections.latest(conn, identifier)
        row["manual_revision"] = corrections.public_revision(latest_revision, row["template_snapshot"])
        recent = {"items": [], "has_more": False}
        if latest_revision:
            history_status.ensure_index(engine, identifier)
            with engine.connect() as conn:
                recent = corrections.history(conn, identifier, size=10)
        row["correction_history"] = recent["items"]
        row["correction_history_has_more"] = recent["has_more"]
        row["manual_standard_eligibility"] = draft_eligibility(row.get("ocr"),
            (row.get("manual_revision") or {}).get("patches"), row.get("result"))
        return row

    @app.get("/api/inspections/<identifier>")
    def inspection(identifier):
        return jsonify(inspection_payload(get_one(db.inspections, identifier)))

    @app.get("/api/inspections/<identifier>/corrections")
    def correction_history(identifier):
        get_one(db.inspections, identifier)
        try:
            page = int(request.args.get("page", 1))
            if not 1 <= page <= 1_000_000:
                raise ValueError()
        except ValueError:
            abort(400, description="頁碼不正確。")
        history_status.ensure_index(engine, identifier)
        with engine.connect() as conn:
            return jsonify(corrections.history(conn, identifier, page=page))

    @app.post("/api/inspections/<identifier>/corrections")
    def add_correction(identifier):
        body = request.get_json(silent=True)
        try:
            with correction_lock, engine.begin() as conn:
                original = conn.execute(select(db.inspections).where(db.inspections.c.id == identifier)
                    .with_for_update()).mappings().first()
                if original is None:
                    abort(404, description="找不到這筆資料。")
                history_cleanup.ensure_active(conn, identifier)
                original = dict(original)
                action = corrections.validate_request(body, original)
                current = corrections.latest(conn, identifier)
                if action["base_revision"] != (current["revision"] if current else 0):
                    abort(409, description="其他人已儲存新的訂正，請載入最新版本後再確認。")
                revision = corrections.build_revision(original, current, action, db.now())
                conn.execute(insert(db.corrections).values(**revision))
        except corrections.CorrectionInputError as exc:
            abort(400, description=str(exc))
        except IntegrityError:
            abort(409, description="訂正版本已更新，請載入最新版本後再確認。")
        return jsonify(inspection_payload(original)), 201

    @app.post("/api/inspections/<identifier>/reviews")
    def add_review(identifier):
        get_one(db.inspections, identifier)
        body = request.get_json(silent=True) or {}
        if body.get("decision") not in {"confirmed_good", "confirmed_bad", "retake"}:
            abort(400, description="請選擇複核結果。")
        reviewer, note = str(body.get("reviewer", "")).strip(), str(body.get("note", "")).strip()
        if not reviewer or len(reviewer) > 100 or not note or len(note) > 2000:
            abort(400, description="請填寫複核人員與原因（原因最多 2,000 字）。")
        row = dict(id=db.uid(), inspection_id=identifier, decision=body["decision"], reviewer=reviewer, note=note, created_at=db.now())
        with engine.begin() as conn:
            conn.execute(select(db.inspections.c.id).where(db.inspections.c.id == identifier).with_for_update()).first()
            history_cleanup.ensure_active(conn, identifier)
            conn.execute(insert(db.reviews).values(**row))
        return jsonify(row), 201

    @app.post("/api/inspections/<identifier>/recheck")
    def recheck(identifier):
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="請確認核對設定。")
        inputs = scan_inputs(body)
        template_id = body.get("template_id", "")
        if not isinstance(template_id, str) or len(template_id) > 80 or any(ord(char) < 32 for char in template_id):
            abort(400, description="照片標準代碼不正確。")
        template_id = template_id.strip()
        if template_id and inputs["source_code"]:
            abort(400, description="請選擇一份標準後再重新核對。")
        new_id = db.uid()
        copied_from = None
        with correction_lock, engine.begin() as conn:
            original = conn.execute(select(db.inspections).where(db.inspections.c.id == identifier)
                .with_for_update()).mappings().first()
            if original is None:
                abort(404, description="找不到這筆資料。")
            history_cleanup.ensure_active(conn, identifier)
            # Existing standard edits/reference attachments lock inspection
            # before manual source; keep the same order for PostgreSQL.
            ensure_explicit_source(inputs["source_code"], conn)
            original = dict(original)
            current = corrections.latest(conn, identifier)
            active = current if current and current["patches"] else None
            if template_id:
                standard_library.ensure_selectable(conn, template_id=template_id)
                standard = dict(conn.execute(select(db.templates).where(db.templates.c.id == template_id)
                    .with_for_update()).mappings().one())
                inputs["template_id"] = template_id
                result = evaluate(original["ocr"]["lines"], standard, inputs["batch_date"], inputs["arrival_date"],
                                  base_date=inputs["base_date"])
                augment(result, original["ocr"])
                result["inputs"] = inputs
            else:
                standard, result = check_source(original["ocr"]["lines"], inputs, original["ocr"],
                    match_lines=active["ocr"]["lines"] if active else None)
                ensure_result_standard(conn, standard)
            result["recheck_of"] = identifier
            result["recognition_reused"] = True
            fresh = dict(id=new_id, image_id=original["image_id"],
                template_id=template_id, template_snapshot=standard, status=result["status"],
                result=result, ocr=original["ocr"], created_at=db.now())
            conn.execute(insert(db.inspections).values(**fresh))
            if active:
                copied_from = {"inspection_id":identifier, "revision":active["revision"]}
                revision = corrections.build_revision(fresh, {"revision":0, "patches":active["patches"]},
                    {"operation":"copy", "reviewer":active["reviewer"], "note":"重新核對時沿用已儲存的人工訂正。",
                     "copied_from":copied_from}, db.now())
                conn.execute(insert(db.corrections).values(**revision))
        return jsonify(inspection_id=new_id, manual_revision=1 if copied_from else 0, copied_from=copied_from), 201

    @app.get("/api/inspections/<identifier>/barcode-rule")
    def get_barcode_rule(identifier):
        return jsonify(barcode_rule_authoring.suggest(engine, identifier))

    @app.post("/api/inspections/<identifier>/barcode-rule/preview")
    def preview_barcode_rule(identifier):
        access.require_admin()
        return jsonify(barcode_rule_authoring.preview(engine, identifier, request.get_json(silent=True)))

    @app.post("/api/inspections/<identifier>/barcode-rule")
    def save_barcode_rule(identifier):
        access.require_admin()
        return jsonify(barcode_rule_authoring.save(engine, identifier, request.get_json(silent=True))), 201

    standard_reference.register_routes(app, engine)
    history_cleanup.register_routes(app, engine, access.require_admin)
    pending_drafts.register_routes(app, engine, access.require_admin)
    standard_library.register_routes(app, engine, access.require_admin, image_payload)
    recognition_samples.register_routes(app, engine, access.require_admin, data_dir)
    reference_photos.register_routes(app,engine,access.require_admin,
        lambda identifier:get_one(db.inspections,identifier),image_payload,
        lambda identifier:recognition_samples._image_available(data_dir,identifier))
    return app
