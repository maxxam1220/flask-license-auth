from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import io
import os
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

register_heif_opener()
Image.MAX_IMAGE_PIXELS = 32_000_000
ROOT = Path(__file__).resolve().parent


def create_app(config=None, ocr=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    data_dir = Path(os.environ.get("LABELCHECK_DATA_DIR", ROOT / "data"))
    app.config.update(DATA_DIR=data_dir, DATABASE_URL=os.environ.get("LABELCHECK_DATABASE_URL", ""),
        APP_PASSWORD=os.environ.get("LABELCHECK_PASSWORD", ""),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024, MAX_FORM_MEMORY_SIZE=128 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("LABELCHECK_HTTPS", "") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8))
    if config:
        app.config.update(config)
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
    engine = db.open_database(app.config["DATABASE_URL"], data_dir)
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

    def check_source(lines, inputs, ocr_info=None, match_lines=None):
        scope = analyze_label_scope(lines)
        match = ({"status": "scope_review", "reason": scope["reason"], "candidates": []}
                 if scope["blocked"] else
                 label_source.resolve(engine, lines if match_lines is None else match_lines, inputs["source_code"]))
        source = prepare_source(match.get("source"), inputs["base_date"])
        prefix = {"catalog": "清單比對", "manual": "人工文字標準"}.get((source or {}).get("source_kind"), "系統標籤")
        standard = {"id": "", "name": f"{prefix} {source['code']} · {source['name']}" if source else "直接掃描・文字與日期檢查",
                    "version": 0, "image_id": "", "mode": "system_label", "source": source}
        result = evaluate_source(lines, source, inputs["batch_date"], inputs["arrival_date"], base_date=inputs["base_date"],
                                 ocr_capabilities=(ocr_info or {}).get("capabilities"))
        result["source_match"] = {key: value for key, value in match.items() if key != "source"}
        result["inputs"] = inputs
        return standard, result

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
            if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.get("csrf", "invalid")):
                abort(403, description="頁面已過期，請重新整理後再試。")

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
        session.setdefault("csrf", secrets.token_urlsafe(32))
        return jsonify(csrf=session["csrf"], requires_login=bool(app.config["APP_PASSWORD"]), authenticated=not app.config["APP_PASSWORD"] or bool(session.get("authenticated")))

    login_attempts = {}
    login_lock = threading.Lock()

    @app.post("/api/login")
    def login():
        import time
        addr = request.remote_addr
        with login_lock:
            recent = [t for t in login_attempts.get(addr, []) if time.monotonic() - t < 300]
            if len(recent) >= 10:
                abort(429, description="嘗試次數過多，請 5 分鐘後再試。")
            login_attempts[addr] = recent + [time.monotonic()]
        body = request.get_json(silent=True) or {}
        password = body.get("password", "")
        if not isinstance(password, str) or not secrets.compare_digest(password.encode(), app.config["APP_PASSWORD"].encode()):
            abort(401, description="登入密碼不正確。")
        session.clear()
        session.update(authenticated=True, csrf=secrets.token_urlsafe(32))
        session.permanent = True
        return jsonify(csrf=session["csrf"], authenticated=True)

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/templates")
    def list_templates():
        with engine.connect() as conn:
            rows = conn.execute(select(db.templates).where(db.templates.c.active.is_(True)).order_by(db.templates.c.created_at.desc())).mappings().all()
        return jsonify(items=[template_payload(x) for x in rows])

    @app.get("/api/scan-config")
    def scan_config():
        return jsonify(standards=[], version=RULE_VERSION, mode="system_label", today=taiwan_today())

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
                arrival = parse_date(reference_dates.get("arrival", ""))
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
                if body.get("supersedes_id"):
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
        try:
            with engine.begin() as conn:
                conn.execute(update(db.jobs).where(db.jobs.c.id == job["id"]).values(state="running"))
            with image_lock:
                ocr_result = recognizer.recognize(data_dir / "images" / job["image_id"] / "image.jpg")
            saved_request = (job.get("result") or {}).get("request", {})
            inputs = {"batch_date": job["batch_date"], "arrival_date": saved_request.get("arrival_date", ""),
                      "source_code": saved_request.get("source_code", ""),
                      "base_date": saved_request.get("base_date") or taiwan_today()}
            result = {"ocr": ocr_result, "fields": extract_fields(ocr_result["lines"]), "request": inputs}
            for key in ("retry_of", "retry_root"):
                if (job.get("result") or {}).get(key):
                    result[key] = job["result"][key]
            source_evaluation = None
            if job["kind"] == "recognition":
                source_evaluation = check_source(ocr_result["lines"], inputs, ocr_result)
            with engine.begin() as conn:
                if job["kind"] in {"inspection", "recognition"}:
                    if job["kind"] == "inspection":
                        standard = dict(conn.execute(select(db.templates).where(db.templates.c.id == job["template_id"])).mappings().one())
                        evaluation = evaluate(ocr_result["lines"], standard, inputs["batch_date"], inputs["arrival_date"])
                    else:
                        standard, evaluation = source_evaluation
                    evaluation["inputs"] = inputs
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
        kind = request.form.get("kind")
        if kind not in {"reference", "inspection", "recognition"} or "photo" not in request.files:
            abort(400, description="請選擇照片。")
        template_id = request.form.get("template_id", "")
        inputs = scan_inputs(request.form)
        source_code = inputs["source_code"]
        if source_code and (kind != "recognition" or template_id):
            abort(400, description="請選擇系統標籤或照片標準其中一種。")
        if kind == "inspection":
            standard = get_one(db.templates, template_id)
            if not standard["active"]:
                abort(409, description="標準已更新，請重新選擇。")
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
            with engine.begin() as conn:
                conn.execute(insert(db.jobs).values(**row))
            worker.submit(process_job, row)
        except Exception:
            slots.release()
            raise
        return jsonify(id=row["id"], image=image_payload(image["id"])), 202

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
            if original["state"] != "failed":
                abort(409, description="這張照片並非失敗狀態，請查看原本辨識結果。")
            root = (original.get("result") or {}).get("retry_root") or original["id"]
            with engine.connect() as conn:
                existing = conn.execute(select(db.jobs).where(
                    db.jobs.c.result["retry_root"].as_string() == root,
                    db.jobs.c.state.in_(["pending", "running", "done"])
                ).order_by(db.jobs.c.created_at.desc()).limit(1)).mappings().first()
            if existing:
                return jsonify(id=existing["id"], image=image_payload(existing["image_id"])), 202
            if not (data_dir / "images" / original["image_id"] / "image.jpg").is_file():
                abort(404, description="原照片已不存在，請重新上傳。")
            if original["kind"] == "inspection":
                standard = get_one(db.templates, original["template_id"])
                if not standard["active"]:
                    abort(409, description="原標準已更新，請選擇新版標準後重新上傳。")
            inputs = dict((original.get("result") or {}).get("request") or {})
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
                with engine.begin() as conn:
                    conn.execute(insert(db.jobs).values(**row))
                worker.submit(process_job, row)
            except Exception:
                slots.release()
                raise
            return jsonify(id=row["id"], image=image_payload(row["image_id"])), 202

    @app.get("/api/jobs/<identifier>")
    def job_status(identifier):
        row = get_one(db.jobs, identifier)
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
        try:
            page = max(1, int(request.args.get("page", 1)))
        except ValueError:
            abort(400, description="頁碼不正確。")
        query = select(db.inspections.c.id, db.inspections.c.image_id, db.inspections.c.status,
                       db.inspections.c.template_snapshot, db.inspections.c.created_at)
        if request.args.get("status") in {"pass", "fail", "review"}:
            query = query.where(db.inspections.c.status == request.args["status"])
        with engine.connect() as conn:
            rows = conn.execute(query.order_by(db.inspections.c.created_at.desc()).offset((page - 1) * 24).limit(25)).mappings().all()
            manual = corrections.latest_summaries(conn, [x["id"] for x in rows[:24]])
        return jsonify(items=[dict(id=x["id"], status=x["status"], name=x["template_snapshot"]["name"],
            version=x["template_snapshot"]["version"], created_at=x["created_at"], image=image_payload(x["image_id"]),
            manual_revision=manual.get(x["id"], {}).get("revision", 0),
            manual_status=manual.get(x["id"], {}).get("status")) for x in rows[:24]],
            has_more=len(rows) > 24, page=page)

    def inspection_payload(original):
        row = dict(original)
        identifier = row["id"]
        row["image"] = image_payload(row["image_id"])
        row["reference_image"] = image_payload(row["template_snapshot"]["image_id"])
        with engine.connect() as conn:
            row["reviews"] = [dict(x) for x in conn.execute(select(db.reviews).where(db.reviews.c.inspection_id == identifier).order_by(db.reviews.c.created_at)).mappings()]
            row["manual_revision"] = corrections.public_revision(corrections.latest(conn, identifier))
            recent = corrections.history(conn, identifier, size=10)
            row["correction_history"] = recent["items"]
            row["correction_history_has_more"] = recent["has_more"]
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
            conn.execute(insert(db.reviews).values(**row))
        return jsonify(row), 201

    @app.post("/api/inspections/<identifier>/recheck")
    def recheck(identifier):
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="請確認核對設定。")
        inputs = scan_inputs(body)
        new_id = db.uid()
        copied_from = None
        with correction_lock, engine.begin() as conn:
            original = conn.execute(select(db.inspections).where(db.inspections.c.id == identifier)
                .with_for_update()).mappings().first()
            if original is None:
                abort(404, description="找不到這筆資料。")
            original = dict(original)
            current = corrections.latest(conn, identifier)
            active = current if current and current["patches"] else None
            standard, result = check_source(original["ocr"]["lines"], inputs, original["ocr"],
                match_lines=active["ocr"]["lines"] if active else None)
            result["recheck_of"] = identifier
            result["recognition_reused"] = True
            fresh = dict(id=new_id, image_id=original["image_id"],
                template_id="", template_snapshot=standard, status=result["status"],
                result=result, ocr=original["ocr"], created_at=db.now())
            conn.execute(insert(db.inspections).values(**fresh))
            if active:
                copied_from = {"inspection_id":identifier, "revision":active["revision"]}
                revision = corrections.build_revision(fresh, {"revision":0, "patches":active["patches"]},
                    {"operation":"copy", "reviewer":active["reviewer"], "note":"重新核對時沿用已儲存的人工訂正。",
                     "copied_from":copied_from}, db.now())
                conn.execute(insert(db.corrections).values(**revision))
        return jsonify(inspection_id=new_id, manual_revision=1 if copied_from else 0, copied_from=copied_from), 201

    standard_reference.register_routes(app, engine)
    return app
