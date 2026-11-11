from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import io
import os
import secrets
import threading
import warnings

from flask import Flask, jsonify, request, session, send_from_directory, abort
from PIL import Image, ImageOps, UnidentifiedImageError
from pillow_heif import register_heif_opener
from sqlalchemy import select, insert, update, func
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

import database as db
from ocr_worker import IsolatedOCR
from validation import extract_fields, evaluate, parse_date, recognize_only, TEXT_FIELDS, BUILTIN_STANDARDS, RULE_VERSION
import label_source

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
    recognizer = ocr or IsolatedOCR(ROOT / "models")
    app.extensions.update(label_engine=engine, label_worker=worker)
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
        return jsonify(standards=BUILTIN_STANDARDS, version=RULE_VERSION)

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
        normalized.thumbnail((2400, 2400))
        normalized.save(folder / "image.jpg", quality=95)
        thumbnail = normalized.copy()
        thumbnail.thumbnail((420, 420))
        thumbnail.save(folder / "thumb.jpg", quality=85)
        row = dict(id=identifier, created_at=db.now(), filename=(upload.filename or "photo")[:255],
                   sha256=hashlib.sha256(raw).hexdigest(), width=normalized.width, height=normalized.height)
        with engine.begin() as conn:
            conn.execute(insert(db.images).values(**row))
        return row

    def process_job(job):
        try:
            with engine.begin() as conn:
                conn.execute(update(db.jobs).where(db.jobs.c.id == job["id"]).values(state="running"))
            with image_lock:
                ocr_result = recognizer.recognize(data_dir / "images" / job["image_id"] / "image.jpg")
            inputs = {"batch_date": job["batch_date"], "arrival_date": (job.get("result") or {}).get("request", {}).get("arrival_date", "")}
            result = {"ocr": ocr_result, "fields": extract_fields(ocr_result["lines"]), "request": inputs}
            with engine.begin() as conn:
                if job["kind"] in {"inspection", "recognition"}:
                    if job["kind"] == "inspection":
                        standard = dict(conn.execute(select(db.templates).where(db.templates.c.id == job["template_id"])).mappings().one())
                        evaluation = evaluate(ocr_result["lines"], standard, inputs["batch_date"], inputs["arrival_date"])
                    else:
                        standard = {"id": "", "name": "直接掃描・固定文字與日期檢查", "version": 0, "image_id": "", "mode": "recognition"}
                        evaluation = recognize_only(ocr_result["lines"], inputs["batch_date"], inputs["arrival_date"])
                    evaluation["inputs"] = inputs
                    inspection_id = db.uid()
                    conn.execute(insert(db.inspections).values(id=inspection_id, image_id=job["image_id"],
                        template_id=standard["id"], template_snapshot=standard, status=evaluation["status"],
                        result=evaluation, ocr=ocr_result, created_at=db.now()))
                    result["inspection_id"] = inspection_id
                conn.execute(update(db.jobs).where(db.jobs.c.id == job["id"]).values(state="done", result=result))
        except Exception:
            app.logger.exception("OCR job failed")
            with engine.begin() as conn:
                conn.execute(update(db.jobs).where(db.jobs.c.id == job["id"]).values(state="failed", error="照片辨識失敗。請稍後重新上傳，或改用更清楚的照片。"))
        finally:
            slots.release()

    @app.post("/api/jobs")
    def create_job():
        kind = request.form.get("kind")
        if kind not in {"reference", "inspection", "recognition"} or "photo" not in request.files:
            abort(400, description="請選擇照片。")
        template_id = request.form.get("template_id", "")
        if kind == "inspection":
            standard = get_one(db.templates, template_id)
            if not standard["active"]:
                abort(409, description="標準已更新，請重新選擇。")
        batch = request.form.get("batch_date", "")
        if batch:
            try:
                date.fromisoformat(batch)
            except ValueError:
                abort(400, description="本批製造日期格式不正確。")
        arrival = request.form.get("arrival_date", "")
        if arrival:
            try:
                if date.fromisoformat(arrival).isoformat() != arrival:
                    raise ValueError()
            except ValueError:
                abort(400, description="本批到店日期格式不正確。")
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
                       result={"request": {"batch_date": batch, "arrival_date": arrival}})
            with engine.begin() as conn:
                conn.execute(insert(db.jobs).values(**row))
            worker.submit(process_job, row)
        except Exception:
            slots.release()
            raise
        return jsonify(id=row["id"], image=image_payload(image["id"])), 202

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
        return jsonify(items=[dict(id=x["id"], status=x["status"], name=x["template_snapshot"]["name"],
            version=x["template_snapshot"]["version"], created_at=x["created_at"], image=image_payload(x["image_id"])) for x in rows[:24]],
            has_more=len(rows) > 24, page=page)

    @app.get("/api/inspections/<identifier>")
    def inspection(identifier):
        row = get_one(db.inspections, identifier)
        row["image"] = image_payload(row["image_id"])
        row["reference_image"] = image_payload(row["template_snapshot"]["image_id"])
        with engine.connect() as conn:
            row["reviews"] = [dict(x) for x in conn.execute(select(db.reviews).where(db.reviews.c.inspection_id == identifier).order_by(db.reviews.c.created_at)).mappings()]
        return jsonify(row)

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

    return app
