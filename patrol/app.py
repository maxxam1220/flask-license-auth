"""Factory patrol: QR confirmation, approved browsers and durable records."""
from datetime import date, datetime, time, timedelta, timezone
from functools import wraps
import csv
import hashlib
import hmac
import io
import os
from pathlib import Path
import re
import secrets
from types import SimpleNamespace
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import click
from flask import Flask, abort, flash, g, make_response, redirect, render_template, request, session, url_for
import qrcode
import qrcode.image.svg
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix

from models import AuditLog, DeviceBinding, Inspection, LoginAttempt, Point, PointSchedule, User, db

TAIPEI = ZoneInfo("Asia/Taipei")
DEVICE_COOKIE = "patrol_device"


def now_utc():
    return datetime.now(timezone.utc)


def naive_utc(value=None):
    value = value or now_utc()
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def local_dt(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(TAIPEI)


def hash_device_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def period_for(point, instant):
    local_day = local_dt(instant).date()
    if point.frequency == "weekly":
        local_day -= timedelta(days=local_day.weekday())
    start = datetime.combine(local_day, time.min, TAIPEI)
    end = start + timedelta(days=7 if point.frequency == "weekly" else 1)
    return local_day.isoformat(), start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def create_app(config=None):
    instance = Path(__file__).resolve().parent / "instance"
    instance.mkdir(exist_ok=True)
    app = Flask(__name__, instance_path=str(instance))
    production = os.environ.get("APP_ENV", "development") == "production"
    provided = config or {}
    secret = provided.get("SECRET_KEY") or os.environ.get("SECRET_KEY")
    if not secret and not production:
        secret_path = instance / "secret.key"
        try:
            with secret_path.open("x", encoding="utf-8") as fp:
                fp.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        secret = secret_path.read_text(encoding="utf-8").strip()
    database_url = os.environ.get("DATABASE_URL", "sqlite:///patrol.sqlite3")
    if database_url.startswith("postgres://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
    elif database_url.startswith("postgresql://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]
    app.config.update(
        SECRET_KEY=secret,
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        PUBLIC_BASE_URL=(os.environ.get("PUBLIC_BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "http://127.0.0.1:5087").rstrip("/"),
        APP_ENV="production" if production else "development",
        COOKIE_SECURE=production,
        SESSION_COOKIE_NAME="patrol_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
        MAX_CONTENT_LENGTH=128 * 1024,
        CSRF_ENABLED=True,
        DEMO_MODE=os.environ.get("DEMO_MODE", "0") == "1",
    )
    app.config.update(provided)
    app.config["SESSION_COOKIE_SECURE"] = app.config["COOKIE_SECURE"]
    if app.config["APP_ENV"] == "production":
        if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
            raise RuntimeError("Production requires a SECRET_KEY of at least 32 characters.")
        if not app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql"):
            raise RuntimeError("Production requires a PostgreSQL DATABASE_URL.")
        parsed_base = urlsplit(app.config["PUBLIC_BASE_URL"])
        if parsed_base.scheme != "https" or not parsed_base.hostname or parsed_base.username or parsed_base.query or parsed_base.fragment or parsed_base.path not in ("", "/"):
            raise RuntimeError("Production PUBLIC_BASE_URL must be the HTTPS site origin.")
        if app.config["DEMO_MODE"] or not app.config["COOKIE_SECURE"]:
            raise RuntimeError("Production cannot enable demo mode or insecure cookies.")
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    db.init_app(app)

    @app.template_filter("localtime")
    def format_localtime(value):
        return local_dt(value).strftime("%Y-%m-%d %H:%M:%S") if value else "—"

    @app.template_filter("shorttime")
    def format_shorttime(value):
        return local_dt(value).strftime("%H:%M") if value else "—"

    @app.template_filter("localdate")
    def format_localdate(value):
        if isinstance(value, datetime):
            value = local_dt(value).date()
        return value.strftime("%Y-%m-%d") if value else "—"

    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.context_processor
    def common_context():
        return {"current_user": g.get("user"), "csrf_token": csrf_token, "today": local_dt(now_utc()).date()}

    @app.before_request
    def load_user_and_protect():
        g.user = None
        if session.get("user_id"):
            user = db.session.get(User, session["user_id"])
            if user and user.active and session.get("auth_version") == user.auth_version:
                g.user = user
            else:
                session.clear()
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and app.config["CSRF_ENABLED"]:
            expected = session.get("csrf_token", "")
            received = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not expected or not received or not hmac.compare_digest(expected, received):
                abort(400, description="表單已過期，請重新載入頁面後再試。")
        if g.user and g.user.must_change_password and request.endpoint not in ("change_password", "logout", "static", "healthz"):
            return redirect(url_for("change_password"))

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        if app.config["COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login", next=request.full_path.rstrip("?")))
            return fn(*args, **kwargs)
        return wrapped

    def admin_required(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user.role != "admin":
                abort(403, description="此功能僅限管理員使用。")
            return fn(*args, **kwargs)
        return wrapped

    def audit(action, target="", detail=""):
        db.session.add(AuditLog(actor_id=g.user.id if g.get("user") else None, action=action, target=str(target), detail=detail))

    def lock_user(user_id):
        return db.session.scalar(select(User).where(User.id == user_id).with_for_update().execution_options(populate_existing=True))

    def device_binding():
        token = request.cookies.get(DEVICE_COOKIE, "")
        if not g.user or not token or len(token) > 256:
            return None
        return db.session.scalar(select(DeviceBinding).where(DeviceBinding.user_id == g.user.id, DeviceBinding.token_hash == hash_device_token(token)))

    def device_status():
        binding = device_binding()
        return binding.status if binding else "none"

    def parse_date(value, default):
        if not value:
            return default
        try:
            parsed = date.fromisoformat(value)
            if not 2000 <= parsed.year <= 2100:
                raise ValueError("unsupported year")
            return parsed
        except ValueError:
            abort(400, description="日期格式不正確。")

    def safe_next(value):
        return value if value and value.startswith("/") and not value.startswith("//") and "\\" not in value and not any(ord(c) < 32 for c in value) else url_for("dashboard")

    @app.get("/healthz")
    def healthz():
        db.session.execute(db.text("SELECT 1"))
        return {"status": "ok"}

    @app.get("/")
    def index():
        return redirect(url_for("dashboard") if g.user else url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()[:80]
            # Scope the limit to the account and source, so a shared factory
            # connection does not lock out all employees after one user's errors.
            attempt_key = hashlib.sha256((username + "|" + (request.remote_addr or "unknown")).encode()).hexdigest()
            cutoff = naive_utc() - timedelta(minutes=15)
            attempts = db.session.scalar(select(db.func.count(LoginAttempt.id)).where(LoginAttempt.key == attempt_key, LoginAttempt.created_at >= cutoff))
            if attempts >= 15:
                abort(429, description="登入嘗試過多，請於 15 分鐘後再試。")
            user = db.session.scalar(select(User).where(User.username == username))
            if not user or not user.active or not user.check_password(request.form.get("password", "")):
                db.session.execute(db.delete(LoginAttempt).where(LoginAttempt.created_at < cutoff))
                db.session.add(LoginAttempt(key=attempt_key, created_at=naive_utc()))
                db.session.commit()
                flash("帳號或密碼不正確，或帳號已停用。", "error")
            else:
                next_url = safe_next(request.form.get("next") or request.args.get("next"))
                session.clear()
                session["user_id"] = user.id
                session["auth_version"] = user.auth_version
                session.permanent = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                if user.must_change_password:
                    session["after_password"] = next_url
                    return redirect(url_for("change_password"))
                return redirect(next_url)
        return render_template("login.html", next=safe_next(request.args.get("next")))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            lock_user(g.user.id)
            password = request.form.get("new_password", "")
            if not g.user.check_password(request.form.get("current_password", "")):
                flash("目前密碼不正確。", "error")
            elif len(password) < 12 or len(password) > 256:
                flash("新密碼請使用 12 至 256 個字元。", "error")
            elif password != request.form.get("confirm_password"):
                flash("兩次輸入的新密碼不同。", "error")
            elif g.user.check_password(password):
                flash("新密碼不可與目前密碼相同，請設定不同的密碼。", "error")
            else:
                g.user.set_password(password)
                g.user.auth_version += 1
                g.user.must_change_password = False
                audit("change_password", g.user.id)
                db.session.commit()
                after = safe_next(session.pop("after_password", None))
                session["auth_version"] = g.user.auth_version
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash("密碼已更新。", "success")
                return redirect(after)
        return render_template("change_password.html")

    @app.get("/dashboard")
    @login_required
    def dashboard():
        today = local_dt(now_utc()).date()
        selected = parse_date(request.args.get("date"), today)
        view = request.args.get("view", "daily")
        if view not in ("daily", "weekly"):
            abort(400)
        monday = selected - timedelta(days=selected.weekday())
        period_day = monday if view == "weekly" else selected
        reference_day = min(monday + timedelta(days=6), today) if view == "weekly" else selected
        points = db.session.scalars(select(Point).order_by(Point.floor, Point.code)).all()
        floor_filter = request.args.get("floor", "")
        if floor_filter and floor_filter not in ("1", "2", "3", "4", "5"):
            abort(400)
        completions = db.session.scalars(select(Inspection).where(Inspection.period_key == period_day.isoformat(), Inspection.frequency == view)).all()
        found = {r.point_id: r for r in completions}
        cards, floors = [], [{"floor": f, "total": 0, "done": 0} for f in range(1, 6)]
        for point in points:
            record = found.get(point.id)
            schedule = next((s for s in reversed(point.schedules) if s.effective_date <= reference_day), None)
            frequency = schedule.frequency if schedule else point.frequency
            active = schedule.active if schedule else point.active
            if (frequency != view or not active) and not record:
                continue
            due = selected <= today and point.schedule_start <= reference_day
            status = "done" if record else ("pending" if due else "not_due")
            displayed_point = SimpleNamespace(id=point.id, code=record.point_code if record else point.code,
                                             name=record.point_name if record else point.name,
                                             floor=record.point_floor if record else point.floor, frequency=view)
            if due or record:
                floors[displayed_point.floor - 1]["total"] += 1
                floors[displayed_point.floor - 1]["done"] += int(record is not None)
            if not floor_filter or displayed_point.floor == int(floor_filter):
                # Progress is shared, but staff never receive another person's identity.
                visible_record = record if g.user.role == "admin" or (record and record.user_id == g.user.id) else None
                cards.append({"point": displayed_point, "status": status, "latest": visible_record, "period_label": f"{monday:%m/%d} – {monday + timedelta(days=6):%m/%d}" if view == "weekly" else selected.isoformat()})
        total = sum(c["status"] != "not_due" for c in cards)
        done = sum(c["status"] == "done" for c in cards)
        recent_query = select(Inspection).order_by(Inspection.created_at.desc()).limit(6)
        if g.user.role != "admin":
            recent_query = recent_query.where(Inspection.user_id == g.user.id)
        return render_template("dashboard.html", selected_date=selected, view=view, floors=floors, cards=cards, totals={"total": total, "done": done, "pending": total - done}, device_state=device_status(), recent=db.session.scalars(recent_query).all(), week_label=f"{monday:%m/%d} – {monday + timedelta(days=6):%m/%d}")

    def get_point(token, lock=False):
        query = select(Point).where(Point.qr_token == token)
        if lock:
            query = query.with_for_update()
        point = db.session.scalar(query)
        if not point:
            abort(404, description="巡檢點不存在，或這張 QR Code 已被更新。")
        if not point.active or point.schedule_start > local_dt(now_utc()).date():
            abort(403, description="此巡檢點目前尚未啟用或已停用。")
        return point

    @app.get("/c/<token>")
    @login_required
    def checkin(token):
        point = get_point(token)
        key, _, _ = period_for(point, now_utc())
        existing = db.session.scalar(select(Inspection).where(Inspection.point_id == point.id, Inspection.frequency == point.frequency, Inspection.period_key == key))
        return render_template("checkin.html", point=point, device_state=device_status(), existing=existing if not existing or g.user.role == "admin" or existing.user_id == g.user.id else {"created_at": existing.created_at, "user": {"display_name": "其他巡檢人員"}}, token=token)

    @app.post("/c/<token>/confirm")
    @login_required
    def confirm_checkin(token):
        # Serialize with approval/revocation for the same employee on PostgreSQL.
        locked_user = lock_user(g.user.id)
        if not locked_user.active or locked_user.must_change_password or locked_user.auth_version != session.get("auth_version"):
            abort(403, description="帳號狀態已更新，請重新登入。")
        binding = device_binding()
        if not binding or binding.status != "approved":
            abort(403, description="此瀏覽器尚未核准，請先申請綁定並由管理員核准。")
        point = get_point(token, lock=True)
        instant = now_utc()
        key, _, _ = period_for(point, instant)
        record = db.session.scalar(select(Inspection).where(Inspection.point_id == point.id, Inspection.frequency == point.frequency, Inspection.period_key == key))
        if record:
            flash("這個巡檢點本期已完成，沒有新增重複紀錄。", "info")
            return redirect(url_for("checkin_success", record_id=record.id)) if g.user.role == "admin" or record.user_id == g.user.id else redirect(url_for("checkin", token=token))
        record = Inspection(user_id=g.user.id, point_id=point.id, binding_id=binding.id, created_at=naive_utc(instant), period_key=key, frequency=point.frequency, point_code=point.code, point_name=point.name, point_floor=point.floor, user_name=g.user.display_name)
        db.session.add(record)
        binding.last_seen_at = naive_utc(instant)
        audit("checkin", point.code)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            record = db.session.scalar(select(Inspection).where(Inspection.point_id == point.id, Inspection.frequency == point.frequency, Inspection.period_key == key))
            if not record:
                raise
            flash("這個巡檢點本期已完成，沒有新增重複紀錄。", "info")
        if g.user.role != "admin" and record.user_id != g.user.id:
            return redirect(url_for("checkin", token=token))
        return redirect(url_for("checkin_success", record_id=record.id))

    @app.get("/checkins/<int:record_id>")
    @login_required
    def checkin_success(record_id):
        record = db.get_or_404(Inspection, record_id)
        if g.user.role != "admin" and record.user_id != g.user.id:
            abort(403)
        return render_template("checkin_success.html", record=record)

    @app.get("/devices")
    @login_required
    def devices():
        bindings = db.session.scalars(select(DeviceBinding).where(DeviceBinding.user_id == g.user.id).order_by(DeviceBinding.created_at.desc())).all()
        return render_template("devices.html", current_binding=device_binding(), bindings=bindings)

    @app.post("/devices/request")
    @login_required
    def request_device():
        binding = device_binding()
        if binding and binding.status in ("pending", "approved"):
            flash("此瀏覽器已經提出申請或已核准。", "info")
            return redirect(url_for("devices"))
        label = request.form.get("label", "我的手機").strip()
        if not label or len(label) > 100:
            abort(400, description="請填寫 1 至 100 字的裝置名稱。")
        pending = db.session.scalar(select(db.func.count(DeviceBinding.id)).where(DeviceBinding.user_id == g.user.id, DeviceBinding.status == "pending"))
        if pending >= 3:
            abort(400, description="已有三筆待審核申請，請先聯絡管理員處理。")
        token = secrets.token_urlsafe(32)
        binding = DeviceBinding(user_id=g.user.id, token_hash=hash_device_token(token), label=label, status="pending")
        db.session.add(binding)
        audit("device_requested", g.user.username, label)
        db.session.commit()
        response = redirect(url_for("devices"))
        response.set_cookie(DEVICE_COOKIE, token, max_age=365 * 86400, httponly=True, secure=app.config["COOKIE_SECURE"], samesite="Lax", path="/")
        flash("申請已送出，請管理員核准後再打卡。", "success")
        return response

    @app.post("/devices/<int:binding_id>/revoke")
    @login_required
    def revoke_own_device(binding_id):
        binding = db.get_or_404(DeviceBinding, binding_id)
        if binding.user_id != g.user.id:
            abort(403)
        lock_user(g.user.id)
        binding.status = "revoked"
        audit("device_self_revoked", binding.id)
        db.session.commit()
        flash("已解除此瀏覽器綁定。", "success")
        return redirect(url_for("devices"))

    @app.get("/admin/devices")
    @admin_required
    def admin_devices():
        bindings = db.session.scalars(select(DeviceBinding).order_by(db.case((DeviceBinding.status == "pending", 0), else_=1), DeviceBinding.created_at.desc())).all()
        return render_template("admin_devices.html", bindings=bindings)

    @app.post("/admin/devices/<int:binding_id>/approve")
    @admin_required
    def approve_device(binding_id):
        binding = db.get_or_404(DeviceBinding, binding_id)
        lock_user(binding.user_id)
        db.session.refresh(binding)
        if binding.status != "pending" or not binding.user.active:
            abort(400, description="此申請已處理或員工帳號已停用。")
        db.session.execute(db.update(DeviceBinding).where(DeviceBinding.user_id == binding.user_id, DeviceBinding.status == "approved").values(status="revoked"))
        db.session.flush()
        binding.status = "approved"
        binding.approved_at = naive_utc()
        audit("device_approved", binding.id, f"employee={binding.user_id}; previous approval revoked")
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            abort(409, description="裝置狀態已由另一位管理員更新，請重新整理。")
        flash("已核准此瀏覽器，舊的有效綁定已解除。", "success")
        return redirect(url_for("admin_devices"))

    @app.post("/admin/devices/<int:binding_id>/reject")
    @admin_required
    def reject_device(binding_id):
        binding = db.get_or_404(DeviceBinding, binding_id)
        lock_user(binding.user_id)
        db.session.refresh(binding)
        if binding.status != "pending":
            abort(400)
        binding.status = "rejected"
        audit("device_rejected", binding.id)
        db.session.commit()
        flash("已拒絕申請。", "success")
        return redirect(url_for("admin_devices"))

    @app.post("/admin/devices/<int:binding_id>/revoke")
    @admin_required
    def revoke_device(binding_id):
        binding = db.get_or_404(DeviceBinding, binding_id)
        lock_user(binding.user_id)
        binding.status = "revoked"
        audit("device_revoked", binding.id)
        db.session.commit()
        flash("已解除綁定。", "success")
        return redirect(url_for("admin_devices"))

    def record_query():
        today = local_dt(now_utc()).date()
        begin = parse_date(request.args.get("date_from"), today - timedelta(days=6))
        end = parse_date(request.args.get("date_to"), today)
        if begin > end or (end - begin).days > 366:
            abort(400, description="請選擇正確的日期範圍，最多可查詢 367 天。")
        start_time = datetime.combine(begin, time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
        end_time = datetime.combine(end + timedelta(days=1), time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
        query = select(Inspection).where(Inspection.created_at >= start_time, Inspection.created_at < end_time)
        floor = request.args.get("floor", "")
        user_id = request.args.get("user_id", "")
        if floor:
            if floor not in ("1", "2", "3", "4", "5"):
                abort(400)
            query = query.where(Inspection.point_floor == int(floor))
        if g.user.role != "admin":
            query = query.where(Inspection.user_id == g.user.id)
            user_id = str(g.user.id)
        elif user_id:
            if not user_id.isdigit():
                abort(400)
            query = query.where(Inspection.user_id == int(user_id))
        return query.order_by(Inspection.created_at.desc(), Inspection.id.desc()), {"date_from": begin.isoformat(), "date_to": end.isoformat(), "floor": floor, "user_id": user_id}

    @app.get("/records")
    @login_required
    def records():
        query, filters = record_query()
        rows = db.session.scalars(query.limit(1001)).all()
        if len(rows) > 1000:
            flash("畫面顯示最近 1,000 筆，完整資料請匯出 CSV 或縮小日期範圍。", "info")
        users = db.session.scalars(select(User).order_by(User.display_name)).all() if g.user.role == "admin" else []
        return render_template("records.html", records=rows[:1000], users=users, filters=filters)

    @app.get("/records/export")
    @login_required
    def export_records():
        query, filters = record_query()
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["人員", "樓層", "點位編號", "點位名稱", "打卡時間（台北）", "巡檢頻率", "週期開始日"])
        def cell(value):
            value = str(value)
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
        for row in db.session.scalars(query).yield_per(500):
            writer.writerow([cell(row.user_name or row.user.display_name), f"{row.point_floor}F", cell(row.point_code), cell(row.point_name), format_localtime(row.created_at), "每日" if row.frequency == "daily" else "每週", row.period_key])
        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="patrol-{filters["date_from"]}-{filters["date_to"]}.csv"'
        return response

    @app.get("/admin/points")
    @admin_required
    def points():
        return render_template("points.html", points=db.session.scalars(select(Point).order_by(Point.floor, Point.code)).all())

    def point_values():
        code = request.form.get("code", "").strip().upper()
        name = request.form.get("name", "").strip()
        floor = request.form.get("floor", "")
        frequency = request.form.get("frequency", "daily")
        if floor not in ("1", "2", "3", "4", "5") or not re.fullmatch(r"[1-5]F-[A-Z0-9]{2,20}", code) or not code.startswith(floor + "F-"):
            abort(400, description="點位編號請使用如 1F-A01 的格式，並與樓層一致。")
        if not name or len(name) > 100 or frequency not in ("daily", "weekly"):
            abort(400, description="請填寫點位名稱（最多 100 字）與正確的巡檢頻率。")
        return {"code": code, "name": name, "floor": int(floor), "frequency": frequency}

    def save_point(point, action):
        audit(action, point.code)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            abort(400, description="點位編號已存在，請使用不同的編號。")
        flash("點位設定已儲存。", "success")
        return redirect(url_for("points"))

    @app.post("/admin/points/create")
    @admin_required
    def create_point():
        point = Point(**point_values(), active=True, schedule_start=local_dt(now_utc()).date())
        db.session.add(point)
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=point.frequency, active=True))
        return save_point(point, "point_created")

    @app.post("/admin/points/<int:point_id>/update")
    @admin_required
    def update_point(point_id):
        point = db.session.scalar(select(Point).where(Point.id == point_id).with_for_update())
        if not point:
            abort(404)
        values = point_values()
        active = request.form.get("active", "") in ("on", "1", "true", "yes")
        if point.frequency != values["frequency"] or point.active != active:
            point.schedules.append(PointSchedule(effective_date=local_dt(now_utc()).date(), frequency=values["frequency"], active=active))
        for key, value in values.items():
            setattr(point, key, value)
        point.active = active
        return save_point(point, "point_updated")

    @app.post("/admin/points/<int:point_id>/rotate-qr")
    @admin_required
    def rotate_point_qr(point_id):
        point = db.session.scalar(select(Point).where(Point.id == point_id).with_for_update())
        if not point:
            abort(404)
        point.qr_token = secrets.token_urlsafe(24)
        audit("qr_rotated", point.code)
        db.session.commit()
        flash("QR Code 已更新，舊碼已失效。請重新列印並更換現場標籤。", "success")
        return redirect(url_for("points"))

    @app.get("/admin/points/<int:point_id>/qr.svg")
    @admin_required
    def point_qr(point_id):
        point = db.get_or_404(Point, point_id)
        address = app.config["PUBLIC_BASE_URL"] + url_for("checkin", token=point.qr_token)
        img = qrcode.make(address, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
        output = io.BytesIO()
        img.save(output)
        response = make_response(output.getvalue())
        response.headers["Content-Type"] = "image/svg+xml"
        return response

    @app.get("/admin/points/print")
    @admin_required
    def print_qr():
        query = select(Point).where(Point.active.is_(True))
        ids = request.args.get("ids", "")
        if ids:
            if not re.fullmatch(r"\d+(,\d+)*", ids) or len(ids) > 2000:
                abort(400)
            query = query.where(Point.id.in_([int(x) for x in ids.split(",")]))
        return render_template("print_qr.html", points=db.session.scalars(query.order_by(Point.floor, Point.code)).all(), public_base_url=app.config["PUBLIC_BASE_URL"], base_url_set=app.config["PUBLIC_BASE_URL"].startswith("https://"))

    @app.get("/admin/users")
    @admin_required
    def users():
        return render_template("users.html", users=db.session.scalars(select(User).order_by(User.id)).all())

    @app.post("/admin/users/create")
    @admin_required
    def create_user():
        username = request.form.get("username", "").strip().lower()
        name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "inspector")
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username) or not name or len(name) > 100 or not 12 <= len(password) <= 256 or role not in ("admin", "inspector"):
            abort(400, description="請填寫有效帳號（3–80 個英數字或 _.-）、姓名、角色與至少 12 字元的密碼。")
        user = User(username=username, display_name=name, role=role, must_change_password=True)
        user.set_password(password)
        db.session.add(user)
        audit("user_created", username)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            abort(400, description="此帳號已存在。")
        flash("員工帳號已建立，首次登入需變更密碼。", "success")
        return redirect(url_for("users"))

    @app.post("/admin/users/<int:user_id>/update")
    @admin_required
    def update_user(user_id):
        user = lock_user(user_id)
        if not user:
            abort(404)
        name = request.form.get("display_name", "").strip()
        role = request.form.get("role", "inspector")
        active = request.form.get("active", "") in ("on", "1", "true", "yes")
        if not name or len(name) > 100 or role not in ("admin", "inspector"):
            abort(400)
        if user.id == g.user.id and (role != "admin" or not active):
            abort(400, description="不能停用自己或移除自己的管理員權限。")
        if user.role != role or user.active != active:
            user.auth_version += 1
        user.display_name, user.role, user.active = name, role, active
        if not active:
            db.session.execute(db.update(DeviceBinding).where(DeviceBinding.user_id == user.id, DeviceBinding.status.in_(["approved", "pending"])).values(status="revoked"))
        audit("user_updated", user.username)
        db.session.commit()
        flash("帳號設定已更新。", "success")
        return redirect(url_for("users"))

    @app.post("/admin/users/<int:user_id>/reset-password")
    @admin_required
    def reset_password(user_id):
        user = lock_user(user_id)
        if not user:
            abort(404)
        password = request.form.get("password", "")
        if not 12 <= len(password) <= 256:
            abort(400, description="密碼需為 12 至 256 個字元。")
        user.set_password(password)
        user.must_change_password = True
        user.auth_version += 1
        audit("password_reset", user.username)
        db.session.commit()
        flash("密碼已重設，既有登入已失效；員工下次登入需變更密碼。", "success")
        return redirect(url_for("users"))

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def show_error(error):
        return render_template("error.html", code=error.code, message=error.description), error.code

    @app.cli.command("init-db")
    def init_db():
        db.create_all()
        click.echo("Patrol tables are ready. Existing tables and records were preserved.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--name", prompt=True)
    @click.password_option()
    def create_admin(username, name, password):
        username = username.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username) or not name.strip() or not 12 <= len(password) <= 256:
            raise click.ClickException("Use a valid username/name and a password with 12–256 characters.")
        if db.session.scalar(select(User).where(User.username == username)):
            raise click.ClickException("Username already exists.")
        user = User(username=username, display_name=name.strip()[:100], role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo("Administrator created.")

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin():
        """Create the first admin from a provisioned hash; never reset an account."""
        password_hash = os.environ.get("INITIAL_ADMIN_PASSWORD_HASH", "")
        username = os.environ.get("INITIAL_ADMIN_USERNAME", "admin").strip().lower()
        if not password_hash:
            click.echo("Initial administrator provisioning is not configured; skipped.")
            return
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username):
            raise click.ClickException("Invalid initial administrator username.")
        if not re.fullmatch(r"scrypt:32768:8:1\$[A-Za-z0-9]{16}\$[a-f0-9]{128}", password_hash):
            raise click.ClickException("Initial administrator requires a valid scrypt password hash, never a plaintext password.")
        if db.engine.dialect.name == "postgresql":
            db.session.execute(db.text("SELECT pg_advisory_xact_lock(714032610301)"))
        if db.session.scalar(select(User.id).where(User.role == "admin").limit(1)):
            db.session.rollback()
            click.echo("An administrator already exists; credentials were not changed.")
            return
        if db.session.scalar(select(User.id).where(User.username == username)):
            db.session.rollback()
            raise click.ClickException("The initial username is already in use; no account was changed.")
        db.session.add(User(username=username, display_name="巡檢管理員", role="admin", password_hash=password_hash, must_change_password=True))
        db.session.add(AuditLog(action="initial_admin_created", target=username, detail="Password change required at first login."))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            raise click.ClickException("Administrator provisioning conflicted; no existing account was changed.")
        click.echo("Initial administrator created; password change is required at first login.")

    @app.cli.command("seed-demo")
    def seed_demo():
        if app.config["APP_ENV"] == "production" or not app.config["DEMO_MODE"]:
            raise click.ClickException("Only allowed with DEMO_MODE=1 in a non-production environment.")
        db.create_all()
        if db.session.scalar(select(db.func.count(User.id))):
            raise click.ClickException("Demo seed requires an empty database.")
        passwords = {}
        for username, name, role in [("admin", "巡檢管理員", "admin"), ("inspector", "示範巡檢員", "inspector")]:
            password = secrets.token_urlsafe(15)
            passwords[username] = password
            user = User(username=username, display_name=name, role=role)
            user.set_password(password)
            db.session.add(user)
        db.session.flush()
        inspector = db.session.scalar(select(User).where(User.username == "inspector"))
        today = local_dt(now_utc()).date()
        names = {1: ["大門入口", "卸貨區", "消防設備"], 2: ["生產區入口", "包裝區", "緊急出口"], 3: ["倉儲區", "配電箱", "逃生通道"], 4: ["設備機房", "冷藏區", "安全出口"], 5: ["頂樓出入口", "水塔區", "機電設備"]}
        for floor in range(1, 6):
            for number, name in enumerate(names[floor], 1):
                frequency = "weekly" if number == 3 else "daily"
                point = Point(code=f"{floor}F-A{number:02}", name=name, floor=floor, frequency=frequency, schedule_start=today - timedelta(days=30))
                point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=frequency, active=True))
                db.session.add(point)
                db.session.flush()
                if number == 1 and floor in (1, 2, 4):
                    instant = datetime.combine(today, time(8, floor * 7), TAIPEI).astimezone(timezone.utc)
                    if instant > now_utc():
                        instant = now_utc() - timedelta(minutes=floor)
                    key, _, _ = period_for(point, instant)
                    db.session.add(Inspection(user_id=inspector.id, point_id=point.id, created_at=naive_utc(instant), period_key=key, frequency=frequency, point_code=point.code, point_name=point.name, point_floor=floor, user_name=inspector.display_name))
        db.session.commit()
        access_file = instance / "preview-access.txt"
        access_file.write_text("LOCAL DEMO ONLY / 本機示範帳號\n" + app.config["PUBLIC_BASE_URL"] + "\n\n" + "\n".join(f"{u}: {p}" for u, p in passwords.items()), encoding="utf-8")
        click.echo(f"Demo created. Local credentials are in {access_file}; not printed or used in production.")

    return app


application = create_app()
