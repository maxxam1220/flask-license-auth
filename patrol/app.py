"""Factory patrol: QR confirmation, approved browsers and durable records."""
from datetime import date, datetime, time, timedelta, timezone
from functools import wraps
import base64
import csv
import hashlib
import hmac
import io
import json
from calendar import monthrange
import os
from pathlib import Path
import re
import secrets
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode, urlsplit
from zoneinfo import ZoneInfo

import click
from flask import Flask, abort, before_render_template, flash, g, make_response, redirect, render_template, request, session, url_for
import qrcode
import qrcode.image.svg
from itsdangerous import BadData, URLSafeSerializer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from models import AuditLog, DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, LoginAttempt, PatrolExecution, Point, PointSchedule, RevokedSession, User, db
from general_workflow import execution_in_slot, new_execution, personal_inspection_in_slot
from catalog_general import catalogue_rows as general_catalogue_rows
from domain import CATEGORY_OPTIONS, FLOOR_OPTIONS, FLOOR_ORDER, category_label, floor_label
from images import PhotoValidationError, process_uploads
from patrol_access import can_access_category, can_read_inspection, patrol_scope
from issues import IssueActionError, issue_state, issue_version, open_issue_condition, open_issue_counts, open_issue_for, transition_issue

TAIPEI = ZoneInfo("Asia/Taipei")
DEVICE_COOKIE = "patrol_device"
QR_RETURN_PATH = re.compile(r"/c/([A-Za-z0-9_-]{1,100})")


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


def checkin_location_revision(point):
    """Identify the actual location shown on the confirmation form."""
    location = (str(point.id), point.code, point.name, str(point.floor), point.category, point.workflow_mode)
    return hashlib.sha256("\x00".join(location).encode("utf-8")).hexdigest()


def management_state(item):
    """Detect a browser tab submitting settings that have since changed."""
    if isinstance(item, Point):
        values = (item.id, item.code, item.name, item.floor, item.category, item.frequency,
                  item.workflow_mode, item.active, item.qr_token, item.deleted_at.isoformat() if item.deleted_at else None)
    else:
        values = (item.id, item.display_name, item.role, item.patrol_category, item.active, item.auth_version)
    return hashlib.sha256(json.dumps(values).encode("utf-8")).hexdigest()


def period_for(point, instant):
    local_day = local_dt(instant).date()
    if point.frequency == "weekly":
        local_day -= timedelta(days=local_day.weekday())
    elif point.frequency == "monthly":
        local_day = local_day.replace(day=1)
    start = datetime.combine(local_day, time.min, TAIPEI)
    days = {"weekly": 7, "monthly": monthrange(local_day.year, local_day.month)[1]}.get(point.frequency, 1)
    end = start + timedelta(days=days)
    return local_day.isoformat(), start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def slot_for(point, instant):
    return ("am" if local_dt(instant).hour < 12 else "pm") if point.frequency == "daily2" else "any"


def slot_label(slot):
    return {"am": "上午", "pm": "下午", "any": "不限時段"}.get(slot, "不限時段")


def frequency_label(frequency):
    return {"daily": "每日一次", "daily2": "每日兩次", "weekly": "每週一次", "monthly": "每月一次",
            "irregular": "不定期"}.get(frequency, frequency)


def progress_view(frequency):
    return frequency if frequency in ("weekly", "monthly") else "daily"


def normalise_return_to(value, user):
    """Allow only validated list filters; never use arbitrary redirect targets."""
    if not value or len(value) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path not in ("/records", "/issues"):
            return None
        if parsed.path == "/issues" and not user:
            return None
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=8)
        if len({key for key, _ in pairs}) != len(pairs):
            return None
        allowed = ({"date_from", "date_to", "floor", "user_id", "category", "abnormal", "frequency", "stage"}
                   if parsed.path == "/records" else {"status", "floor", "category", "point_id", "page"})
        values = {}
        for key, item in pairs:
            if key not in allowed or any(ord(char) < 32 or ord(char) == 127 for char in item):
                return None
            if not item:
                continue
            if key in ("date_from", "date_to"):
                parsed_date = date.fromisoformat(item)
                if not 2000 <= parsed_date.year <= 2100:
                    return None
                item = parsed_date.isoformat()
            elif key == "floor" and item not in {str(floor) for floor, _ in FLOOR_OPTIONS}:
                return None
            elif key == "category" and item not in dict(CATEGORY_OPTIONS):
                return None
            elif key == "abnormal" and item not in ("0", "1"):
                return None
            elif key == "stage" and item not in ("execution", "inspection"):
                return None
            elif key == "frequency" and item not in ("daily", "daily2", "weekly", "monthly", "irregular", "daily_all"):
                return None
            elif key == "status" and item not in ("open", "resolved", "all"):
                return None
            elif key in ("user_id", "point_id", "page"):
                if not re.fullmatch(r"[0-9]{1,10}", item) or not 1 <= int(item) <= 2147483647:
                    return None
                item = str(int(item))
            if key == "user_id" and (not user or user.role != "admin"):
                continue
            if key == "category" and user and user.role != "admin":
                item = patrol_scope(user)
                if not item:
                    continue
            values[key] = item
        if parsed.path == "/records":
            today = local_dt(now_utc()).date()
            begin = date.fromisoformat(values.get("date_from", (today - timedelta(days=6)).isoformat()))
            end = date.fromisoformat(values.get("date_to", today.isoformat()))
            if begin > end or (end - begin).days > 366:
                return None
        return parsed.path + ("?" + urlencode(values) if values else "")
    except (ValueError, TypeError):
        return None


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
        MAX_CONTENT_LENGTH=25 * 1024 * 1024,
        PHOTO_STORAGE_LIMIT_BYTES=int(os.environ.get("PHOTO_STORAGE_LIMIT_BYTES", str(200 * 1024 * 1024))),
        CSRF_ENABLED=True,
        DEMO_MODE=os.environ.get("DEMO_MODE", "0") == "1",
    )
    app.config.update(provided)
    # The private register is supplied only to the designated patrol service.
    general_codes = {row["code"].casefold(): (row["code"], row["floor"]) for row in general_catalogue_rows()}
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

    def signed_session_nonce():
        # Older signed login cookies already contain a random per-login CSRF
        # token. Use it until the next rotation, preserving valid v5 sessions.
        return session.get("sid") or session.get("csrf_token")

    def session_revoked():
        return select(RevokedSession.token_hash).where(
            RevokedSession.token_hash == g.patrol_session_hash).exists()

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["issue_state"] = issue_state
    app.jinja_env.globals["management_state"] = management_state

    @app.context_processor
    def common_context():
        user = g.get("user")
        def role_label(account):
            if account and account.role == "admin":
                return "系統管理員"
            if account and account.role == "executor" and patrol_scope(account):
                return "總務執行人員"
            return {"safety": "職安巡檢員", "general": "總務巡檢員"}.get(patrol_scope(account), "尚未指派")
        return {"current_user": user, "role_label": role_label, "is_patrol_admin": bool(user and user.role == "admin"),
                "viewer_category": patrol_scope(user) or None, "csrf_token": csrf_token, "today": local_dt(now_utc()).date(),
                "floor_options": FLOOR_OPTIONS, "category_options": CATEGORY_OPTIONS,
                "floor_label": floor_label, "category_label": category_label,
                "slot_label": slot_label, "frequency_label": frequency_label, "issue_state": issue_state}

    @before_render_template.connect_via(app)
    def configure_scanner(sender, template, context, **extra):
        # Grant camera access only to rendered work pages that actually offer scanning.
        viewer = g.get("user")
        can_scan = bool(viewer and not viewer.must_change_password
                        and (viewer.role == "admin" or patrol_scope(viewer))
                        and template.name in {
                            "dashboard.html", "checkin.html", "checkin_success.html", "records.html",
                            "record_detail.html", "issues.html", "missed.html", "devices.html",
                            "admin_devices.html", "points.html", "users.html",
                        })
        context["can_scan"] = g.patrol_scanner_page = can_scan

    @app.before_request
    def load_user_and_protect():
        g.user = None
        # PostgreSQL Integer primary keys cannot represent arbitrary URL integers.
        for name, value in (request.view_args or {}).items():
            if name.endswith("_id") and not 1 <= value <= 2147483647:
                abort(404, description="找不到指定的資料。")
        if session.get("user_id"):
            nonce = signed_session_nonce()
            if isinstance(nonce, str) and nonce:
                g.patrol_session_hash = hashlib.sha256(f"{session['user_id']}:{nonce}".encode("utf-8")).hexdigest()
                g.user = db.session.scalar(select(User).where(
                    User.id == session["user_id"], User.active.is_(True),
                    User.auth_version == session.get("auth_version"), ~session_revoked()
                ).execution_options(populate_existing=True))
            if not g.user:
                session.clear()
        # An expired protected submission has no authority to write. Recover its
        # safe GET confirmation page before checking the now-missing CSRF secret;
        # the sign-in form itself retains its normal CSRF protection.
        if not g.user and request.method == "POST":
            destination = protected_post_destination()
            if destination:
                return redirect(url_for("login", next=safe_next(destination)))
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and app.config["CSRF_ENABLED"]:
            expected = session.get("csrf_token", "")
            received = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not expected or not received or not received.isascii() or not hmac.compare_digest(expected, received):
                abort(400, description="表單已過期，請重新載入頁面後再試。")
        if g.user and g.user.must_change_password and request.endpoint not in ("change_password", "logout", "static", "healthz"):
            if request.method == "GET" and request.endpoint not in (None, "login"):
                session["after_password"] = safe_next(request.full_path.rstrip("?"))
            return redirect(url_for("change_password", next=safe_next(session.get("after_password"))))

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        can_scan = g.get("patrol_scanner_page", False)
        if can_scan:
            response.headers["Content-Security-Policy"] += "; media-src 'self' blob:"
        camera_policy = "(self)" if can_scan else "()"
        response.headers["Permissions-Policy"] = f"camera={camera_policy}, microphone=(), geolocation=()"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "private, no-store" if request.endpoint == "photo_file" else "no-store"
        if app.config["COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not g.user:
                destination = protected_post_destination() if request.method == "POST" else None
                destination = destination or request.full_path.rstrip("?")
                return redirect(url_for("login", next=safe_next(destination)))
            return fn(*args, **kwargs)
        return wrapped

    def protected_post_destination():
        args = request.view_args or {}
        if request.endpoint == "confirm_checkin":
            return url_for("checkin", token=args["token"])
        if request.endpoint in ("resolve_issue", "reopen_issue"):
            # This remains an encoded query value on a fixed local detail URL.
            # It is normalized with the authenticated role after sign-in.
            source = request.form.get("return_to", "")
            return url_for("record_detail", record_id=args["inspection_id"], return_to=source[:1600])
        if request.endpoint in ("request_device", "revoke_own_device"):
            # Preserve the scanned QR through sign-in. The authenticated GET
            # rechecks point availability and category before showing the link.
            destination = request.form.get("next", "")
            return devices_url(destination if QR_RETURN_PATH.fullmatch(destination) else "")
        if request.endpoint == "change_password":
            return url_for("change_password", next=safe_next(request.form.get("next")))
        destinations = {"create_point": "points", "update_point": "points", "rotate_point_qr": "points",
                        "delete_point": "points", "restore_point": "points",
                        "create_user": "users", "update_user": "users", "reset_password": "users",
                        "approve_device": "admin_devices", "reject_device": "admin_devices", "revoke_device": "admin_devices"}
        endpoint = destinations.get(request.endpoint)
        return url_for(endpoint) if endpoint else None

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
        # FOR NO KEY UPDATE still serializes account changes, while allowing
        # foreign-key KEY SHARE checks from inspection/audit inserts.  Using
        # FOR UPDATE here can deadlock with a point update in another request.
        return db.session.scalar(select(User).where(User.id == user_id).with_for_update(key_share=True).execution_options(populate_existing=True))

    def lock_current_user(allow_password_change=False):
        user = lock_user(g.user.id)
        if (not user or not user.active or user.auth_version != session.get("auth_version")
                or (user.must_change_password and not allow_password_change)
                or db.session.scalar(select(session_revoked()))):
            abort(403, description="帳號狀態已更新，請重新登入。")
        return user

    def lock_current_admin():
        user = lock_current_user()
        if user.role != "admin":
            abort(403, description="管理員權限已更新，請重新登入後再試。")
        return user

    def lock_admin_users(*target_ids):
        # Admin actions can touch two accounts. Always take every User lock in
        # primary-key order, including the actor, so opposing admin actions do
        # not deadlock or both succeed after one actor has lost authority.
        actor_id = g.user.id
        locked = {user_id: lock_user(user_id) for user_id in sorted({actor_id, *target_ids})}
        actor = locked[actor_id]
        if (not actor or not actor.active or actor.auth_version != session.get("auth_version")
                or actor.must_change_password or actor.role != "admin"
                or db.session.scalar(select(session_revoked()))):
            abort(403, description="管理員權限或帳號狀態已更新，請重新登入後再試。")
        return locked

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
        fallback = url_for("dashboard")
        if not value or len(value) > 2048 or not value.startswith("/") or value.startswith("//") or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            return fallback
        try:
            app.url_map.bind_to_environ(request.environ).match(urlsplit(value).path, method="GET")
        except (HTTPException, ValueError):
            return fallback
        return value

    def binding_destination():
        """Keep a scanned point through approval, without trusting a return URL."""
        value = request.form.get("next") if request.method == "POST" else request.args.get("next")
        if value is None:
            value = session.get("after_binding", "")
        match = QR_RETURN_PATH.fullmatch(value or "")
        point = db.session.scalar(select(Point).where(Point.qr_token == match.group(1))) if match else None
        if (point and point.deleted_at is None and can_access_category(g.user, point.category)
                and (g.user.role != "executor" or point.workflow_mode == "two_stage")
                and point.active and point.schedule_start <= local_dt(now_utc()).date()):
            target = url_for("checkin", token=point.qr_token)
            session["after_binding"] = target
            return target
        session.pop("after_binding", None)
        return ""

    def devices_url(destination):
        return url_for("devices", next=destination) if destination else url_for("devices")

    def parse_id(value):
        if not re.fullmatch(r"[0-9]{1,10}", value) or not 1 <= int(value) <= 2147483647:
            abort(400, description="資料編號格式不正確。")
        return int(value)

    def valid_label(value, limit=100):
        return bool(value) and len(value) <= limit and not any(ord(c) < 32 or ord(c) == 127 for c in value)

    def scope_filters():
        floor = request.args.get("floor", "")
        category = request.args.get("category", "")
        if floor and floor not in {str(value) for value, _ in FLOOR_OPTIONS}:
            abort(400, description="樓層選項不正確。")
        if category and category not in dict(CATEGORY_OPTIONS):
            abort(400, description="分類選項不正確。")
        scope = patrol_scope(g.user)
        return floor, category if scope is None else scope

    def private_records(query, category):
        """Always intersect report ownership and its immutable category snapshot."""
        scope = patrol_scope(g.user)
        if scope is None:
            return query.where(Inspection.category == category) if category else query
        if not scope:
            return query.where(db.false())
        if g.user.role == "executor":
            return query.where(db.false())
        return query.where(Inspection.user_id == g.user.id, Inspection.category == scope)

    def historical_points(scope):
        # A recategorized point can still have obligations and snapshots in
        # its original category. Filtering only Point.category would lose them.
        query = select(Point).options(selectinload(Point.schedules)).order_by(*point_order())
        if scope == "":
            return []
        if scope is not None:
            query = query.where(db.or_(Point.category == scope, Point.schedules.any(PointSchedule.category == scope),
                              select(Inspection.id).where(Inspection.point_id == Point.id, Inspection.category == scope).exists()))
        points = db.session.scalars(query).all()
        if scope is None:
            return points
        # Old schedule rows can lack a name/code snapshot. After a team
        # transfer, that fallback must not display the new team's labels.
        return [p if p.category == scope else SimpleNamespace(
            id=p.id, code=f"#{p.id}", name="歷史巡檢點", floor=p.floor, category=p.category,
            frequency=p.frequency, workflow_mode=p.workflow_mode, active=p.active, created_at=p.created_at, schedule_start=p.schedule_start,
            schedules=p.schedules) for p in points]

    def point_order():
        return db.case({value: index for index, (value, _) in enumerate(FLOOR_OPTIONS)}, value=Point.floor), Point.code

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
            username = request.form.get("username", "").strip().lower()
            # Scope the limit to the account and source, so a shared factory
            # connection does not lock out all employees after one user's errors.
            attempt_key = hashlib.sha256((username + "|" + (request.remote_addr or "unknown")).encode()).hexdigest()
            cutoff = naive_utc() - timedelta(minutes=15)
            attempts = db.session.scalar(select(db.func.count(LoginAttempt.id)).where(LoginAttempt.key == attempt_key, LoginAttempt.created_at >= cutoff))
            if attempts >= 15:
                abort(429, description="登入嘗試過多，請於 15 分鐘後再試。")
            user = db.session.scalar(select(User).where(User.username == username)) if re.fullmatch(r"[a-z0-9_.-]{3,80}", username) else None
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
                session["sid"] = secrets.token_urlsafe(32)
                session.permanent = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                if user.must_change_password:
                    if urlsplit(next_url).path == url_for("change_password"):
                        # This GET already contains the safe post-change return
                        # target. Do not nest it as the next destination again.
                        return redirect(next_url)
                    session["after_password"] = next_url
                    return redirect(url_for("change_password"))
                return redirect(next_url)
        return render_template("login.html", next=safe_next(request.form.get("next") or request.args.get("next")))

    @app.post("/logout")
    def logout():
        if g.user:
            # Serialize the revocation against writes authorized by this login.
            # A late response can refresh a signed cookie after logout, so the
            # hash stays revoked regardless of the cookie's refreshed timestamp.
            actor = lock_user(g.user.id)
            if actor:
                revoke = db.text(
                    "INSERT INTO patrol_revoked_sessions (token_hash, user_id, auth_version, revoked_at) "
                    "VALUES (:token_hash, :user_id, :auth_version, :revoked_at) "
                    "ON CONFLICT (token_hash) DO NOTHING"
                ).bindparams(db.bindparam("revoked_at", type_=db.DateTime()))
                db.session.execute(revoke, {"token_hash": g.patrol_session_hash, "user_id": actor.id,
                                            "auth_version": actor.auth_version, "revoked_at": naive_utc()})
                db.session.commit()
        session.clear()
        return redirect(url_for("login"))

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        destination = safe_next(request.form.get("next") or request.args.get("next") or session.get("after_password"))
        if request.method == "POST":
            lock_current_user(allow_password_change=True)
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
                session.pop("after_password", None)
                session["auth_version"] = g.user.auth_version
                session["sid"] = signed_session_nonce()
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash("密碼已更新。", "success")
                return redirect(destination)
        return render_template("change_password.html", next_url=destination)

    @app.get("/dashboard")
    @login_required
    def dashboard():
        from missed import VIEW_FREQUENCIES, period_bounds, schedule_timeline, slot_plans
        instant = now_utc()
        today = local_dt(instant).date()
        selected = parse_date(request.args.get("date"), today)
        view = request.args.get("view", "daily")
        if view not in VIEW_FREQUENCIES:
            abort(400)
        period_day, period_end = period_bounds(selected, view)
        reference_day = min(period_end, today) if view != "daily" else selected
        scope = patrol_scope(g.user)
        points = historical_points(scope)
        floor_filter, category_filter = scope_filters()
        executor = g.user.role == "executor"
        issue_counts = {} if executor else open_issue_counts(category=scope)
        frequencies = VIEW_FREQUENCIES[view]
        # Attribute a completed team slot exactly once to the first inspection's
        # snapshot, even if later inspectors used a renamed or relocated point.
        # An inspector may also see their own latest receipt for the same slot.
        slot_key = (Inspection.point_id, Inspection.frequency, Inspection.slot)
        completion_query = select(Inspection.id, Inspection.user_id,
            db.func.row_number().over(partition_by=slot_key, order_by=(Inspection.created_at, Inspection.id)).label("first"),
            db.func.row_number().over(partition_by=(*slot_key, Inspection.user_id, Inspection.category,
                Inspection.point_floor, Inspection.workflow_mode),
                order_by=(Inspection.created_at.desc(), Inspection.id.desc())).label("personal")
        ).where(Inspection.period_key == period_day.isoformat(), Inspection.frequency.in_(frequencies),
                Inspection.legacy_unscheduled.is_(False))
        if scope is not None:
            completion_query = completion_query.where(Inspection.point_id.in_([point.id for point in points]))
        ranked = completion_query.subquery()
        wanted = ranked.c.first == 1
        if g.user.role == "inspector":
            wanted = db.or_(wanted, db.and_(ranked.c.personal == 1, ranked.c.user_id == g.user.id))
        found = {}
        own_records = {}
        for record, first, personal in db.session.execute(select(Inspection, ranked.c.first, ranked.c.personal).join(
                ranked, Inspection.id == ranked.c.id).where(wanted)):
            if first == 1:
                found.setdefault(record.point_id, []).append(record)
            if personal == 1 and record.user_id == g.user.id:
                own_records[record.point_id, record.frequency, record.slot, record.category, record.point_floor, record.workflow_mode] = record
        executed_at = {}
        if scope in (None, "general") and category_filter in ("", "general"):
            progress_query = select(PatrolExecution.point_id, PatrolExecution.frequency, PatrolExecution.slot,
                                    PatrolExecution.created_at).where(PatrolExecution.period_key == period_day.isoformat(),
                                        PatrolExecution.frequency.in_(frequencies), PatrolExecution.category == "general")
            executed_at = {(pid, freq, slot): timestamp for pid, freq, slot, timestamp in db.session.execute(progress_query)}
        cards, floors = [], [{"floor": f, "label": label, "total": 0, "done": 0} for f, label in FLOOR_OPTIONS]
        irregular_points = []
        floor_counts = {item["floor"]: item for item in floors}
        period_label = f"{period_day:%Y/%m}" if view == "monthly" else (f"{period_day:%m/%d} – {period_end:%m/%d}" if view == "weekly" else selected.isoformat())
        for point in points:
            point_records = found.get(point.id, [])
            schedule = next((s for s in reversed(point.schedules) if s.effective_date <= reference_day), None)
            frequency = schedule.frequency if schedule else point.frequency
            active = schedule.active if schedule else point.active
            category = schedule.category if schedule else point.category
            scheduled_floor = schedule.floor if schedule and schedule.floor is not None else point.floor
            scheduled_code = schedule.point_code if schedule and schedule.point_code is not None else point.code
            scheduled_name = schedule.point_name if schedule and schedule.point_name is not None else point.name
            mode = schedule.workflow_mode if schedule else point.workflow_mode
            legacy_unscheduled = bool(schedule and schedule.legacy_unscheduled)
            if ((frequency == "irregular" or legacy_unscheduled) and active and (not executor or mode == "two_stage") and point.schedule_start <= reference_day
                    and (not category_filter or category_filter == category)
                    and (not floor_filter or int(floor_filter) == scheduled_floor)):
                irregular_points.append(SimpleNamespace(id=point.id, code=scheduled_code, name=scheduled_name, floor=scheduled_floor,
                    category=category, frequency=frequency, workflow_mode=mode, legacy_unscheduled=legacy_unscheduled))
            planned_slots = {}
            for plan, slot, _ in slot_plans(point, reference_day, schedule_timeline(point), view=view):
                key = (plan["frequency"], plan["category"], plan["floor"], plan["workflow_mode"])
                planned_slots.setdefault(key, {})[slot] = plan
            groups = {group: {} for group in planned_slots}
            for record in point_records:
                groups.setdefault((record.frequency, record.category, record.point_floor, record.workflow_mode), {})[record.slot] = record
            for group, records_by_slot in groups.items():
                group_frequency, group_category, group_floor, group_mode = group
                if (category_filter and category_filter != group_category) or (executor and group_mode != "two_stage"):
                    continue
                planned = planned_slots.get(group, {})
                slot_keys = ("am", "pm") if group_frequency == "daily2" else ("any",)
                slots = []
                for slot in slot_keys:
                    record = records_by_slot.get(slot)
                    scheduled_slot = slot in planned
                    due = scheduled_slot and point.schedule_start <= reference_day and period_day <= today
                    # Do not create an obligation for a slot that had already
                    # ended when the point was introduced. Existing inspection
                    # snapshots still count, even for inconsistent legacy dates.
                    slot_deadline = (datetime.combine(period_day, time(12), TAIPEI) if slot == "am" else
                                     datetime.combine(period_end + timedelta(days=1), time.min, TAIPEI))
                    if not record and point.created_at and slot_deadline <= local_dt(point.created_at):
                        continue
                    # A classification/floor edit cannot create another obligation
                    # for a slot already completed under its historical snapshot.
                    if scheduled_slot and not record and any(item.frequency == group_frequency and item.slot == slot for item in point_records):
                        continue
                    if not scheduled_slot and not record:
                        continue
                    future_slot = group_frequency == "daily2" and selected == today and slot == "pm" and local_dt(instant).hour < 12
                    status = "done" if record else ("pending" if due and not future_slot else "not_due")
                    visible = record if record and g.user.role == "admin" else None
                    if record and g.user.role == "inspector":
                        visible = own_records.get((point.id, group_frequency, slot, group_category, group_floor, group_mode))
                    executed = executed_at.get((point.id, group_frequency, slot)) if group_mode == "two_stage" else None
                    stage_status = None
                    if group_mode == "two_stage":
                        stage_status = "done" if record else "awaiting_inspection" if executed else "awaiting_execution"
                    slots.append({"key": slot, "label": slot_label(slot), "status": status, "record": visible,
                                  "due": bool(due or record), "stage_status": stage_status, "executed_at": executed})
                if not slots:
                    continue
                snapshot = max(records_by_slot.values(), key=lambda item: item.created_at, default=None)
                # A partial card still directs staff to an outstanding/current
                # slot. Keep its schedule label after a same-floor rename, while
                # wholly completed cards retain the original record snapshot.
                pending_plan = next((planned[slot["key"]] for slot in reversed(slots) if slot["key"] in planned and slot["status"] != "done"), None)
                if pending_plan:
                    scheduled_code, scheduled_name = pending_plan["code"], pending_plan["name"]
                use_schedule_label = pending_plan is not None
                display_snapshot = snapshot if not use_schedule_label else None
                displayed_point = SimpleNamespace(id=point.id, code=display_snapshot.point_code if display_snapshot else scheduled_code,
                                                 name=display_snapshot.point_name if display_snapshot else scheduled_name,
                                                 floor=group_floor, frequency=group_frequency, category=group_category, workflow_mode=group_mode)
                group_total = sum(slot["due"] for slot in slots)
                group_done = sum(slot["status"] == "done" for slot in slots)
                floor_counts[group_floor]["total"] += group_total
                floor_counts[group_floor]["done"] += group_done
                if not floor_filter or group_floor == int(floor_filter):
                    status = "done" if group_done == len(slots) else ("pending" if group_total else "not_due")
                    visible_records = [slot["record"] for slot in slots if slot["record"]]
                    latest = max(visible_records, key=lambda item: item.created_at, default=None)
                    cards.append({"point": displayed_point, "status": status, "latest": latest, "period_label": period_label, "slots": slots,
                                  "open_issue_count": issue_counts.get(point.id, 0)})
        total = sum(slot["due"] for card in cards for slot in card["slots"])
        done = sum(slot["status"] == "done" for card in cards for slot in card["slots"])
        recent_query = select(Inspection).options(selectinload(Inspection.issue)).order_by(Inspection.created_at.desc()).limit(6)
        recent_query = private_records(recent_query, category_filter)
        if floor_filter:
            recent_query = recent_query.where(Inspection.point_floor == int(floor_filter))
        recent_executions = []
        if executor and scope == "general":
            own = select(PatrolExecution).where(PatrolExecution.user_id == g.user.id, PatrolExecution.category == scope)
            if floor_filter:
                own = own.where(PatrolExecution.point_floor == int(floor_filter))
            recent_executions = db.session.scalars(own.order_by(PatrolExecution.created_at.desc(), PatrolExecution.id.desc()).limit(6)).all()
        return render_template("dashboard.html", selected_date=selected, selected_category=category_filter, selected_floor=floor_filter,
                               view=view, floors=floors, cards=cards, totals={"total": total, "done": done, "pending": total - done},
                               open_issue_counts=issue_counts, device_state=device_status(), irregular_points=irregular_points, spot_points=irregular_points,
                               recent=[] if executor else db.session.scalars(recent_query).all(), recent_executions=recent_executions,
                               missed_query_url=url_for("missed", date_from=period_day.isoformat(),
                                   date_to=period_end.isoformat(), category=category_filter, floor=floor_filter,
                                   frequency="daily_all" if view == "daily" else view),
                               records_query_url=url_for("records", date_from=period_day.isoformat(),
                                   date_to=period_end.isoformat(), category=category_filter, floor=floor_filter,
                                   frequency="daily_all" if view == "daily" else view), week_label=period_label, period_title=period_label)

    def get_point(token, lock=False):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", token):
            abort(404, description="巡檢點不存在，或這張 QR Code 已被更新。")
        query = select(Point).where(Point.qr_token == token, Point.deleted_at.is_(None))
        scope = patrol_scope(g.user)
        if scope is not None:
            query = query.where(Point.category == scope if scope else db.false())
        if g.user.role == "executor":
            query = query.where(Point.workflow_mode == "two_stage")
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)
        point = db.session.scalar(query)
        if not point:
            abort(404, description="巡檢點不存在，或這張 QR Code 已被更新。")
        if not point.active or point.schedule_start > local_dt(now_utc()).date():
            abort(403, description="此巡檢點目前尚未啟用或已停用。")
        return point

    def inspection_in_slot(point, key, slot):
        return db.session.scalar(select(Inspection).where(Inspection.point_id == point.id, Inspection.frequency == point.frequency,
            Inspection.period_key == key, Inspection.slot == slot, Inspection.workflow_mode != "spot"))

    def prior_inspection(point, key, slot, day):
        if point.workflow_mode in ("spot", "two_stage"):
            return personal_inspection_in_slot(point, g.user, day, slot)
        return inspection_in_slot(point, key, slot)

    def checkin_stage(point, first):
        if point.workflow_mode != "two_stage":
            return "inspect", g.user.role in ("inspector", "admin"), ""
        if g.user.role == "executor":
            return "execute", first is None, "本時段已登記執行，請由總務巡檢員接續巡檢。" if first else ""
        if g.user.role != "inspector" or patrol_scope(g.user) != "general":
            return "inspect", False, "管理員僅可管理此點，兩段打卡須由對應角色完成。"
        if not first:
            return "inspect", False, "尚未執行，請等總務執行人員先刷同一點位。"
        if first.user_id == g.user.id:
            return "inspect", False, "執行與巡檢必須由不同帳號完成。"
        return "inspect", True, ""

    def spot_ticket(point, key, slot, day, *, validate=False):
        signer = URLSafeSerializer(app.secret_key, salt="patrol-spot-checkin-v2")
        scope = [g.user.id, g.user.auth_version, point.id, key, slot, day.isoformat(), point.frequency, checkin_location_revision(point)]
        if not validate:
            return signer.dumps([scope, secrets.token_hex(16)])
        try:
            value = request.form.get("spot_ticket", "")
            payload = signer.loads(value) if len(value) <= 1024 else None
            if (isinstance(payload, list) and len(payload) == 2 and payload[0] == scope
                    and isinstance(payload[1], str) and re.fullmatch(r"[0-9a-f]{32}", payload[1])):
                return payload[1]
        except BadData:
            pass
        return None

    def checkin_form(point, token, error=None, status=200):
        instant = now_utc()
        day = local_dt(instant).date()
        key, start, end = period_for(point, instant)
        slot = slot_for(point, instant)
        first = execution_in_slot(point, key, slot) if point.workflow_mode == "two_stage" else None
        stage, allowed, notice = checkin_stage(point, first)
        existing = prior_inspection(point, key, slot, day) if stage == "inspect" else None
        if existing and not can_access_category(g.user, existing.category):
            # The obligation is shared even after a point changes teams. Only
            # reveal that it is satisfied, never the old team's actor or time.
            existing = {"created_at": None, "user_name": "本期已有紀錄"}
        elif existing and not can_read_inspection(g.user, existing):
            # Never give another inspector's notes, attachments or identity to the template.
            existing = {"created_at": existing.created_at, "user": {"display_name": "其他巡檢人員"}}
        label = f"{local_dt(start):%m/%d} – {local_dt(end - timedelta(seconds=1)):%m/%d}" if point.frequency in ("weekly", "monthly") else key
        return render_template("checkin.html", point=point, device_state=device_status(), existing=existing, token=token,
                               stage=stage, can_confirm=allowed and not existing, stage_notice=notice,
                               execution_time=first.created_at if first else None,
                               personal_day=day.isoformat(),
                               spot_ticket=spot_ticket(point, key, slot, day) if point.workflow_mode == "spot" else "",
                               point_revision=checkin_location_revision(point),
                               progress_url=url_for("dashboard", view=progress_view(point.frequency),
                                                    date=key, floor=point.floor, category=point.category),
                               current_slot=slot, current_slot_label=slot_label(slot), current_period_key=key, period_label=label,
                               note=request.form.get("note", ""), is_abnormal=request.form.get("is_abnormal", "") in ("on", "1", "true", "yes"),
                               point_open_issue_count=(open_issue_counts([point.id], category=patrol_scope(g.user)).get(point.id, 0)
                                                       if g.user.role != "executor" else 0), form_error=error), status

    @app.get("/c/<token>")
    @login_required
    def checkin(token):
        point = get_point(token)
        return checkin_form(point, token)

    def existing_checkin_response(record, token, note, abnormal, uploads):
        personal = record.workflow_mode in ("spot", "two_stage") and record.user_id == g.user.id
        if note or abnormal or any(upload.filename for upload in uploads):
            # A concurrent completion won. Do not present its receipt as proof
            # that this form's separate observations or photos were saved.
            prefix = "你今天在這個點位的時段已有紀錄" if personal else "這個點位本期已有紀錄"
            flash(prefix + "，本次填寫的回報內容未追加。若現場有新的異常，請聯絡管理員處理。", "warning")
            return redirect(url_for("checkin", token=token))
        flash("你已完成本日此時段的巡檢，以下是你的紀錄。" if personal else "這個巡檢點本期已完成，沒有新增重複紀錄。", "info")
        if can_read_inspection(g.user, record):
            return redirect(url_for("checkin_success", record_id=record.id))
        return redirect(url_for("checkin", token=token))

    def previous_spot_response(record):
        require_inspection_access(record)
        flash("這份巡檢表單先前已送出。以下是原紀錄，重送時更改的備註、異常或照片不會追加。", "info")
        return redirect(url_for("checkin_success", record_id=record.id))

    @app.post("/c/<token>/confirm")
    @login_required
    def confirm_checkin(token):
        # Serialize with approval/revocation for the same employee on PostgreSQL.
        lock_current_user()
        binding = device_binding()
        if not binding or binding.status != "approved":
            abort(403, description="此瀏覽器尚未核准，請先申請綁定並由管理員核准。")
        point = get_point(token, lock=True)
        if point.workflow_mode in ("spot", "two_stage") and db.engine.dialect.name == "sqlite":
            # SQLite ignores FOR UPDATE; serialize stage and personal attendance checks.
            db.session.execute(db.update(Point).where(Point.id == point.id).values(id=Point.id))
            point = get_point(token, lock=True)
        instant = now_utc()
        day = local_dt(instant).date()
        key, _, _ = period_for(point, instant)
        slot = slot_for(point, instant)
        submitted_slot, submitted_period = request.form.get("slot"), request.form.get("period_key")
        def form_error(message, status=400):
            db.session.rollback()
            return checkin_form(get_point(token), token, message, status)
        mode = point.workflow_mode
        confirmed_day = request.form.get("personal_day")
        if mode in ("spot", "two_stage") and (confirmed_day is not None or point.frequency in ("weekly", "monthly")) and confirmed_day != day.isoformat():
            return form_error("打卡日期已變更，請重新確認今天的打卡。", 409)
        if request.form.get("workflow_mode", "standard") != mode:
            return form_error("打卡方式已變更，請依目前顯示的流程重新確認。", 409)
        if request.form.get("frequency") != point.frequency:
            return form_error("點位巡檢頻率已更新，或此表單已過期。請確認最新設定後重新送出；照片需重新選擇。", 409)
        confirmed_location = request.form.get("point_revision")
        if confirmed_location is not None and confirmed_location != checkin_location_revision(point):
            return form_error("點位名稱、樓層、編號或分類已更新。請重新核對現場位置，再確認打卡。", 409)
        if (((point.frequency == "daily2" or mode != "standard") and (not submitted_slot or not submitted_period))
                or (submitted_slot is not None and submitted_slot != slot)
                or (submitted_period is not None and submitted_period != key)):
            return form_error("巡檢日期或時段已變更，請確認目前時段後重新送出。照片需重新選擇。", 409)
        # HTML forms send CRLF for the single newline counted by a textarea.
        note = request.form.get("note", "").replace("\r\n", "\n").replace("\r", "\n").strip()
        abnormal = request.form.get("is_abnormal", "") in ("on", "1", "true", "yes")
        uploads = request.files.getlist("photos")
        first = execution_in_slot(point, key, slot) if mode == "two_stage" else None
        stage, allowed, notice = checkin_stage(point, first)
        if mode == "two_stage" and g.user.role == "admin":
            abort(403, description=notice)
        if mode == "two_stage" and request.form.get("stage") != stage:
            return form_error("打卡階段與目前角色不符，請重新核對。", 409)
        if stage == "execute" and (note or abnormal or any(upload.filename for upload in uploads)):
            return form_error("執行登記不接受巡檢回報內容；備註、照片及異常請於巡檢階段填寫。")
        if stage == "execute" and first and first.user_id == g.user.id:
            return redirect(url_for("execution_success", execution_id=first.id))
        if not allowed:
            return form_error(notice, 409)
        request_id = None
        if mode == "spot":
            request_id = spot_ticket(point, key, slot, day, validate=True)
            if not request_id:
                return form_error("巡檢表單已過期或無效，請重新核對後送出。", 409)
            previous = db.session.scalar(select(Inspection).where(Inspection.spot_request_id == request_id))
            if previous:
                return previous_spot_response(previous)
        record = prior_inspection(point, key, slot, day) if stage == "inspect" else None
        if record:
            return existing_checkin_response(record, token, note, abnormal, uploads)
        if stage == "execute":
            first = new_execution(point, g.user, binding, key, slot, instant)
            db.session.add(first)
            binding.last_seen_at = naive_utc(instant)
            audit("execution", point.code)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                first = execution_in_slot(point, key, slot)
                if not first:
                    raise
                if first.user_id != g.user.id:
                    return form_error("本時段已有執行紀錄。", 409)
            session.pop("after_binding", None)
            return redirect(url_for("execution_success", execution_id=first.id))
        if len(note) > 2000 or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in note):
            return form_error("備註最多 2,000 字，且不可包含無效控制字元。")
        try:
            photos = process_uploads(uploads)
        except PhotoValidationError as error:
            return form_error(str(error))
        if photos:
            if db.engine.dialect.name == "postgresql":
                db.session.execute(db.text("SELECT pg_advisory_xact_lock(714032610303)"))
            used = db.session.scalar(select(db.func.coalesce(db.func.sum(InspectionPhoto.size_bytes), 0)))
            if used + sum(photo["size_bytes"] for photo in photos) > app.config["PHOTO_STORAGE_LIMIT_BYTES"]:
                return form_error("照片儲存空間已滿，這次打卡尚未儲存。請聯絡管理員，或移除照片後重新確認送出。", 409)
        final_instant = now_utc()
        if (period_for(point, final_instant)[0] != key or slot_for(point, final_instant) != slot or
                (mode in ("spot", "two_stage") and local_dt(final_instant).date() != day)):
            return form_error("處理期間巡檢日期或時段已變更，請重新確認後送出。照片需重新選擇。", 409)
        record = Inspection(user_id=g.user.id, point_id=point.id, binding_id=binding.id, created_at=naive_utc(final_instant),
                            period_key=key, frequency=point.frequency, slot=slot, category=point.category,
                            point_code=point.code, point_name=point.name, point_floor=point.floor, user_name=g.user.display_name,
                            workflow_mode=mode, execution_id=first.id if first else None, spot_request_id=request_id,
                            personal_day=day if mode in ("spot", "two_stage") else None,
                            note=note, is_abnormal=abnormal)
        record.photos.extend(InspectionPhoto(**photo) for photo in photos)
        open_issue_for(record)
        db.session.add(record)
        binding.last_seen_at = naive_utc(final_instant)
        audit("checkin", point.code)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            if request_id:
                previous = db.session.scalar(select(Inspection).where(Inspection.spot_request_id == request_id))
                if previous and can_read_inspection(g.user, previous):
                    return previous_spot_response(previous)
            record = prior_inspection(point, key, slot, day)
            if not record:
                raise
            return existing_checkin_response(record, token, note, abnormal, uploads)
        if not can_read_inspection(g.user, record):
            return redirect(url_for("checkin", token=token))
        session.pop("after_binding", None)
        return redirect(url_for("checkin_success", record_id=record.id))

    @app.get("/executions/<int:execution_id>/success")
    @login_required
    def execution_success(execution_id):
        record = db.get_or_404(PatrolExecution, execution_id)
        if not can_access_category(g.user, record.category):
            abort(404)
        if g.user.role != "admin" and (g.user.role != "executor" or record.user_id != g.user.id):
            abort(403)
        return render_template("checkin_success.html", record=record, stage="execute", finalized=execution_reviewed(record),
                               progress_url=url_for("dashboard", view=progress_view(record.frequency),
                                                    date=record.period_key, floor=record.point_floor, category=record.category))

    @app.get("/checkins/<int:record_id>")
    @login_required
    def checkin_success(record_id):
        record = db.get_or_404(Inspection, record_id)
        require_inspection_access(record)
        return render_template("checkin_success.html", record=record, stage="inspect", finalized=True,
                               progress_url=url_for("dashboard", view=progress_view(record.frequency),
                                                    date=record.period_key, floor=record.point_floor, category=record.category),
                               point_open_issue_count=open_issue_counts([record.point_id], category=patrol_scope(g.user)).get(record.point_id, 0))

    def require_inspection_access(record):
        if not can_access_category(g.user, record.category):
            abort(404)
        if not can_read_inspection(g.user, record):
            abort(403)

    @app.get("/records/<int:record_id>")
    @login_required
    def record_detail(record_id):
        record = db.get_or_404(Inspection, record_id)
        return render_record_detail(record)

    def render_record_detail(record, error=None, status=200):
        # Called after a rolled-back transition too; recheck before rendering
        # either a successful detail page or its private validation-error form.
        require_inspection_access(record)
        source = request.form.get("return_to") if request.method == "POST" else request.args.get("return_to")
        back_url = normalise_return_to(source, g.user) or url_for("records", category=record.category)
        return render_template("record_detail.html", record=record, issue_form_error=error,
                               issue_action_note=request.form.get("note", ""), issue_version=issue_version(record.issue),
                               can_manage_issue=g.user.role == "admin" or (g.user.role == "inspector" and record.user_id == g.user.id),
                               can_reopen_issue=g.user.role == "admin",
                               back_url=back_url, back_label="返回異常追蹤" if urlsplit(back_url).path == "/issues" else "返回巡檢紀錄",
                               point_open_issue_count=open_issue_counts([record.point_id], category=patrol_scope(g.user)).get(record.point_id, 0)), status

    def apply_issue_action(inspection_id, target_status):
        actor = lock_current_user()
        source = normalise_return_to(request.form.get("return_to"), actor)
        try:
            changed = transition_issue(inspection_id, target_status, actor, request.form.get("expected_event_id"),
                                       request.form.get("note", ""), naive_utc())
            if changed:
                audit("issue_resolved" if target_status == "resolved" else "issue_reopened", inspection_id)
            db.session.commit()
        except IssueActionError as error:
            db.session.rollback()
            if error.status in (403, 404):
                abort(error.status, description=str(error))
            record = db.get_or_404(Inspection, inspection_id)
            return render_record_detail(record, str(error), error.status)
        flash(("案件已結案。" if target_status == "resolved" else "案件已重新開啟。") if changed else "案件已是指定狀態，沒有新增重複處理紀錄。", "success" if changed else "info")
        return redirect(url_for("record_detail", record_id=inspection_id, **({"return_to": source} if source else {})))

    @app.post("/admin/issues/<int:inspection_id>/resolve")
    @app.post("/issues/<int:inspection_id>/resolve")
    @login_required
    def resolve_issue(inspection_id):
        return apply_issue_action(inspection_id, "resolved")

    @app.post("/admin/issues/<int:inspection_id>/reopen")
    @admin_required
    def reopen_issue(inspection_id):
        return apply_issue_action(inspection_id, "open")

    @app.get("/issues")
    @login_required
    def issues():
        if g.user.role == "executor":
            abort(403, description="異常追蹤由巡檢員與管理員處理。")
        floor, category = scope_filters()
        state = request.args.get("status", "open")
        if state not in ("open", "resolved", "all"):
            abort(400, description="案件狀態選項不正確。")
        page = parse_id(request.args.get("page", "1"))
        point_id = request.args.get("point_id", "")
        selected_point = None
        if point_id:
            selected_id = parse_id(point_id)
            point = db.get_or_404(Point, selected_id)
            if can_access_category(g.user, point.category):
                selected_point = point
            else:
                # A former point owner can filter their own historical case,
                # but must not learn the new category's current point name/code.
                scope = patrol_scope(g.user)
                snapshot_query = private_records(select(Inspection.point_code, Inspection.point_name), scope).where(
                    Inspection.point_id == selected_id, Inspection.is_abnormal.is_(True))
                snapshot = db.session.execute(snapshot_query.order_by(Inspection.created_at.desc(), Inspection.id.desc()).limit(1)).first()
                if not snapshot:
                    abort(404)
                selected_point = SimpleNamespace(id=selected_id, code=snapshot.point_code, name=snapshot.point_name)
        query = (select(Inspection).outerjoin(InspectionIssue, InspectionIssue.inspection_id == Inspection.id)
                 .where(db.or_(InspectionIssue.inspection_id.is_not(None), Inspection.is_abnormal.is_(True))))
        query = private_records(query, category)
        if state == "open":
            query = query.where(open_issue_condition())
        elif state == "resolved":
            query = query.where(InspectionIssue.status == state)
        if floor:
            query = query.where(Inspection.point_floor == int(floor))
        if selected_point:
            query = query.where(Inspection.point_id == selected_point.id)
        total = db.session.scalar(select(db.func.count()).select_from(query.subquery()))
        per_page = 50
        pages = max(1, (total + per_page - 1) // per_page)
        if page > pages:
            return redirect(url_for("issues", status=state, floor=floor, category=category, point_id=point_id, page=pages))
        rows = db.session.scalars(query.options(selectinload(Inspection.issue), selectinload(Inspection.photos), selectinload(Inspection.point))
                                  .order_by(db.func.coalesce(InspectionIssue.opened_at, Inspection.created_at).desc(), Inspection.id.desc()).offset((page - 1) * per_page).limit(per_page)).all()
        if page > 1 and not rows:
            # At READ COMMITTED another manager can resolve the last row after
            # our count and before our fetch. Recover that now-empty last page.
            total = db.session.scalar(select(db.func.count()).select_from(query.subquery()))
            pages = max(1, (total + per_page - 1) // per_page)
            if page > pages:
                return redirect(url_for("issues", status=state, floor=floor, category=category, point_id=point_id, page=pages))
        open_total = sum(open_issue_counts(user_id=g.user.id if g.user.role != "admin" else None,
                                         category=patrol_scope(g.user)).values())
        return render_template("issues.html", records=rows, filters={"status": state, "floor": floor, "category": category, "point_id": point_id},
                               selected_point=selected_point, pagination={"page": page, "pages": pages, "total": total, "per_page": per_page}, open_total=open_total)

    @app.get("/photos/<int:photo_id>")
    @login_required
    def photo_file(photo_id):
        photo = db.get_or_404(InspectionPhoto, photo_id)
        require_inspection_access(photo.inspection)
        response = make_response(photo.data)
        response.headers["Content-Type"] = photo.mime_type
        response.headers["Content-Disposition"] = f'inline; filename="inspection-{photo.id}.jpg"'
        return response

    @app.get("/devices")
    @login_required
    def devices():
        bindings = db.session.scalars(select(DeviceBinding).where(DeviceBinding.user_id == g.user.id).order_by(DeviceBinding.created_at.desc())).all()
        return render_template("devices.html", current_binding=device_binding(), bindings=bindings, next_url=binding_destination())

    @app.post("/devices/request")
    @login_required
    def request_device():
        lock_current_user()
        destination = binding_destination()
        binding = device_binding()
        if binding and binding.status in ("pending", "approved"):
            flash("此瀏覽器已經提出申請或已核准。", "info")
            return redirect(devices_url(destination))
        label = request.form.get("label", "我的手機").strip()
        if not valid_label(label):
            abort(400, description="請填寫 1 至 100 字的裝置名稱。")
        pending = db.session.scalar(select(db.func.count(DeviceBinding.id)).where(DeviceBinding.user_id == g.user.id, DeviceBinding.status == "pending"))
        if pending >= 3:
            abort(400, description="已有三筆待審核申請，請先聯絡管理員處理。")
        token = secrets.token_urlsafe(32)
        binding = DeviceBinding(user_id=g.user.id, token_hash=hash_device_token(token), label=label, status="pending")
        db.session.add(binding)
        audit("device_requested", g.user.username, label)
        db.session.commit()
        response = redirect(devices_url(destination))
        response.set_cookie(DEVICE_COOKIE, token, max_age=365 * 86400, httponly=True, secure=app.config["COOKIE_SECURE"], samesite="Lax", path="/")
        flash("申請已送出，請管理員核准後再打卡。", "success")
        return response

    @app.post("/devices/<int:binding_id>/revoke")
    @login_required
    def revoke_own_device(binding_id):
        lock_current_user()
        binding = db.get_or_404(DeviceBinding, binding_id, populate_existing=True)
        if binding.user_id != g.user.id:
            abort(403)
        destination = devices_url(binding_destination())
        if binding.status not in ("approved", "pending"):
            flash("這筆綁定已經處理，請查看目前狀態。", "info")
            return redirect(destination)
        binding.status = "revoked"
        audit("device_self_revoked", binding.id)
        db.session.commit()
        flash("已解除此瀏覽器綁定。", "success")
        return redirect(destination)

    @app.get("/admin/devices")
    @admin_required
    def admin_devices():
        bindings = db.session.scalars(select(DeviceBinding).options(selectinload(DeviceBinding.user)).order_by(db.case((DeviceBinding.status == "pending", 0), else_=1), DeviceBinding.created_at.desc())).all()
        return render_template("admin_devices.html", bindings=bindings)

    @app.post("/admin/devices/<int:binding_id>/approve")
    @admin_required
    def approve_device(binding_id):
        binding = db.get_or_404(DeviceBinding, binding_id)
        lock_admin_users(binding.user_id)
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
        lock_admin_users(binding.user_id)
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
        lock_admin_users(binding.user_id)
        db.session.refresh(binding)
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
        executor = g.user.role == "executor"
        stage = request.args.get("stage", "execution" if executor else "inspection")
        if stage not in ("inspection", "execution"):
            abort(400, description="紀錄階段不正確。")
        if (stage == "execution" and g.user.role not in ("admin", "executor")) or (executor and stage != "execution"):
            abort(403)
        model = PatrolExecution if stage == "execution" else Inspection
        query = select(model).where(model.created_at >= start_time, model.created_at < end_time)
        floor, category = scope_filters()
        user_id = request.args.get("user_id", "")
        if floor:
            query = query.where(model.point_floor == int(floor))
        if stage == "inspection":
            query = private_records(query, category)
        else:
            if category:
                query = query.where(PatrolExecution.category == category)
            if executor:
                query = query.where(PatrolExecution.user_id == g.user.id, PatrolExecution.category == patrol_scope(g.user))
        abnormal = request.args.get("abnormal", "")
        if abnormal not in ("", "0", "1"):
            abort(400, description="異常篩選選項不正確。")
        if abnormal and stage == "execution":
            abort(400, description="執行紀錄不適用異常篩選。")
        if abnormal:
            query = query.where(Inspection.is_abnormal.is_(abnormal == "1"))
        frequency = request.args.get("frequency", "")
        if frequency not in ("", "daily", "daily2", "weekly", "monthly", "irregular", "daily_all"):
            abort(400, description="巡檢頻率選項不正確。")
        if frequency == "daily_all":
            query = query.where(model.frequency.in_(("daily", "daily2")))
        elif frequency:
            query = query.where(model.frequency == frequency)
        if g.user.role != "admin":
            user_id = str(g.user.id)
        elif user_id:
            query = query.where(model.user_id == parse_id(user_id))
        if stage == "execution":
            # Only fetch completion status; the inspector's name and report are private.
            query = query.add_columns(select(Inspection.id).where(Inspection.execution_id == PatrolExecution.id).exists())
        return query.order_by(model.created_at.desc(), model.id.desc()), {"date_from": begin.isoformat(), "date_to": end.isoformat(),
                "floor": floor, "user_id": user_id, "category": category, "abnormal": abnormal, "frequency": frequency, "stage": stage}

    @app.get("/records")
    @login_required
    def records():
        query, filters = record_query()
        stage = filters["stage"]
        if stage == "execution":
            rows = db.session.execute(query.limit(1001)).all()
        else:
            rows = db.session.scalars(query.options(selectinload(Inspection.photos), selectinload(Inspection.issue),
                                                    selectinload(Inspection.execution)).limit(1001)).all()
        if len(rows) > 1000:
            flash("畫面顯示最近 1,000 筆，完整資料請匯出 CSV 或縮小日期範圍。", "info")
        users = db.session.scalars(select(User).order_by(User.display_name)).all() if g.user.role == "admin" else []
        storage = {}
        if g.user.role == "admin":
            storage = {"photo_storage_used": db.session.scalar(select(db.func.coalesce(db.func.sum(InspectionPhoto.size_bytes), 0))),
                       "photo_storage_limit": app.config["PHOTO_STORAGE_LIMIT_BYTES"]}
        rows = rows[:1000]
        return render_template("records.html", records=rows if stage == "inspection" else [],
                               executions=[row for row, _ in rows] if stage == "execution" else [],
                               reviewed_execution_ids={row.id for row, reviewed in rows if reviewed} if stage == "execution" else set(),
                               stage=stage, users=users, filters=filters, **storage)

    @app.get("/records/export")
    @login_required
    def export_records():
        query, filters = record_query()
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        def cell(value):
            value = str(value)
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
        if filters["stage"] == "execution":
            writer.writerow(["執行人員", "樓層", "點位編號", "點位名稱", "執行時間（台北）", "巡檢頻率", "週期開始日", "分類", "時段", "巡檢狀態"])
            for row, reviewed in db.session.execute(query.execution_options(yield_per=500)):
                writer.writerow([cell(row.user_name), floor_label(row.point_floor), cell(row.point_code), cell(row.point_name),
                                 format_localtime(row.created_at), frequency_label(row.frequency), row.period_key,
                                 category_label(row.category), slot_label(row.slot), "已巡檢" if reviewed else "待巡檢"])
        else:
            has_workflows = db.session.scalar(select(query.order_by(None).where(Inspection.workflow_mode != "standard").exists()))
            header = ["人員", "樓層", "點位編號", "點位名稱", "打卡時間（台北）", "巡檢頻率", "週期開始日", "分類", "時段", "異常", "備註", "照片數", "處理狀態", "結案人員", "結案時間（台北）", "處理說明"]
            writer.writerow(header + (["作業模式", "執行人員", "執行時間（台北）"] if has_workflows else []))
            query = query.options(selectinload(Inspection.photos), selectinload(Inspection.issue), selectinload(Inspection.execution))
            for row in db.session.scalars(query.execution_options(yield_per=500)):
                fields = [cell(row.user_name or row.user.display_name), floor_label(row.point_floor), cell(row.point_code), cell(row.point_name),
                          format_localtime(row.created_at), frequency_label(row.frequency), row.period_key,
                          category_label(row.category), slot_label(row.slot), "是" if row.is_abnormal else "否", cell(row.note), len(row.photos),
                          {"open": "未結案", "resolved": "已結案", "": ""}[issue_state(row)],
                          cell(row.issue.resolved_by_name) if row.issue else "", format_localtime(row.issue.resolved_at) if row.issue and row.issue.resolved_at else "",
                          cell(row.issue.resolution_note) if row.issue else ""]
                if has_workflows:
                    mode_label = "抽查" if row.legacy_unscheduled else {"standard": "一般巡檢", "spot": "單段巡檢", "two_stage": "執行後巡檢"}[row.workflow_mode]
                    fields.extend([mode_label,
                                   cell(row.execution.user_name) if row.execution else "",
                                   format_localtime(row.execution.created_at) if row.execution else ""])
                writer.writerow(fields)
        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="patrol-{filters["date_from"]}-{filters["date_to"]}.csv"'
        return response

    def missed_report():
        from missed import calculate_missed

        instant = now_utc()
        today = local_dt(instant).date()
        begin = parse_date(request.args.get("date_from"), today - timedelta(days=6))
        end = parse_date(request.args.get("date_to"), today)
        if begin > end or (end - begin).days > 366:
            abort(400, description="請選擇正確的應完成日期範圍，最多可查詢 367 天。")
        floor, category = scope_filters()
        frequency = request.args.get("frequency", "")
        if frequency not in ("", "daily", "daily2", "weekly", "monthly", "irregular", "daily_all"):
            abort(400, description="巡檢頻率選項不正確。")
        # Read historical schedules, not the point's current classification.
        scope = patrol_scope(g.user)
        points = historical_points(scope)
        first_period = min(begin.replace(day=1), begin - timedelta(days=begin.weekday()))
        completion_query = select(Inspection.point_id, Inspection.frequency, Inspection.period_key, Inspection.slot,
                                  Inspection.workflow_mode).distinct().where(Inspection.period_key >= first_period.isoformat(),
                                      Inspection.period_key <= end.isoformat(), Inspection.legacy_unscheduled.is_(False),
                                      Inspection.frequency != "irregular")
        if scope is not None:
            completion_query = completion_query.where(Inspection.point_id.in_([point.id for point in points]))
        completions = db.session.execute(completion_query).all()
        executions = []
        if scope in (None, "general") and category in ("", "general"):
            executions = db.session.execute(select(PatrolExecution.point_id, PatrolExecution.frequency,
                PatrolExecution.period_key, PatrolExecution.slot).where(PatrolExecution.period_key >= first_period.isoformat(),
                    PatrolExecution.period_key <= end.isoformat(), PatrolExecution.category == "general")).all()
        rows = calculate_missed(points, completions, begin, end, instant,
                                category=category, floor=int(floor) if floor else None, frequency=frequency,
                                executions=executions, two_stage_only=g.user.role == "executor")
        filters = {"date_from": begin.isoformat(), "date_to": end.isoformat(), "category": category,
                   "floor": floor, "frequency": frequency}
        return rows, filters

    @app.get("/missed")
    @login_required
    def missed():
        page = parse_id(request.args.get("page", "1"))
        rows, filters = missed_report()
        summaries = {}
        for row in rows:
            group = tuple(row[key] for key in ("point_id", "code", "name", "floor", "category", "frequency"))
            if group not in summaries:
                summaries[group] = {key: row[key] for key in ("point_id", "code", "name", "floor", "category", "frequency")}
                summaries[group]["missed_count"] = 0
            summaries[group]["missed_count"] += 1
        point_summaries = sorted(summaries.values(), key=lambda row: (-row["missed_count"], FLOOR_ORDER.get(row["floor"], 99), row["code"]))
        per_page = 50
        pages = max(1, (len(rows) + per_page - 1) // per_page)
        if page > pages:
            return redirect(url_for("missed", **filters, page=pages))
        return render_template("missed.html", filters=filters,
            totals={"missed": len(rows), "points": len({row["point_id"] for row in rows})},
            point_summaries=point_summaries, occurrences=rows[(page - 1) * per_page:page * per_page],
            pagination={"page": page, "pages": pages, "total": len(rows), "per_page": per_page})

    @app.get("/missed/export")
    @login_required
    def missed_export():
        rows, filters = missed_report()
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        has_stages = any(row["workflow_mode"] == "two_stage" for row in rows)
        writer.writerow(["應完成日期", "巡檢期間", "分類", "樓層", "點位編號", "點位名稱", "巡檢頻率", "時段", "到期時間（台北）", "漏打次數"]
                        + (["缺少階段"] if has_stages else []))
        def cell(value):
            value = str(value)
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
        for row in rows:
            writer.writerow([row["due_date"].isoformat(), row["period_label"], category_label(row["category"]),
                floor_label(row["floor"]), cell(row["code"]), cell(row["name"]), frequency_label(row["frequency"]),
                slot_label(row["slot"]), format_localtime(row["deadline"]), 1] + ([row["missing_stage_label"]] if has_stages else []))
        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="patrol-missed-{filters["date_from"]}-{filters["date_to"]}.csv"'
        return response

    @app.get("/admin/points")
    @admin_required
    def points():
        floor, category = scope_filters()
        selected_list = request.args.get("list", "current")
        if selected_list not in ("current", "deleted"):
            abort(400, description="點位清單不正確。")
        query = select(Point)
        if floor:
            query = query.where(Point.floor == int(floor))
        if category:
            query = query.where(Point.category == category)
        deleted = query.where(Point.deleted_at.is_not(None))
        deleted_count = db.session.scalar(select(db.func.count()).select_from(deleted.with_only_columns(Point.id).subquery()))
        query = deleted if selected_list == "deleted" else query.where(Point.deleted_at.is_(None))
        return render_template("points.html", points=db.session.scalars(query.order_by(*point_order())).all(), selected_floor=floor, selected_category=category,
                               official_general_codes=dict(general_codes.values()),
                               selected_list=selected_list, deleted_count=deleted_count,
                               open_issue_counts=open_issue_counts())

    def point_values(point=None):
        raw_code = request.form.get("code", "").strip()
        name = request.form.get("name", "").strip()
        floor = request.form.get("floor", "")
        frequency = request.form.get("frequency", "daily")
        category = request.form.get("category", point.category if point else "")
        known_entry = general_codes.get(raw_code.casefold())
        code = known_entry[0] if known_entry else raw_code.upper()
        if floor not in {str(value) for value, _ in FLOOR_OPTIONS}:
            abort(400, description="請選擇有效樓層。")
        if known_entry:
            if category != "general" or int(floor) != known_entry[1]:
                abort(400, description="清冊中的點位編號須使用原來的總務分類與樓層。")
        elif point and category == point.category == "general" and raw_code == point.code and int(floor) == point.floor:
            code = point.code
        elif (not re.fullmatch(r"(?:B[12]|[1-5]F|[145]M)-[A-Z0-9]{2,20}", code)
              or not code.startswith(floor_label(int(floor)) + "-")):
            abort(400, description="點位編號請使用如 1F-A01、B1-A01 或 1M-A01 的格式，並與樓層一致。")
        frequencies = ("daily", "daily2", "weekly", "monthly", "irregular") if category == "general" else ("daily", "daily2", "weekly")
        if not valid_label(name) or frequency not in frequencies:
            abort(400, description="請填寫點位名稱（最多 100 字）與正確的巡檢頻率。")
        if category not in ("safety", "general") and not (point and point.category == category == "uncategorized"):
            abort(400, description="請指定點位屬於職安或總務。")
        default_mode = point.workflow_mode if point and point.category == category else ("spot" if category == "general" else "standard")
        mode = request.form.get("workflow_mode") or default_mode
        allowed = {"spot", "two_stage"} if category == "general" else {"standard"}
        if point and point.category == category == "general" and point.workflow_mode == "standard":
            allowed.add("standard")
        if mode not in allowed:
            abort(400, description="打卡方式與分類不符。總務請選直接巡檢或先執行再巡檢。")
        return {"code": code, "name": name, "floor": int(floor), "frequency": frequency, "category": category, "workflow_mode": mode}

    def protect_pending_execution(point):
        if point.workflow_mode == "two_stage":
            instant = now_utc()
            first = execution_in_slot(point, period_for(point, instant)[0], slot_for(point, instant))
            if first and not execution_reviewed(first):
                abort(409, description="本時段已執行、尚未巡檢。請完成巡檢或待時段結束後，再調整點位流程或停用。")

    def execution_reviewed(first):
        return db.session.scalar(select(Inspection.id).where(Inspection.execution_id == first.id).limit(1)) is not None

    def point_list_url(deleted=False):
        floor, category = scope_filters()
        return url_for("points", floor=floor or None, category=category or None, list="deleted" if deleted else None)

    def check_management_state(item, destination):
        # Older forms and clients did not submit a revision. All new admin
        # forms include one; compare against the row after taking the lock.
        expected = request.form.get("expected_state")
        if expected is not None and expected != management_state(item):
            db.session.rollback()
            return render_template("error.html", code=409, message="這個分頁上的資料已變更，本次操作未套用。",
                                   recovery_url=destination, recovery_label="返回清單查看最新設定"), 409

    def managed_point(point_id, *, deleted=False):
        condition = Point.deleted_at.is_not(None) if deleted else Point.deleted_at.is_(None)
        point = db.session.scalar(select(Point).where(Point.id == point_id, condition)
                                  .with_for_update().execution_options(populate_existing=True))
        if not point:
            abort(404, description="點位不存在或清單狀態已變更，請重新整理。")
        return point

    def save_point(point, action):
        destination = point_list_url()
        audit(action, point.code)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            abort(400, description="點位編號已被使用（含已刪除點位）。請使用不同編號，或至已刪除清單還原。")
        flash("點位設定已儲存。", "success")
        return redirect(destination)

    @app.post("/admin/points/create")
    @admin_required
    def create_point():
        lock_current_admin()
        instant = now_utc()
        point = Point(**point_values(), active=True, schedule_start=local_dt(instant).date(), created_at=naive_utc(instant))
        db.session.add(point)
        point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=point.frequency, category=point.category, workflow_mode=point.workflow_mode, active=True,
                                             floor=point.floor, point_code=point.code, point_name=point.name))
        return save_point(point, "point_created")

    @app.post("/admin/points/<int:point_id>/update")
    @admin_required
    def update_point(point_id):
        lock_current_admin()
        point = managed_point(point_id)
        if conflict := check_management_state(point, point_list_url()):
            return conflict
        values = point_values(point)
        active = request.form.get("active", "") in ("on", "1", "true", "yes")
        if not active or any(getattr(point, key) != values[key] for key in values):
            protect_pending_execution(point)
        # Freeze unknown snapshots before editing the current point. Older workers
        # may still have inserted NULL snapshots during a rolling deployment.
        for schedule in point.schedules:
            if schedule.floor is None:
                schedule.floor = point.floor
            if schedule.point_code is None:
                schedule.point_code = point.code
            if schedule.point_name is None:
                schedule.point_name = point.name
        if point.active != active or any(getattr(point, key) != values[key] for key in values):
            instant = now_utc()
            changed = (point.workflow_mode != values["workflow_mode"] or (point.workflow_mode != "standard" and
                       (point.active != active or point.frequency != values["frequency"] or point.category != values["category"])))
            point.schedules.append(PointSchedule(effective_date=local_dt(instant).date(), frequency=values["frequency"], category=values["category"], active=active,
                                                 workflow_changed_at=naive_utc(instant) if changed else None,
                                                 workflow_mode=values["workflow_mode"], floor=values["floor"], point_code=values["code"], point_name=values["name"]))
        for key, value in values.items():
            setattr(point, key, value)
        point.active = active
        return save_point(point, "point_updated")

    @app.post("/admin/points/<int:point_id>/rotate-qr")
    @admin_required
    def rotate_point_qr(point_id):
        lock_current_admin()
        point = managed_point(point_id)
        destination = point_list_url()
        if conflict := check_management_state(point, destination):
            return conflict
        point.qr_token = secrets.token_urlsafe(24)
        audit("qr_rotated", point.code)
        db.session.commit()
        flash("QR Code 已更新，舊碼已失效。請重新列印並更換現場標籤。", "success")
        return redirect(destination)

    @app.post("/admin/points/<int:point_id>/delete")
    @admin_required
    def delete_point(point_id):
        lock_current_admin()
        point = managed_point(point_id)
        destination = point_list_url()
        if conflict := check_management_state(point, destination):
            return conflict
        instant = now_utc()
        protect_pending_execution(point)
        point.deleted_at = naive_utc(instant)
        point.active = False
        point.qr_token = secrets.token_urlsafe(24)
        point.schedules.append(PointSchedule(effective_date=local_dt(instant).date(), frequency=point.frequency, retired_at=naive_utc(instant),
            category=point.category, workflow_mode=point.workflow_mode, active=False, floor=point.floor, point_code=point.code, point_name=point.name))
        audit("point_deleted", point.code)
        db.session.commit()
        flash("點位已移至已刪除，舊 QR Code 已失效；歷史紀錄仍保留。", "success")
        return redirect(destination)

    @app.post("/admin/points/<int:point_id>/restore")
    @admin_required
    def restore_point(point_id):
        lock_current_admin()
        point = managed_point(point_id, deleted=True)
        destination = point_list_url(deleted=True)
        if conflict := check_management_state(point, destination):
            return conflict
        point.deleted_at, point.active = None, False
        audit("point_restored", point.code)
        db.session.commit()
        flash("點位已還原為停用。請至現有點位啟用，再列印新的 QR Code。", "success")
        return redirect(destination)

    def qr_image(point, factory=None):
        address = app.config["PUBLIC_BASE_URL"] + url_for("checkin", token=point.qr_token)
        img = qrcode.make(address, image_factory=factory, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
        output = io.BytesIO()
        img.save(output)
        return output.getvalue()

    @app.get("/admin/points/<int:point_id>/qr.svg")
    @admin_required
    def point_qr(point_id):
        point = db.get_or_404(Point, point_id)
        if point.deleted_at is not None or not point.active:
            abort(404)
        response = make_response(qr_image(point, qrcode.image.svg.SvgPathImage))
        response.headers["Content-Type"] = "image/svg+xml"
        return response

    @app.get("/admin/points/print")
    @admin_required
    def print_qr():
        query = select(Point).where(Point.active.is_(True), Point.deleted_at.is_(None))
        floor, category = scope_filters()
        if floor:
            query = query.where(Point.floor == int(floor))
        if category:
            query = query.where(Point.category == category)
        ids = request.args.get("ids", "")
        if ids:
            if len(ids) > 2000:
                abort(400)
            query = query.where(Point.id.in_([parse_id(x) for x in ids.split(",")]))
        points = db.session.scalars(query.order_by(*point_order())).all()
        # The code and label come from the same snapshot, in one HTTP response.
        qr_images = {point.id: base64.b64encode(qr_image(point)).decode("ascii") for point in points}
        return render_template("print_qr.html", points=points, qr_images=qr_images, selected_floor=floor, selected_category=category,
                               public_base_url=app.config["PUBLIC_BASE_URL"], base_url_set=app.config["PUBLIC_BASE_URL"].startswith("https://"))

    @app.get("/admin/users")
    @admin_required
    def users():
        return render_template("users.html", users=db.session.scalars(select(User).order_by(User.id)).all())

    def submitted_role():
        choice = request.form.get("role", "")
        if choice == "admin":
            return "admin", None
        if choice == "general_executor":
            return "executor", "general"
        if choice in ("safety", "general"):
            return "inspector", choice
        abort(400, description="請指定管理員、職安巡檢員、總務執行人員或總務巡檢員。")

    def choice_label(role, category):
        return "general_executor" if role == "executor" else category or role

    @app.post("/admin/users/create")
    @admin_required
    def create_user():
        lock_admin_users()
        username = request.form.get("username", "").strip().lower()
        name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        role, category = submitted_role()
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username) or not valid_label(name) or not 12 <= len(password) <= 256:
            abort(400, description="請填寫有效帳號（3–80 個英數字或 _.-）、姓名、角色與至少 12 字元的密碼。")
        user = User(username=username, display_name=name, role=role, patrol_category=category, must_change_password=True)
        user.set_password(password)
        db.session.add(user)
        audit("user_created", username, choice_label(role, category))
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
        user = lock_admin_users(user_id)[user_id]
        if not user:
            abort(404)
        if conflict := check_management_state(user, url_for("users")):
            return conflict
        name = request.form.get("display_name", "").strip()
        role, category = submitted_role()
        active = request.form.get("active", "") in ("on", "1", "true", "yes")
        if not valid_label(name):
            abort(400)
        if user.id == g.user.id and (role != "admin" or not active):
            abort(400, description="不能停用自己或移除自己的管理員權限。")
        previous = choice_label(user.role, user.patrol_category)
        if user.role != role or user.patrol_category != category or user.active != active:
            user.auth_version += 1
        user.display_name, user.role, user.patrol_category, user.active = name, role, category, active
        if not active:
            db.session.execute(db.update(DeviceBinding).where(DeviceBinding.user_id == user.id, DeviceBinding.status.in_(["approved", "pending"])).values(status="revoked"))
        audit("user_updated", user.username, f"{previous} -> {choice_label(role, category)}")
        db.session.commit()
        flash("帳號設定已更新。", "success")
        return redirect(url_for("users"))

    @app.post("/admin/users/<int:user_id>/reset-password")
    @admin_required
    def reset_password(user_id):
        user = lock_admin_users(user_id)[user_id]
        if not user:
            abort(404)
        if conflict := check_management_state(user, url_for("users")):
            return conflict
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
        from migrations import upgrade_schema
        has_general_register = bool(os.environ.get("GENERAL_PATROL_CATALOG_JSON"))
        if has_general_register:
            from catalog_general import preflight_general_catalog, import_general_catalog
            preflight_general_catalog(db.engine)
        upgrade_schema(db.engine)
        if os.environ.get("IMPORT_SAFETY_POINTS") == "1":
            from catalog import import_safety_catalog
            import_safety_catalog(apply=True)
        if has_general_register:
            result = import_general_catalog(apply=True)
            click.echo(f"General catalogue: new={result['created']} existing={result['existing']} already_imported={result['already_imported']}")
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
            user = User(username=username, display_name=name, role=role, patrol_category="safety" if role == "inspector" else None)
            user.set_password(password)
            db.session.add(user)
        db.session.flush()
        inspector = db.session.scalar(select(User).where(User.username == "inspector"))
        today = local_dt(now_utc()).date()
        names = {1: ["大門入口", "卸貨區", "消防設備"], 2: ["生產區入口", "包裝區", "緊急出口"], 3: ["倉儲區", "配電箱", "逃生通道"], 4: ["設備機房", "冷藏區", "安全出口"], 5: ["頂樓出入口", "水塔區", "機電設備"]}
        for floor in range(1, 6):
            for number, name in enumerate(names[floor], 1):
                frequency = "weekly" if number == 3 else "daily"
                point = Point(code=f"{floor}F-A{number:02}", name=name, floor=floor, frequency=frequency, category="safety", schedule_start=today - timedelta(days=30))
                point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=frequency, active=True, category=point.category,
                                                     floor=point.floor, point_code=point.code, point_name=point.name))
                db.session.add(point)
                db.session.flush()
                if number == 1 and floor in (1, 2, 4):
                    instant = datetime.combine(today, time(8, floor * 7), TAIPEI).astimezone(timezone.utc)
                    if instant > now_utc():
                        instant = now_utc() - timedelta(minutes=floor)
                    key, _, _ = period_for(point, instant)
                    db.session.add(Inspection(user_id=inspector.id, point_id=point.id, created_at=naive_utc(instant), period_key=key, frequency=frequency, category=point.category, point_code=point.code, point_name=point.name, point_floor=floor, user_name=inspector.display_name))
        db.session.commit()
        access_file = instance / "preview-access.txt"
        access_file.write_text("LOCAL DEMO ONLY / 本機示範帳號\n" + app.config["PUBLIC_BASE_URL"] + "\n\n" + "\n".join(f"{u}: {p}" for u, p in passwords.items()), encoding="utf-8")
        click.echo(f"Demo created. Local credentials are in {access_file}; not printed or used in production.")

    from catalog import register_catalog_commands
    register_catalog_commands(app)
    return app


application = create_app()
