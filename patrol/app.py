"""Factory patrol: QR confirmation, approved browsers and durable records."""
from datetime import date, datetime, time, timedelta, timezone
from functools import lru_cache, wraps
import base64
import csv
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import threading
from tempfile import SpooledTemporaryFile
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlencode, urlsplit
from zoneinfo import ZoneInfo

import click
from flask import Flask, abort, before_render_template, flash as flask_flash, g, make_response, redirect, render_template, request, send_file, session, url_for
import qrcode
import qrcode.image.svg
from itsdangerous import BadData, URLSafeSerializer, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload, selectinload
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from account_roles import ACCOUNT_CHOICES, ACCOUNT_ROLE_LABELS, account_role_choice, role_label
from checklist_catalog import checklist_for_point, checklist_revision, validate_checklist
from checklist_records import checklist_snapshot, encode_checklist, checklist_text
from i18n import client_catalog, get_locale, point_name as localized_point_name, t

from models import AuditLog, DeviceBinding, Inspection, InspectionIssue, InspectionPhoto, IssueEvent, IssueEventPhoto, LoginAttempt, LoginEvent, PatrolExecution, Point, PointSchedule, RevokedSession, User, db
from login_client import classify_login_client
from login_history import login_records_page
from general_workflow import (EXECUTION_STATUS_LABELS, execution_deadline, execution_in_slot, execution_review_status,
                              new_execution, personal_inspection_in_slot)
from catalog_general import catalogue_rows as general_catalogue_rows
from domain import CATEGORY_OPTIONS, FLOOR_OPTIONS, FLOOR_ORDER, category_label, floor_label
from missed import period_bounds
from images import PhotoValidationError, photo_storage_used, process_uploads
from patrol_access import (apply_point_scope, can_access_category, can_access_point, can_access_point_team,
                           can_read_inspection, can_view_execution_records, can_view_general_team,
                           inspection_team_scope, patrol_scope)
from ready_patrol import ready_patrol_points
from daily_rounds import daily2_anytime, next_daily2_slot
from issues import (IssueActionError, append_resolution_photos, can_resolve_issue, issue_state, issue_version,
                    open_issue_condition, open_issue_counts as count_open_issues, open_issue_for, transition_issue_event)

TAIPEI = ZoneInfo("Asia/Taipei")
DEVICE_COOKIE = "patrol_device"
QR_RETURN_PATH = re.compile(r"/c/([A-Za-z0-9_-]{1,100})")
PASSWORD_MIN_LENGTH = 6
PASSWORD_MAX_LENGTH = 256
UI_LANGUAGES = {"zh-Hant": "繁體中文", "id": "Bahasa Indonesia（印尼文）", "vi": "Tiếng Việt（越南文）"}
ISSUE_EXPORT_SLOT = threading.BoundedSemaphore(1)


def flash(message, category="message"):
    """Translate at presentation time without changing stored audit or record data."""
    return flask_flash(t(message), category)


def uses_simple_executor_ui(user):
    return bool(user and user.role == "executor" and user.simple_executor_ui)


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
    if getattr(point, "inspection_team", "general") == "engineering":
        location += ("engineering",)
    if revision := checklist_revision(point):
        location += ("checklist", revision)
    return hashlib.sha256("\x00".join(location).encode("utf-8")).hexdigest()


def management_state(item):
    """Detect a browser tab submitting settings that have since changed."""
    if isinstance(item, Point):
        values = (item.id, item.code, item.name, item.floor, item.category, item.frequency,
                  item.workflow_mode, item.active, item.qr_token, item.deleted_at.isoformat() if item.deleted_at else None)
        if item.inspection_team == "engineering":
            values += ("engineering",)
    else:
        values = (item.id, item.display_name, item.role, item.patrol_category, item.active, item.auth_version)
        if item.general_manager_title:
            values += ("general_manager",)
        if item.engineering_inspector_title:
            values += ("engineering_inspector",)
        if item.ui_language != "zh-Hant":
            values += ("ui_language", item.ui_language)
        if item.simple_executor_ui:
            values += ("simple_executor_ui",)
    return hashlib.sha256(json.dumps(values).encode("utf-8")).hexdigest()


def period_for(point, instant):
    first, last = period_bounds(local_dt(instant).date(), point.frequency)
    start = datetime.combine(first, time.min, TAIPEI)
    end = datetime.combine(last + timedelta(days=1), time.min, TAIPEI)
    return first.isoformat(), start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def handoff_period(frequency, period_key):
    """Describe the saved weekly/monthly first stage, including on historical receipts."""
    if frequency not in ("weekly", "monthly"):
        return None
    deadline = execution_deadline(frequency, period_key, "any")
    if deadline is None:
        return None
    first = date.fromisoformat(period_key)
    last = deadline.date() - timedelta(days=1)
    return {"start": first, "end": last}


def slot_for(point, instant):
    return ("am" if local_dt(instant).hour < 12 else "pm") if point.frequency == "daily2" else "any"


def slot_label(slot):
    return {"am": "第 1 次", "pm": "第 2 次", "any": "不限時段"}.get(slot, "不限時段")


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
        executor = bool(user and user.role == "executor")
        if parsed.path == "/issues" and (not user or executor):
            return None
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=10)
        if len({key for key, _ in pairs}) != len(pairs):
            return None
        allowed = ({"date_from", "date_to", "floor", "user_id", "category", "abnormal", "frequency", "stage", "page", "inspection_team"}
                   if parsed.path == "/records" else {"status", "floor", "category", "point_id", "page", "inspection_team", "date_from", "date_to"})
        values = {}
        for key, item in pairs:
            if key not in allowed or any(ord(char) < 32 or ord(char) == 127 for char in item):
                return None
            if not item:
                if parsed.path == "/issues" and key in ("date_from", "date_to"):
                    values[key] = ""
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
            elif key == "inspection_team" and item not in ("general", "engineering"):
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
            if key == "user_id" and (not user or (user.role != "admin" and not can_view_general_team(user))):
                continue
            if key == "inspection_team" and not (user and (user.role == "admin" or
                    (can_view_general_team(user) and user.general_manager_title and not user.engineering_inspector_title))):
                continue
            if key == "category" and user and user.role != "admin":
                item = patrol_scope(user)
                if not item:
                    continue
            values[key] = item
        if parsed.path == "/records":
            stage = values.get("stage", "execution" if executor else "inspection")
            if (stage == "execution" and not can_view_execution_records(user)
                    or values.get("abnormal") and (stage == "execution" or executor)):
                return None
            today = local_dt(now_utc()).date()
            begin = date.fromisoformat(values.get("date_from", (today - timedelta(days=6)).isoformat()))
            end = date.fromisoformat(values.get("date_to", today.isoformat()))
            if begin > end or (end - begin).days > 366:
                return None
        elif values.get("date_from") and values.get("date_to") and values["date_from"] > values["date_to"]:
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
    register = general_catalogue_rows()
    general_codes = {row["code"].casefold(): (row["code"], row["floor"]) for row in register}
    app.config["EXECUTOR_VISIT_CODES"] = frozenset(
        row["code"] for row in register
        if row["category"] == "general" and row["workflow_mode"] == "spot" and row["frequency"] == "irregular"
    )
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
    app.jinja_env.globals["t"] = t

    @app.template_global()
    def reporter_name(record):
        if record.user_name:
            return record.user_name
        if can_view_general_team(g.user) and record.user_id != g.user.id:
            return f"人員 {record.user_id}"
        return record.user.display_name

    @app.template_global()
    def report_point_location(record):
        code, name, floor = record.point_code, record.point_name, record.point_floor
        if not code or not name or floor is None:
            current = record.point
            if current and can_access_point(g.user, current):
                code = code or current.code
                name = name or current.name
                floor = current.floor if floor is None else floor
        return SimpleNamespace(code=code or f"#{record.point_id}", name=name or "歷史巡檢點",
                               floor=floor_label(floor) if floor is not None else "未記錄")

    @app.context_processor
    def common_context():
        user = g.get("user")
        return {"current_user": user, "role_label": role_label, "is_patrol_admin": bool(user and user.role == "admin"),
                "t": t, "ui_locale": get_locale(), "ui_languages": UI_LANGUAGES,
                "checklist_snapshot": checklist_snapshot,
                "simple_executor_ui": uses_simple_executor_ui(user), "home_url": home_url(user),
                "localized_point_name": localized_point_name, "client_i18n": client_catalog(),
                "account_role_labels": ACCOUNT_ROLE_LABELS, "account_role_choice": account_role_choice,
                "viewer_category": patrol_scope(user) or None, "can_view_general_team": can_view_general_team(user),
                "csrf_token": csrf_token, "today": local_dt(now_utc()).date(),
                "password_min_length": PASSWORD_MIN_LENGTH, "password_max_length": PASSWORD_MAX_LENGTH,
                "floor_options": FLOOR_OPTIONS, "category_options": CATEGORY_OPTIONS,
                "floor_label": floor_label, "category_label": category_label,
                "point_team_label": point_team_label, "point_team_key": point_team_key,
                "selected_inspection_team": selected_inspection_team(),
                "can_filter_inspection_team": can_filter_inspection_team(user),
                "viewer_team_label": ("總務與工務" if can_filter_inspection_team(user) else
                                      "工務" if inspection_team_scope(user) == "engineering" else "總務"),
                "slot_label": slot_label, "frequency_label": frequency_label, "issue_state": issue_state,
                "can_resolve_issue": lambda record: can_resolve_issue(user, record)}

    def can_filter_inspection_team(user):
        return bool(user and (user.role == "admin" or (can_view_general_team(user)
                    and user.general_manager_title and not user.engineering_inspector_title)))

    def selected_inspection_team():
        if not can_filter_inspection_team(g.get("user")):
            return ""
        if request.args.get("category") in ("safety", "uncategorized") and g.user.role == "admin":
            return ""
        value = request.args.get("inspection_team", "")
        # Validate at report entry rather than in the error page's context processor.
        return value if value in ("general", "engineering") else ""

    def scoped_query(query, model=Point):
        return apply_point_scope(query, g.user, model, selected_inspection_team())

    def point_team_key(item):
        get = item.get if isinstance(item, dict) else lambda key, default=None: getattr(item, key, default)
        category = get("category", "uncategorized")
        if category != "general":
            return category
        team = get("inspection_team")
        if team is None:
            point = get("point")
            if point is None and get("point_id"):
                point = db.session.get(Point, get("point_id"))
            team = getattr(point, "inspection_team", "general")
        return "engineering" if team == "engineering" else "general"

    def point_team_label(item):
        key = point_team_key(item)
        return "工務" if key == "engineering" else category_label(key)

    def open_issue_counts(point_ids=None, user_id=None, category=None):
        return count_open_issues(point_ids, user_id, category, actor=g.get("user"),
                                 inspection_team=selected_inspection_team())

    def visible_open_issue_total():
        if not g.get("user") or g.user.role == "executor":
            return 0
        owner = None if g.user.role == "admin" or can_view_general_team(g.user) else g.user.id
        return sum(open_issue_counts(user_id=owner, category=patrol_scope(g.user)).values())

    @app.url_defaults
    def preserve_inspection_team(endpoint, values):
        if endpoint in {"dashboard", "ready", "dashboard_ready", "records", "export_records", "missed",
                        "missed_export", "issues", "export_issues_xlsx", "points", "print_qr", "create_point", "update_point",
                        "restore_point", "delete_point", "rotate_point_qr"} and request:
            if values.get("category") in ("safety", "uncategorized"):
                values.pop("inspection_team", None)
                return
            team = selected_inspection_team()
            if team and "inspection_team" not in values:
                values["inspection_team"] = team

    @before_render_template.connect_via(app)
    def configure_scanner(sender, template, context, **extra):
        # Grant camera access only to rendered work pages that actually offer scanning.
        viewer = g.get("user")
        can_scan = template.name == "offline.html" or bool(viewer and not viewer.must_change_password
                        and (viewer.role == "admin" or patrol_scope(viewer))
                        and template.name in {
                            "dashboard.html", "ready.html", "checkin.html", "checkin_success.html", "records.html",
                            "record_detail.html", "issues.html", "missed.html", "devices.html",
                            "admin_devices.html", "points.html", "users.html", "login_records.html",
                        })
        context["can_scan"] = g.patrol_scanner_page = can_scan

    @app.before_request
    def load_user_and_protect():
        g.user = None
        g.patrol_voice_result = None
        # Activate a scheduled frequency before any page or submission can use
        # the prior day's current rule. This transaction precedes user work.
        if request.endpoint not in ("static", "offline_worker", "offline_page", "healthz"):
            from point_assignment_revision import activate_due_point_frequencies
            try:
                activate_due_point_frequencies(now_utc())
            except ValueError:
                # Keep management/diagnostic pages available, while refusing to
                # show or submit an obsolete work schedule.
                g.frequency_update_error = True
                app.logger.error("Scheduled point frequency requires administrator review.")
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
                language = get_locale()
                session.clear()
                if language != "zh-Hant":
                    session["ui_language"] = language
            else:
                session["ui_language"] = get_locale()
        if g.get("frequency_update_error") and request.endpoint in (
                "dashboard", "ready", "dashboard_ready", "checkin", "confirm_checkin",
                "offline_prepare", "offline_sync"):
            abort(503, description="點位排程更新需要管理員確認，請稍後重試；本次未新增打卡，手機暫存仍保留。")
        # An expired protected submission has no authority to write. Recover its
        # safe GET confirmation page before checking the now-missing CSRF secret;
        # the sign-in form itself retains its normal CSRF protection.
        if request.path.startswith("/api/offline/"):
            if not g.user:
                source = "請連網登入原帳號後再同步；暫存仍保留。"
                return {"ok": False, "code": "login_required", "message": t(source), "message_source": source, "retryable": False}, 401
            if g.user.must_change_password:
                source = "請先完成密碼變更；暫存仍保留。"
                return {"ok": False, "code": "password_required", "message": t(source), "message_source": source, "retryable": False}, 403
        if not g.user and request.method == "POST":
            if request.endpoint == "logout":
                # A second open tab may still show the previous logout button.
                return redirect(url_for("login"))
            destination = protected_post_destination()
            if destination:
                return redirect(url_for("login", next=safe_next(destination)))
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and app.config["CSRF_ENABLED"]:
            expected = session.get("csrf_token", "")
            received = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not expected or not received or not received.isascii() or not hmac.compare_digest(expected, received):
                if request.endpoint == "login" and request.method == "POST" and not g.user:
                    flash("登入表單已過期，請重新輸入密碼後再登入。", "error")
                    return render_template("login.html", next=safe_next(request.form.get("next") or request.args.get("next"))), 400
                abort(400, description="表單已過期，請重新載入頁面後再試。")
        if g.user and g.user.must_change_password and request.endpoint not in ("change_password", "logout", "static", "healthz", "offline_page", "offline_worker", "ui_preferences"):
            if (request.method == "GET" and request.endpoint not in (None, "login")
                    and (request.endpoint == "checkin" or not session.get("after_password")
                         or session["after_password"] == url_for("dashboard"))):
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
            response.headers["Cache-Control"] = "private, no-store" if request.endpoint in ("photo_file", "issue_photo_file", "export_issues_xlsx", "ui_preferences") else "no-store"
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
        if request.endpoint in ("confirm_checkin", "checkin"):
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
                abort(403, description="此功能僅限系統管理員使用。")
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
            abort(403, description="系統管理員權限已更新，請重新登入後再試。")
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
            abort(403, description="系統管理員權限或帳號狀態已更新，請重新登入後再試。")
        return locked

    def device_binding():
        token = request.cookies.get(DEVICE_COOKIE, "")
        if not g.user or not token or len(token) > 256:
            return None
        return db.session.scalar(select(DeviceBinding).where(DeviceBinding.user_id == g.user.id, DeviceBinding.token_hash == hash_device_token(token)))

    def device_status():
        binding = device_binding()
        return binding.status if binding else "none"

    def browser_in_use_by_another_account():
        # Setting the single device cookie here would silently strand the first
        # account before an administrator has approved the second request.
        token = request.cookies.get(DEVICE_COOKIE, "")
        if not token or len(token) > 256:
            return False
        return db.session.scalar(select(DeviceBinding.id).where(
            DeviceBinding.token_hash == hash_device_token(token), DeviceBinding.user_id != g.user.id,
            DeviceBinding.status.in_(("pending", "approved")))) is not None

    def binding_overview(bindings=None):
        """Identify this browser and this account's approved device in one read."""
        token = request.cookies.get(DEVICE_COOKIE, "")
        digest = hash_device_token(token) if token and len(token) <= 256 else None
        if bindings is None:
            relevant = DeviceBinding.status == "approved"
            if digest:
                relevant = db.or_(relevant, DeviceBinding.token_hash == digest)
            bindings = db.session.scalars(select(DeviceBinding).where(DeviceBinding.user_id == g.user.id, relevant)).all()
        current = next((row for row in bindings if row.token_hash == digest), None)
        other = next((row for row in bindings if row.status == "approved" and row is not current), None)
        return current, other

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

    def home_url(user=None):
        return url_for("ready" if uses_simple_executor_ui(user or g.get("user")) else "dashboard")

    def safe_next(value, user=None):
        fallback = home_url(user)
        if not value or len(value) > 2048 or not value.startswith("/") or value.startswith("//") or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            return fallback
        try:
            app.url_map.bind_to_environ(request.environ).match(urlsplit(value).path, method="GET")
        except (HTTPException, ValueError):
            return fallback
        return value

    def registered_visit_owners():
        # One lookup per request, including a dashboard listing all seven points.
        cache_key = "patrol.registered_visit_owners"
        if cache_key not in request.environ:
            first = select(db.func.min(PointSchedule.id)).where(PointSchedule.category == "general",
                PointSchedule.point_code.in_(app.config["EXECUTOR_VISIT_CODES"])).group_by(PointSchedule.point_code)
            rows = db.session.execute(select(PointSchedule.point_code, PointSchedule.point_id).where(PointSchedule.id.in_(first)))
            request.environ[cache_key] = dict(rows.all())
        return request.environ[cache_key]

    def executor_can_scan(point):
        return point.category == "general" and (point.workflow_mode == "two_stage" or
                (point.workflow_mode == "spot" and point.frequency == "irregular" and
                 point.code in app.config["EXECUTOR_VISIT_CODES"] and
                 registered_visit_owners().get(point.code, point.id) == point.id))

    def binding_destination():
        """Keep a scanned point through approval, without trusting a return URL."""
        value = request.form.get("next") if request.method == "POST" else request.args.get("next")
        if value is None:
            value = session.get("after_binding", "")
        match = QR_RETURN_PATH.fullmatch(value or "")
        point = db.session.scalar(select(Point).where(Point.qr_token == match.group(1))) if match else None
        if (point and point.deleted_at is None and can_access_point(g.user, point)
                and (g.user.role != "executor" or executor_can_scan(point))
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
        if request.args.get("inspection_team", "") not in ("", "general", "engineering"):
            abort(400, description="巡檢負責單位選項不正確。")
        scope = patrol_scope(g.user)
        if scope is None and not category and selected_inspection_team():
            category = "general"
        return floor, category if scope is None else scope

    def private_records(query, category):
        """Use the category at submission. Only general inspectors have team-wide reads."""
        scope = patrol_scope(g.user)
        query = scoped_query(query, Inspection)
        if scope is None:
            return query.where(Inspection.category == category) if category else query
        if not scope:
            return query.where(db.false())
        if can_view_general_team(g.user):
            return query.where(Inspection.category == scope)
        if g.user.role == "executor":
            return query.where(Inspection.user_id == g.user.id, Inspection.category == "general",
                               Inspection.executor_visit.is_(True), Inspection.workflow_mode == "spot",
                               Inspection.frequency == "irregular")
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
        # Category is evaluated from each historical schedule below. A point
        # now in safety can still have general history, whose current team
        # must remain consistent with the record/photo authorization checks.
        team = selected_inspection_team() or inspection_team_scope(g.user)
        if team is not None:
            query = query.where(Point.inspection_team == team if team else db.false())
        points = db.session.scalars(query).all()
        if scope is None:
            return points
        # Old schedule rows can lack a name/code snapshot. After a team
        # transfer, that fallback must not display the new team's labels.
        return [p if p.category == scope else SimpleNamespace(
            id=p.id, code=f"#{p.id}", name="歷史巡檢點", floor=p.floor, category=p.category,
            frequency=p.frequency, workflow_mode=p.workflow_mode, active=p.active, created_at=p.created_at, schedule_start=p.schedule_start,
            schedules=p.schedules, inspection_team=p.inspection_team, deleted_at=p.deleted_at) for p in points]

    def point_order():
        return db.case({value: index for index, (value, _) in enumerate(FLOOR_OPTIONS)}, value=Point.floor), Point.code

    @app.get("/healthz")
    def healthz():
        db.session.execute(db.text("SELECT 1"))
        return {"status": "ok"}

    @app.get("/api/ui-preferences")
    def ui_preferences():
        # A public offline shell can display the signed-in account's language
        # even on an unbound browser. This hint grants no offline capabilities.
        if not g.user:
            return {"ok": False, "code": "login_required"}, 401
        return {"ok": True, "ui_language": get_locale(),
                "simple_executor_ui": uses_simple_executor_ui(g.user), "home_url": home_url(g.user)}

    @app.get("/")
    def index():
        return redirect(home_url() if g.user else url_for("login"))

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
                next_url = safe_next(request.form.get("next") or request.args.get("next"), user)
                # Use the identity and version that actually matched the password.
                user_id, version, change_required = user.id, user.auth_version, user.must_change_password
                client_type, browser = classify_login_client(request.user_agent.string, request.headers.get("Sec-CH-UA-Mobile"))
                revoke_current_login()
                # A reset or deactivation during an account switch must not
                # produce a success event or start a session for the stale login.
                source = select(User.id, User.username, User.display_name, db.literal(client_type),
                                db.literal(browser), db.literal(naive_utc(), type_=db.DateTime())).where(
                                    User.id == user_id, User.active.is_(True), User.auth_version == version)
                saved_id = db.session.scalar(db.insert(LoginEvent).from_select(
                    ["user_id", "username", "display_name", "client_type", "browser", "created_at"], source
                ).returning(LoginEvent.id))
                db.session.commit()
                language = user.ui_language
                session.clear()
                session["ui_language"] = language
                if saved_id is None:
                    flash("帳號設定已更新，請重新登入。", "error")
                    return redirect(url_for("login", next=next_url))
                session["user_id"] = user_id
                session["auth_version"] = version
                session["sid"] = secrets.token_urlsafe(32)
                session.permanent = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                if change_required:
                    if urlsplit(next_url).path == url_for("change_password"):
                        # This GET already contains the safe post-change return
                        # target. Do not nest it as the next destination again.
                        return redirect(next_url)
                    session["after_password"] = next_url
                    return redirect(url_for("change_password"))
                return redirect(next_url)
        return render_template("login.html", next=safe_next(request.form.get("next") or request.args.get("next")))

    def revoke_current_login():
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

    @app.post("/logout")
    def logout():
        language = get_locale()
        revoke_current_login()
        if g.user:
            db.session.commit()
        session.clear()
        if language != "zh-Hant":
            session["ui_language"] = language
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
            elif not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
                flash(t("新密碼請使用 {minimum} 至 {maximum} 個字元。", minimum=PASSWORD_MIN_LENGTH, maximum=PASSWORD_MAX_LENGTH), "error")
            elif password != request.form.get("confirm_password"):
                flash("兩次輸入的新密碼不同。", "error")
            elif g.user.check_password(password):
                flash("新密碼不可與目前密碼相同，請設定不同的密碼。", "error")
            else:
                g.user.set_password(password)
                g.user.auth_version += 1
                # Keep the version we wrote while holding the account lock.
                # A later admin reset must invalidate even this pending response.
                changed_version = g.user.auth_version
                g.user.must_change_password = False
                audit("change_password", g.user.id)
                db.session.commit()
                session.pop("after_password", None)
                session["auth_version"] = changed_version
                session["sid"] = signed_session_nonce()
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash("密碼已更新。", "success")
                return redirect(destination)
        return render_template("change_password.html", next_url=destination)

    def ready_context():
        floor, category = scope_filters()
        local_now = local_dt(now_utc())
        points = []
        simple_executor = uses_simple_executor_ui(g.user)
        if category or g.user.role == "admin":
            query = select(Point).where(Point.active.is_(True), Point.deleted_at.is_(None),
                                        Point.schedule_start <= local_now.date())
            if not simple_executor:
                query = query.where(Point.frequency != "irregular")
            if category:
                query = query.where(Point.category == category)
            if floor:
                query = query.where(Point.floor == int(floor))
            points = db.session.scalars(scoped_query(query).options(selectinload(Point.schedules)).order_by(*point_order())).all()
        ready_points = ready_patrol_points(points, g.user, local_now, floor, category)
        if simple_executor:
            visits = [point for point in points if point.frequency == "irregular"
                      and point.workflow_mode == "spot" and executor_can_scan(point)]
            if visits:
                completed = set(db.session.scalars(select(Inspection.point_id).where(
                    Inspection.point_id.in_([point.id for point in visits]), Inspection.user_id == g.user.id,
                    Inspection.personal_day == local_now.date())))
                ready_points.extend(dict(id=point.id, floor=point.floor, code=point.code, name=point.name,
                                         frequency=point.frequency, period_end=local_now.date(),
                                         status_key="visit", status_label="可直接簽到")
                                    for point in visits if point.id not in completed)
                ready_points.sort(key=lambda row: (FLOOR_ORDER.get(row["floor"], len(FLOOR_ORDER)), row["code"]))
        return dict(selected_floor=floor, selected_category=category,
                    ready_points=ready_points,
                    ready_date=local_now.date(), ready_as_of=local_now,
                    ready_slot_label="不限時段")

    @app.get("/ready")
    @login_required
    def ready():
        return render_template("ready.html", **ready_context())

    @app.get("/dashboard/ready")
    @login_required
    def dashboard_ready():
        return render_template("_today_ready.html", **ready_context())

    @app.get("/dashboard")
    @login_required
    def dashboard():
        if uses_simple_executor_ui(g.user):
            return redirect(url_for("ready", **({"floor": request.args["floor"]} if request.args.get("floor") else {})))
        from missed import VIEW_FREQUENCIES, schedule_snapshot, schedule_timeline, slot_plans
        instant = now_utc()
        local_now = local_dt(instant)
        today = local_now.date()
        selected = parse_date(request.args.get("date"), today)
        view = request.args.get("view", "daily")
        if view not in VIEW_FREQUENCIES:
            abort(400)
        period_day, period_end = period_bounds(selected, view)
        previous_period = period_bounds(period_day - timedelta(days=1), view)[0]
        following_period = period_end + timedelta(days=1)
        # Live periods use today's schedule. For another period, show the
        # schedule effective in that period, even when it has not started yet.
        reference_day = today if period_day <= today <= period_end else period_end
        scope = patrol_scope(g.user)
        points = historical_points(scope)
        floor_filter, category_filter = scope_filters()
        executor = g.user.role == "executor"
        team_view = can_view_general_team(g.user)
        issue_counts = {} if executor else open_issue_counts(category=category_filter or scope)
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
            executed_at = {(pid, freq, slot): timestamp for pid, freq, slot, timestamp in db.session.execute(scoped_query(progress_query, PatrolExecution))}
        cards, floors = [], [{"floor": f, "label": label, "total": 0, "done": 0} for f, label in FLOOR_OPTIONS]
        irregular_points = []
        floor_counts = {item["floor"]: item for item in floors}
        period_label = f"{period_day:%Y/%m}" if view == "monthly" else (f"{period_day:%m/%d} – {period_end:%m/%d}" if view == "weekly" else selected.isoformat())
        for point in points:
            point_records = found.get(point.id, [])
            schedule = next((s for s in reversed(point.schedules) if s.effective_date <= reference_day), None)
            settings = schedule_snapshot(point, schedule)
            frequency, active, category = settings["frequency"], settings["active"], settings["category"]
            scheduled_floor, scheduled_code, scheduled_name = settings["floor"], settings["code"], settings["name"]
            mode, legacy_unscheduled = settings["workflow_mode"], settings["legacy_unscheduled"]
            direct_visit = (executor and mode == "spot" and frequency == "irregular" and not legacy_unscheduled
                            and point.code == scheduled_code and point.workflow_mode == "spot" and executor_can_scan(point))
            if ((frequency == "irregular" or legacy_unscheduled) and (schedule or not point.schedules) and active
                    and (not executor or mode == "two_stage" or direct_visit) and point.schedule_start <= reference_day
                    and (not category_filter or category_filter == category)
                    and (not floor_filter or int(floor_filter) == scheduled_floor)):
                irregular_points.append(SimpleNamespace(id=point.id, code=scheduled_code, name=scheduled_name, floor=scheduled_floor,
                    category=category, frequency=frequency, workflow_mode=mode, legacy_unscheduled=legacy_unscheduled, inspection_team=point.inspection_team))
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
                    slot_deadline = execution_deadline(group_frequency, period_day.isoformat(), slot)
                    if not record and point.created_at and slot_deadline <= local_dt(point.created_at):
                        continue
                    # A classification/floor edit cannot create another obligation
                    # for a slot already completed under its historical snapshot.
                    if scheduled_slot and not record and any(item.frequency == group_frequency and item.slot == slot for item in point_records):
                        continue
                    if not scheduled_slot and not record:
                        continue
                    future_slot = (group_frequency == "daily2" and not daily2_anytime(period_day)
                                   and selected == today and slot == "pm" and local_dt(instant).hour < 12)
                    status = "done" if record else ("pending" if due and not future_slot else "not_due")
                    visible = record if record and g.user.role == "admin" else None
                    if record and g.user.role == "inspector":
                        visible = own_records.get((point.id, group_frequency, slot, group_category, group_floor, group_mode),
                                                  record if team_view and record.category == scope else None)
                    executed = executed_at.get((point.id, group_frequency, slot)) if group_mode == "two_stage" else None
                    stage_status = None
                    expired = status == "pending" and local_now >= slot_deadline
                    if group_mode == "two_stage":
                        if record:
                            stage_status = "done"
                        elif expired:
                            stage_status = "expired_unreviewed" if executed else "expired_unexecuted"
                        else:
                            stage_status = "awaiting_inspection" if executed else "awaiting_execution"
                    slots.append({"key": slot, "label": slot_label(slot), "status": status, "record": visible,
                                  "due": bool(due or record), "expired": expired, "stage_status": stage_status, "executed_at": executed})
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
                                                 floor=group_floor, frequency=group_frequency, category=group_category, workflow_mode=group_mode, inspection_team=point.inspection_team)
                group_total = sum(slot["due"] for slot in slots)
                group_done = sum(slot["status"] == "done" for slot in slots)
                if group_floor is not None:
                    floor_counts[group_floor]["total"] += group_total
                    floor_counts[group_floor]["done"] += group_done
                if not floor_filter or group_floor == int(floor_filter):
                    status = "done" if group_done == len(slots) else ("pending" if group_total else "not_due")
                    visible_records = [slot["record"] for slot in slots if slot["record"]]
                    latest = max(visible_records, key=lambda item: item.created_at, default=None)
                    cards.append({"point": displayed_point, "status": status, "latest": latest, "period_label": period_label, "slots": slots,
                                  "missed_count": sum(s["expired"] for s in slots), "open_issue_count": issue_counts.get(point.id, 0)})
        total = sum(slot["due"] for card in cards for slot in card["slots"])
        done = sum(slot["status"] == "done" for card in cards for slot in card["slots"])
        recent_query = select(Inspection).options(selectinload(Inspection.issue)).order_by(Inspection.created_at.desc(), Inspection.id.desc()).limit(6)
        recent_query = private_records(recent_query, category_filter)
        if floor_filter:
            recent_query = recent_query.where(Inspection.point_floor == int(floor_filter))
        recent_executions = []
        if (executor or team_view) and scope == "general":
            executions = select(PatrolExecution).where(PatrolExecution.category == scope)
            if executor:
                executions = executions.where(PatrolExecution.user_id == g.user.id)
            if floor_filter:
                executions = executions.where(PatrolExecution.point_floor == int(floor_filter))
            recent_executions = db.session.scalars(scoped_query(executions, PatrolExecution).order_by(PatrolExecution.created_at.desc(), PatrolExecution.id.desc()).limit(6)).all()
        current_binding, approved_elsewhere = binding_overview()
        # A boundary week can begin or end outside the date picker's range.
        first_date, last_date = date(2000, 1, 1), date(2100, 12, 31)
        report_filters = dict(date_from=max(first_date, period_day).isoformat(),
                              date_to=min(last_date, period_end).isoformat(), category=category_filter,
                              floor=floor_filter, frequency="daily_all" if view == "daily" else view)
        return render_template("dashboard.html", selected_date=selected, selected_category=category_filter, selected_floor=floor_filter,
                               view=view, floors=floors, cards=cards, totals={"total": total, "done": done, "pending": total - done},
                               previous_period=max(previous_period, first_date) if period_day > first_date else None,
                               following_period=following_period if following_period <= last_date else None,
                               current_period=period_day <= today <= period_end,
                               missed_count=sum(card["missed_count"] for card in cards),
                               open_issue_counts=issue_counts, outstanding_issue_count=visible_open_issue_total(),
                               device_state=current_binding.status if current_binding else "none",
                               approved_elsewhere=approved_elsewhere, irregular_points=irregular_points, spot_points=irregular_points,
                               recent=db.session.scalars(recent_query).all(), recent_executions=recent_executions,
                               missed_query_url=url_for("missed", **report_filters),
                               records_query_url=url_for("records", **report_filters), week_label=period_label, period_title=period_label)

    def get_point(token, lock=False):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", token):
            abort(404, description="巡檢點不存在，或這張 QR Code 已被更新。")
        query = select(Point).where(Point.qr_token == token, Point.deleted_at.is_(None))
        scope = patrol_scope(g.user)
        if scope is not None:
            query = query.where(Point.category == scope if scope else db.false())
        query = apply_point_scope(query, g.user)
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)
        point = db.session.scalar(query)
        if point and point.pending_frequency and point.frequency_effective_date <= local_dt(now_utc()).date():
            abort(409, description="點位頻率正在切換，請重新開啟此點確認。")
        if not point or (g.user.role == "executor" and not executor_can_scan(point)):
            abort(404, description=("此點不開放執行人員簽到，或 QR Code 已更新。" if g.user.role == "executor"
                                    else "巡檢點不存在，或這張 QR Code 已被更新。"))
        if not point.active or point.schedule_start > local_dt(now_utc()).date():
            abort(403, description="此巡檢點目前尚未啟用或已停用。")
        return point

    def inspection_in_slot(point, key, slot):
        # A scheduled completion survives a transfer to the shared standard
        # workflow. Use the same first qualifying receipt as the dashboard.
        return db.session.scalar(select(Inspection).where(
            Inspection.point_id == point.id, Inspection.frequency == point.frequency,
            Inspection.period_key == key, Inspection.slot == slot, Inspection.legacy_unscheduled.is_(False),
            Inspection.executor_visit.is_(False)).order_by(Inspection.created_at, Inspection.id).limit(1))

    def prior_inspection(point, key, slot, day):
        if point.workflow_mode in ("spot", "two_stage"):
            return personal_inspection_in_slot(point, g.user, day, slot)
        return inspection_in_slot(point, key, slot)

    def confirmation_slot(point, instant):
        """Choose the actor's next round only when opening a fresh confirmation form.

        The stored am/pm keys remain stable for historical receipts and execution
        links; from the cutover they identify round one/two, not clock windows.
        A submitted form must keep its signed round instead of selecting again.
        """
        day = local_dt(instant).date()
        if point.frequency != "daily2" or not daily2_anytime(day):
            return slot_for(point, instant)
        key = day.isoformat()
        available = ("am", "pm")
        if point.workflow_mode == "two_stage" and g.user.role == "executor":
            used = db.session.scalars(select(PatrolExecution.slot).where(
                PatrolExecution.point_id == point.id, PatrolExecution.frequency == point.frequency,
                PatrolExecution.period_key == key)).all()
        elif point.workflow_mode in ("spot", "two_stage"):
            used = db.session.scalars(select(Inspection.slot).where(
                Inspection.point_id == point.id, Inspection.user_id == g.user.id,
                Inspection.personal_day == day)).all()
            if point.workflow_mode == "two_stage":
                available = db.session.scalars(select(PatrolExecution.slot).where(
                    PatrolExecution.point_id == point.id, PatrolExecution.frequency == point.frequency,
                    PatrolExecution.period_key == key, PatrolExecution.user_id != g.user.id)).all()
        else:
            used = db.session.scalars(select(Inspection.slot).where(
                Inspection.point_id == point.id, Inspection.frequency == point.frequency,
                Inspection.period_key == key, Inspection.legacy_unscheduled.is_(False),
                Inspection.executor_visit.is_(False))).all()
        # If no execution is ready, show the next unfilled round as waiting.
        # Both complete: retain the final round so the existing receipt is shown.
        return next_daily2_slot(used, available) or next_daily2_slot(used) or "pm"

    def daily_round_ticket(point, key, slot, day, *, validate=False):
        """Bind confirmation to one displayed round, including across concurrent tabs."""
        signer = URLSafeSerializer(app.secret_key, salt="patrol-daily-round-v1")
        scope = [g.user.id, g.user.auth_version, point.id, key, slot, day.isoformat(),
                 point.frequency, point.workflow_mode, g.user.role, checkin_location_revision(point)]
        if not validate:
            return signer.dumps(scope)
        value = request.form.get("round_ticket", "")
        try:
            return len(value) <= 2048 and signer.loads(value) == scope
        except BadData:
            return False

    def checkin_stage(point, first):
        if point.workflow_mode != "two_stage":
            if g.user.role == "executor":
                return "visit", executor_can_scan(point), ""
            return "inspect", g.user.role in ("inspector", "admin"), ""
        if g.user.role == "executor":
            period = "本週期" if point.frequency in ("weekly", "monthly") else "本次"
            return "execute", first is None, f"{period}已登記執行，不需重複簽到。" if first else ""
        if g.user.role != "inspector" or patrol_scope(g.user) != "general":
            return "inspect", False, "系統管理員僅可管理此點，兩段打卡須由對應角色完成。"
        if not first:
            return "inspect", False, "尚未執行，請等總務執行人員先刷同一點位。"
        if first.user_id == g.user.id:
            return "inspect", False, "執行與巡檢必須由不同帳號完成。"
        return "inspect", True, ""

    def voice_marker(kind, *, result_id=None, auto="scan"):
        """Presentation only: a voice result never grants access or writes attendance."""
        return {"kind": kind, "id": result_id or secrets.token_hex(16), "auto": auto}

    def voice_receipt_redirect(record, receipt_type, kind):
        payload = {"v": 1, "user": g.user.id, "auth": g.user.auth_version,
                   "receipt": receipt_type, "record": record.id, "kind": kind,
                   "nonce": secrets.token_hex(16)}
        token = URLSafeTimedSerializer(app.secret_key, salt="patrol-voice-feedback-v1").dumps(payload)
        endpoint = "execution_success" if receipt_type == "execution" else "checkin_success"
        args = {"execution_id": record.id} if receipt_type == "execution" else {"record_id": record.id}
        return redirect(url_for(endpoint, **args, voice_feedback=token))

    def receipt_voice_marker(record, receipt_type, saved_kind):
        # Receipt authorization runs before this cosmetic signature is examined.
        # Missing, old, forged or misdirected tokens remain replay-only receipts.
        fallback = voice_marker("receipt_confirmed", result_id=f"{receipt_type}:{record.id}", auto="false")
        tokens = request.args.getlist("voice_feedback")
        if len(tokens) != 1 or not 1 <= len(tokens[0]) <= 2048:
            return fallback
        try:
            payload = URLSafeTimedSerializer(app.secret_key, salt="patrol-voice-feedback-v1").loads(tokens[0], max_age=120)
        except (BadData, ValueError, TypeError):
            return fallback
        if (not isinstance(payload, dict)
                or set(payload) != {"v", "user", "auth", "receipt", "record", "kind", "nonce"}
                or any(type(payload.get(key)) is not int for key in ("v", "user", "auth", "record"))
                or payload["v"] != 1 or payload["user"] != g.user.id or payload["auth"] != g.user.auth_version
                or payload["receipt"] != receipt_type or payload["record"] != record.id
                or payload["kind"] not in (saved_kind, "already_recorded")
                or not isinstance(payload["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", payload["nonce"])):
            return fallback
        return voice_marker(payload["kind"], result_id=payload["nonce"], auto="true")

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
        slot = confirmation_slot(point, instant)
        flexible_daily2 = point.frequency == "daily2" and daily2_anytime(day)
        # Preserve the origin of an unsent report even through repeated read-only
        # handoff checks. The final submit always uses the newly displayed slot.
        report_day = request.form.get("draft_day") or request.form.get("personal_day", "")
        report_slot = request.form.get("draft_slot") or request.form.get("slot", "")
        previous_period = ""
        if (re.fullmatch(r"\d{4}-\d{2}-\d{2}", report_day) and report_slot in ("any", "am", "pm")
                and (report_day != day.isoformat() or report_slot != slot)):
            previous_period = report_day + (" " + slot_label(report_slot) if report_slot != "any" else "")
        first = execution_in_slot(point, key, slot) if point.workflow_mode == "two_stage" else None
        stage, allowed, notice = checkin_stage(point, first)
        existing = prior_inspection(point, key, slot, day) if stage != "execute" else None
        # An earlier all-day receipt still consumes the personal quota after
        # a same-day frequency change, but it is not two completed inspections.
        daily2_existing_daily_record = bool(flexible_daily2 and existing and existing.slot == "any")
        receipt_url = None
        saved = first if stage == "execute" else existing
        if saved and saved.user_id == g.user.id and (stage == "execute" or can_read_inspection(g.user, saved)):
            saved_day = local_dt(saved.created_at).date().isoformat()
            list_url = url_for("records", stage="execution" if stage == "execute" else "inspection",
                               date_from=saved_day, date_to=saved_day)
            receipt_url = (url_for("execution_success", execution_id=saved.id, return_to=list_url, from_scan=1) if stage == "execute"
                           else url_for("checkin_success", record_id=saved.id, return_to=list_url, from_scan=1))
        if existing and not can_access_category(g.user, existing.category):
            # The obligation is shared even after a point changes teams. Only
            # reveal that it is satisfied, never the old team's actor or time.
            existing = {"created_at": None, "user_name": "本期已有紀錄"}
        elif existing and not can_read_inspection(g.user, existing):
            # Never give another inspector's notes, attachments or identity to the template.
            if stage == "visit":
                existing = {"created_at": None, "user_name": "你今天已在此點登記"}
            else:
                existing = {"created_at": existing.created_at, "user": {"display_name": "其他巡檢人員"}}
        label = f"{local_dt(start):%m/%d} – {local_dt(end - timedelta(seconds=1)):%m/%d}" if point.frequency in ("weekly", "monthly") else key
        binding_state = device_status()
        waiting_for_execution = point.workflow_mode == "two_stage" and g.user.role == "inspector" and not first and not existing
        result_kind = ("not_saved" if error else "already_recorded" if existing or (stage == "execute" and first) else
                       "device_required" if binding_state != "approved" and (allowed or waiting_for_execution) else
                       "waiting_execution" if waiting_for_execution else "point_unavailable" if not allowed else None)
        return render_template("checkin.html", point=point, device_state=binding_state, existing=existing, token=token,
                               checkin_checklist=checklist_for_point(point),
                               checkin_selected=(request.form.getlist("checklist") if not previous_period
                                   and request.form.get("point_revision") == checkin_location_revision(point)
                                   and request.form.get("slot") == slot else []),
                               voice_result=voice_marker(result_kind) if result_kind else None,
                               stage=stage, can_confirm=allowed and not existing, stage_notice=t(notice), receipt_url=receipt_url,
                               waiting_for_execution=waiting_for_execution,
                               previous_period=previous_period, draft_day=report_day, draft_slot=report_slot,
                               long_period=handoff_period(point.frequency, key) if point.workflow_mode == "two_stage" else None,
                               first_reviewed=bool(first and point.frequency in ("weekly", "monthly") and execution_reviewed(first)),
                               execution_time=first.created_at if first else None, checkin_execution=first,
                               personal_day=day.isoformat(),
                               flexible_daily2=flexible_daily2,
                               daily2_existing_daily_record=daily2_existing_daily_record,
                               round_ticket=daily_round_ticket(point, key, slot, day) if flexible_daily2 else "",
                               spot_ticket=spot_ticket(point, key, slot, day) if point.workflow_mode == "spot" else "",
                               point_revision=checkin_location_revision(point),
                               progress_url=url_for("dashboard", view=progress_view(point.frequency),
                                                    date=key, floor=point.floor, category=point.category),
                               current_slot=slot, current_slot_label=slot_label(slot), current_period_key=key, period_label=label,
                               note=request.form.get("note", ""), is_abnormal=request.form.get("is_abnormal", "") in ("on", "1", "true", "yes"),
                               point_open_issue_count=(open_issue_counts([point.id], category=patrol_scope(g.user)).get(point.id, 0)
                                                       if g.user.role != "executor" else 0), form_error=t(error) if error else error), status

    def changed_checkin_settings(point, *, require_location=False):
        if request.form.get("frequency") != point.frequency:
            return "點位巡檢頻率已更新，或此表單已過期。請確認最新設定後重新送出；照片需重新選擇。"
        revision = request.form.get("point_revision")
        if require_location and not revision:
            return "草稿的點位資料已過期。請核對現場位置，再確認打卡。"
        if revision is not None and revision != checkin_location_revision(point):
            return "點位名稱、樓層、編號或分類已更新。請重新核對現場位置，再確認打卡。"
        return None

    @app.route("/c/<token>", methods=["GET", "POST"])
    @login_required
    def checkin(token):
        # POST carries unsaved notes back to the same point when checking whether
        # the executor has signed. Only /confirm can create attendance records.
        point = get_point(token)
        if request.method == "POST":
            if (request.form.get("draft_point") != str(point.id) or point.workflow_mode != "two_stage"
                    or g.user.role != "inspector" or device_status() != "approved"):
                return redirect(url_for("checkin", token=token))
            if error := changed_checkin_settings(point, require_location=True):
                return checkin_form(point, token, error, 409)
        return checkin_form(point, token)

    def existing_checkin_response(record, token, note, abnormal, uploads):
        personal = record.workflow_mode in ("spot", "two_stage") and record.user_id == g.user.id
        if note or abnormal or any(upload.filename for upload in uploads):
            # A concurrent completion won. Do not present its receipt as proof
            # that this form's separate observations or photos were saved.
            prefix = "你今天在這個點位的本次巡檢已有紀錄" if personal else "這個點位本次已有紀錄"
            flash(prefix + "，本次填寫的回報內容未追加。若現場有新的異常，請聯絡系統管理員處理。", "warning")
            return redirect(url_for("checkin", token=token))
        if g.user.role == "executor":
            flash("你今天已在此點登記。", "info")
        else:
            flash("你已完成本日這一次巡檢，以下是你的紀錄。" if personal else "這個巡檢點本次已完成，沒有新增重複紀錄。", "info")
        if can_read_inspection(g.user, record):
            return voice_receipt_redirect(record, "inspection", "already_recorded")
        return redirect(url_for("checkin", token=token))

    def previous_spot_response(record):
        require_inspection_access(record)
        message = ("你今天已在此點簽到，以下是原紀錄。" if record.executor_visit else
                   "這份巡檢表單先前已送出。以下是原紀錄，重送時更改的備註、異常或照片不會追加。")
        flash(message, "info")
        return voice_receipt_redirect(record, "inspection", "already_recorded")

    @app.post("/c/<token>/confirm")
    @login_required
    def confirm_checkin(token):
        # Serialize with approval/revocation for the same employee on PostgreSQL.
        lock_current_user()
        binding = device_binding()
        if not binding or binding.status != "approved":
            g.patrol_voice_result = "device_required"
            abort(403, description="此瀏覽器尚未核准，請先申請綁定並由系統管理員核准。")
        point = get_point(token, lock=True)
        if (point.workflow_mode in ("spot", "two_stage") or point.frequency == "daily2") and db.engine.dialect.name == "sqlite":
            # SQLite ignores FOR UPDATE; serialize stage and personal attendance checks.
            db.session.execute(db.update(Point).where(Point.id == point.id).values(id=Point.id))
            point = get_point(token, lock=True)
        instant = now_utc()
        day = local_dt(instant).date()
        key, _, _ = period_for(point, instant)
        slot = slot_for(point, instant)
        flexible_daily2 = point.frequency == "daily2" and daily2_anytime(day)
        submitted_slot, submitted_period = request.form.get("slot"), request.form.get("period_key")
        def form_error(message, status=400):
            db.session.rollback()
            return checkin_form(get_point(token), token, message, status)
        mode = point.workflow_mode
        confirmed_day = request.form.get("personal_day")
        if request.form.get("workflow_mode", "standard") != mode:
            return form_error("打卡方式已變更，請依目前顯示的流程重新確認。", 409)
        if error := changed_checkin_settings(point):
            return form_error(error, 409)
        if flexible_daily2:
            # Never assign the next free round here: a double click or retry of
            # round one must only resolve to round one's original receipt.
            if (submitted_slot not in ("am", "pm") or submitted_period != key
                    or not daily_round_ticket(point, key, submitted_slot, day, validate=True)):
                return form_error("打卡日期、次數或表單已變更，請重新掃描並確認本次打卡。", 409)
            slot = submitted_slot
        if (((point.frequency == "daily2" or mode != "standard") and (not submitted_slot or not submitted_period))
                or (submitted_slot is not None and submitted_slot != slot)
                or (submitted_period is not None and submitted_period != key)):
            return form_error("巡檢日期或次數已變更，請重新確認後送出。照片需重新選擇。", 409)
        # HTML forms send CRLF for the single newline counted by a textarea.
        note = request.form.get("note", "").replace("\r\n", "\n").replace("\r", "\n").strip()
        abnormal = request.form.get("is_abnormal", "") in ("on", "1", "true", "yes")
        uploads = request.files.getlist("photos")
        first = execution_in_slot(point, key, slot) if mode == "two_stage" else None
        stage, allowed, notice = checkin_stage(point, first)
        if mode == "two_stage" and g.user.role == "admin":
            abort(403, description=notice)
        submitted_stage = request.form.get("stage")
        if (mode == "two_stage" or "visit" in (stage, submitted_stage)) and submitted_stage != stage:
            return form_error("打卡階段與目前角色不符，請重新核對。", 409)
        if stage in ("execute", "visit") and (note or abnormal or any(upload.filename for upload in uploads)):
            if stage == "visit":
                return form_error("直接簽到不接受備註或照片。")
            return form_error("執行登記不接受巡檢回報內容；備註、照片及異常請於巡檢階段填寫。")
        own_execution = stage == "execute" and first is not None and first.user_id == g.user.id
        requires_day = flexible_daily2 or (mode in ("spot", "two_stage") and (confirmed_day is not None or point.frequency in ("weekly", "monthly")))
        if requires_day and confirmed_day != day.isoformat():
            # A delayed retry may read the actor's original shared execution
            # receipt. A stale form must never create a new day's attendance.
            if not own_execution or confirmed_day != local_dt(first.created_at).date().isoformat():
                return form_error("打卡日期已變更，請重新確認今天的打卡。", 409)
        if own_execution:
            return voice_receipt_redirect(first, "execution", "already_recorded")
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
        record = prior_inspection(point, key, slot, day) if stage != "execute" else None
        if record:
            return existing_checkin_response(record, token, note, abnormal, uploads)
        try:
            checklist_data = encode_checklist(validate_checklist(point, request.form.getlist("checklist")))
        except ValueError as error:
            return form_error(str(error))
        if len(note) > 2000 or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in note):
            return form_error("備註最多 2,000 字，且不可包含無效控制字元。")
        try:
            photos = process_uploads(uploads) if stage == "inspect" else []
        except PhotoValidationError as error:
            return form_error(str(error))
        if photos:
            if db.engine.dialect.name == "postgresql":
                db.session.execute(db.text("SELECT pg_advisory_xact_lock(714032610303)"))
            used = photo_storage_used()
            if used + sum(photo["size_bytes"] for photo in photos) > app.config["PHOTO_STORAGE_LIMIT_BYTES"]:
                return form_error("照片儲存空間已滿，這次打卡尚未儲存。請聯絡系統管理員，或移除照片後重新確認送出。", 409)
        final_instant = now_utc()
        if (period_for(point, final_instant)[0] != key or (not flexible_daily2 and slot_for(point, final_instant) != slot) or
                (mode in ("spot", "two_stage") and local_dt(final_instant).date() != day)):
            message = "處理期間巡檢日期或次數已變更，請重新確認後送出。"
            return form_error(message + ("照片需重新選擇。" if photos else ""), 409)
        if stage == "execute":
            result_kind = "saved_execute"
            first = new_execution(point, g.user, binding, key, slot, final_instant)
            first.checklist_data = checklist_data
            db.session.add(first)
            binding.last_seen_at = naive_utc(final_instant)
            audit("execution", point.code)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                first = execution_in_slot(point, key, slot)
                if not first:
                    raise
                if first.user_id != g.user.id:
                    return form_error(checkin_stage(point, first)[2], 409)
                result_kind = "already_recorded"
            session.pop("after_binding", None)
            return voice_receipt_redirect(first, "execution", result_kind)
        record = Inspection(user_id=g.user.id, point_id=point.id, binding_id=binding.id, created_at=naive_utc(final_instant),
                            period_key=key, frequency=point.frequency, slot=slot, category=point.category,
                            point_code=point.code, point_name=point.name, point_floor=point.floor, user_name=g.user.display_name,
                            workflow_mode=mode, execution_id=first.id if first else None, spot_request_id=request_id,
                            personal_day=day if mode in ("spot", "two_stage") else None,
                            executor_visit=stage == "visit", note=note, is_abnormal=abnormal, checklist_data=checklist_data)
        record.photos.extend(InspectionPhoto(**photo) for photo in photos)
        open_issue_for(record)
        db.session.add(record)
        binding.last_seen_at = naive_utc(final_instant)
        audit("executor_visit" if record.executor_visit else "checkin", point.code)
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
        return voice_receipt_redirect(record, "inspection", "saved_visit" if record.executor_visit else "saved_inspect")

    @app.get("/executions/<int:execution_id>/success")
    @login_required
    def execution_success(execution_id):
        record = db.get_or_404(PatrolExecution, execution_id)
        if (not can_access_category(g.user, record.category) or
                (record.category == "general" and not can_access_point_team(g.user, record.point))):
            abort(404)
        if (g.user.role != "admin" and not can_view_general_team(g.user)
                and (g.user.role != "executor" or record.user_id != g.user.id)):
            abort(403)
        reviewed = execution_reviewed(record)
        instant = now_utc()
        return render_template("checkin_success.html", record=record, stage="execute", finalized=reviewed,
                               voice_result=receipt_voice_marker(record, "execution", "saved_execute"),
                               flexible_daily2=record.frequency == "daily2" and daily2_anytime(record.period_key),
                               review_status=execution_review_status(record.frequency, record.period_key, record.slot, reviewed, instant),
                               long_period=handoff_period(record.frequency, record.period_key),
                               back_url=normalise_return_to(request.args.get("return_to"), g.user) or url_for("records", stage="execution"),
                               progress_url=url_for("dashboard", view=progress_view(record.frequency),
                                                    date=record.period_key, floor=record.point_floor, category=record.category))

    @app.get("/checkins/<int:record_id>")
    @login_required
    def checkin_success(record_id):
        record = db.get_or_404(Inspection, record_id)
        require_inspection_access(record)
        return render_template("checkin_success.html", record=record, stage="visit" if record.executor_visit else "inspect", finalized=True,
                               voice_result=receipt_voice_marker(record, "inspection", "saved_visit" if record.executor_visit else "saved_inspect"),
                               flexible_daily2=record.frequency == "daily2" and daily2_anytime(record.period_key),
                               long_period=handoff_period(record.frequency, record.period_key) if record.workflow_mode == "two_stage" else None,
                               back_url=normalise_return_to(request.args.get("return_to"), g.user) or url_for("records", stage="inspection"),
                               progress_url=url_for("dashboard", view=progress_view(record.frequency),
                                                    date=record.period_key, floor=record.point_floor, category=record.category),
                               point_open_issue_count=0 if record.executor_visit else
                               open_issue_counts([record.point_id], category=patrol_scope(g.user)).get(record.point_id, 0))

    def require_inspection_access(record):
        if (not can_access_category(g.user, record.category) or
                (record.category == "general" and not can_access_point_team(g.user, record.point))):
            abort(404)
        if not can_read_inspection(g.user, record):
            abort(403)

    @app.get("/records/<int:record_id>")
    @login_required
    def record_detail(record_id):
        record = db.get_or_404(Inspection, record_id)
        if record.executor_visit:
            require_inspection_access(record)
            source = normalise_return_to(request.args.get("return_to"), g.user)
            return redirect(url_for("checkin_success", record_id=record.id, return_to=source))
        return render_record_detail(record)

    def render_record_detail(record, error=None, status=200):
        # Called after a rolled-back transition too; recheck before rendering
        # either a successful detail page or its private validation-error form.
        require_inspection_access(record)
        source = request.form.get("return_to") if request.method == "POST" else request.args.get("return_to")
        back_url = normalise_return_to(source, g.user) or url_for("records", category=record.category)
        return render_template("record_detail.html", record=record, issue_form_error=error,
                               long_period=handoff_period(record.frequency, record.period_key) if record.workflow_mode == "two_stage" else None,
                               issue_action_note=request.form.get("note", "").replace("\r\n", "\n").replace("\r", "\n"),
                               issue_version=issue_version(record.issue),
                               can_manage_issue=can_resolve_issue(g.user, record),
                               can_reopen_issue=g.user.role == "admin",
                               back_url=back_url, back_label="返回異常追蹤" if urlsplit(back_url).path == "/issues" else "返回巡檢紀錄",
                               point_open_issue_count=open_issue_counts([record.point_id], category=patrol_scope(g.user)).get(record.point_id, 0)), status

    def apply_issue_action(inspection_id, target_status):
        actor = lock_current_user()
        source = normalise_return_to(request.form.get("return_to"), actor)
        try:
            instant = naive_utc()
            event = transition_issue_event(inspection_id, target_status, actor, request.form.get("expected_event_id"),
                                           request.form.get("note", ""), instant)
            changed = event is not None
            uploads = request.files.getlist("photos")
            if target_status != "resolved" and any(upload.filename for upload in uploads):
                raise IssueActionError("重新開啟案件不接受照片，請於結案時附上處理後照片。")
            if changed:
                # The locked transition authorizes the actor and checks the
                # event version before any private image decoding or storage.
                photos = process_uploads(uploads) if target_status == "resolved" else []
                if photos:
                    if db.engine.dialect.name == "postgresql":
                        db.session.execute(db.text("SELECT pg_advisory_xact_lock(714032610303)"))
                    if photo_storage_used() + sum(photo["size_bytes"] for photo in photos) > app.config["PHOTO_STORAGE_LIMIT_BYTES"]:
                        raise IssueActionError("照片儲存空間已滿，本次尚未結案。請聯絡系統管理員，或移除照片後重新送出。", 409)
                    append_resolution_photos(event, photos, instant)
                audit("issue_resolved" if target_status == "resolved" else "issue_reopened", inspection_id,
                      f"photos={len(photos)}")
            db.session.commit()
        except (IssueActionError, PhotoValidationError) as error:
            db.session.rollback()
            status = getattr(error, "status", 400)
            message = str(error).replace("每次打卡最多上傳", "每次結案最多上傳")
            if status in (403, 404):
                abort(status, description=message)
            record = db.get_or_404(Inspection, inspection_id)
            return render_record_detail(record, message, status)
        flash(("案件已結案。" if target_status == "resolved" else "案件已重新開啟。") if changed else
              "案件已是指定狀態，沒有新增重複處理紀錄；本次照片與說明未追加。", "success" if changed else "info")
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

    def issue_query():
        """One authorization/filter contract for the list and its full export."""
        if g.user.role == "executor":
            abort(403, description="異常追蹤由巡檢員與系統管理員處理。")
        floor, category = scope_filters()
        state = request.args.get("status", "open")
        if state not in ("open", "resolved", "all"):
            abort(400, description="案件狀態選項不正確。")
        point_id = request.args.get("point_id", "")
        default_week = "date_from" not in request.args and "date_to" not in request.args
        today = local_dt(now_utc()).date()
        begin = parse_date(request.args.get("date_from"), today - timedelta(days=6) if default_week else None)
        end = parse_date(request.args.get("date_to"), today if default_week else None)
        if begin and end and begin > end:
            abort(400, description="回報日期的起日不能晚於迄日。")
        selected_point = None
        if point_id:
            selected_id = parse_id(point_id)
            point = db.get_or_404(Point, selected_id)
            if can_access_point(g.user, point):
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
        if begin:
            query = query.where(Inspection.created_at >= naive_utc(datetime.combine(begin, time.min, TAIPEI)))
        if end:
            query = query.where(Inspection.created_at < naive_utc(datetime.combine(end + timedelta(days=1), time.min, TAIPEI)))
        order_time = InspectionIssue.resolved_at if state == "resolved" else db.func.coalesce(InspectionIssue.opened_at, Inspection.created_at)
        filters = {"status": state, "floor": floor, "category": category, "point_id": point_id,
                   "date_from": begin.isoformat() if begin else "", "date_to": end.isoformat() if end else ""}
        return query, filters, selected_point, order_time

    @app.get("/issues")
    @login_required
    def issues():
        query, filters, selected_point, order_time = issue_query()
        page = parse_id(request.args.get("page", "1"))
        total = db.session.scalar(select(db.func.count()).select_from(query.subquery()))
        per_page = 50
        pages = max(1, (total + per_page - 1) // per_page)
        if page > pages:
            return redirect(url_for("issues", **filters, page=pages))
        rows = db.session.scalars(query.options(selectinload(Inspection.issue), selectinload(Inspection.photos), selectinload(Inspection.point))
                                  .order_by(order_time.desc(), Inspection.id.desc()).offset((page - 1) * per_page).limit(per_page)).all()
        if page > 1 and not rows:
            # At READ COMMITTED another manager can resolve the last row after
            # our count and before our fetch. Recover that now-empty last page.
            total = db.session.scalar(select(db.func.count()).select_from(query.subquery()))
            pages = max(1, (total + per_page - 1) // per_page)
            if page > pages:
                return redirect(url_for("issues", **filters, page=pages))
        return render_template("issues.html", records=rows, filters=filters,
                               selected_point=selected_point, pagination={"page": page, "pages": pages, "total": total, "per_page": per_page},
                               open_total=visible_open_issue_total())

    @app.get("/issues/export.xlsx")
    @login_required
    def export_issues_xlsx():
        from issue_export import (ExportEvent, ExportImageError, ExportIssue, ExportLimitError, ExportPhoto,
                                  MAX_EXPORT_ISSUES, MAX_EXPORT_PHOTOS, MAX_SOURCE_PHOTO_BYTES, build_issue_workbook)
        query, filters, _, order_time = issue_query()
        # This covers database image loading as well as XLSX compression, so
        # concurrent downloads cannot multiply memory usage in the web worker.
        if not ISSUE_EXPORT_SLOT.acquire(blocking=False):
            abort(429, description="正在產生另一份異常報表，請稍後再匯出。")
        data = None
        try:
            ids = list(db.session.scalars(query.with_only_columns(Inspection.id).order_by(
                order_time.desc(), Inspection.id.desc()).limit(MAX_EXPORT_ISSUES + 1)))
            if len(ids) > MAX_EXPORT_ISSUES:
                raise ExportLimitError(f"單次最多匯出 {MAX_EXPORT_ISSUES} 件異常。請縮小回報日期、樓層或狀態後再匯出。")
            # Serialize evidence reads against resolve/reopen (which take
            # FOR UPDATE on the inspection, including legacy cases). Hold
            # only while making the DTO snapshot, never during XLSX encoding.
            db.session.execute(select(Inspection.id).where(Inspection.id.in_(ids))
                               .order_by(Inspection.id).with_for_update(read=True)).all()
            original_count, original_size = db.session.execute(select(
                db.func.count(InspectionPhoto.id), db.func.coalesce(db.func.sum(InspectionPhoto.size_bytes), 0)
            ).where(InspectionPhoto.inspection_id.in_(ids))).one()
            treatment_count, treatment_size = db.session.execute(select(
                db.func.count(IssueEventPhoto.id), db.func.coalesce(db.func.sum(IssueEventPhoto.size_bytes), 0)
            ).join(IssueEvent).where(IssueEvent.inspection_id.in_(ids))).one()
            if original_count + treatment_count > MAX_EXPORT_PHOTOS or original_size + treatment_size > MAX_SOURCE_PHOTO_BYTES:
                raise ExportLimitError("這次匯出的照片超過 500 張或 50 MB，請縮小回報日期、樓層或狀態後再匯出。")
            rows = db.session.scalars(query.where(Inspection.id.in_(ids)).options(
                selectinload(Inspection.photos).undefer(InspectionPhoto.data),
                selectinload(Inspection.issue).selectinload(InspectionIssue.events).selectinload(IssueEvent.photos).undefer(IssueEventPhoto.data),
                selectinload(Inspection.point), selectinload(Inspection.user)
            ).order_by(order_time.desc(), Inspection.id.desc())).all()
            exports = []
            for row in rows:
                location = report_point_location(row)
                issue = row.issue
                exports.append(ExportIssue(
                    inspection_id=row.id, point_code=location.code, point_name=location.name, floor=location.floor,
                    responsible_team=point_team_label(row), reporter=reporter_name(row), reported_at=row.created_at,
                    status=issue_state(row), note=row.note or "",
                    photos=tuple(ExportPhoto(photo.data, f"回報照片 {index}") for index, photo in enumerate(row.photos, 1)),
                    events=tuple(ExportEvent(event.action, event.actor_name, event.created_at, event.note,
                                 tuple(ExportPhoto(photo.data, f"處理後照片 {index}") for index, photo in enumerate(event.photos, 1)))
                                 for event in issue.events) if issue else (),
                    resolved_by=issue.resolved_by_name if issue else "", resolved_at=issue.resolved_at if issue else None,
                    resolution_note=issue.resolution_note if issue else "", checklist=checklist_text(row),
                    execution_checklist=checklist_text(row.execution) if row.execution else ""))
            description = " · ".join((
                {"open": "未結案", "resolved": "已結案", "all": "全部異常"}[filters["status"]],
                category_label(filters["category"]) if filters["category"] else "可查看的全部分類",
                ("工務" if selected_inspection_team() == "engineering" else "總務") if selected_inspection_team() else "全部負責單位",
                floor_label(filters["floor"]) if filters["floor"] else "全部樓層",
                f"回報日期：{filters['date_from'] or '不限起日'} ～ {filters['date_to'] or '不限迄日'}"))
            db.session.rollback()  # Pure read transaction; release snapshot locks.
            data = build_issue_workbook(exports, generated_at=now_utc(), filter_description=description)
            response = send_file(data, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                 as_attachment=True, download_name=f"patrol-issues-{local_dt(now_utc()):%Y%m%d-%H%M%S}.xlsx", conditional=False)
            response.call_on_close(data.close)
            return response
        except ExportLimitError as error:
            abort(413, description=str(error))
        except ExportImageError:
            abort(409, description="部分照片無法讀取，報表尚未匯出。請聯絡系統管理員檢查照片。")
        except Exception:
            if data is not None:
                data.close()
            raise
        finally:
            ISSUE_EXPORT_SLOT.release()

    @app.get("/photos/<int:photo_id>")
    @login_required
    def photo_file(photo_id):
        photo = db.get_or_404(InspectionPhoto, photo_id)
        require_inspection_access(photo.inspection)
        response = make_response(photo.data)
        response.headers["Content-Type"] = photo.mime_type
        response.headers["Content-Disposition"] = f'inline; filename="inspection-{photo.id}.jpg"'
        return response

    @app.get("/issue-photos/<int:photo_id>")
    @login_required
    def issue_photo_file(photo_id):
        photo = db.get_or_404(IssueEventPhoto, photo_id)
        require_inspection_access(photo.event.issue.inspection)
        response = make_response(photo.data)
        response.headers["Content-Type"] = photo.mime_type
        response.headers["Content-Disposition"] = f'inline; filename="resolution-{photo.id}.jpg"'
        return response

    @app.get("/devices")
    @login_required
    def devices():
        bindings = db.session.scalars(select(DeviceBinding).where(DeviceBinding.user_id == g.user.id).order_by(DeviceBinding.created_at.desc())).all()
        current, other = binding_overview(bindings)
        return render_template("devices.html", current_binding=current, approved_elsewhere=other, bindings=bindings,
                               other_account_browser=not current and browser_in_use_by_another_account(),
                               next_url=binding_destination())

    @app.post("/devices/request")
    @login_required
    def request_device():
        lock_current_user()
        destination = binding_destination()
        binding = device_binding()
        if binding and binding.status in ("pending", "approved"):
            flash("此瀏覽器已經提出申請或已核准。", "info")
            return redirect(devices_url(destination))
        if not binding and browser_in_use_by_another_account():
            flash("此瀏覽器另有使用中的綁定或申請，未送出新申請。", "info")
            return redirect(devices_url(destination))
        label = request.form.get("label", "我的手機").strip()
        if not valid_label(label):
            abort(400, description="請填寫 1 至 100 字的裝置名稱。")
        pending = db.session.scalar(select(db.func.count(DeviceBinding.id)).where(DeviceBinding.user_id == g.user.id, DeviceBinding.status == "pending"))
        if pending >= 3:
            abort(400, description="已有三筆待審核申請，請先聯絡系統管理員處理。")
        token = secrets.token_urlsafe(32)
        binding = DeviceBinding(user_id=g.user.id, token_hash=hash_device_token(token), label=label, status="pending")
        db.session.add(binding)
        audit("device_requested", g.user.username, label)
        db.session.commit()
        response = redirect(devices_url(destination))
        response.set_cookie(DEVICE_COOKIE, token, max_age=365 * 86400, httponly=True, secure=app.config["COOKIE_SECURE"], samesite="Lax", path="/")
        flash("申請已送出，請系統管理員核准後再打卡。", "success")
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
        # Withdrawing a pending request is not consent to disconnect a phone
        # that an administrator has since approved. Include pre-update tabs.
        if request.form.getlist("reviewed_status") != [binding.status]:
            db.session.rollback()
            return render_template("error.html", code=409, message="綁定狀態已更新，尚未撤回或解除。請先查看最新綁定狀態。",
                                   recovery_url=destination, recovery_label="查看最新綁定"), 409
        was_pending = binding.status == "pending"
        binding.status = "revoked"
        audit("device_self_revoked", binding.id)
        db.session.commit()
        flash(f"已撤回「{binding.label}」的綁定申請。" if was_pending else f"已解除「{binding.label}」的綁定。", "success")
        return redirect(destination)

    @app.get("/admin/login-records")
    @admin_required
    def login_records():
        return login_records_page(local_dt(now_utc()).date(), parse_date, parse_id)

    @app.get("/admin/devices")
    @admin_required
    def admin_devices():
        bindings = db.session.scalars(select(DeviceBinding).options(selectinload(DeviceBinding.user)).order_by(db.case((DeviceBinding.status == "pending", 0), else_=1), DeviceBinding.created_at.desc())).all()
        approved = {row.user_id: row for row in bindings if row.status == "approved"}
        return render_template("admin_devices.html", bindings=bindings, approved_devices=approved)

    def device_review_conflict(message):
        db.session.rollback()
        return render_template("error.html", code=409, message=message, recovery_url=url_for("admin_devices"),
                               recovery_label="返回綁定審核"), 409

    @app.post("/admin/devices/<int:binding_id>/approve")
    @admin_required
    def approve_device(binding_id):
        binding = db.get_or_404(DeviceBinding, binding_id)
        lock_admin_users(binding.user_id)
        db.session.refresh(binding)
        if binding.status != "pending" or not binding.user.active:
            return device_review_conflict("此申請已處理或員工帳號已停用，請查看最新狀態。")
        # The target account lock serializes changes from its other review tabs.
        previous = db.session.scalar(select(DeviceBinding).where(
            DeviceBinding.user_id == binding.user_id, DeviceBinding.status == "approved"))
        if request.form.get("reviewed_approved_id", "") != (str(previous.id) if previous else ""):
            return device_review_conflict("此人員的有效綁定已變更，請重新核對要更換的瀏覽器。")
        if previous:
            previous.status = "revoked"
            db.session.flush()
        binding.status = "approved"
        binding.approved_at = naive_utc()
        audit("device_approved", binding.id, f"employee={binding.user_id}; replaced={previous.id if previous else 'none'}")
        try:
            db.session.commit()
        except IntegrityError:
            return device_review_conflict("裝置狀態已變更，請重新核對申請。")
        flash(f"已核准「{binding.label}」，原綁定「{previous.label}」已解除。" if previous else f"已核准「{binding.label}」。", "success")
        return redirect(url_for("admin_devices"))

    @app.post("/admin/devices/<int:binding_id>/reject")
    @admin_required
    def reject_device(binding_id):
        binding = db.get_or_404(DeviceBinding, binding_id)
        lock_admin_users(binding.user_id)
        db.session.refresh(binding)
        if binding.status != "pending":
            return device_review_conflict("此申請已處理，請查看最新審核結果。")
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
        if binding.status != "approved":
            return device_review_conflict("此瀏覽器目前沒有有效綁定，請查看最新狀態。")
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
        if stage == "execution" and not can_view_execution_records(g.user):
            abort(403)
        model = PatrolExecution if stage == "execution" else Inspection
        # Missing legacy snapshots can need the related point and author while
        # rendering or exporting. Fetch only the fallback fields in this query.
        query = select(model).options(
            joinedload(model.point).load_only(Point.code, Point.name, Point.floor, Point.category, Point.inspection_team),
            joinedload(model.user).load_only(User.display_name),
        ).where(model.created_at >= start_time, model.created_at < end_time)
        floor, category = scope_filters()
        user_id = request.args.get("user_id", "")
        if floor:
            query = query.where(model.point_floor == int(floor))
        if stage == "inspection":
            query = private_records(query, category)
        else:
            query = scoped_query(query, PatrolExecution)
            if category:
                query = query.where(PatrolExecution.category == category)
            if executor:
                query = query.where(PatrolExecution.user_id == g.user.id, PatrolExecution.category == patrol_scope(g.user))
        abnormal = request.args.get("abnormal", "")
        if abnormal not in ("", "0", "1"):
            abort(400, description="異常篩選選項不正確。")
        if abnormal and (stage == "execution" or executor):
            abort(400, description="簽到紀錄不適用異常篩選。")
        if abnormal:
            # Attendance-only visits have no inspection outcome.
            query = query.where(Inspection.executor_visit.is_(False), Inspection.is_abnormal.is_(abnormal == "1"))
        frequency = request.args.get("frequency", "")
        if frequency not in ("", "daily", "daily2", "weekly", "monthly", "irregular", "daily_all"):
            abort(400, description="巡檢頻率選項不正確。")
        if frequency == "daily_all":
            query = query.where(model.frequency.in_(("daily", "daily2")))
        elif frequency:
            query = query.where(model.frequency == frequency)
        if g.user.role != "admin" and not can_view_general_team(g.user):
            user_id = str(g.user.id)
        elif user_id:
            selected_id = parse_id(user_id)
            query = query.where(model.user_id == selected_id)
            user_id = str(selected_id)
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
        model = PatrolExecution if stage == "execution" else Inspection
        page = parse_id(request.args.get("page", "1"))
        per_page = 50
        # Count only matching IDs; related people, points, photos and stage
        # progress are loaded only for the page currently being viewed.
        total = db.session.scalar(query.with_only_columns(db.func.count(model.id)).order_by(None))
        pages = max(1, (total + per_page - 1) // per_page)
        page_filters = {key: value for key, value in filters.items() if value}
        if g.user.role != "admin":
            page_filters.pop("category", None)
            if not can_view_general_team(g.user):
                page_filters.pop("user_id", None)
        if page > pages:
            return redirect(url_for("records", **page_filters, page=pages, _anchor="record-results"))
        query = query.offset((page - 1) * per_page).limit(per_page)
        if stage == "execution":
            rows = db.session.execute(query).all()
        elif g.user.role == "executor":
            rows = db.session.scalars(query).all()
        else:
            rows = db.session.scalars(query.options(selectinload(Inspection.photos), selectinload(Inspection.issue),
                                                    selectinload(Inspection.execution))).all()
        users = []
        if g.user.role == "admin":
            users = db.session.scalars(select(User).order_by(User.display_name)).all()
        elif can_view_general_team(g.user):
            # Include former or inactive contributors without exposing a current
            # name from another team. Use one recent saved name per author.
            ranked = scoped_query(select(model.user_id, model.user_name, db.func.row_number().over(
                partition_by=model.user_id, order_by=(model.created_at.desc(), model.id.desc())).label("position")
            ).where(model.category == "general"), model).subquery()
            users = [SimpleNamespace(id=user_id, display_name=name or f"人員 {user_id}")
                     for user_id, name in db.session.execute(select(ranked.c.user_id, ranked.c.user_name)
                         .where(ranked.c.position == 1).order_by(ranked.c.user_name, ranked.c.user_id))]
        # The same person may only have records in the other stage. Keep their
        # option selected so the next form submission cannot widen to the team.
        if filters["user_id"] and (g.user.role == "admin" or can_view_general_team(g.user)):
            selected_id = int(filters["user_id"])
            if all(person.id != selected_id for person in users):
                name = None
                if can_view_general_team(g.user):
                    other = Inspection if stage == "execution" else PatrolExecution
                    name = db.session.scalar(scoped_query(select(other.user_name).where(
                        other.category == "general", other.user_id == selected_id, other.user_name != ""
                    ), other).order_by(other.created_at.desc(), other.id.desc()).limit(1))
                users.append(SimpleNamespace(id=selected_id, display_name=name or f"人員 {selected_id}"))
        storage = {}
        if g.user.role == "admin":
            storage = {"photo_storage_used": photo_storage_used(),
                       "photo_storage_limit": app.config["PHOTO_STORAGE_LIMIT_BYTES"]}
        execution_states = {}
        if stage == "execution":
            instant = now_utc()
            execution_states = {row.id: execution_review_status(row.frequency, row.period_key, row.slot, reviewed, instant)
                                for row, reviewed in rows}
        return render_template("records.html", records=rows if stage == "inspection" else [],
                               executions=[row for row, _ in rows] if stage == "execution" else [],
                               reviewed_execution_ids={row.id for row, reviewed in rows if reviewed} if stage == "execution" else set(),
                               execution_states=execution_states, execution_state_labels=EXECUTION_STATUS_LABELS,
                               pagination={"page": page, "pages": pages, "total": total, "per_page": per_page},
                               page_filters=page_filters,
                               stage=stage, users=users, filters=filters, **storage)

    def csv_text(value):
        # Excel also recognizes full-width formula prefixes in Chinese CSVs.
        value = str(value)
        return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠")) else value

    def write_record_csv(writer, query, filters):
        offline_condition = (PatrolExecution.offline_submission.has() if filters["stage"] == "execution" else
                             db.or_(Inspection.offline_submission.has(), Inspection.execution.has(PatrolExecution.offline_submission.has())))
        has_offline = db.session.scalar(select(query.order_by(None).where(offline_condition).exists()))
        offline_header = ["打卡時間來源", "伺服器收件時間（台北）", "對應執行時間來源", "執行收件時間（台北）"] if has_offline else []
        checklist_condition = (PatrolExecution.checklist_data != "" if filters["stage"] == "execution" else
                               db.or_(Inspection.checklist_data != "", Inspection.execution.has(PatrolExecution.checklist_data != "")))
        has_checklist = db.session.scalar(select(query.order_by(None).where(checklist_condition).exists()))
        checklist_header = ["點檢項目（☑已勾選／☐未勾選）", "對應執行點檢項目"] if has_checklist else []

        def checklist_fields(row):
            if not has_checklist:
                return []
            first = row.execution if isinstance(row, Inspection) else None
            return [csv_text(checklist_text(row)), csv_text(checklist_text(first)) if first else ""]

        def offline_fields(row):
            if not has_offline:
                return []
            submission = row.offline_submission
            execution = row.execution if isinstance(row, Inspection) else None
            first = execution.offline_submission if execution else None
            return ["手機離線記錄時間" if submission else "伺服器時間",
                    format_localtime(submission.received_at) if submission else "",
                    ("手機離線記錄時間" if first else "伺服器時間") if execution else "",
                    format_localtime(first.received_at) if first else ""]

        if filters["stage"] == "execution":
            instant = now_utc()
            writer.writerow(["執行人員", "樓層", "點位編號", "點位名稱", "執行時間（台北）", "巡檢頻率", "週期開始日", "分類", "次數", "巡檢狀態"] + offline_header + checklist_header)
            for row, reviewed in db.session.execute(query.execution_options(yield_per=500)):
                point = report_point_location(row)
                state = execution_review_status(row.frequency, row.period_key, row.slot, reviewed, instant)
                writer.writerow([csv_text(reporter_name(row)), point.floor, csv_text(point.code), csv_text(point.name),
                                 format_localtime(row.created_at), frequency_label(row.frequency), row.period_key,
                                 point_team_label(row), slot_label(row.slot), EXECUTION_STATUS_LABELS[state]] + offline_fields(row) + checklist_fields(row))
        elif g.user.role == "executor":
            writer.writerow(["簽到人員", "樓層", "點位編號", "點位名稱", "簽到時間（台北）"] + offline_header + checklist_header)
            for row in db.session.scalars(query.execution_options(yield_per=500)):
                point = report_point_location(row)
                writer.writerow([csv_text(reporter_name(row)), point.floor, csv_text(point.code), csv_text(point.name),
                                 format_localtime(row.created_at)] + offline_fields(row) + checklist_fields(row))
        else:
            has_workflows = db.session.scalar(select(query.order_by(None).where(Inspection.workflow_mode != "standard").exists()))
            header = ["人員", "樓層", "點位編號", "點位名稱", "打卡時間（台北）", "巡檢頻率", "週期開始日", "分類", "次數", "異常", "備註", "照片數", "處理狀態", "結案人員", "結案時間（台北）", "處理說明"]
            writer.writerow(header + (["作業模式", "執行人員", "執行時間（台北）"] if has_workflows else []) + offline_header + checklist_header)
            query = query.options(selectinload(Inspection.photos), selectinload(Inspection.issue), selectinload(Inspection.execution))
            for row in db.session.scalars(query.execution_options(yield_per=500)):
                point = report_point_location(row)
                fields = [csv_text(reporter_name(row)), point.floor, csv_text(point.code), csv_text(point.name),
                          format_localtime(row.created_at), frequency_label(row.frequency), row.period_key,
                          point_team_label(row), slot_label(row.slot), "是" if row.is_abnormal else "否", csv_text(row.note), len(row.photos),
                          {"open": "未結案", "resolved": "已結案", "": ""}[issue_state(row)],
                          csv_text(row.issue.resolved_by_name) if row.issue else "", format_localtime(row.issue.resolved_at) if row.issue and row.issue.resolved_at else "",
                          csv_text(row.issue.resolution_note) if row.issue else ""]
                if has_workflows:
                    if row.executor_visit:
                        # Direct visits record attendance only. Empty report fields
                        # keep a visit distinct from an inspection reporting no issue.
                        fields[9:] = [""] * 7
                        mode_label = "直接簽到"
                    else:
                        mode_label = "抽查" if row.legacy_unscheduled else {"standard": "一般巡檢", "spot": "單段巡檢", "two_stage": "執行後巡檢"}[row.workflow_mode]
                    fields.extend([mode_label,
                                   csv_text(row.execution.user_name) if row.execution else "",
                                   format_localtime(row.execution.created_at) if row.execution else ""])
                writer.writerow(fields + offline_fields(row) + checklist_fields(row))

    @app.get("/records/export")
    @login_required
    def export_records():
        query, filters = record_query()
        # Keep small exports in memory. Finish reading the database before
        # serving a larger file to a slow client. Its response owns the file.
        data = SpooledTemporaryFile(max_size=512 * 1024, mode="w+b")
        try:
            output = io.TextIOWrapper(data, encoding="utf-8-sig", newline="")
            write_record_csv(csv.writer(output), query, filters)
            output.detach()  # flush the encoder and pass ownership to send_file
            length = data.tell()
            data.seek(0)
            name = f"patrol-{filters['date_from']}-{filters['date_to']}.csv"
            response = send_file(data, mimetype="text/csv", as_attachment=True, download_name=name, conditional=False)
            response.content_length = length
            return response
        except BaseException:
            data.close()
            raise

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
        filters = {"date_from": begin.isoformat(), "date_to": end.isoformat(), "category": category,
                   "floor": floor, "frequency": frequency}
        if begin > today or frequency == "irregular":
            return [], filters
        scope = patrol_scope(g.user)
        points = historical_points(scope)
        first_period = min(begin.replace(day=1), begin - timedelta(days=begin.weekday()))
        completion_query = select(Inspection.point_id, Inspection.frequency, Inspection.period_key, Inspection.slot,
                                  Inspection.workflow_mode).distinct().where(Inspection.period_key >= first_period.isoformat(),
                                      Inspection.period_key <= end.isoformat(), Inspection.legacy_unscheduled.is_(False),
                                      Inspection.frequency != "irregular")
        completion_query = completion_query.where(Inspection.point_id.in_([point.id for point in points]))
        completions = db.session.execute(completion_query).all()
        executions = []
        if scope in (None, "general") and category in ("", "general"):
            executions = db.session.execute(scoped_query(select(PatrolExecution.point_id, PatrolExecution.frequency,
                PatrolExecution.period_key, PatrolExecution.slot).where(PatrolExecution.period_key >= first_period.isoformat(),
                    PatrolExecution.period_key <= end.isoformat(), PatrolExecution.category == "general"), PatrolExecution)).all()
        rows = calculate_missed(points, completions, begin, end, instant,
                                category=category, floor=int(floor) if floor else None, frequency=frequency,
                                executions=executions, two_stage_only=g.user.role == "executor")
        teams = {point.id: point.inspection_team for point in points}
        for row in rows:
            row["inspection_team"] = teams.get(row["point_id"], "general")
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
                summaries[group]["inspection_team"] = row["inspection_team"]
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
        writer.writerow(["應完成日期", "巡檢期間", "分類", "樓層", "點位編號", "點位名稱", "巡檢頻率", "次數", "到期時間（台北）", "漏打次數"]
                        + (["缺少階段"] if has_stages else []))
        for row in rows:
            writer.writerow([row["due_date"].isoformat(), row["period_label"], point_team_label(row),
                floor_label(row["floor"]), csv_text(row["code"]), csv_text(row["name"]), frequency_label(row["frequency"]),
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
        query = scoped_query(select(Point))
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

    @app.route("/admin/points/revision-20261109", methods=["GET", "POST"])
    @admin_required
    def point_assignment_revision():
        from point_assignment_revision import revise_point_assignments, revision_plan_digest
        effective = date(2026, 11, 10)
        if request.method == "POST":
            lock_current_admin()
            expected = request.form.get("expected_plan", "")
            if not re.fullmatch(r"[a-f0-9]{64}", expected):
                abort(400, description="請先開啟點位調整預覽，再套用修改。")
            try:
                result = revise_point_assignments(apply=True, instant=now_utc(),
                    effective_date=effective, expected_plan=expected)
            except ValueError as error:
                return render_template("point_assignment_revision.html", plan=None,
                                       revision_error=str(error), expected_plan=""), 409
            return render_template("point_assignment_revision.html",
                plan={**result, "already_applied": True}, revision_error=None, expected_plan="")
        try:
            plan = revise_point_assignments(instant=now_utc(), effective_date=effective)
        except ValueError as error:
            return render_template("point_assignment_revision.html", plan=None,
                                   revision_error=str(error), expected_plan="")
        return render_template("point_assignment_revision.html", plan=plan,
                               revision_error=None, expected_plan=revision_plan_digest(plan))

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
            if code in app.config["EXECUTOR_VISIT_CODES"] and (point is None or point.code != code):
                # These codes grant executor access. Only the original point can
                # recover a reserved code after an administrator renames it.
                if point is None or point.id != registered_visit_owners().get(code):
                    abort(409, description="此編號保留給原有的不定期簽到點。其他點位請使用新的編號。")
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
        team = request.form.get("inspection_team", point.inspection_team if point and category == "general" else "general")
        if team not in ("general", "engineering") or (team == "engineering" and category != "general"):
            abort(400, description="工務負責單位僅適用於總務作業分類的點位。")
        return {"code": code, "name": name, "floor": int(floor), "frequency": frequency, "category": category, "workflow_mode": mode, "inspection_team": team}

    def protect_pending_execution(point):
        if point.workflow_mode == "two_stage":
            instant = now_utc()
            key = period_for(point, instant)[0]
            flexible_daily2 = point.frequency == "daily2" and daily2_anytime(key)
            slots = ("am", "pm") if flexible_daily2 else (slot_for(point, instant),)
            for slot in slots:
                first = execution_in_slot(point, key, slot)
                if first and not execution_reviewed(first):
                    abort(409, description="已有執行、尚未巡檢。請完成巡檢或待本期結束後，再調整點位流程或停用。")

    def execution_reviewed(first):
        return db.session.scalar(select(Inspection.id).where(Inspection.execution_id == first.id).limit(1)) is not None

    def protect_started_daily_rounds(point, values, instant):
        """Do not replace today's personal quota or add unreviewable executions."""
        day = local_dt(instant).date()
        changes_rounds = (point.frequency != values["frequency"]
                          and "daily2" in (point.frequency, values["frequency"]))
        adds_execution = (point.frequency == values["frequency"] == "daily2"
                          and point.workflow_mode != "two_stage" and values["workflow_mode"] == "two_stage")
        if (not daily2_anytime(day) or "general" not in (point.category, values["category"])
                or not (changes_rounds or adds_execution)):
            return
        start = naive_utc(datetime.combine(day, time.min, TAIPEI))
        end = naive_utc(datetime.combine(day + timedelta(days=1), time.min, TAIPEI))
        inspected = db.session.scalar(select(Inspection.id).where(Inspection.point_id == point.id,
            db.or_(Inspection.personal_day == day,
                   db.and_(Inspection.created_at >= start, Inspection.created_at < end))).limit(1))
        executed = db.session.scalar(select(PatrolExecution.id).where(PatrolExecution.point_id == point.id,
            PatrolExecution.created_at >= start, PatrolExecution.created_at < end).limit(1))
        if inspected is not None or executed is not None:
            abort(409, description="此點今日已有簽到或巡檢紀錄，請隔日再變更每日兩次的頻率或改為兩階段，避免重複計算或無法接續巡檢。")

    def point_list_url(deleted=False, *, changed=None):
        floor, category = scope_filters()
        anchor = None
        if changed and (not floor or floor == str(changed.floor)) and (not category or category == changed.category):
            anchor = f"point-{changed.id}"
        return url_for("points", floor=floor or None, category=category or None, list="deleted" if deleted else None, _anchor=anchor)

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
        if point.pending_frequency and request.endpoint in ("update_point", "delete_point", "restore_point"):
            abort(409, description="此點已有預定生效的頻率調整，請於生效後再編輯或停用；現有打卡與 QR Code 不受影響。")
        return point

    def save_point(point, action):
        audit(action, point.code)
        try:
            db.session.flush()
            destination = point_list_url(changed=point)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            abort(400, description="點位編號已被使用（含已刪除點位）。請使用不同編號，或至已刪除清單還原。")
        flash(f"點位「{point.code}」設定已儲存。", "success")
        return redirect(destination)

    def preserve_initial_schedule(point, day):
        # With no history the current point is the report's only known plan.
        # Never project later settings backwards across a partially known history.
        if not point.schedules and point.schedule_start <= day:
            point.schedules.append(PointSchedule(effective_date=point.schedule_start, frequency=point.frequency,
                category=point.category, workflow_mode=point.workflow_mode, active=point.active,
                floor=point.floor, point_code=point.code, point_name=point.name))

    @app.post("/admin/points/create")
    @admin_required
    def create_point():
        lock_current_admin()
        instant = now_utc()
        point = Point(**point_values(), active=True, schedule_start=local_dt(instant).date(), created_at=naive_utc(instant))
        db.session.add(point)
        preserve_initial_schedule(point, point.schedule_start)
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
        if not active or any(getattr(point, key) != values[key] for key in values if key != "inspection_team"):
            protect_pending_execution(point)
        instant = now_utc()
        protect_started_daily_rounds(point, values, instant)
        # Freeze unknown snapshots before editing the current point. Older workers
        # may still have inserted NULL snapshots during a rolling deployment.
        for schedule in point.schedules:
            if schedule.category != point.category:
                continue
            if schedule.floor is None:
                schedule.floor = point.floor
            if schedule.point_code is None:
                schedule.point_code = point.code
            if schedule.point_name is None:
                schedule.point_name = point.name
        if point.active != active or any(getattr(point, key) != values[key] for key in values):
            day = local_dt(instant).date()
            preserve_initial_schedule(point, day)
            # An archived point stays unavailable up to its actual reactivation,
            # even if an administrator edited the inactive copy after restoring it.
            reactivating_archive = not point.active and active and next(
                (s.retired_at is not None for s in reversed(point.schedules) if s.active or s.retired_at is not None), False)
            changed = (reactivating_archive or point.workflow_mode != values["workflow_mode"] or (point.workflow_mode != "standard" and
                       (point.active != active or point.frequency != values["frequency"] or point.category != values["category"])))
            point.schedules.append(PointSchedule(effective_date=day, frequency=values["frequency"], category=values["category"], active=active,
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
        destination = point_list_url(changed=point)
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
        preserve_initial_schedule(point, local_dt(instant).date())
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

    @lru_cache(maxsize=256)
    def encode_qr(address, factory):
        # Cache only the graphic. Authorization, active status and the printed
        # name/category are checked again for each request.
        img = qrcode.make(address, image_factory=factory, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
        output = io.BytesIO()
        img.save(output)
        return output.getvalue()

    def qr_image(point, factory=None):
        address = app.config["PUBLIC_BASE_URL"] + url_for("checkin", token=point.qr_token)
        return encode_qr(address, factory)

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
        query = scoped_query(select(Point).where(Point.active.is_(True), Point.deleted_at.is_(None)))
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
        selections = request.form.getlist("role")
        if len(selections) != 1 or selections[0] not in ACCOUNT_CHOICES:
            abort(400, description="請從人員角色清單選擇一個角色。")
        return ACCOUNT_CHOICES[selections[0]]

    def submitted_ui_preferences(choice, user=None):
        """Old administration forms preserve new preferences; names never select a locale."""
        languages = request.form.getlist("ui_language")
        simple_values = request.form.getlist("simple_executor_ui")
        if len(languages) > 1 or (languages and languages[0] not in UI_LANGUAGES):
            abort(400, description="請從顯示語言清單選擇一種語言。")
        if len(simple_values) > 1 or (simple_values and simple_values[0] not in ("0", "1")):
            abort(400, description="請選擇有效的操作介面。")
        language = languages[0] if languages else (user.ui_language if user else "zh-Hant")
        simple = simple_values[0] == "1" if simple_values else bool(user and user.simple_executor_ui)
        return language, simple and choice.role == "executor"

    @app.post("/admin/users/create")
    @admin_required
    def create_user():
        lock_admin_users()
        username = request.form.get("username", "").strip().lower()
        name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        choice = submitted_role()
        language, simple = submitted_ui_preferences(choice)
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username) or not valid_label(name) or not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            abort(400, description=f"請填寫有效帳號（3–80 個英數字或 _.-）、姓名、角色與 {PASSWORD_MIN_LENGTH} 至 {PASSWORD_MAX_LENGTH} 個字元的密碼。")
        user = User(username=username, display_name=name, role=choice.role, patrol_category=choice.category,
                    general_manager_title=choice.manager_title, engineering_inspector_title=choice.engineering_title,
                    ui_language=language, simple_executor_ui=simple,
                    must_change_password=True)
        user.set_password(password)
        db.session.add(user)
        audit("user_created", username, account_role_choice(user))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            abort(400, description="此帳號已存在。")
        flash("員工帳號已建立，首次登入需變更密碼。", "success")
        return redirect(url_for("users", _anchor=f"user-{user.id}"))

    @app.post("/admin/users/<int:user_id>/update")
    @admin_required
    def update_user(user_id):
        user = lock_admin_users(user_id)[user_id]
        if not user:
            abort(404)
        if conflict := check_management_state(user, url_for("users")):
            return conflict
        name = request.form.get("display_name", "").strip()
        choice = submitted_role()
        language, simple = submitted_ui_preferences(choice, user)
        active = request.form.get("active", "") in ("on", "1", "true", "yes")
        if not valid_label(name):
            abort(400)
        if user.id == g.user.id and (choice.role != "admin" or not active):
            abort(400, description="不能停用自己或移除自己的系統管理員權限。")
        previous = account_role_choice(user) or user.role
        previous_preferences = (user.ui_language, user.simple_executor_ui)
        if (user.role != choice.role or user.patrol_category != choice.category or user.active != active
                or user.general_manager_title != choice.manager_title or user.engineering_inspector_title != choice.engineering_title):
            user.auth_version += 1
        user.display_name, user.role, user.patrol_category, user.active = name, choice.role, choice.category, active
        user.general_manager_title = choice.manager_title
        user.engineering_inspector_title = choice.engineering_title
        user.ui_language, user.simple_executor_ui = language, simple
        if not active:
            db.session.execute(db.update(DeviceBinding).where(DeviceBinding.user_id == user.id, DeviceBinding.status.in_(["approved", "pending"])).values(status="revoked"))
        detail = f"{previous} -> {account_role_choice(user)}"
        if previous_preferences != (language, simple):
            detail += f"; ui_language={language}; simple_executor_ui={int(simple)}"
        audit("user_updated", user.username, detail)
        db.session.commit()
        flash("帳號設定已更新。", "success")
        return redirect(url_for("users", _anchor=f"user-{user.id}"))

    @app.post("/admin/users/<int:user_id>/reset-password")
    @admin_required
    def reset_password(user_id):
        user = lock_admin_users(user_id)[user_id]
        if not user:
            abort(404)
        if user.id == g.user.id:
            abort(403, description="變更自己的密碼請使用「變更密碼」，並輸入目前密碼。")
        if conflict := check_management_state(user, url_for("users")):
            return conflict
        password = request.form.get("password", "")
        if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            abort(400, description=f"密碼需為 {PASSWORD_MIN_LENGTH} 至 {PASSWORD_MAX_LENGTH} 個字元。")
        user.set_password(password)
        user.must_change_password = True
        user.auth_version += 1
        audit("password_reset", user.username)
        db.session.commit()
        flash("密碼已重設，既有登入已失效；員工下次登入需變更密碼。", "success")
        return redirect(url_for("users", _anchor=f"user-{user.id}"))

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(503)
    def show_error(error):
        # Bare HTTP exceptions carry English framework text; the template
        # supplies a localized fallback while preserving our route messages.
        source = None if error.description == type(error).description else error.description
        message = t(source) if source else None
        voice_result = None
        if request.endpoint in ("checkin", "confirm_checkin"):
            kind = ("login_required" if not g.get("user") else g.get("patrol_voice_result") or
                    ("not_saved" if request.endpoint == "confirm_checkin" and error.code not in (403, 404) else "point_unavailable"))
            voice_result = voice_marker(kind)
        if request.path.startswith("/api/offline/"):
            source = source or "同步未完成，暫存仍保留；請重新連線後再試。"
            return {"ok": False, "code": "request_rejected", "message": t(source), "message_source": source,
                    "retryable": error.code in (429,)}, error.code
        if request.endpoint == "confirm_checkin" and g.get("user") and error.code in (400, 413):
            # The multipart parser may already have rejected the body. Recover
            # by GET from the matched route; never parse or replay the old form.
            if error.code == 413:
                message = t("上傳內容太大，這次打卡未儲存。請重新選取照片，最多 3 張，每張不超過 8 MB。")
            label = "Retry · 返回此點重新確認" if g.user.role == "executor" else "返回此點重新確認"
            return render_template("error.html", code=error.code, message=message,
                                   voice_result=voice_result,
                                   recovery_url=url_for("checkin", token=request.view_args["token"]),
                                   recovery_label=t(label)), error.code
        if request.endpoint == "resolve_issue" and g.get("user") and error.code == 413:
            return render_template("error.html", code=413,
                                   message=t("上傳內容太大，本次尚未結案。請重新選取照片，最多 3 張，每張不超過 8 MB。"),
                                   recovery_url=url_for("record_detail", record_id=request.view_args["inspection_id"]),
                                   recovery_label=t("返回異常明細")), 413
        # Preserve the protocol headers (particularly Allow for 405) while
        # displaying the same recovery links as our other error pages.
        response = error.get_response()
        response.set_data(render_template("error.html", code=error.code, message=message, voice_result=voice_result))
        return response

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

    @app.cli.command("revise-general-points")
    @click.option("--apply", "apply_changes", is_flag=True, help="Apply the verified revision; default is preview only.")
    @click.option("--effective-date", default="2026-11-10", help="Taipei date when changed frequencies take effect.")
    def revise_general_points(apply_changes, effective_date):
        from point_assignment_revision import revise_point_assignments
        try:
            result = revise_point_assignments(apply=apply_changes, instant=now_utc(), effective_date=effective_date)
        except ValueError as error:
            raise click.ClickException(str(error)) from error
        click.echo(json.dumps(result, ensure_ascii=False, sort_keys=True))

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--name", prompt=True)
    @click.password_option()
    def create_admin(username, name, password):
        username = username.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username) or not name.strip() or not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            raise click.ClickException(f"Use a valid username/name and a password with {PASSWORD_MIN_LENGTH}–{PASSWORD_MAX_LENGTH} characters.")
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
    from offline import register_offline
    register_offline(app, now=lambda: now_utc(), local_dt=local_dt, naive_utc=naive_utc,
                     period_for=period_for, timezone_local=TAIPEI, csrf_token=csrf_token,
                     device_binding=device_binding, lock_current_user=lock_current_user,
                     executor_can_scan=executor_can_scan, point_revision=checkin_location_revision,
                     inspection_in_slot=inspection_in_slot, audit=audit)
    return app


application = create_app()
