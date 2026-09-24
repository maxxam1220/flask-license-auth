"""Audit browsing and explicit, bounded retention cleanup for the admin website."""
import csv
from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import io
import re
import secrets
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from flask import flash, get_flashed_messages, redirect, render_template, request, session, url_for
from psycopg2.extras import Json, RealDictCursor

from security import csrf_token, valid_csrf_token


TAIPEI = ZoneInfo("Asia/Taipei")
EXPORT_LIMIT = 5000
PREVIEW_SECONDS = 600
PREVIEW_SESSION_KEY = "_audit_prune_preview"
ACTION_LABELS = {
    "login_success": "登入成功",
    "login_fail": "登入失敗",
    "audit_prune": "清除紀錄",
}
TIME_HELP = "時間條件採台北時間；結束時間包含所選分鐘，例如 18:30 包含到 18:30:59。"
_ROWS_SQL = """
    SELECT to_char(a.event_time AT TIME ZONE 'Asia/Taipei',
                   'YYYY-MM-DD HH24:MI:SS') AS event_time,
           a.username, a.action, a.machine_name, a.local_ip, a.public_ip,
           a.app_version, a.client_os, COALESCE(a.note, '') AS note
    FROM audit_login AS a
    WHERE {where}
    ORDER BY a.event_time DESC, a.id DESC
"""


class AuditInputError(ValueError):
    """An invalid, user-correctable form value; no query should be issued."""


class AuditPreviewUsedError(Exception):
    """A successful transaction has already consumed this preview nonce."""


def _utcnow():
    return datetime.now(timezone.utc)


def _integer(value, label, minimum, maximum=None):
    raw = str(value)
    if not re.fullmatch(r"[0-9]+", raw):
        raise AuditInputError(f"{label}必須是整數。")
    try:
        number = int(raw)
    except ValueError:
        raise AuditInputError(f"{label}超出可處理範圍。") from None
    if number < minimum or (maximum is not None and number > maximum):
        bounds = f"{minimum}～{maximum}" if maximum is not None else f"至少 {minimum}"
        raise AuditInputError(f"{label}必須為 {bounds}。")
    return number


def _local_minute(value, label):
    if not value:
        return None
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}", value):
        raise AuditInputError(f"{label}格式錯誤，請使用日期與時間欄位（台北時間，精確到分鐘）。")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M").replace(tzinfo=TAIPEI)
    except ValueError:
        raise AuditInputError(f"{label}不是有效的日期或時間。") from None


def _display_filters(values):
    """Keep correctable text while providing a safe numeric template default."""
    filters = {key: str(values.get(key, "") or "").strip()[:256]
               for key in ("username", "action", "from", "to")}
    filters["limit"] = 50
    try:
        filters["limit"] = _integer(values.get("limit", "50"), "每頁筆數", 10, 500)
    except AuditInputError:
        pass
    return filters


def _parse_filters(values, *, ignore_page=False):
    for key, label, maximum in (("username", "使用者", 128), ("action", "事件", 80)):
        if len(str(values.get(key, "") or "").strip()) > maximum:
            raise AuditInputError(f"{label}條件不可超過 {maximum} 個字元。")
    filters = _display_filters(values)
    filters["limit"] = _integer(values.get("limit", "50"), "每頁筆數", 10, 500)
    supplied_page = _integer(values.get("page", "1"), "頁碼", 1)
    page = 1 if ignore_page else supplied_page
    start = _local_minute(filters["from"], "開始時間")
    end = _local_minute(filters["to"], "結束時間")
    if start and end and start > end:
        raise AuditInputError("開始時間不可晚於結束時間。")

    where, parameters = ["1=1"], []
    for key in ("username", "action"):
        if filters[key]:
            where.append(f"a.{key} = %s")
            parameters.append(filters[key])
    if start:
        try:
            utc_start = start.astimezone(timezone.utc)
        except (OverflowError, ValueError):
            raise AuditInputError("開始時間超出可處理範圍。") from None
        where.append("a.event_time >= %s")
        parameters.append(utc_start)
    if end:
        try:
            exclusive_end = (end + timedelta(minutes=1)).astimezone(timezone.utc)
        except (OverflowError, ValueError):
            raise AuditInputError("結束時間超出可處理範圍。") from None
        where.append("a.event_time < %s")
        parameters.append(exclusive_end)
    return filters, page, " AND ".join(where), parameters


def _query_url(endpoint, filters, page=None):
    values = {key: filters[key] for key in ("username", "action", "from", "to", "limit")
              if filters.get(key) not in (None, "")}
    if page is not None:
        values["page"] = page
    query = urlencode(values)
    return url_for(endpoint) + ("?" + query if query else "")


def _active_preview():
    preview = session.get(PREVIEW_SESSION_KEY)
    if not isinstance(preview, dict):
        return None
    try:
        created = datetime.fromisoformat(preview["created_at"])
        cutoff = datetime.fromisoformat(preview["cutoff"])
        age = (_utcnow() - created).total_seconds()
        if (created.tzinfo is None or cutoff.tzinfo is None or not 0 <= age < PREVIEW_SECONDS
                or not isinstance(preview["token"], str) or not preview["token"]
                or type(preview["count"]) is not int or preview["count"] < 0
                or type(preview["max_id"]) is not int or preview["max_id"] < 0
                or type(preview["days"]) is not int or not 1 <= preview["days"] <= 3650):
            raise ValueError("Invalid preview")
    except (KeyError, TypeError, ValueError, OverflowError):
        session.pop(PREVIEW_SESSION_KEY, None)
        return None
    return preview


def _template_context(filters, *, rows=None, summary=None, page=1, error=""):
    summary = summary or {"total": 0, "success": 0, "failed": 0}
    total = summary["total"]
    limit = filters["limit"]
    total_pages = max(1, (total + limit - 1) // limit)
    page = min(page, total_pages)
    rows = rows or []
    start_row = (page - 1) * limit + 1 if rows else 0
    preview = _active_preview()
    preview_display = None
    if preview:
        preview_display = {key: preview[key] for key in ("token", "count", "days")}
        preview_display["cutoff_display"] = datetime.fromisoformat(preview["cutoff"]).astimezone(TAIPEI).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "filters": filters, "rows": rows, "summary": summary,
        "page": page, "total_pages": total_pages,
        "start_row": start_row, "end_row": start_row + len(rows) - 1 if rows else 0,
        "prev_url": _query_url("audit_list", filters, page - 1) if page > 1 else None,
        "next_url": _query_url("audit_list", filters, page + 1) if page < total_pages else None,
        "first_url": _query_url("audit_list", filters, 1),
        "last_url": _query_url("audit_list", filters, total_pages),
        "export_url": _query_url("audit_export_csv", filters),
        "reset_url": url_for("audit_list"), "prune_url": url_for("audit_prune"),
        "action_labels": ACTION_LABELS, "error": error,
        "message": "\n".join(get_flashed_messages(category_filter=["success"])),
        "prune_preview": preview_display, "csrf_token": csrf_token, "time_help": TIME_HELP,
    }


def _csv_cell(value):
    text = "" if value is None else str(value)
    first = text.lstrip(" \t\r\n\v\f\x00\ufeff")
    if text.startswith(("\t", "\r", "\n")) or first.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def register_audit_routes(app, get_db, admin_username):
    """Register the existing endpoints using the application's transaction context."""
    def render_error(values, error, status=400):
        return render_template("audit.html", **_template_context(_display_filters(values), error=error)), status

    def audit_list():
        if not session.get("logged_in"):
            return redirect("/login")
        try:
            filters, page, where, parameters = _parse_filters(request.args)
        except AuditInputError as exc:
            return render_error(request.args, str(exc))
        try:
            with get_db() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT COUNT(*) AS total,
                               COUNT(*) FILTER (WHERE a.action = 'login_success') AS success,
                               COUNT(*) FILTER (WHERE a.action = 'login_fail') AS failed
                        FROM audit_login AS a WHERE """ + where, parameters)
                    result = cursor.fetchone() or {}
                    summary = {key: int(result.get(key) or 0) for key in ("total", "success", "failed")}
                    total_pages = max(1, (summary["total"] + filters["limit"] - 1) // filters["limit"])
                    page = min(page, total_pages)
                    cursor.execute(_ROWS_SQL.format(where=where) + " LIMIT %s OFFSET %s",
                                   parameters + [filters["limit"], (page - 1) * filters["limit"]])
                    rows = [dict(row) for row in cursor.fetchall()]
        except Exception:
            app.logger.exception("Audit list query failed")
            return render_error(request.args, "暫時無法讀取稽核紀錄，請稍後再試。", 500)
        return render_template("audit.html", **_template_context(filters, rows=rows, summary=summary, page=page))

    def audit_export_csv():
        if not session.get("logged_in"):
            return redirect("/login")
        try:
            filters, _, where, parameters = _parse_filters(request.args, ignore_page=True)
        except AuditInputError as exc:
            return render_error(request.args, str(exc))
        try:
            with get_db() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute(_ROWS_SQL.format(where=where) + " LIMIT %s", parameters + [EXPORT_LIMIT + 1])
                    rows = cursor.fetchall()
        except Exception:
            app.logger.exception("Audit CSV query failed")
            return render_error(request.args, "暫時無法匯出稽核紀錄，請稍後再試。", 500)
        if len(rows) > EXPORT_LIMIT:
            return render_error(request.args, "符合條件的紀錄超過 5,000 筆，請縮小時間或帳號範圍後再下載；此次未匯出檔案。", 409)
        output = io.StringIO(newline="")
        output.write("\ufeff")
        writer = csv.writer(output)
        writer.writerow(["time_tw", "username", "action", "machine", "local_ip", "public_ip", "version", "os", "note"])
        columns = ("event_time", "username", "action", "machine_name", "local_ip", "public_ip", "app_version", "client_os", "note")
        for row in rows:
            writer.writerow([_csv_cell(row.get(column)) for column in columns])
        response = app.response_class(output.getvalue().encode("utf-8"), content_type="text/csv; charset=utf-8")
        response.headers["Content-Disposition"] = 'attachment; filename="audit_login.csv"'
        return response

    def audit_prune():
        if not session.get("logged_in"):
            return redirect("/login")
        if not valid_csrf_token():
            return render_error(request.form, "表單已失效，請重新整理後再試。")
        try:
            filters, page, _, _ = _parse_filters(request.form)
            operation = request.form.get("operation", "preview")
            if operation not in ("preview", "confirm", "cancel"):
                raise AuditInputError("清除操作無效，請重新預覽。")
            if operation == "cancel":
                session.pop(PREVIEW_SESSION_KEY, None)
                return redirect(_query_url("audit_list", filters, page))
            if operation == "preview":
                days = _integer(request.form.get("days", ""), "保留天數", 1, 3650)
            else:
                preview = _active_preview()
                if not preview:
                    raise AuditInputError("清除預覽已失效或超過 10 分鐘，請重新預覽。")
                supplied = request.form.get("preview_token", "")
                if not supplied or not hmac.compare_digest(preview["token"].encode(), supplied.encode()):
                    raise AuditInputError("清除預覽不符，請重新預覽。")
                if request.form.get("confirm_scope") != "all_users":
                    raise AuditInputError("請確認此操作會清除全部使用者的舊紀錄，與目前篩選條件無關。")
                if "days" in request.form and _integer(request.form["days"], "保留天數", 1, 3650) != preview["days"]:
                    raise AuditInputError("保留天數與預覽不符，請重新預覽。")
        except AuditInputError as exc:
            return render_error(request.form, str(exc))

        if operation == "preview":
            created = _utcnow()
            cutoff = created - timedelta(days=days)
            try:
                with get_db() as connection:
                    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                        cursor.execute("""
                            SELECT COUNT(*) AS count, COALESCE(MAX(a.id), 0) AS max_id
                            FROM audit_login AS a WHERE a.event_time < %s
                        """, (cutoff,))
                        result = cursor.fetchone() or {}
                session[PREVIEW_SESSION_KEY] = {
                    "token": secrets.token_urlsafe(32), "cutoff": cutoff.isoformat(),
                    "max_id": int(result.get("max_id") or 0), "count": int(result.get("count") or 0),
                    "days": days, "created_at": created.isoformat(),
                }
            except Exception:
                app.logger.exception("Audit prune preview failed")
                return render_error(request.form, "暫時無法預覽清除範圍，尚未刪除任何紀錄。", 500)
            return redirect(_query_url("audit_list", filters, page))

        cutoff = datetime.fromisoformat(preview["cutoff"]).astimezone(timezone.utc)
        preview_digest = hashlib.sha256(preview["token"].encode()).digest()
        preview_hash = preview_digest.hex()
        lock_key = int.from_bytes(preview_digest[:8], "big", signed=True)
        try:
            with get_db() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    # Cookies are client-held: removing a session field alone cannot
                    # prevent replaying an older signed cookie on another worker.
                    cursor.execute("SELECT pg_advisory_xact_lock(%s)", (lock_key,))
                    if not _active_preview():
                        raise AuditInputError("清除預覽等待期間已逾時，請重新預覽。")
                    cursor.execute("""
                        SELECT 1 AS used FROM audit_login
                        WHERE action = 'audit_prune'
                          AND extra->>'preview_hash' = %s AND event_time >= %s
                        LIMIT 1
                    """, (preview_hash, _utcnow() - timedelta(seconds=PREVIEW_SECONDS)))
                    if cursor.fetchone():
                        raise AuditPreviewUsedError
                    cursor.execute("DELETE FROM audit_login WHERE event_time < %s AND id <= %s",
                                   (cutoff, preview["max_id"]))
                    deleted = cursor.rowcount
                    cursor.execute("""
                        INSERT INTO audit_login (event_time, username, action, note, source, extra)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (_utcnow(), admin_username, "audit_prune",
                          f"清除全部使用者 {preview['days']} 天前的紀錄，共 {deleted} 筆。", "web_admin",
                          Json({"days": preview["days"], "cutoff": cutoff.isoformat(),
                                "max_id": preview["max_id"], "preview_count": preview["count"],
                                "deleted": deleted, "preview_hash": preview_hash})))
        except AuditPreviewUsedError:
            session.pop(PREVIEW_SESSION_KEY, None)
            return render_error(request.form, "此清除預覽已執行，請重新預覽；沒有再次刪除紀錄。", 409)
        except AuditInputError as exc:
            return render_error(request.form, str(exc))
        except Exception:
            app.logger.exception("Audit prune transaction failed")
            return render_error(request.form, "清除未完成，交易已取消。請稍後重新預覽再試。", 500)
        session.pop(PREVIEW_SESSION_KEY, None)
        flash(f"已清除全部使用者 {preview['days']} 天前的舊紀錄，共 {deleted} 筆；預覽後新增的紀錄保留。", "success")
        return redirect(_query_url("audit_list", filters, page))

    app.add_url_rule("/audit", endpoint="audit_list", view_func=audit_list, methods=["GET"])
    app.add_url_rule("/audit/export.csv", endpoint="audit_export_csv", view_func=audit_export_csv, methods=["GET"])
    app.add_url_rule("/audit/prune", endpoint="audit_prune", view_func=audit_prune, methods=["POST"])

    @app.after_request
    def audit_no_store(response):
        if request.endpoint in {"audit_list", "audit_export_csv", "audit_prune"}:
            response.headers["Cache-Control"] = "no-store"
        return response
