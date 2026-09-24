"""Read-only license overview; bindings are the device inventory of record."""
from datetime import date, datetime
import re
from urllib.parse import urlencode

from flask import redirect, render_template, request, session, url_for
from psycopg2.extras import RealDictCursor


PAGE_SIZES = (25, 50, 100)
SEARCH_LIMIT = 256
EXPIRING_DAYS = 30
STATUS_LABELS = {
    "all": "全部授權",
    "valid": "未到期",
    "expiring": "30 天內到期",
    "expired": "已過期",
    "exhausted": "新增名額用盡",
    "invalid": "資料異常",
}
DATE_BASIS = "到期狀態依伺服器日期判定；到期當日仍有效。"


class AdminInputError(ValueError):
    """Invalid query parameters are rejected before opening a database connection."""


def _today():
    # Match check_license exactly; changing the licensing timezone is separate work.
    return datetime.today().date()


def _positive_integer(value, label):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise AdminInputError(f"{label}必須是正整數。")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        raise AdminInputError(f"{label}超出可處理範圍。") from None
    if number < 1:
        raise AdminInputError(f"{label}必須至少為 1。")
    return number


def _display_filters(values):
    query = str(values.get("q", "") or "").strip()[:SEARCH_LIMIT]
    status = values.get("status", "all")
    status = status if status in STATUS_LABELS else "all"
    limit = 25
    try:
        candidate = _positive_integer(values.get("limit", "25"), "每頁筆數")
        if candidate in PAGE_SIZES:
            limit = candidate
    except AdminInputError:
        pass
    return {"q": query, "status": status, "limit": limit}


def _parse_filters(values):
    raw_query = str(values.get("q", "") or "").strip()
    if len(raw_query) > SEARCH_LIMIT:
        raise AdminInputError(f"搜尋條件不可超過 {SEARCH_LIMIT} 個字元。")
    status = values.get("status", "all")
    if status not in STATUS_LABELS:
        raise AdminInputError("授權狀態無效，請從清單選擇。")
    limit = _positive_integer(values.get("limit", "25"), "每頁筆數")
    if limit not in PAGE_SIZES:
        raise AdminInputError("每頁筆數只能選擇 25、50 或 100。")
    page = _positive_integer(values.get("page", "1"), "頁碼")
    return {"q": raw_query, "status": status, "limit": limit}, page


def _expiry_date(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            pass
    return None


def _license_row(record, devices, today):
    auth_code = str(record.get("auth_code") or "")
    expiry = _expiry_date(record.get("expiry"))
    remaining = record.get("remaining")
    valid_remaining = isinstance(remaining, int) and not isinstance(remaining, bool)
    days_left = (expiry - today).days if expiry is not None else None
    if not auth_code or expiry is None or not valid_remaining:
        status, status_label = "invalid", "資料異常"
    elif days_left < 0:
        status, status_label = "expired", "已過期"
    elif days_left <= EXPIRING_DAYS:
        status, status_label = "expiring", "即將到期"
    else:
        status, status_label = "valid", "未到期"
    not_expired = status in ("valid", "expiring")
    return {
        "auth_code": auth_code,
        "expiry": expiry.isoformat() if expiry is not None else "資料異常",
        "days_left": days_left,
        "remaining": remaining if valid_remaining else None,
        "devices": devices,
        "device_count": len(devices),
        "status": status,
        "status_label": status_label,
        "exhausted": bool(not_expired and remaining <= 0),
    }


def _matches_status(row, status):
    if status == "all":
        return True
    if status == "valid":
        return row["status"] in ("valid", "expiring")
    if status == "exhausted":
        return row["exhausted"]
    return row["status"] == status


def _summary(rows):
    valid = [row for row in rows if row["status"] in ("valid", "expiring")]
    return {
        "total": len(rows),
        "valid": len(valid),
        "expiring": sum(row["status"] == "expiring" for row in rows),
        "expired": sum(row["status"] == "expired" for row in rows),
        "exhausted": sum(row["exhausted"] for row in rows),
        "bound_devices": sum(row["device_count"] for row in rows),
        "remaining_slots": sum(max(0, row["remaining"]) for row in valid),
    }


def _page_url(filters, page):
    query = {"status": filters["status"], "limit": filters["limit"], "page": page}
    if filters["q"]:
        query["q"] = filters["q"]
    return url_for("admin") + "?" + urlencode(query)


def _context(filters, today, *, rows=None, summary=None, page=1, error=""):
    rows = rows or []
    summary = summary or _summary([])
    total_count = summary["total"]
    total_pages = max(1, (total_count + filters["limit"] - 1) // filters["limit"])
    page = min(page, total_pages)
    start_row = (page - 1) * filters["limit"] + 1 if rows else 0
    return {
        "filters": filters, "rows": rows, "summary": summary,
        "page": page, "total_pages": total_pages, "total_count": total_count,
        "start_row": start_row, "end_row": start_row + len(rows) - 1 if rows else 0,
        "prev_url": _page_url(filters, page - 1) if page > 1 else None,
        "next_url": _page_url(filters, page + 1) if page < total_pages else None,
        "first_url": _page_url(filters, 1), "last_url": _page_url(filters, total_pages),
        "reset_url": url_for("admin"), "status_labels": STATUS_LABELS,
        "error": error, "today": today.isoformat(), "date_basis": DATE_BASIS,
    }


def register_admin_routes(app, get_db):
    """Register only the read-only website route, leaving all licensing APIs intact."""
    def admin():
        if not session.get("logged_in"):
            return redirect("/login")
        today = _today()
        try:
            filters, page = _parse_filters(request.args)
        except AdminInputError as exc:
            return render_template("admin.html", **_context(_display_filters(request.args), today, error=str(exc))), 400

        try:
            with get_db() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("SELECT auth_code, expiry, remaining FROM licenses ORDER BY auth_code")
                    licenses = cursor.fetchall()
                    cursor.execute("SELECT auth_code, mac FROM bindings ORDER BY auth_code, mac")
                    bindings = cursor.fetchall()
            device_sets = {}
            for binding in bindings:
                code = str(binding.get("auth_code") or "")
                mac = str(binding.get("mac") or "")
                if code and mac:
                    device_sets.setdefault(code, set()).add(mac)
            rows = [
                _license_row(record,
                             sorted(device_sets.get(str(record.get("auth_code") or ""), ()),
                                    key=lambda value: (value.casefold(), value)), today)
                for record in licenses
            ]
            query = filters["q"].casefold()
            rows = [row for row in rows
                    if (not query or query in row["auth_code"].casefold()
                        or any(query in mac.casefold() for mac in row["devices"]))
                    and _matches_status(row, filters["status"])]
            rows.sort(key=lambda row: row["auth_code"])
            summary = _summary(rows)
            total_pages = max(1, (len(rows) + filters["limit"] - 1) // filters["limit"])
            page = min(page, total_pages)
            offset = (page - 1) * filters["limit"]
            rows = rows[offset:offset + filters["limit"]]
        except Exception:
            app.logger.exception("Admin license overview query failed")
            return render_template("admin.html", **_context(filters, today, error="暫時無法讀取授權清單，請稍後再試。")), 500
        return render_template("admin.html", **_context(filters, today, rows=rows, summary=summary, page=page))

    app.add_url_rule("/admin", endpoint="admin", view_func=admin, methods=["GET"])

    @app.after_request
    def admin_no_store(response):
        if request.endpoint == "admin":
            response.headers["Cache-Control"] = "no-store"
        return response
