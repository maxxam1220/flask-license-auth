"""Administrator listing of successful sign-ins, using the site's local calendar."""
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import abort, redirect, render_template, request, url_for
from sqlalchemy import select

from models import LoginEvent, User, db


CLIENT_LABELS = {"mobile": "手機", "tablet": "平板", "desktop": "電腦", "unknown": "未辨識"}
TAIPEI = ZoneInfo("Asia/Taipei")
PAGE_SIZE = 50


def login_records_page(today, parse_date, parse_id):
    begin = parse_date(request.args.get("date_from"), today - timedelta(days=6))
    end = parse_date(request.args.get("date_to"), today)
    if begin > end or (end - begin).days > 366:
        abort(400, description="請選擇正確的日期範圍，最多可查詢 367 天。")
    page = parse_id(request.args.get("page", "1"))
    client_type = request.args.get("client_type", "")
    if client_type and client_type not in CLIENT_LABELS:
        abort(400, description="請選擇有效的裝置類型。")
    user_arg = request.args.get("user_id", "")
    user_id = parse_id(user_arg) if user_arg else None
    users = db.session.execute(select(User.id, User.display_name, User.username, User.active)
                               .order_by(User.display_name, User.username)).all()
    selected = next((user for user in users if user.id == user_id), None)
    if user_id and not selected:
        abort(400, description="找不到所選的人員。")

    # Query the bounds in UTC so both the midnight boundary and time index apply.
    start = datetime.combine(begin, time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
    stop = datetime.combine(end + timedelta(days=1), time.min, TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
    query = select(LoginEvent).where(LoginEvent.created_at >= start, LoginEvent.created_at < stop)
    filters = {"date_from": begin.isoformat(), "date_to": end.isoformat()}
    if user_id:
        query = query.where(LoginEvent.user_id == user_id)
        filters["user_id"] = user_id
    if client_type:
        query = query.where(LoginEvent.client_type == client_type)
        filters["client_type"] = client_type

    total = db.session.scalar(query.with_only_columns(db.func.count(LoginEvent.id)))
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if page > pages:
        return redirect(url_for("login_records", page=pages, _anchor="login-results", **filters))
    events = db.session.scalars(query.order_by(LoginEvent.created_at.desc(), LoginEvent.id.desc())
                                .limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)).all()
    return render_template("login_records.html", events=events, users=users, filters=filters,
                           selected_user=selected, client_labels=CLIENT_LABELS,
                           pagination=dict(total=total, page=page, pages=pages, per_page=PAGE_SIZE))
