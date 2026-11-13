"""Audited, department-wide safety patrol leave exclusions.

This is a patrol scheduling exception, not a personnel leave approval system.
Existing check-ins and evidence are retained when a date is excluded or restored.
"""
from datetime import date, datetime, timedelta, timezone
from functools import wraps
import re

from flask import abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import select

from models import AuditLog, RevokedSession, TAIPEI, User, db, utcnow


LEAVE_LOCK_ID = 714032610319
MAX_RANGE_DAYS = 62
DATE_WINDOW_DAYS = 366


class SafetyLeaveExclusion(db.Model):
    __tablename__ = "patrol_safety_leave_exclusions"
    id = db.Column(db.Integer, primary_key=True)
    date_from = db.Column(db.Date, nullable=False, index=True)
    date_to = db.Column(db.Date, nullable=False, index=True)
    note = db.Column(db.String(100), nullable=False, default="")
    created_by = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    cancelled_by = db.Column(db.Integer, db.ForeignKey("patrol_users.id"))
    cancelled_at = db.Column(db.DateTime)
    creator = db.relationship(User, foreign_keys=[created_by], lazy="joined")
    canceller = db.relationship(User, foreign_keys=[cancelled_by], lazy="joined")
    __table_args__ = (
        db.CheckConstraint("date_from <= date_to", name="patrol_safety_leave_date_order"),
        db.CheckConstraint("(cancelled_at IS NULL AND cancelled_by IS NULL) OR "
                           "(cancelled_at IS NOT NULL AND cancelled_by IS NOT NULL)",
                           name="patrol_safety_leave_cancellation"),
    )

    @property
    def days(self):
        return (self.date_to - self.date_from).days + 1


def can_manage_safety_leave(user):
    return bool(user and user.active and (user.role == "admin" or
                (user.role == "inspector" and user.patrol_category == "safety")))


def get_safety_leave_dates(start, end):
    """Return active safety-only excluded dates within an inclusive query range."""
    if (not isinstance(start, date) or isinstance(start, datetime)
            or not isinstance(end, date) or isinstance(end, datetime) or start > end):
        raise ValueError("Expected an ordered date range")
    ranges = db.session.execute(select(SafetyLeaveExclusion.date_from, SafetyLeaveExclusion.date_to).where(
        SafetyLeaveExclusion.cancelled_at.is_(None),
        SafetyLeaveExclusion.date_from <= end, SafetyLeaveExclusion.date_to >= start))
    days = set()
    for first, last in ranges:
        first, last = max(first, start), min(last, end)
        days.update(first + timedelta(days=offset) for offset in range((last - first).days + 1))
    return days


def _lock_leave_updates():
    # Serialize even the first insertion, when no matching row exists to lock.
    # Take the user lock first, matching the application's account-edit order.
    with db.session.no_autoflush:
        if db.engine.dialect.name == "postgresql":
            db.session.execute(db.text("SELECT pg_advisory_xact_lock(:key)"), {"key": LEAVE_LOCK_ID})
        elif db.engine.dialect.name == "sqlite":
            db.session.execute(db.update(SafetyLeaveExclusion).where(db.false()).values(note=""))
        else:
            abort(503, description="目前無法安全更新請休排除，請稍後再試。")


def _parse_day(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        abort(400, description="請填寫有效日期。")
    try:
        return date.fromisoformat(value)
    except ValueError:
        abort(400, description="請填寫有效日期。")


def register_routes(app, *, now_utc=None):
    """Register after the application's shared auth/CSRF hooks are configured."""
    clock = now_utc or (lambda: datetime.now(timezone.utc))

    def instant():
        value = clock()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def allowed(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not g.get("user"):
                return redirect(url_for("login", next=url_for("safety_leave")))
            if not can_manage_safety_leave(g.user):
                abort(403, description="請休排除僅限職安巡檢員與系統管理員使用。")
            return fn(*args, **kwargs)
        return wrapped

    def lock_actor():
        actor = db.session.scalar(select(User).where(User.id == g.user.id).with_for_update(key_share=True)
                                  .execution_options(populate_existing=True))
        revoked = db.session.scalar(select(RevokedSession.token_hash).where(
            RevokedSession.token_hash == g.get("patrol_session_hash")))
        if (not can_manage_safety_leave(actor) or actor.auth_version != session.get("auth_version")
                or actor.must_change_password or revoked is not None):
            abort(403, description="帳號權限已變更，請重新登入。")
        return actor

    @app.get("/safety-leave")
    @allowed
    def safety_leave():
        today = instant().astimezone(TAIPEI).date()
        show_cancelled = request.args.get("status") == "cancelled"
        query = select(SafetyLeaveExclusion)
        query = query.where(SafetyLeaveExclusion.cancelled_at.is_not(None) if show_cancelled
                            else SafetyLeaveExclusion.cancelled_at.is_(None))
        entries = db.session.scalars(query.order_by(SafetyLeaveExclusion.date_from.desc(),
                                                   SafetyLeaveExclusion.id.desc()).limit(200)).unique().all()
        return render_template("safety_leave.html", entries=entries, show_cancelled=show_cancelled,
                               leave_today=today, min_date=today - timedelta(days=DATE_WINDOW_DAYS),
                               max_date=today + timedelta(days=DATE_WINDOW_DAYS), max_range_days=MAX_RANGE_DAYS)

    @app.post("/safety-leave/add")
    @allowed
    def add_safety_leave():
        actor = lock_actor()
        first = _parse_day(request.form.get("date_from", ""))
        last = _parse_day(request.form.get("date_to") or request.form.get("date_from", ""))
        note = request.form.get("note", "").strip()
        now = instant()
        today = now.astimezone(TAIPEI).date()
        if first > last:
            abort(400, description="結束日期不得早於開始日期。")
        if (last - first).days + 1 > MAX_RANGE_DAYS:
            abort(400, description=f"每次最多排除 {MAX_RANGE_DAYS} 天，請分段填寫。")
        if first < today - timedelta(days=DATE_WINDOW_DAYS) or last > today + timedelta(days=DATE_WINDOW_DAYS):
            abort(400, description="請選擇前後一年內的日期。")
        if len(note) > 100 or any(ord(char) < 32 for char in note):
            abort(400, description="備註最多 100 字，請使用單行文字。")
        _lock_leave_updates()
        overlap = db.session.scalar(select(SafetyLeaveExclusion.id).where(
            SafetyLeaveExclusion.cancelled_at.is_(None),
            SafetyLeaveExclusion.date_from <= last, SafetyLeaveExclusion.date_to >= first).limit(1))
        if overlap is not None:
            abort(409, description="選擇的日期已有請休排除，請查看現有紀錄，或調整日期後再新增。")
        entry = SafetyLeaveExclusion(date_from=first, date_to=last, note=note,
                                    created_by=actor.id, created_at=now.replace(tzinfo=None))
        db.session.add(entry)
        db.session.flush()
        db.session.add(AuditLog(actor_id=actor.id, action="safety_leave_added", target=str(entry.id),
                               detail=f"{first.isoformat()}~{last.isoformat()}"))
        db.session.commit()
        flash("請休排除已新增，指定日期不列入職安漏打；原有打卡紀錄保留。", "success")
        return redirect(url_for("safety_leave"))

    @app.post("/safety-leave/<int:leave_id>/cancel")
    @allowed
    def cancel_safety_leave(leave_id):
        actor = lock_actor()
        _lock_leave_updates()
        entry = db.session.scalar(select(SafetyLeaveExclusion).where(SafetyLeaveExclusion.id == leave_id)
                                  .execution_options(populate_existing=True))
        if entry is None:
            abort(404, description="找不到這筆請休排除。")
        if actor.role != "admin" and entry.created_by != actor.id:
            abort(403, description="僅可取消自己新增的請休排除。")
        if entry.cancelled_at is not None:
            abort(409, description="此筆請休排除已取消，請重新整理清單。")
        entry.cancelled_by = actor.id
        entry.cancelled_at = instant().replace(tzinfo=None)
        db.session.add(AuditLog(actor_id=actor.id, action="safety_leave_cancelled", target=str(entry.id),
                               detail=f"{entry.date_from.isoformat()}~{entry.date_to.isoformat()}"))
        db.session.commit()
        flash("請休排除已取消，這段日期恢復依巡檢排程計算。", "success")
        return redirect(url_for("safety_leave"))
