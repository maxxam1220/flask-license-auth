"""Patrol data. All table names are isolated from other applications."""
from datetime import datetime, timezone
import secrets
import sqlite3

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def configure_sqlite(connection, _):
    if isinstance(connection, sqlite3.Connection):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "patrol_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="inspector")
    active = db.Column(db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    auth_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Point(db.Model):
    __tablename__ = "patrol_points"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False)
    floor = db.Column(db.Integer, nullable=False)
    frequency = db.Column(db.String(10), nullable=False, default="daily")
    active = db.Column(db.Boolean, nullable=False, default=True)
    qr_token = db.Column(db.String(100), nullable=False, unique=True, default=lambda: secrets.token_urlsafe(24))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    schedule_start = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc).date())
    schedules = db.relationship("PointSchedule", backref="point", lazy="select", order_by="PointSchedule.effective_date, PointSchedule.id")
    __table_args__ = (db.CheckConstraint("floor >= 1 AND floor <= 5", name="patrol_point_floor"),)


class PointSchedule(db.Model):
    __tablename__ = "patrol_point_schedules"
    id = db.Column(db.Integer, primary_key=True)
    point_id = db.Column(db.Integer, db.ForeignKey("patrol_points.id"), nullable=False, index=True)
    effective_date = db.Column(db.Date, nullable=False)
    frequency = db.Column(db.String(10), nullable=False)
    active = db.Column(db.Boolean, nullable=False)


class DeviceBinding(db.Model):
    __tablename__ = "patrol_device_bindings"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    label = db.Column(db.String(100), nullable=False, default="我的手機")
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    approved_at = db.Column(db.DateTime)
    last_seen_at = db.Column(db.DateTime)
    user = db.relationship(User)
    __table_args__ = (db.Index("patrol_one_approved_device", "user_id", unique=True,
                               sqlite_where=db.text("status = 'approved'"),
                               postgresql_where=db.text("status = 'approved'")),)


class Inspection(db.Model):
    __tablename__ = "patrol_inspections"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False, index=True)
    point_id = db.Column(db.Integer, db.ForeignKey("patrol_points.id"), nullable=False, index=True)
    binding_id = db.Column(db.Integer, db.ForeignKey("patrol_device_bindings.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    period_key = db.Column(db.String(10), nullable=False)
    frequency = db.Column(db.String(10), nullable=False)
    point_code = db.Column(db.String(30), nullable=False)
    point_name = db.Column(db.String(100), nullable=False)
    point_floor = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(100), nullable=False, default="")
    user = db.relationship(User)
    point = db.relationship(Point)
    __table_args__ = (db.UniqueConstraint("point_id", "frequency", "period_key", name="patrol_one_inspection_per_period"),)


class AuditLog(db.Model):
    __tablename__ = "patrol_audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"))
    action = db.Column(db.String(80), nullable=False)
    target = db.Column(db.String(120), nullable=False, default="")
    detail = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class LoginAttempt(db.Model):
    __tablename__ = "patrol_login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
