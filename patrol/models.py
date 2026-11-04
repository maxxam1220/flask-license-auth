"""Patrol data. All table names are isolated from other applications."""
from datetime import datetime, timezone
import secrets
import sqlite3

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()

POINT_WORKFLOW_RULE = "workflow_mode = 'standard' OR (category = 'general' AND workflow_mode IN ('spot','two_stage'))"


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
    # NULL means unassigned; no patrol scope is inferred from names or roles.
    patrol_category = db.Column(db.String(20), db.CheckConstraint(
        "patrol_category IN ('safety', 'general')", name="patrol_user_category_allowed"), nullable=True)
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
    category = db.Column(db.String(20), nullable=False, default="uncategorized", server_default="uncategorized")
    workflow_mode = db.Column(db.String(10), db.CheckConstraint(POINT_WORKFLOW_RULE, name="patrol_point_workflow"),
                              nullable=False, default="standard", server_default="standard")
    active = db.Column(db.Boolean, nullable=False, default=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    qr_token = db.Column(db.String(100), nullable=False, unique=True, default=lambda: secrets.token_urlsafe(24))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    schedule_start = db.Column(db.Date, nullable=False, default=lambda: datetime.now(timezone.utc).date())
    schedules = db.relationship("PointSchedule", backref="point", lazy="select", order_by="PointSchedule.effective_date, PointSchedule.id")
    __table_args__ = (db.CheckConstraint("floor IN (-2, -1, 1, 11, 2, 3, 4, 14, 5, 15)", name="patrol_point_floor"),)


class PointSchedule(db.Model):
    __tablename__ = "patrol_point_schedules"
    id = db.Column(db.Integer, primary_key=True)
    point_id = db.Column(db.Integer, db.ForeignKey("patrol_points.id"), nullable=False, index=True)
    effective_date = db.Column(db.Date, nullable=False)
    frequency = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(20), nullable=False, default="uncategorized", server_default="uncategorized")
    workflow_mode = db.Column(db.String(10), db.CheckConstraint(POINT_WORKFLOW_RULE, name="patrol_schedule_workflow"),
                              nullable=False, default="standard", server_default="standard")
    workflow_changed_at = db.Column(db.DateTime)
    # Nullable so older workers can finish during a rolling deployment.
    floor = db.Column(db.Integer)
    point_code = db.Column(db.String(30))
    point_name = db.Column(db.String(100))
    active = db.Column(db.Boolean, nullable=False)
    retired_at = db.Column(db.DateTime, nullable=True)


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


class PatrolExecution(db.Model):
    """The executor's submitted first stage, independently retained before and after review."""
    __tablename__ = "patrol_executions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False, index=True)
    point_id = db.Column(db.Integer, db.ForeignKey("patrol_points.id"), nullable=False)
    binding_id = db.Column(db.Integer, db.ForeignKey("patrol_device_bindings.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    frequency = db.Column(db.String(10), nullable=False)
    period_key = db.Column(db.String(10), nullable=False)
    slot = db.Column(db.String(8), nullable=False)
    category = db.Column(db.String(20), nullable=False, default="general", server_default="general")
    point_code = db.Column(db.String(30), nullable=False)
    point_name = db.Column(db.String(100), nullable=False)
    point_floor = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(100), nullable=False)
    user = db.relationship(User)
    point = db.relationship(Point)
    inspection = db.relationship("Inspection", back_populates="execution", uselist=False,
                                 foreign_keys="Inspection.execution_id", viewonly=True)
    __table_args__ = (
        db.CheckConstraint("category = 'general'", name="patrol_execution_general"),
        db.CheckConstraint("(frequency IN ('daily','weekly') AND slot = 'any') OR "
                           "(frequency = 'daily2' AND slot IN ('am','pm'))", name="patrol_execution_valid_slot"),
        db.UniqueConstraint("point_id", "frequency", "period_key", "slot", name="patrol_one_execution_per_slot"),
        # A final review may only reference the first stage from the exact same obligation.
        db.UniqueConstraint("id", "point_id", "frequency", "period_key", "slot", name="patrol_execution_identity"),
    )


class Inspection(db.Model):
    __tablename__ = "patrol_inspections"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False, index=True)
    point_id = db.Column(db.Integer, db.ForeignKey("patrol_points.id"), nullable=False, index=True)
    binding_id = db.Column(db.Integer, db.ForeignKey("patrol_device_bindings.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    period_key = db.Column(db.String(10), nullable=False)
    frequency = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(20), nullable=False, default="uncategorized", server_default="uncategorized")
    slot = db.Column(db.String(8), nullable=False, default="any", server_default="any")
    workflow_mode = db.Column(db.String(10), nullable=False, default="standard", server_default="standard")
    execution_id = db.Column(db.Integer)
    spot_request_id = db.Column(db.String(64))
    note = db.Column(db.Text, nullable=False, default="", server_default="")
    is_abnormal = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    point_code = db.Column(db.String(30), nullable=False)
    point_name = db.Column(db.String(100), nullable=False)
    point_floor = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(100), nullable=False, default="")
    user = db.relationship(User)
    point = db.relationship(Point)
    execution = db.relationship(PatrolExecution, back_populates="inspection", foreign_keys=[execution_id])
    photos = db.relationship("InspectionPhoto", back_populates="inspection", lazy="select", cascade="all, delete-orphan")
    issue = db.relationship("InspectionIssue", back_populates="inspection", uselist=False, lazy="select")
    __table_args__ = (
        db.Index("patrol_one_required_inspection_per_slot", "point_id", "frequency", "period_key", "slot", unique=True,
                 sqlite_where=db.text("workflow_mode <> 'spot'"), postgresql_where=db.text("workflow_mode <> 'spot'")),
        db.ForeignKeyConstraint(["execution_id", "point_id", "frequency", "period_key", "slot"],
                                ["patrol_executions.id", "patrol_executions.point_id", "patrol_executions.frequency",
                                 "patrol_executions.period_key", "patrol_executions.slot"],
                                name="patrol_final_execution_slot"),
        db.CheckConstraint("(workflow_mode = 'standard' AND execution_id IS NULL AND spot_request_id IS NULL) OR "
                           "(workflow_mode = 'spot' AND category = 'general' AND execution_id IS NULL "
                           "AND spot_request_id IS NOT NULL AND spot_request_id <> '') OR "
                           "(workflow_mode = 'two_stage' AND category = 'general' AND execution_id IS NOT NULL "
                           "AND spot_request_id IS NULL)", name="patrol_inspection_workflow"),
        db.Index("patrol_spot_request_once", "spot_request_id", unique=True,
                 sqlite_where=db.text("spot_request_id IS NOT NULL"), postgresql_where=db.text("spot_request_id IS NOT NULL")),
        db.Index("patrol_execution_review_once", "execution_id", unique=True,
                 sqlite_where=db.text("execution_id IS NOT NULL"), postgresql_where=db.text("execution_id IS NOT NULL")),
        db.Index("patrol_recent_spot_at_point", "point_id", "created_at",
                 sqlite_where=db.text("workflow_mode = 'spot'"), postgresql_where=db.text("workflow_mode = 'spot'")),
    )


def protect_execution_link(connection):
    """A historical final cannot be reassigned, detached or retrofitted to a different first stage."""
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("""
            CREATE TRIGGER patrol_execution_link_fixed BEFORE UPDATE OF execution_id ON patrol_inspections
            WHEN NEW.execution_id IS NOT OLD.execution_id
            BEGIN SELECT RAISE(ABORT, 'Patrol execution link is immutable'); END
        """)
    elif connection.dialect.name == "postgresql":
        connection.exec_driver_sql("""
            CREATE OR REPLACE FUNCTION patrol_keep_execution_link() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Patrol execution link is immutable' USING ERRCODE = '23514'; END
            $$
        """)
        connection.exec_driver_sql("""
            CREATE TRIGGER patrol_execution_link_fixed BEFORE UPDATE OF execution_id ON patrol_inspections
            FOR EACH ROW WHEN (NEW.execution_id IS DISTINCT FROM OLD.execution_id)
            EXECUTE FUNCTION patrol_keep_execution_link()
        """)


@event.listens_for(Inspection.__table__, "after_create")
def install_execution_link_protection(_table, connection, **_):
    protect_execution_link(connection)


class InspectionPhoto(db.Model):
    __tablename__ = "patrol_inspection_photos"
    id = db.Column(db.Integer, primary_key=True)
    inspection_id = db.Column(db.Integer, db.ForeignKey("patrol_inspections.id"), nullable=False, index=True)
    data = db.deferred(db.Column(db.LargeBinary, nullable=False))
    mime_type = db.Column(db.String(40), nullable=False, default="image/jpeg", server_default="image/jpeg")
    size_bytes = db.Column(db.Integer, nullable=False)
    width = db.Column(db.Integer, nullable=False)
    height = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    inspection = db.relationship(Inspection, back_populates="photos")


class InspectionIssue(db.Model):
    __tablename__ = "patrol_inspection_issues"
    inspection_id = db.Column(db.Integer, db.ForeignKey("patrol_inspections.id"), primary_key=True, autoincrement=False)
    status = db.Column(db.String(10), nullable=False, default="open", server_default="open")
    opened_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"))
    resolved_by_name = db.Column(db.String(100), nullable=False, default="", server_default="")
    resolution_note = db.Column(db.Text, nullable=False, default="", server_default="")
    inspection = db.relationship(Inspection, back_populates="issue")
    events = db.relationship("IssueEvent", back_populates="issue", lazy="select",
                             order_by="IssueEvent.created_at, IssueEvent.id")
    __table_args__ = (
        db.CheckConstraint("status IN ('open', 'resolved')", name="patrol_issue_status"),
        db.CheckConstraint(
            "(status = 'open' AND resolved_at IS NULL AND resolved_by_id IS NULL "
            "AND resolved_by_name = '' AND resolution_note = '') OR "
            "(status = 'resolved' AND resolved_at IS NOT NULL AND resolved_by_id IS NOT NULL "
            "AND resolved_by_name <> '')", name="patrol_issue_resolution_fields"),
        db.Index("patrol_issue_status_opened", "status", "opened_at", "inspection_id"),
    )


class IssueEvent(db.Model):
    __tablename__ = "patrol_issue_events"
    id = db.Column(db.Integer, primary_key=True)
    inspection_id = db.Column(db.Integer, db.ForeignKey("patrol_inspection_issues.inspection_id"), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False)
    actor_name = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(20), nullable=False)
    note = db.Column(db.Text, nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    issue = db.relationship(InspectionIssue, back_populates="events")
    __table_args__ = (db.CheckConstraint("action IN ('resolved', 'reopened')", name="patrol_issue_event_action"),)


class SchemaVersion(db.Model):
    __tablename__ = "patrol_schema_versions"
    version = db.Column(db.Integer, primary_key=True)
    applied_at = db.Column(db.DateTime, nullable=False, default=utcnow, server_default=db.func.current_timestamp())


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


class RevokedSession(db.Model):
    __tablename__ = "patrol_revoked_sessions"
    token_hash = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False, index=True)
    auth_version = db.Column(db.Integer, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=False, default=utcnow)
