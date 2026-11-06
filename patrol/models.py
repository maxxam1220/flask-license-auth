"""Patrol data. All table names are isolated from other applications."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import secrets
import sqlite3

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()

POINT_WORKFLOW_RULE = "workflow_mode = 'standard' OR (category = 'general' AND workflow_mode IN ('spot','two_stage'))"
EXECUTION_SLOT_RULE = ("(frequency IN ('daily','weekly','monthly','irregular') AND slot = 'any') OR "
                       "(frequency = 'daily2' AND slot IN ('am','pm'))")
ENGINEERING_TITLE_RULE = ("NOT engineering_inspector_title OR (role = 'inspector' AND patrol_category IS NOT NULL "
                          "AND patrol_category = 'general' AND NOT general_manager_title)")
TAIPEI = ZoneInfo("Asia/Taipei")


@event.listens_for(Engine, "connect")
def configure_sqlite(connection, _):
    if isinstance(connection, sqlite3.Connection):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def inspection_personal_day(context):
    values = context.get_current_parameters()
    if values.get("workflow_mode") in ("spot", "two_stage"):
        instant = values.get("created_at") or utcnow()
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        return instant.astimezone(TAIPEI).date()
    return None


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
    # Display title for a general inspector. Access checks use role and patrol_category.
    general_manager_title = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    engineering_inspector_title = db.Column(db.Boolean, db.CheckConstraint(
        ENGINEERING_TITLE_RULE, name="patrol_engineering_inspector_title"),
        nullable=False, default=False, server_default=db.false())
    ui_language = db.Column(db.String(10), db.CheckConstraint(
        "ui_language IN ('zh-Hant', 'id', 'vi')", name="patrol_user_ui_language"),
        nullable=False, default="zh-Hant", server_default="zh-Hant")
    # Presentation only: applied solely to executors, never an access permission.
    simple_executor_ui = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
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
    legacy_unscheduled = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
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
    inspections = db.relationship("Inspection", back_populates="execution", order_by="Inspection.created_at, Inspection.id",
                                  foreign_keys="Inspection.execution_id", viewonly=True)
    offline_submission = db.relationship("OfflineSubmission", back_populates="execution", uselist=False, lazy="selectin")
    __table_args__ = (
        db.CheckConstraint("category = 'general'", name="patrol_execution_general"),
        db.CheckConstraint(EXECUTION_SLOT_RULE, name="patrol_execution_valid_slot"),
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
    personal_day = db.Column(db.Date, default=inspection_personal_day)
    legacy_slot_repeat = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    legacy_unscheduled = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    executor_visit = db.Column(db.Boolean, db.CheckConstraint(
        "NOT executor_visit OR (workflow_mode = 'spot' AND category = 'general' AND frequency = 'irregular' "
        "AND slot = 'any' AND note = '' AND NOT is_abnormal)", name="patrol_executor_visit_fields"),
        nullable=False, default=False, server_default=db.false())
    note = db.Column(db.Text, nullable=False, default="", server_default="")
    is_abnormal = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    point_code = db.Column(db.String(30), nullable=False)
    point_name = db.Column(db.String(100), nullable=False)
    point_floor = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(100), nullable=False, default="")
    user = db.relationship(User)
    point = db.relationship(Point)
    execution = db.relationship(PatrolExecution, back_populates="inspections", foreign_keys=[execution_id])
    photos = db.relationship("InspectionPhoto", back_populates="inspection", lazy="select", cascade="all, delete-orphan")
    issue = db.relationship("InspectionIssue", back_populates="inspection", uselist=False, lazy="select")
    offline_submission = db.relationship("OfflineSubmission", back_populates="inspection", uselist=False, lazy="selectin")
    __table_args__ = (
        db.Index("patrol_one_standard_per_slot", "point_id", "frequency", "period_key", "slot", unique=True,
                 sqlite_where=db.text("workflow_mode = 'standard'"), postgresql_where=db.text("workflow_mode = 'standard'")),
        # An all-day entry consumes both halves if the point is reconfigured during that day.
        db.Index("patrol_person_am_once", "point_id", "user_id", "personal_day", unique=True,
                 sqlite_where=db.text("personal_day IS NOT NULL AND NOT legacy_slot_repeat AND slot <> 'pm'"),
                 postgresql_where=db.text("personal_day IS NOT NULL AND NOT legacy_slot_repeat AND slot <> 'pm'")),
        db.Index("patrol_person_pm_once", "point_id", "user_id", "personal_day", unique=True,
                 sqlite_where=db.text("personal_day IS NOT NULL AND NOT legacy_slot_repeat AND slot <> 'am'"),
                 postgresql_where=db.text("personal_day IS NOT NULL AND NOT legacy_slot_repeat AND slot <> 'am'")),
        db.ForeignKeyConstraint(["execution_id", "point_id", "frequency", "period_key", "slot"],
                                ["patrol_executions.id", "patrol_executions.point_id", "patrol_executions.frequency",
                                 "patrol_executions.period_key", "patrol_executions.slot"],
                                name="patrol_final_execution_slot"),
        db.CheckConstraint("(workflow_mode = 'standard' AND execution_id IS NULL AND spot_request_id IS NULL) OR "
                           "(workflow_mode = 'spot' AND category = 'general' AND execution_id IS NULL "
                           "AND spot_request_id IS NOT NULL AND spot_request_id <> '') OR "
                           "(workflow_mode = 'two_stage' AND category = 'general' AND execution_id IS NOT NULL "
                           "AND spot_request_id IS NULL)", name="patrol_inspection_workflow"),
        db.CheckConstraint("(workflow_mode = 'standard' AND personal_day IS NULL AND NOT legacy_slot_repeat) OR "
                           "(workflow_mode IN ('spot','two_stage') AND personal_day IS NOT NULL AND slot IN ('any','am','pm'))",
                           name="patrol_personal_day_required"),
        db.Index("patrol_spot_request_once", "spot_request_id", unique=True,
                 sqlite_where=db.text("spot_request_id IS NOT NULL"), postgresql_where=db.text("spot_request_id IS NOT NULL")),
        db.Index("patrol_execution_reviews", "execution_id",
                 sqlite_where=db.text("execution_id IS NOT NULL"), postgresql_where=db.text("execution_id IS NOT NULL")),
    )


class OfflineSubmission(db.Model):
    """One accepted offline visit, committed atomically with its original receipt.

    Pending/rejected phone drafts never create rows here. The server receipt
    timestamp is separate from the phone's claimed observation timestamp; old
    online receipts retain their original schema and have no submission row.
    """
    __tablename__ = "patrol_offline_submissions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False)
    binding_id = db.Column(db.Integer, db.ForeignKey("patrol_device_bindings.id"), nullable=False)
    client_id = db.Column(db.String(36), nullable=False)
    payload_hash = db.Column(db.String(64), nullable=False)
    observed_at = db.Column(db.DateTime, nullable=False)
    received_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    inspection_id = db.Column(db.Integer, db.ForeignKey("patrol_inspections.id"))
    execution_id = db.Column(db.Integer, db.ForeignKey("patrol_executions.id"))
    inspection = db.relationship(Inspection, back_populates="offline_submission")
    execution = db.relationship(PatrolExecution, back_populates="offline_submission")
    __table_args__ = (
        db.UniqueConstraint("user_id", "client_id", name="patrol_offline_client_once"),
        db.UniqueConstraint("inspection_id", name="patrol_offline_inspection_once"),
        db.UniqueConstraint("execution_id", name="patrol_offline_execution_once"),
        db.CheckConstraint("(inspection_id IS NOT NULL AND execution_id IS NULL) OR "
                           "(inspection_id IS NULL AND execution_id IS NOT NULL)", name="patrol_offline_one_result"),
        db.CheckConstraint("length(client_id) = 36", name="patrol_offline_client_length"),
        db.CheckConstraint("length(payload_hash) = 64", name="patrol_offline_payload_hash_length"),
        db.Index("patrol_offline_user_received", "user_id", "received_at", "id"),
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


def protect_legacy_exemptions(connection):
    """Only the v7 migration may exempt an existing row from the new daily limit."""
    if connection.dialect.name == "sqlite":
        for operation, name in (("INSERT", "insert"), ("UPDATE OF legacy_slot_repeat", "update")):
            condition = "NEW.legacy_slot_repeat" if name == "insert" else "NEW.legacy_slot_repeat IS NOT OLD.legacy_slot_repeat"
            connection.exec_driver_sql(f"""
                CREATE TRIGGER patrol_protect_legacy_{name} BEFORE {operation} ON patrol_inspections
                WHEN {condition} BEGIN SELECT RAISE(ABORT, 'Legacy exemption is immutable'); END
            """)
    elif connection.dialect.name == "postgresql":
        connection.exec_driver_sql("""
            CREATE OR REPLACE FUNCTION patrol_keep_legacy_exemption() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF (TG_OP = 'INSERT' AND NEW.legacy_slot_repeat) OR
                   (TG_OP = 'UPDATE' AND NEW.legacy_slot_repeat IS DISTINCT FROM OLD.legacy_slot_repeat) THEN
                    RAISE EXCEPTION 'Legacy exemption is immutable' USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END
            $$
        """)
        connection.exec_driver_sql("""
            CREATE TRIGGER patrol_protect_legacy_exemption BEFORE INSERT OR UPDATE OF legacy_slot_repeat ON patrol_inspections
            FOR EACH ROW EXECUTE FUNCTION patrol_keep_legacy_exemption()
        """)


@event.listens_for(Inspection.__table__, "after_create")
def install_execution_link_protection(_table, connection, **_):
    protect_execution_link(connection)
    protect_legacy_exemptions(connection)


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


class LoginEvent(db.Model):
    __tablename__ = "patrol_login_events"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    client_type = db.Column(db.String(10), nullable=False)
    browser = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    __table_args__ = (
        db.CheckConstraint("client_type IN ('mobile','tablet','desktop','unknown')", name="patrol_login_event_client_type"),
        db.Index("patrol_login_events_time", "created_at", "id"),
        db.Index("patrol_login_events_user_time", "user_id", "created_at", "id"),
    )


class RevokedSession(db.Model):
    __tablename__ = "patrol_revoked_sessions"
    token_hash = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("patrol_users.id"), nullable=False, index=True)
    auth_version = db.Column(db.Integer, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=False, default=utcnow)
