from datetime import datetime, timezone
from pathlib import Path
import uuid

from sqlalchemy import (create_engine, event, MetaData, Table, Column, String, Integer,
                        Boolean, JSON, Text, UniqueConstraint)


def uid():
    return uuid.uuid4().hex


def now():
    return datetime.now(timezone.utc).isoformat()


metadata = MetaData()
images = Table("labelcheck_images", metadata,
    Column("id", String(32), primary_key=True), Column("created_at", String(40), nullable=False),
    Column("filename", String(255)), Column("sha256", String(64), index=True),
    Column("width", Integer), Column("height", Integer))
templates = Table("labelcheck_templates", metadata,
    Column("id", String(32), primary_key=True), Column("family_id", String(32), nullable=False, index=True),
    Column("version", Integer, nullable=False), Column("active", Boolean, nullable=False),
    Column("name", String(200), nullable=False), Column("image_id", String(32), nullable=False),
    Column("fields", JSON, nullable=False), Column("rules", JSON, nullable=False),
    Column("reference_dates", JSON, nullable=False), Column("approved_by", String(100), nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint("family_id", "version", name="uq_labelcheck_template_version"))
jobs = Table("labelcheck_jobs", metadata,
    Column("id", String(32), primary_key=True), Column("image_id", String(32), nullable=False),
    Column("kind", String(20)), Column("template_id", String(32)), Column("batch_date", String(10)),
    Column("state", String(20), index=True), Column("result", JSON), Column("error", Text),
    Column("created_at", String(40), nullable=False))
inspections = Table("labelcheck_inspections", metadata,
    Column("id", String(32), primary_key=True), Column("image_id", String(32), nullable=False),
    Column("template_id", String(32), nullable=False, index=True), Column("template_snapshot", JSON, nullable=False),
    Column("status", String(20), nullable=False, index=True), Column("result", JSON, nullable=False),
    Column("ocr", JSON, nullable=False), Column("created_at", String(40), nullable=False, index=True))
reviews = Table("labelcheck_reviews", metadata,
    Column("id", String(32), primary_key=True), Column("inspection_id", String(32), nullable=False, index=True),
    Column("decision", String(20), nullable=False), Column("reviewer", String(100), nullable=False),
    Column("note", Text, nullable=False), Column("created_at", String(40), nullable=False))


def open_database(url, data_dir):
    url = url or "sqlite:///" + str(Path(data_dir) / "labelcheck.sqlite3")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    engine = create_engine(url, pool_pre_ping=True, **({"connect_args": {"timeout": 20}} if url.startswith("sqlite:") else {"pool_size": 3, "max_overflow": 2, "pool_timeout": 10}))
    if url.startswith("sqlite:"):
        @event.listens_for(engine, "connect")
        def set_pragmas(dbapi, _record):
            dbapi.execute("PRAGMA journal_mode=WAL")
            dbapi.execute("PRAGMA foreign_keys=ON")
    metadata.create_all(engine)
    return engine
