"""Schema 16 adds one evidence table without rewriting historical patrol data."""
from datetime import date, datetime

import pytest
from sqlalchemy import MetaData, event, func, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import migrations
from migrations import LATEST_VERSION, SchemaMigrationError, upgrade_schema
from models import (Inspection, InspectionIssue, InspectionPhoto, IssueEvent, IssueEventPhoto,
                    Point, SchemaVersion, User, db)
from test_migrations import snapshot
from test_offline_migrations import engine, postgres_store, sqlite_store


NOW = datetime(2026, 11, 9, 4)


@pytest.fixture
def v15(engine):
    with engine.begin() as connection:
        db.metadata.create_all(connection, tables=[table for table in db.metadata.sorted_tables
            if table.name.startswith("patrol_") and table.name != IssueEventPhoto.__tablename__])
        connection.execute(User.__table__.insert().values(id=17, username="old-admin", display_name="Old admin",
            password_hash="untouched", role="admin", active=True, must_change_password=False, auth_version=1,
            created_at=NOW))
        connection.execute(Point.__table__.insert().values(id=23, code="1F-S001", name="Original point", floor=1,
            category="safety", inspection_team="general", frequency="daily", workflow_mode="standard", active=True,
            qr_token="preserved-qr", schedule_start=date(2026, 1, 1), created_at=NOW))
        connection.execute(Inspection.__table__.insert().values(id=51, user_id=17, point_id=23, created_at=NOW,
            period_key="2026-11-09", frequency="daily", category="safety", slot="any", workflow_mode="standard",
            point_code="1F-S001", point_name="Original point", point_floor=1, user_name="Old admin",
            note="Original abnormal note", is_abnormal=True))
        connection.execute(InspectionPhoto.__table__.insert().values(id=61, inspection_id=51, data=b"original-evidence",
            size_bytes=17, width=10, height=20, created_at=NOW))
        connection.execute(InspectionIssue.__table__.insert().values(inspection_id=51, status="resolved", opened_at=NOW,
            resolved_at=NOW, resolved_by_id=17, resolved_by_name="Old admin", resolution_note="Existing repair"))
        connection.execute(IssueEvent.__table__.insert().values(id=71, inspection_id=51, actor_id=17,
            actor_name="Old admin", action="resolved", note="Existing repair", created_at=NOW))
        connection.execute(SchemaVersion.__table__.insert().values(version=15))
        connection.exec_driver_sql("CREATE TABLE unrelated_repair (id INTEGER PRIMARY KEY, event_id INTEGER "
                                   "REFERENCES patrol_issue_events(id), note VARCHAR(40))")
        connection.exec_driver_sql("INSERT INTO unrelated_repair VALUES (1, 71, 'Preserve foreign evidence link')")
        metadata = MetaData()
        metadata.reflect(connection)
        return metadata


def test_v16_only_adds_evidence_table_and_preserves_all_prior_data(engine, v15):
    with engine.connect() as connection:
        before = snapshot(connection, v15)
        old_tables = set(inspect(connection).get_table_names())
    statements = []
    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert upgrade_schema(engine) == LATEST_VERSION
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not any(s.lstrip().upper().startswith(("DROP ", "ALTER ", "DELETE ", "UPDATE ")) for s in statements)
    with engine.begin() as connection:
        after = snapshot(connection, v15)
        assert after.pop("patrol_schema_versions")[:-1] == before.pop("patrol_schema_versions")
        assert after == before
        assert set(inspect(connection).get_table_names()) == old_tables | {IssueEventPhoto.__tablename__}
        assert connection.scalar(select(func.count(IssueEventPhoto.id))) == 0
        # A draining old worker can still append its existing event shape.
        connection.execute(v15.tables[IssueEvent.__tablename__].insert().values(id=72, inspection_id=51, actor_id=17,
            actor_name="Old admin", action="reopened", note="Old worker still valid", created_at=NOW))
    assert upgrade_schema(engine) == LATEST_VERSION
    with Session(engine) as session:
        assert session.get(IssueEvent, 71).photos == []
        assert session.get(IssueEvent, 72).photos == []
        assert session.get(Inspection, 51).photos[0].data == b"original-evidence"


def test_v16_relationship_order_deferred_binary_and_foreign_keys(engine, v15):
    upgrade_schema(engine)
    with Session(engine) as session:
        resolved = session.get(IssueEvent, 71)
        for value in (b"first", b"second"):
            resolved.photos.append(IssueEventPhoto(data=value, size_bytes=len(value), width=20, height=10, created_at=NOW))
        session.commit()
        session.expire_all()
        photos = session.get(IssueEvent, 71).photos
        assert [photo.id for photo in photos] == sorted(photo.id for photo in photos)
        assert all("data" in inspect(photo).unloaded for photo in photos)
        assert [photo.data for photo in photos] == [b"first", b"second"]
        assert all(photo.event is resolved for photo in photos)
    with engine.begin() as connection:
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(IssueEventPhoto.__table__.insert().values(event_id=99999, data=b"orphan", size_bytes=6,
                width=1, height=1, created_at=NOW))
        with pytest.raises(IntegrityError), connection.begin_nested():
            connection.execute(IssueEventPhoto.__table__.insert().values(event_id=71, data=None, size_bytes=1,
                width=1, height=1, created_at=NOW))
        assert connection.scalar(select(func.count(IssueEventPhoto.id))) == 2


def test_v16_failure_rolls_back_table_indexes_version_and_all_existing_data(engine, v15, monkeypatch):
    with engine.connect() as connection:
        before = snapshot(connection, v15)
        tables = inspect(connection).get_table_names()
    original = migrations._validate_current
    def fail(connection):
        original(connection)
        raise RuntimeError("Injected evidence migration failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="Injected evidence"):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert inspect(connection).get_table_names() == tables
        assert snapshot(connection, v15) == before


@pytest.mark.parametrize("defect", ["missing_index", "nullable_data", "wrong_mime_default", "missing_event_fk"])
def test_v16_partial_or_invalid_preexisting_table_refuses_upgrade(engine, v15, defect):
    metadata = MetaData()
    with engine.begin() as connection:
        metadata.reflect(connection)
        photos = IssueEventPhoto.__table__.to_metadata(metadata)
        if defect == "nullable_data":
            photos.c.data.nullable = True
        elif defect == "wrong_mime_default":
            photos.c.mime_type.server_default = None
        elif defect == "missing_event_fk":
            photos.constraints.remove(next(c for c in photos.constraints if getattr(c, "elements", None)))
        photos.create(connection)
        if defect == "missing_index":
            connection.exec_driver_sql("DROP INDEX ix_patrol_issue_event_photos_event_id")
    with pytest.raises(SchemaMigrationError):
        upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(select(func.max(SchemaVersion.version))) == 15
        assert connection.scalar(select(func.count(IssueEvent.id))) == 1


def test_v16_migration_replay_preserves_new_resolution_evidence(engine, v15):
    upgrade_schema(engine)
    with engine.begin() as connection:
        connection.execute(IssueEventPhoto.__table__.insert().values(event_id=71, data=b"new-evidence", size_bytes=12,
            width=4, height=3, created_at=NOW))
        before = connection.execute(select(IssueEventPhoto.__table__)).all()
    upgrade_schema(engine)
    with engine.connect() as connection:
        assert connection.execute(select(IssueEventPhoto.__table__)).all() == before
