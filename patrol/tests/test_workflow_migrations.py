"""Real v6 data and two-stage constraints on SQLite and the opt-in local PostgreSQL cluster."""
from datetime import date, datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import os
from threading import Barrier
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import migrations
from general_workflow import new_execution
from migrations import LATEST_VERSION, upgrade_schema
from models import DeviceBinding, Inspection, PatrolExecution, Point, PointSchedule, RevokedSession, User
from test_migrations import engine as sqlite_store, version_two, version_three, version_four, version_five
from test_postgres import engine as postgres_store


@pytest.fixture(params=["sqlite", "postgres"])
def engine(request):
    if request.param == "postgres" and not os.environ.get("PATROL_TEST_POSTGRES_URL"):
        pytest.skip("Set PATROL_TEST_POSTGRES_URL for the disposable local PostgreSQL database.")
    return request.getfixturevalue("postgres_store" if request.param == "postgres" else "sqlite_store")


@pytest.fixture
def v6(engine, version_five):
    # The original schema contains preserved devices, closed issues, photos and non-patrol tables.
    tables = version_five.tables
    with engine.begin() as conn:
        RevokedSession.__table__.create(conn)
        conn.execute(tables["patrol_schema_versions"].insert().values(version=6))
        conn.execute(tables["patrol_points"].update().where(tables["patrol_points"].c.id == 23).values(
            category="general", active=True, deleted_at=None))
        conn.execute(tables["patrol_point_schedules"].update().values(category="general"))
        conn.execute(tables["patrol_inspections"].update().values(category="general"))
        # A deployed point without historical snapshots still needs a pre-cutover baseline.
        for point_id, start in ((24, date(2020, 1, 1)), (25, date.today() + timedelta(days=30))):
            conn.execute(tables["patrol_points"].insert().values(id=point_id, code=f"1F-G{point_id}",
                name="舊總務點", floor=1, category="general", frequency="daily2", active=True,
                created_at=datetime(2020, 1, 1), qr_token=f"existing-{point_id}", schedule_start=start))
        if conn.dialect.name == "postgresql":
            # The frozen fixtures insert explicit IDs; emulate the real application's sequences.
            for name in ("patrol_points", "patrol_inspections", "patrol_point_schedules"):
                conn.exec_driver_sql(f"SELECT setval(pg_get_serial_sequence('{name}', 'id'), "
                                     f"(SELECT MAX(id) FROM {name}))")


def test_v6_rollout_keeps_existing_finals_and_history_changes_only_from_taipei_cutover(engine, v6):
    assert upgrade_schema(engine) == LATEST_VERSION
    with Session(engine) as session:
        final = session.get(Inspection, 51)
        assert (final.category, final.workflow_mode, final.execution, final.spot_request_id) == ("general", "standard", None, None)
        assert final.issue.status == "resolved"
        assert final.photos and final.note == "Original abnormal note"
        assert not session.scalars(select(PatrolExecution)).all()
        for pid in (23, 24, 25):
            point = session.get(Point, pid)
            assert point.workflow_mode == "spot"
            spot = point.schedules[-1]
            assert spot.workflow_mode == "spot" and spot.workflow_changed_at
            assert spot.effective_date == max(point.schedule_start, spot.workflow_changed_at.replace(
                tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Taipei")).date())
            assert all(row.workflow_mode == "standard" and row.workflow_changed_at is None for row in point.schedules[:-1])
        assert session.get(Point, 24).schedules[0].effective_date == date(2020, 1, 1)
        assert session.get(Point, 24).schedules[0].workflow_mode == "standard"
        for row in (session.get(Point, 24), session.get(Point, 24).schedules[-1]):
            with pytest.raises(IntegrityError), session.begin_nested():
                row.category = "safety"
                session.flush()
        before = session.execute(select(PointSchedule.id, PointSchedule.workflow_changed_at).order_by(PointSchedule.id)).all()
    assert upgrade_schema(engine) == LATEST_VERSION
    with Session(engine) as session:
        assert before == session.execute(select(PointSchedule.id, PointSchedule.workflow_changed_at).order_by(PointSchedule.id)).all()


def test_v6_to_v7_rollback_leaves_general_points_and_history_untouched(engine, v6, monkeypatch):
    def fail(conn):
        assert conn.exec_driver_sql("SELECT workflow_mode FROM patrol_points WHERE id=23").scalar_one() == "spot"
        raise RuntimeError("test rollback after cutover")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="test rollback"):
        upgrade_schema(engine)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT MAX(version) FROM patrol_schema_versions").scalar_one() == 6
        assert conn.exec_driver_sql("SELECT COUNT(*) FROM patrol_point_schedules").scalar_one() == 2
        assert not migrations.inspect(conn).has_table("patrol_executions")
        assert "workflow_mode" not in {col["name"] for col in migrations.inspect(conn).get_columns("patrol_points")}


def test_execution_and_final_match_same_point_period_slot_and_cannot_be_detached(engine, v6):
    upgrade_schema(engine)
    with Session(engine) as session:
        person = session.get(User, 17)
        person.role, person.patrol_category = "executor", "general"
        point = session.get(Point, 24)
        point.workflow_mode = "two_stage"
        binding = session.get(DeviceBinding, 41)
        stamp = datetime(2026, 11, 16, 10, tzinfo=ZoneInfo("Asia/Taipei"))
        first = new_execution(point, person, binding, "2026-11-16", "am", stamp)
        session.add(first)
        session.commit()
        assert first.created_at == datetime(2026, 11, 16, 2)
        assert first.inspection is None and first.user_name == person.display_name
        assert not session.scalars(select(Inspection).where(Inspection.point_id == point.id)).all()
        with pytest.raises(IntegrityError), session.begin_nested():
            session.add(new_execution(point, person, binding, "2026-11-16", "am", stamp))
            session.flush()
        values = dict(user_id=18, point_id=24, frequency="daily2", period_key="2026-11-16", slot="am",
                      point_code=point.code, point_name=point.name, point_floor=point.floor, category="general",
                      workflow_mode="two_stage", execution_id=first.id, created_at=datetime(2026, 11, 16, 3))
        for change in ({"execution_id": None}, {"slot": "pm"}, {"period_key": "2026-11-17"},
                       {"point_id": 23}, {"category": "safety"}, {"workflow_mode": "standard"}):
            with pytest.raises(IntegrityError), session.begin_nested():
                session.add(Inspection(**(values | change)))
                session.flush()
        final = Inspection(**values)
        session.add(final)
        session.commit()
        assert first.inspection.id == final.id and final.execution.id == first.id
        with pytest.raises(IntegrityError), session.begin_nested():
            final.execution_id, final.workflow_mode = None, "standard"
            session.flush()
        with pytest.raises(IntegrityError), session.begin_nested():
            session.delete(first)
            session.flush()
        assert final.execution.id == first.id


def test_spot_allows_successive_submissions_but_rejects_duplicate_request_and_missing_id(engine, v6):
    upgrade_schema(engine)
    base = dict(user_id=17, point_id=23, frequency="daily", period_key="2026-11-03", slot="any",
                point_code="1F-A01", point_name="舊總務點", point_floor=1, category="general", workflow_mode="spot")
    with Session(engine) as session:
        for key in ("request-a", "request-b"):
            session.add(Inspection(**base, spot_request_id=key))
        session.commit()
        assert len(session.scalars(select(Inspection).where(Inspection.workflow_mode == "spot")).all()) == 2
        for values in (dict(spot_request_id="request-a"), dict(spot_request_id=""), dict(spot_request_id=None),
                       dict(spot_request_id="x", category="safety"), dict(spot_request_id=None, workflow_mode="standard")):
            with pytest.raises(IntegrityError), session.begin_nested():
                session.add(Inspection(**(base | values)))
                session.flush()


def test_simultaneous_first_stages_reviews_and_same_spot_request_each_persist_once(engine, v6):
    upgrade_schema(engine)
    base = dict(point_id=24, frequency="daily2", period_key="2026-11-16", slot="am", point_code="1F-G24",
                point_name="巡檢點", point_floor=1, category="general", user_name="測試巡檢員")

    def race(table, values):
        barrier = Barrier(2)
        def write():
            with engine.connect() as connection:
                barrier.wait(timeout=10)
                try:
                    row_id = connection.execute(table.insert().values(**values).returning(table.c.id)).scalar_one()
                    connection.commit()
                    return row_id
                except IntegrityError as error:
                    if connection.dialect.name == "postgresql":
                        assert error.orig.sqlstate == "23505"
                    else:
                        assert error.orig.sqlite_errorname == "SQLITE_CONSTRAINT_UNIQUE"
                    return None
        with ThreadPoolExecutor(max_workers=2) as workers:
            jobs = [workers.submit(write) for _ in range(2)]
            results = [job.result(timeout=20) for job in jobs]
        assert results.count(None) == 1
        return next(value for value in results if value is not None)

    execution = race(PatrolExecution.__table__, base | dict(user_id=17, binding_id=41))
    final = race(Inspection.__table__, base | dict(user_id=18, workflow_mode="two_stage", execution_id=execution))
    spot = race(Inspection.__table__, base | dict(user_id=18, workflow_mode="spot", spot_request_id="signed-request"))
    with Session(engine) as session:
        assert session.get(Inspection, final).execution.id == execution
        assert session.get(Inspection, spot).execution is None
