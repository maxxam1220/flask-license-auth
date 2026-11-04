"""Real v6 data and two-stage constraints on SQLite and the opt-in local PostgreSQL cluster."""
from datetime import date, datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import os
from threading import Barrier
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import CheckConstraint, MetaData, Table, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import migrations
import general_workflow
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
            assert spot.frequency == "irregular" and not spot.legacy_unscheduled
            assert all((row.workflow_mode == "standard" and row.workflow_changed_at is None) or
                       (row.workflow_mode == "spot" and row.legacy_unscheduled) for row in point.schedules[:-1])
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
        point.frequency = "daily2"
        binding = session.get(DeviceBinding, 41)
        stamp = datetime(2026, 11, 16, 10, tzinfo=ZoneInfo("Asia/Taipei"))
        first = new_execution(point, person, binding, "2026-11-16", "am", stamp)
        session.add(first)
        session.commit()
        assert first.created_at == datetime(2026, 11, 16, 2)
        assert first.inspections == [] and first.user_name == person.display_name
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
        assert [review.id for review in first.inspections] == [final.id] and final.execution.id == first.id
        with pytest.raises(IntegrityError), session.begin_nested():
            final.execution_id, final.workflow_mode = None, "standard"
            session.flush()
        with pytest.raises(IntegrityError), session.begin_nested():
            session.delete(first)
            session.flush()
        assert final.execution.id == first.id


def test_spot_allows_different_people_but_rejects_duplicate_request_and_missing_id(engine, v6):
    upgrade_schema(engine)
    base = dict(user_id=17, point_id=23, frequency="daily", period_key="2026-11-03", slot="any",
                point_code="1F-A01", point_name="舊總務點", point_floor=1, category="general", workflow_mode="spot")
    with Session(engine) as session:
        for user_id, key in ((17, "request-a"), (18, "request-b")):
            session.add(Inspection(**(base | {"user_id": user_id, "spot_request_id": key})))
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
    spot = race(Inspection.__table__, base | dict(user_id=19, workflow_mode="spot", spot_request_id="signed-request"))
    with Session(engine) as session:
        assert session.get(Inspection, final).execution.id == execution
        assert session.get(Inspection, spot).execution is None


@pytest.fixture
def v7(engine, v6):
    """Materialize the deployed v7 shape, including its original per-slot and per-review locks."""
    with engine.connect() as conn:
        if conn.dialect.name == "sqlite":
            conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
            conn.commit()
            conn.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            metadata = MetaData()
            for name in ("patrol_users", "patrol_points", "patrol_device_bindings"):
                Table(name, metadata, autoload_with=conn)
            first = PatrolExecution.__table__.to_metadata(metadata)
            first.constraints.remove(next(c for c in first.constraints if c.name == "patrol_execution_valid_slot"))
            first.append_constraint(CheckConstraint("(frequency IN ('daily','weekly') AND slot = 'any') OR "
                                                    "(frequency = 'daily2' AND slot IN ('am','pm'))", name="patrol_execution_valid_slot"))
            first.create(conn)
            migrations._upgrade_v6_to_v7(conn)
            conn.exec_driver_sql("INSERT INTO patrol_schema_versions(version) VALUES(7)")
            old = Table("patrol_inspections", metadata, autoload_with=conn)
            assert "personal_day" not in old.c
            # Same person, multiple old spot tickets, with microseconds just before local midnight.
            samples = ((101, 18, "am", datetime(2026, 3, 3, 1)), (102, 18, "any", datetime(2026, 3, 3, 8)),
                       (103, 18, "any", datetime(2026, 3, 3, 15, 59, 59, 999999)),
                       (104, 18, "any", datetime(2026, 3, 3, 16)), (105, 19, "any", datetime(2026, 3, 3, 8)))
            for row_id, user_id, slot, when in samples:
                conn.execute(old.insert().values(id=row_id, point_id=23, user_id=user_id, created_at=when, period_key="2026-03-02",
                    category="general", frequency="daily2" if slot == "am" else "weekly", slot=slot, workflow_mode="spot",
                    spot_request_id=f"archived-ticket-{row_id}", point_code="1F-G23", point_name="歷史點", point_floor=1,
                    user_name="舊巡檢員", note=f"old-note-{row_id}", is_abnormal=False))
            if conn.dialect.name == "postgresql":
                conn.exec_driver_sql("SELECT setval(pg_get_serial_sequence('patrol_inspections','id'),105)")
            conn.commit()
        finally:
            conn.rollback()
            if conn.dialect.name == "sqlite":
                conn.exec_driver_sql("PRAGMA foreign_keys=ON")
                conn.commit()


def test_v8_keeps_all_legacy_spot_tickets_while_enforcing_personal_taipei_days(engine, v7, monkeypatch):
    upgrade_schema(engine)
    with Session(engine) as session:
        rows = session.scalars(select(Inspection).where(Inspection.id >= 101).order_by(Inspection.id)).all()
        assert [r.note for r in rows] == [f"old-note-{i}" for i in range(101, 106)]
        assert all(r.legacy_unscheduled and r.spot_request_id == f"archived-ticket-{r.id}" for r in rows)
        assert [(r.personal_day, r.legacy_slot_repeat) for r in rows] == [
            (date(2026, 3, 3), True), (date(2026, 3, 3), False), (date(2026, 3, 3), True),
            (date(2026, 3, 4), False), (date(2026, 3, 3), False)]
        monkeypatch.setattr(general_workflow, "db", SimpleNamespace(session=session))
        point, user = session.get(Point, 23), session.get(User, 18)
        for slot, expected in (("any", 101), ("am", 101), ("pm", 102)):
            assert general_workflow.personal_inspection_in_slot(point, user, date(2026, 3, 3), slot).id == expected
        assert general_workflow.personal_inspection_in_slot(point, user, date(2026, 3, 5), "any") is None
        standard = session.get(Inspection, 51)
        assert standard.personal_day is None and not standard.legacy_unscheduled
        assert standard.photos and standard.issue.status == "resolved"
        unit = dict(point_id=23, user_id=18, workflow_mode="spot", frequency="daily", period_key="2026-03-03",
                    personal_day=date(2026, 3, 3), category="general", point_floor=1, point_code="1F-G23", point_name="測試點")
        for slot in ("am", "pm", "any"):
            with pytest.raises(IntegrityError), session.begin_nested():
                session.add(Inspection(**unit, slot=slot, spot_request_id=f"new-{slot}"))
                session.flush()
        with pytest.raises(IntegrityError), session.begin_nested():
            session.add(Inspection(**unit, slot="any", spot_request_id="override", legacy_slot_repeat=True))
            session.flush()
        with pytest.raises(IntegrityError), session.begin_nested():
            rows[1].legacy_slot_repeat = True
            session.flush()
        assert [(s.frequency, s.legacy_unscheduled) for s in session.get(Point, 23).schedules if s.workflow_mode == "spot"] == [
            ("daily", True), ("irregular", False)]
    assert upgrade_schema(engine) == LATEST_VERSION


def test_v8_multiple_inspectors_share_execution_and_can_revisit_next_taipei_day(engine, v7):
    upgrade_schema(engine)
    base = dict(point_id=24, frequency="monthly", period_key="2026-03-01", slot="any", point_code="1F-G24",
                point_name="月巡點", point_floor=1, category="general", user_name="測試巡檢員")
    with Session(engine) as session:
        one = PatrolExecution(**base, user_id=17, binding_id=41)
        session.add(one)
        session.flush()
        final = base | dict(workflow_mode="two_stage", execution_id=one.id)
        for user_id, day in ((18, 3), (19, 3), (18, 4)):
            session.add(Inspection(**final, user_id=user_id, created_at=datetime(2026, 3, day, 3)))
        session.commit()
        assert [(r.user_id, r.personal_day.day) for r in one.inspections] == [(18, 3), (19, 3), (18, 4)]
        with pytest.raises(IntegrityError), session.begin_nested():
            session.add(Inspection(**final, user_id=18, created_at=datetime(2026, 3, 3, 5)))
            session.flush()
        with pytest.raises(IntegrityError), session.begin_nested():
            session.delete(one)
            session.flush()
        session.add(PatrolExecution(**(base | {"frequency": "irregular", "period_key": "2026-03-03"}),
                                    user_id=17, binding_id=41))
        session.commit()


def test_v8_failure_rolls_back_general_frequency_old_review_limit_and_cutover_history(engine, v7, monkeypatch):
    before = {i["name"] for i in inspect(engine).get_indexes("patrol_inspections")}
    def fail(conn):
        assert conn.exec_driver_sql("SELECT COUNT(*) FROM patrol_inspections WHERE legacy_slot_repeat=true").scalar_one() == 2
        raise RuntimeError("simulated failure")
    monkeypatch.setattr(migrations, "_validate_current", fail)
    with pytest.raises(RuntimeError, match="simulated failure"):
        upgrade_schema(engine)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT MAX(version) FROM patrol_schema_versions").scalar_one() == 7
        assert "personal_day" not in {column["name"] for column in inspect(conn).get_columns("patrol_inspections")}
        assert {i["name"] for i in inspect(conn).get_indexes("patrol_inspections")} == before
        assert conn.execute(text("SELECT count(*) FROM patrol_inspections WHERE id BETWEEN 101 AND 105")).scalar_one() == 5


def test_v8_rejects_a_misplaced_index_without_touching_the_shared_table(engine, v7):
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP INDEX patrol_recent_spot_at_point")
        conn.exec_driver_sql("CREATE INDEX patrol_recent_spot_at_point ON unrelated_license(value)")
    with pytest.raises(migrations.SchemaMigrationError, match="Required v7 inspection indexes"):
        upgrade_schema(engine)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT MAX(version) FROM patrol_schema_versions").scalar_one() == 7
        assert [i["name"] for i in inspect(conn).get_indexes("unrelated_license")] == ["patrol_recent_spot_at_point"]


def test_v8_two_people_concurrently_review_one_execution_and_both_halves_remain_distinct(engine, v7):
    upgrade_schema(engine)
    units = dict(point_id=24, point_code="1F-G24", point_name="總務月巡", point_floor=1, category="general",
                 frequency="monthly", period_key="2026-06-01", slot="any", user_name="測試")
    with engine.begin() as conn:
        first_id = conn.execute(PatrolExecution.__table__.insert().values(**units, user_id=17, binding_id=41)
                                .returning(PatrolExecution.id)).scalar_one()
    barrier = Barrier(2)
    def review(user_id):
        with engine.begin() as conn:
            barrier.wait(timeout=10)
            return conn.execute(Inspection.__table__.insert().values(**units, user_id=user_id, execution_id=first_id,
                workflow_mode="two_stage", created_at=datetime(2026, 6, 2, 4)).returning(Inspection.id)).scalar_one()
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(review, user_id) for user_id in (18, 19)]
        assert len({job.result(timeout=20) for job in jobs}) == 2

    with Session(engine) as session:
        spot = units | dict(user_id=18, frequency="daily2", period_key="2026-06-03", workflow_mode="spot")
        for slot, hour in (("am", 0), ("pm", 8)):
            session.add(Inspection(**(spot | dict(slot=slot)), spot_request_id=f"jun03-{slot}", created_at=datetime(2026, 6, 3, hour)))
        session.commit()
        with pytest.raises(IntegrityError), session.begin_nested():
            session.add(Inspection(**(spot | dict(frequency="irregular", slot="any")), spot_request_id="jun03-any",
                                   created_at=datetime(2026, 6, 3, 12)))
            session.flush()
