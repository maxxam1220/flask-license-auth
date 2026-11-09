"""Cross-worker replay and activation on the disposable local PostgreSQL cluster."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
import os
from threading import Barrier
from types import SimpleNamespace

import pytest
from sqlalchemy import and_, false, or_, select, text, update
from sqlalchemy.orm import scoped_session, sessionmaker

from migrations import upgrade_schema
from models import AuditLog, Point, PointSchedule
import point_assignment_revision as revision
from test_postgres import engine

pytestmark = pytest.mark.skipif(not os.environ.get("PATROL_TEST_POSTGRES_URL"), reason="Disposable local PostgreSQL required.")


@pytest.fixture
def database(engine, monkeypatch):
    upgrade_schema(engine)
    session = scoped_session(sessionmaker(bind=engine))
    monkeypatch.setattr(revision,"db",SimpleNamespace(session=session,engine=engine,
        and_=and_,or_=or_,false=false,text=text,update=update))
    for code,(name,floor,frequency,mode,_) in revision.ENGINEERING_POINTS.items():
        point=Point(code=code,name=name,floor=floor,category="general",frequency=frequency,
            workflow_mode=mode,active=True,qr_token="untouched-"+code,schedule_start=date(2026,1,1))
        point.schedules.append(PointSchedule(effective_date=date(2026,1,1),frequency=frequency,
            category="general",workflow_mode=mode,active=True,floor=floor,point_code=code,point_name=name))
        session.add(point)
    session.commit()
    yield session
    session.remove()


def test_parallel_revision_and_activation_each_happen_once(database):
    start=Barrier(2)
    def apply():
        start.wait()
        try:
            return revision.revise_point_assignments(apply=True,
                instant=datetime(2026,11,9,2,tzinfo=timezone.utc),effective_date=date(2026,11,10))
        finally:
            database.remove()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:apply(),range(2)))
    assert sorted(r["already_applied"] for r in results)==[False,True]
    assert database.query(AuditLog).filter_by(action=revision.REVISION_ACTION).count()==1
    assert database.query(PointSchedule).count()==22
    database.remove()
    start=Barrier(2)
    def activate():
        start.wait()
        try:
            return revision.activate_due_point_frequencies(datetime(2026,11,9,16,tzinfo=timezone.utc))
        finally:
            database.remove()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:activate(),range(2)))
    assert sorted(r["activated"] for r in results)==[0,6]
    assert database.query(AuditLog).filter_by(action=revision.ACTIVATION_ACTION).count()==1
    assert database.query(PointSchedule).count()==22
    assert all(p.pending_frequency is None for p in database.scalars(select(Point)))
    assert all(p.qr_token=="untouched-"+p.code for p in database.scalars(select(Point)))
