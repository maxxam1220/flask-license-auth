"""Durable cloud usage accounting with an optional cumulative call cap."""
from sqlalchemy import Table, Column, String, Integer, JSON, select, insert, update
from sqlalchemy.exc import IntegrityError
import database as db

counter = Table("labelcheck_cloud_budget", db.metadata,
    Column("id", String(40), primary_key=True), Column("calls", Integer, nullable=False))
calls = Table("labelcheck_cloud_calls", db.metadata,
    Column("job_id", String(32), primary_key=True), Column("model", String(100)),
    Column("state", String(30), nullable=False), Column("usage", JSON),
    Column("error_code", String(60)), Column("created_at", String(40), nullable=False))
KEY="cloud-trial-v1"


def configured_limit(value):
    """Only an explicit -1 opens usage; other negative values fail closed."""
    value=int(value)
    return -1 if value==-1 else max(0,min(1000,value))


def initialize(engine):
    try:
        with engine.begin() as conn:
            if conn.execute(select(counter.c.id).where(counter.c.id==KEY)).first() is None:
                conn.execute(insert(counter).values(id=KEY,calls=0))
    except IntegrityError:
        pass


def remaining(engine, limit):
    if limit == -1:
        return None  # Unlimited here means no website cap, not free provider usage.
    with engine.connect() as conn:
        used=conn.execute(select(counter.c.calls).where(counter.c.id==KEY)).scalar_one()
    return max(0,limit-used)


def _reserve_call(conn, limit):
    conditions = [counter.c.id == KEY]
    if limit != -1:
        conditions.append(counter.c.calls < limit)
    return conn.execute(update(counter).where(*conditions).values(calls=counter.c.calls + 1)).rowcount == 1


def reserve(engine, job_id, model, limit):
    with engine.begin() as conn:
        # Claim the job before the shared counter in both reservation paths.
        conn.execute(insert(calls).values(job_id=job_id,model=model,state="reserved",usage={},created_at=db.now()))
        if not _reserve_call(conn, limit):
            raise RuntimeError("雲端試用次數已用完，請改用本機辨識或由管理員調整試用上限。")


def reserve_date_retry(engine, job_id, limit):
    """Reserve at most one extra provider request for this active job."""
    with engine.begin() as conn:
        job = calls.c.job_id == job_id
        claimed = conn.execute(update(calls).where(job, calls.c.state == "reserved")
                               .values(state="date_retry_reserved"))
        if claimed.rowcount != 1:
            return False
        if _reserve_call(conn, limit):
            return True
        conn.execute(update(calls).where(job).values(state="date_retry_no_budget"))
        return False


def usage_record(result):
    usage = dict(result.get("usage") or {})
    if result.get("cloud_calls"):
        usage.update(cloud_calls=result["cloud_calls"], cloud_call_count=result["cloud_call_count"],
                     cloud_usage_status=result["cloud_usage_status"])
    return usage


def finish(engine, job_id, state, usage=None, error_code=None):
    with engine.begin() as conn:
        conn.execute(update(calls).where(calls.c.job_id==job_id).values(state=state,usage=usage or {},error_code=error_code))
