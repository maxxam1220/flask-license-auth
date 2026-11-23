"""Display verdicts for immutable inspection snapshots, including pre-policy records."""
from sqlalchemy import Column, JSON, String, Table, func, select
from sqlalchemy.dialects import postgresql, sqlite

import database as db
import inspection_evidence


summaries = Table("labelcheck_history_status", db.metadata,
    Column("policy", String(40), primary_key=True),
    Column("source_table", String(48), primary_key=True),
    Column("row_id", String(32), primary_key=True),
    Column("status", String(20), nullable=False),
    Column("counts", JSON, nullable=False))


def project(result, ocr, snapshot):
    if not isinstance(result, dict):
        return {}
    if result.get("nutrition_policy") == inspection_evidence.NUTRITION_POLICY:
        return result
    source = snapshot.get("source") or (snapshot.get("rules") or {}).get("approved_text_source")
    return inspection_evidence.without_nutrition(result, ocr, source)


def _entry(table):
    return (summaries.c.policy == inspection_evidence.NUTRITION_POLICY,
            summaries.c.source_table == table.name, summaries.c.row_id == table.c.id)


def status_column(table):
    cached = select(summaries.c.status).where(*_entry(table)).correlate(table).scalar_subquery()
    # New scans/corrections can commit between filling the cache and this query.
    # They already store the current verdict.
    return func.coalesce(cached, table.c.status)


def counts_column(table):
    return select(summaries.c.counts).where(*_entry(table)).correlate(table).scalar_subquery()


def ensure_index(engine, identifier=None):
    """Index only missing immutable revisions; each small batch commits independently."""
    dialect = sqlite if engine.dialect.name == "sqlite" else postgresql
    for table in (db.inspections, db.corrections):
        pending = select(table.c.id, table.c.status, table.c.result, table.c.ocr,
                         db.inspections.c.template_snapshot)
        if table is db.corrections:
            pending = pending.select_from(table.join(db.inspections, db.inspections.c.id == table.c.inspection_id))
        if identifier is not None:
            pending = pending.where(db.inspections.c.id == identifier)
        pending = pending.where(~select(summaries.c.row_id).where(*_entry(table)).correlate(table).exists())
        after = None
        while True:
            # Close the read transaction before writing, including on SQLite/WAL.
            page = pending if after is None else pending.where(table.c.id > after)
            with engine.connect() as conn:
                rows = conn.execute(page.order_by(table.c.id).limit(24)).mappings().all()
            if not rows:
                if after is not None:
                    # An insert during the backfill may have an earlier random UUID.
                    after = None
                    continue
                break
            values = []
            for row in rows:
                result = project(row["result"], row["ocr"], row["template_snapshot"])
                values.append(dict(policy=inspection_evidence.NUTRITION_POLICY, source_table=table.name,
                                   row_id=row["id"], status=result.get("status", row["status"]),
                                   counts=result.get("counts", {})))
            with engine.begin() as conn:
                conn.execute(dialect.insert(summaries).on_conflict_do_nothing(), values)
            after = rows[-1]["id"]
