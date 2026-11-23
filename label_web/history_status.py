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


def project(result, ocr, snapshot, patches=()):
    if not isinstance(result, dict):
        return {}
    if result.get("nutrition_policy") == inspection_evidence.NUTRITION_POLICY:
        return result
    source = snapshot.get("source") or (snapshot.get("rules") or {}).get("approved_text_source")
    recovered = None
    if result.get("nutrition_policy") == "excluded-v1" and isinstance(result.get("checks"), list):
        recovered = _recover_checks(result, ocr, snapshot, patches)
    return inspection_evidence.project_nutrition_text(result, ocr, source, recovered_checks=recovered)


def _recover_checks(result, ocr, snapshot, patches):
    """Recreate candidates from this scan/revision only; the caller merges nutrition text only."""
    from source_validation import evaluate_source
    from validation import evaluate

    inputs = result.get("inputs") or {}
    dates = {key: inputs.get(key, "") for key in ("batch_date", "arrival_date", "base_date")}
    lines = ocr.get("lines") or []
    if snapshot.get("mode") == "system_label" or "source" in snapshot:
        evaluated = evaluate_source(lines, snapshot.get("source"), **dates, ocr_capabilities=ocr.get("capabilities"))
    else:
        evaluated = evaluate(lines, snapshot, **dates)
    evaluated["source_match"] = result.get("source_match")
    inspection_evidence.augment(evaluated, ocr)
    if patches:
        from corrections import apply_patch_verdicts
        apply_patch_verdicts(evaluated, {patch["line_id"]: patch for patch in patches})
    return evaluated["checks"]


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
            pending = pending.add_columns(table.c.patches).select_from(
                table.join(db.inspections, db.inspections.c.id == table.c.inspection_id))
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
                result = project(row["result"], row["ocr"], row["template_snapshot"], row.get("patches") or ())
                values.append(dict(policy=inspection_evidence.NUTRITION_POLICY, source_table=table.name,
                                   row_id=row["id"], status=result.get("status", row["status"]),
                                   counts=result.get("counts", {})))
            with engine.begin() as conn:
                conn.execute(dialect.insert(summaries).on_conflict_do_nothing(), values)
            after = rows[-1]["id"]
