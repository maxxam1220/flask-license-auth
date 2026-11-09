"""Real PostgreSQL snapshot locks; opt-in disposable local database only."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import BytesIO
import threading
import time

from openpyxl import load_workbook
import pytest
from sqlalchemy import event, select, text

import issue_export
from models import Inspection, InspectionIssue, IssueEvent, Point, User, db
from test_postgres_features import postgres_app, seed_clients  # noqa: F401


def seed_export_case(application, *, legacy):
    clients = seed_clients(application)
    with application.app_context():
        users = db.session.scalars(select(User).order_by(User.id)).all()
        for user in users:
            user.role, user.patrol_category = 'admin', None
        point = db.session.scalar(select(Point))
        record = Inspection(point_id=point.id, user_id=users[0].id,
            created_at=datetime(2026, 11, 3, 2), period_key='2026-11-03', frequency='daily2', slot='am',
            category='safety', workflow_mode='standard', point_code=point.code, point_name=point.name,
            point_floor=point.floor, user_name='Synthetic concurrent reporter', note='ORIGINAL-EXPORT-SNAPSHOT',
            is_abnormal=True)
        if not legacy:
            record.issue = InspectionIssue(status='open', opened_at=record.created_at)
        db.session.add(record)
        db.session.commit()
        record_id = record.id
    exporter, editor = clients[0][0], clients[1][0]
    version = 0
    if not legacy:
        response = editor.post(f'/issues/{record_id}/resolve', data={
            'expected_event_id': '0', 'note': 'ORIGINAL-RESOLUTION'})
        assert response.status_code == 302
        with application.app_context():
            version = db.session.scalar(select(IssueEvent.id))
    return exporter, editor, record_id, version


@pytest.mark.parametrize('legacy', [False, True])
def test_export_blocks_concurrent_transition_until_dto_then_releases_before_encoding(postgres_app, monkeypatch, legacy):
    """The workbook is one coherent version, including a legacy case without an issue row.

    Pause after the export's Inspection FOR SHARE, while loading its histories.
    A second real connection must be waiting on a PostgreSQL row/transaction
    lock. Let the DTO read finish, then pause workbook encoding and prove the
    editor has already committed: expensive XLSX work must hold no DB locks.
    """
    exporter, editor, record_id, version = seed_export_case(postgres_app, legacy=legacy)
    with postgres_app.app_context():
        engine = db.engine
    snapshot_read = threading.Event()
    continue_read = threading.Event()
    editor_lock_attempt = threading.Event()
    editor_finished = threading.Event()
    encoding_started = threading.Event()
    continue_encoding = threading.Event()
    observed = {}
    original_builder = issue_export.build_issue_workbook

    def before_sql(connection, cursor, statement, parameters, context, executemany):
        if threading.current_thread().name.endswith('_0'):
            # Legacy rows have no related events. Their original-photo load
            # still follows the same shared Inspection lock and issue lookup.
            table = 'patrol_inspection_photos' if legacy else 'patrol_issue_events'
            if not snapshot_read.is_set() and statement.startswith('SELECT ' + table + '.'):
                snapshot_read.set()
                assert continue_read.wait(15), 'test did not release the export read checkpoint'
        elif (threading.current_thread().name.endswith('_1') and 'FOR UPDATE' in statement
                and 'FROM patrol_inspections' in statement):
            observed['editor_pid'] = connection.scalar(text('SELECT pg_backend_pid()'))
            editor_lock_attempt.set()

    def hold_encoding(rows, **options):
        observed['dto'] = tuple(rows)
        observed['transaction_during_encoding'] = db.session().in_transaction()
        encoding_started.set()
        assert editor_finished.wait(15), 'export retained its database lock during XLSX encoding'
        assert continue_encoding.wait(15), 'test did not release XLSX encoding'
        return original_builder(rows, **options)

    def download():
        response = exporter.get('/issues/export.xlsx?status=all')
        result = response.status_code, response.data
        response.close()
        return result

    def edit_case():
        try:
            endpoint = f'/issues/{record_id}/resolve' if legacy else f'/admin/issues/{record_id}/reopen'
            return editor.post(endpoint, data={'expected_event_id': str(version),
                'note': 'CONCURRENT-CHANGE-MUST-NOT-ENTER-EXPORT'}).status_code
        finally:
            editor_finished.set()

    event.listen(engine, 'before_cursor_execute', before_sql)
    monkeypatch.setattr(issue_export, 'build_issue_workbook', hold_encoding)
    pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='issue_export_snapshot')
    try:
        export_future = pool.submit(download)
        assert snapshot_read.wait(15), 'export did not reach its relationship read checkpoint'
        edit_future = pool.submit(edit_case)
        assert editor_lock_attempt.wait(15), 'editor did not attempt to lock Inspection'
        # Observe PostgreSQL itself, rather than treating a slow thread as proof
        # of serialization. pg_stat_activity is visible for this same test user.
        deadline = time.monotonic() + 10
        is_waiting = False
        with engine.connect() as monitor:
            while time.monotonic() < deadline:
                is_waiting = bool(monitor.scalar(text(
                    "SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = :pid"),
                    {'pid': observed['editor_pid']}))
                if is_waiting:
                    break
                monitor.rollback()
                threading.Event().wait(0.02)
        assert is_waiting and not edit_future.done(), 'editor must wait for the export snapshot lock'
        continue_read.set()
        assert encoding_started.wait(15)
        assert edit_future.result(timeout=15) == 302
        assert observed['transaction_during_encoding'] is False
        dto, = observed['dto']
        assert dto.inspection_id == record_id
        assert dto.status == ('open' if legacy else 'resolved')
        assert [entry.action for entry in dto.events] == ([] if legacy else ['resolved'])
        assert all(entry.note != 'CONCURRENT-CHANGE-MUST-NOT-ENTER-EXPORT' for entry in dto.events)
        with postgres_app.app_context():
            current = db.session.get(InspectionIssue, record_id)
            assert current.status == ('resolved' if legacy else 'open')
            assert db.session.scalars(select(IssueEvent).where(IssueEvent.inspection_id == record_id)
                                      .order_by(IssueEvent.id)).all()[-1].note == 'CONCURRENT-CHANGE-MUST-NOT-ENTER-EXPORT'
        continue_encoding.set()
        status, data = export_future.result(timeout=15)
        assert status == 200
        workbook = load_workbook(BytesIO(data))
        assert workbook['異常總表']['H6'].value == ('未結案' if legacy else '已結案')
        text_values = '\n'.join(str(cell.value) for sheet in workbook for row in sheet for cell in row
                                if cell.value is not None)
        assert 'ORIGINAL-EXPORT-SNAPSHOT' in text_values
        assert 'CONCURRENT-CHANGE-MUST-NOT-ENTER-EXPORT' not in text_values
    finally:
        continue_read.set()
        continue_encoding.set()
        pool.shutdown(wait=True, cancel_futures=True)
        event.remove(engine, 'before_cursor_execute', before_sql)
