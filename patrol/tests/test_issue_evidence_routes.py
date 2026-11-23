"""HTTP evidence/export checks against isolated SQLite and synthetic photos."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from io import BytesIO
from threading import Barrier
from zipfile import ZipFile

import pytest
from PIL import Image
from openpyxl import load_workbook
from sqlalchemy import event, select

import app as patrol
import issue_export
from issues import open_issue_for
from models import (AuditLog, Inspection, InspectionIssue, InspectionPhoto, IssueEvent,
                    IssueEventPhoto, PatrolExecution, Point, User, db)
from test_app import application  # noqa: F401
from test_engineering_point_scope import teams, rendered  # noqa: F401
from test_features import png
from test_postgres_features import postgres_app, seed_clients  # noqa: F401


EXPORT = '/issues/export.xlsx'


@pytest.fixture
def evidence(teams):
    t = teams
    # Scope fixtures deliberately use marker bytes; real exports must decode
    # valid stored images so this fixture exercises the actual embedded media.
    raw = png().getvalue()
    for record in t.records.values():
        record.photos[0].data, record.photos[0].size_bytes = raw, len(raw)
        record.photos[0].mime_type = 'image/png'
        record.photos[0].width = record.photos[0].height = 20
    row = Inspection(point_id=t.points['safety'].id, user_id=t.users['safety'].id,
        binding_id=t.bindings['safety'].id, created_at=datetime(2026, 11, 8, 2),
        period_key='2026-11-08', frequency='daily', slot='any', category='safety',
        workflow_mode='standard', point_code=t.points['safety'].code,
        point_name=t.points['safety'].name, point_floor=1, user_name='Safety test reporter',
        note='SAFETY-EVIDENCE-NOTE', is_abnormal=True)
    open_issue_for(row)
    db.session.add(row)
    t.records['safety'] = row
    peer = User(username='evidence-peer', display_name='General test peer', role='inspector',
        patrol_category='general', active=True, must_change_password=False, password_hash='not-used')
    db.session.add(peer)
    db.session.commit()
    client = t.app.test_client()
    with client.session_transaction() as session:
        session.update(user_id=peer.id, auth_version=peer.auth_version, csrf_token='evidence-peer')
    t.users['peer'], t.clients['peer'] = peer, client
    return t


def resolve(client, row, *, version=0, note='Repaired test issue', photos=True):
    fields = {'expected_event_id': str(version), 'note': note}
    if photos is True:
        fields['photos'] = (png(), 'evidence.png')
    elif photos:
        fields['photos'] = photos
    return client.post(f'/issues/{row.id}/resolve', data=fields)


def reopen(client, row, version, **fields):
    return client.post(f'/admin/issues/{row.id}/reopen', data={
        'expected_event_id': str(version), 'note': 'Problem needs another review', **fields})


def events_for(row):
    return db.session.scalars(select(IssueEvent).where(IssueEvent.inspection_id == row.id)
                              .order_by(IssueEvent.id)).all()


def workbook_response(client, query=''):
    response = client.get(EXPORT + query)
    assert response.status_code == 200, (response.status_code, response.text[:300])
    assert response.mimetype == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    assert 'attachment;' in response.headers['Content-Disposition']
    assert '.xlsx' in response.headers['Content-Disposition']
    assert response.headers['Cache-Control'] == 'private, no-store'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    return response, load_workbook(BytesIO(response.data))


def exported_ids(workbook):
    return [row[0].value for row in workbook['異常總表'].iter_rows(min_row=6)
            if isinstance(row[0].value, int)]


def add_case(t, kind, instant, number, *, own_point=False):
    point = t.points[kind]
    if own_point:
        point = Point(code=f'EXPORT-{kind}-{number}', name=f'{kind} export test location', floor=1,
            category='general', inspection_team=kind, workflow_mode='spot', frequency='daily', active=True,
            schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
        db.session.add(point)
        db.session.flush()
    day = patrol.local_dt(instant).date()
    row = Inspection(point_id=point.id, user_id=t.users[kind].id, binding_id=t.bindings[kind].id,
        created_at=instant, period_key=day.isoformat(), frequency='daily', slot='any',
        category='general', workflow_mode='spot', personal_day=day, spot_request_id=f'export-case-{kind}-{number}',
        point_code=point.code, point_name=point.name, point_floor=1, user_name='Synthetic test reporter',
        note=f'{kind.upper()}-EXPORT-NOTE-{number}', is_abnormal=True)
    open_issue_for(row)
    db.session.add(row)
    db.session.flush()
    return row


def test_resolution_saves_event_photo_and_audit_atomically_without_changing_original(evidence):
    t, row = evidence, evidence.records['general']
    original = (row.note, row.photos[0].id, row.photos[0].data)
    response = resolve(t.clients['general'], row, note='處理完成\r\n確認正常')
    assert response.status_code == 302
    db.session.expire_all()
    assert row.issue.status == 'resolved'
    first, = events_for(row)
    assert first.note == '處理完成\n確認正常' and len(first.photos) == 1
    photo = first.photos[0]
    assert photo.mime_type == 'image/jpeg' and photo.data.startswith(b'\xff\xd8')
    assert photo.size_bytes == len(photo.data)
    assert (row.note, row.photos[0].id, row.photos[0].data) == original
    assert db.session.query(AuditLog).filter_by(action='issue_resolved', target=str(row.id)).count() == 1
    context, html = rendered(t.app, t.clients['general'], '/dashboard?view=daily')
    assert row.point_id not in context['open_issue_counts']
    assert f'/issue-photos/{photo.id}' in t.clients['general'].get(f'/records/{row.id}').text
    assert reopen(t.clients['admin'], row, first.id).status_code == 302
    db.session.expire_all()
    assert row.issue.status == 'open' and first.photos[0].data == photo.data
    context, _ = rendered(t.app, t.clients['general'], '/dashboard?view=daily')
    assert context['open_issue_counts'][row.point_id] == 1


@pytest.mark.parametrize('variant', ['bad-second', 'too-many', 'quota'])
def test_rejected_photo_batch_rolls_back_status_event_and_audit(evidence, variant):
    t, row = evidence, evidence.records['general']
    if variant == 'quota':
        t.app.config['PHOTO_STORAGE_LIMIT_BYTES'] = 1
        uploads, status = True, 409
    elif variant == 'too-many':
        uploads, status = [(png(), f'{i}.png') for i in range(4)], 400
    else:
        uploads, status = [(png(), 'first.png'), (BytesIO(b'invalid-photo'), 'second.png')], 400
    response = resolve(t.clients['general'], row, photos=uploads)
    assert response.status_code == status
    db.session.expire_all()
    assert row.issue.status == 'open' and events_for(row) == []
    assert db.session.query(IssueEventPhoto).count() == 0
    assert db.session.query(AuditLog).filter_by(action='issue_resolved').count() == 0
    assert len(row.photos) == 1


def test_failed_photo_insert_rolls_back_the_entire_resolution(evidence):
    t, row = evidence, evidence.records['general']
    def fail_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith('INSERT INTO patrol_issue_event_photos'):
            raise RuntimeError('injected evidence insert failure')
    event.listen(db.engine, 'before_cursor_execute', fail_insert)
    try:
        with pytest.raises(RuntimeError, match='injected evidence'):
            resolve(t.clients['general'], row)
    finally:
        event.remove(db.engine, 'before_cursor_execute', fail_insert)
        db.session.rollback()
    assert db.session.get(InspectionIssue, row.id).status == 'open'
    assert events_for(row) == [] and db.session.query(IssueEventPhoto).count() == 0
    assert db.session.query(AuditLog).filter_by(action='issue_resolved').count() == 0


def test_duplicate_and_stale_resolution_never_decode_or_append_images(evidence, monkeypatch):
    t, row = evidence, evidence.records['general']
    assert resolve(t.clients['general'], row).status_code == 302
    first, = events_for(row)
    first_photo = first.photos[0].data
    def reject_decode(_):
        raise AssertionError('duplicate/stale action must not decode photos')
    monkeypatch.setattr(patrol, 'process_uploads', reject_decode)
    assert resolve(t.clients['general'], row, note='Repeated note').status_code == 302
    assert len(events_for(row)) == 1 and first.photos[0].data == first_photo
    assert reopen(t.clients['admin'], row, first.id).status_code == 302
    assert resolve(t.clients['general'], row, version=0).status_code == 409
    db.session.expire_all()
    assert row.issue.status == 'open' and len(events_for(row)) == 2
    assert db.session.query(IssueEventPhoto).count() == 1


def test_manager_can_resolve_both_general_teams_but_not_safety_or_reopen(evidence):
    t = evidence
    for kind in ('general', 'engineering'):
        row = t.records[kind]
        context, _ = rendered(t.app, t.clients['manager'], f'/records/{row.id}')
        assert context['can_manage_issue'] is True
        assert resolve(t.clients['manager'], row).status_code == 302
        first, = events_for(row)
        assert first.actor_id == t.users['manager'].id
        assert reopen(t.clients['manager'], row, first.id).status_code == 403
    assert resolve(t.clients['manager'], t.records['safety']).status_code == 404
    for kind in ('general', 'engineering'):
        foreign = 'engineering' if kind == 'general' else 'general'
        assert resolve(t.clients[kind], t.records[foreign]).status_code == 404
    assert resolve(t.clients['peer'], t.records['general']).status_code == 403


def test_two_general_executors_can_close_one_old_case_once_with_photo_and_no_note(evidence):
    t, row = evidence, evidence.records['general']
    row.created_at = row.issue.opened_at = datetime(2026, 10, 20, 4)
    second = User(username='executor-two', display_name='Execution two', role='executor',
                  patrol_category='general', active=True, must_change_password=False, password_hash='fixture')
    db.session.add(second)
    db.session.commit()
    first_client, second_client = t.clients['executor'], t.app.test_client()
    with second_client.session_transaction() as session:
        session.update(user_id=second.id, auth_version=second.auth_version, csrf_token='executor-two')
    source = '/issues?status=open&date_from=&date_to='
    for client in (first_client, second_client):
        cases, _ = rendered(t.app, client, '/issues')
        assert cases['open_total'] == 1 and [record.id for record in cases['records']] == [row.id]
        detail, _ = rendered(t.app, client, f'/records/{row.id}?return_to={source.replace("&", "%26")}')
        assert detail['can_manage_issue'] and not detail['can_reopen_issue']
        assert detail['back_url'] == source
        assert client.get(f'/photos/{row.photos[0].id}').status_code == 200
        assert client.get(f'/checkins/{row.id}').status_code == 403
        for kind in ('safety', 'engineering'):
            foreign = t.records[kind]
            assert client.get(f'/issues?point_id={foreign.point_id}').status_code == 404
            assert client.get(f'/records/{foreign.id}').status_code in (403, 404)
            assert resolve(client, foreign, note='').status_code == 404
        assert client.get(EXPORT).status_code == 403
    assert resolve(first_client, row, note='x' * 2001).status_code == 400
    assert not events_for(row)
    assert resolve(first_client, row, note='　').status_code == 302
    assert resolve(second_client, row, note='').status_code == 302
    saved, = events_for(row)
    assert saved.actor_id == t.users['executor'].id and saved.note == ''
    assert len(saved.photos) == 1 and row.issue.status == 'resolved'
    assert db.session.query(AuditLog).filter_by(action='issue_resolved', target=str(row.id)).count() == 1
    for client in (first_client, second_client):
        cases, _ = rendered(t.app, client, '/issues')
        assert cases['open_total'] == 0 and not cases['records']
        assert client.get(f'/issue-photos/{saved.photos[0].id}').status_code == 200
        assert reopen(client, row, saved.id).status_code == 403
    # Work can be assigned to either executor, independently of the original reporter.
    next_case = add_case(t, 'general', datetime(2026, 11, 9, 3), 100, own_point=True)
    db.session.commit()
    assert resolve(second_client, next_case, note='').status_code == 302
    assert events_for(next_case)[0].actor_id == second.id


@pytest.fixture(params=['sqlite', 'postgresql'])
def issue_race_app(tmp_path, request):
    if request.param == 'postgresql':
        yield request.getfixturevalue('postgres_app')
        return
    app = patrol.create_app({'TESTING': True, 'SECRET_KEY': 'local-test', 'CSRF_ENABLED': False,
                             'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + (tmp_path / 'issue.db').as_posix()})
    with app.app_context():
        db.create_all()
    try:
        yield app
    finally:
        with app.app_context():
            db.engine.dispose()


def test_two_phones_resolving_simultaneously_keep_only_the_winning_photo(issue_race_app):
    app = issue_race_app
    clients = [client for client, _, _ in seed_clients(app)]
    widths = {}
    entries = []
    for index, client in enumerate(clients):
        width = 20 + index
        data = BytesIO()
        Image.new('RGB', (width, 20), 'red' if index == 0 else 'blue').save(data, 'PNG')
        data.seek(0)
        with client.session_transaction() as session:
            widths[session['user_id']] = width
        entries.append((client, data))
    with app.app_context():
        users = db.session.scalars(select(User)).all()
        for user in users:
            user.role, user.patrol_category = 'executor', 'general'
        point = db.session.scalar(select(Point))
        point.category = 'general'
        row = Inspection(point_id=point.id, user_id=users[0].id, created_at=datetime(2026, 11, 3, 2),
                         period_key='2026-11-03', frequency='daily2', slot='am', category='general',
                         workflow_mode='standard', point_code=point.code, point_name=point.name,
                         point_floor=point.floor, user_name='Test reporter', is_abnormal=True)
        open_issue_for(row)
        db.session.add(row)
        db.session.commit()
        row_id = row.id
    gate = Barrier(2)
    def close_case(entry):
        client, photo = entry
        gate.wait(timeout=5)
        return client.post(f'/issues/{row_id}/resolve', data={
            'expected_event_id': '0', 'photos': (photo, 'evidence.png')}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(close_case, entries)) == [302, 302]
    with app.app_context():
        saved = db.session.query(IssueEvent).one()
        photo = db.session.query(IssueEventPhoto).one()
        assert photo.event_id == saved.id and photo.width == widths[saved.actor_id]
        assert db.session.get(InspectionIssue, row_id).resolved_by_id == saved.actor_id
        assert db.session.query(AuditLog).filter_by(action='issue_resolved').count() == 1


def test_resolution_photo_urls_follow_current_point_team_and_private_headers(evidence):
    t, row = evidence, evidence.records['general']
    assert resolve(t.clients['manager'], row).status_code == 302
    first, = events_for(row)
    photo = first.photos[0]
    path = f'/issue-photos/{photo.id}'
    for kind in ('general', 'peer', 'manager', 'admin', 'executor'):
        response = t.clients[kind].get(path)
        assert response.status_code == 200 and response.data == photo.data
        assert response.headers['Cache-Control'] == 'private, no-store'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.mimetype == 'image/jpeg'
    for kind in ('engineering', 'safety'):
        assert t.clients[kind].get(path).status_code in (403, 404)
    assert t.app.test_client().get(path).status_code == 302
    t.points['general'].inspection_team = 'engineering'
    db.session.commit()
    assert t.clients['general'].get(path).status_code == 404
    assert t.clients['executor'].get(path).status_code in (403, 404)
    assert t.clients['engineering'].get(path).data == photo.data
    assert t.clients['manager'].get(path).data == photo.data


@pytest.mark.parametrize('change', ['manager-to-general', 'general-to-engineering', 'engineering-to-executor'])
def test_resolution_photos_recheck_changed_user_role_on_existing_session(evidence, change):
    t = evidence
    kind = 'general' if change == 'general-to-engineering' else 'engineering'
    actor = 'manager' if change == 'manager-to-general' else kind
    row = t.records[kind]
    assert resolve(t.clients['manager'], row).status_code == 302
    first, = events_for(row)
    path = f'/issue-photos/{first.photos[0].id}'
    assert t.clients[actor].get(path).status_code == 200
    user = t.users[actor]
    if change == 'manager-to-general':
        user.general_manager_title = False
    elif change == 'general-to-engineering':
        user.engineering_inspector_title = True
    else:
        user.role = 'executor'
        user.engineering_inspector_title = False
    # Deliberately retain the old browser session: each request must recheck
    # authority even if a legacy role change did not revoke the session.
    db.session.commit()
    response = t.clients[actor].get(path)
    assert response.status_code in (403, 404)
    assert response.mimetype != 'image/jpeg'


def test_issue_export_batches_corresponding_execution_checklists(evidence):
    from checklist_catalog import validate_checklist
    from checklist_records import encode_checklist
    t = evidence
    for number in range(5):
        point = Point(code=f'EXPORT-CHECKLIST-{number}', name='4M女廁所-甲', floor=14,
            category='general', inspection_team='general', workflow_mode='two_stage', frequency='daily',
            active=True, schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
        db.session.add(point)
        db.session.flush()
        first = PatrolExecution(point_id=point.id, user_id=t.users['executor'].id,
            binding_id=t.bindings['executor'].id, created_at=datetime(2026, 11, 8, 2),
            period_key='2026-11-08', frequency='daily', slot='any', category='general',
            point_code=point.code, point_name=point.name, point_floor=point.floor, user_name='Executor',
            checklist_data=encode_checklist(validate_checklist(point, ['toilet.soap'])))
        db.session.add(first)
        db.session.flush()
        row = Inspection(point_id=point.id, user_id=t.users['general'].id, binding_id=t.bindings['general'].id,
            created_at=datetime(2026, 11, 8, 3), period_key='2026-11-08', frequency='daily', slot='any',
            category='general', workflow_mode='two_stage', execution_id=first.id,
            personal_day=date(2026, 11, 8), point_code=point.code, point_name=point.name, point_floor=14,
            user_name='Inspector', is_abnormal=True,
            checklist_data=encode_checklist(validate_checklist(point, ['toilet.floor'])))
        open_issue_for(row)
        db.session.add(row)
    db.session.commit()
    db.session.expire_all()
    statements = []
    def record_sql(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(db.engine, 'before_cursor_execute', record_sql)
    try:
        _, workbook = workbook_response(t.clients['manager'], '?status=all&inspection_team=general')
    finally:
        event.remove(db.engine, 'before_cursor_execute', record_sql)
    assert sum('patrol_executions.checklist_data' in sql for sql in statements) == 1
    detail = workbook['照片與處理歷程']
    values = [cell.value for row in detail for cell in row]
    assert values.count('☑ 洗手乳充足') == 5 and values.count('☑ 地面清潔') == 5


def test_export_embeds_before_after_photos_history_and_private_download_headers(evidence):
    t, row = evidence, evidence.records['general']
    assert resolve(t.clients['manager'], row, note='First repair').status_code == 302
    first, = events_for(row)
    assert reopen(t.clients['admin'], row, first.id).status_code == 302
    reopened = events_for(row)[-1]
    assert resolve(t.clients['manager'], row, version=reopened.id, note='Second repair').status_code == 302
    response, workbook = workbook_response(t.clients['manager'], '?status=all&inspection_team=general')
    assert exported_ids(workbook) == [row.id]
    text = '\n'.join(str(c.value) for ws in workbook for cells in ws for c in cells if c.value is not None)
    assert all(note in text for note in (row.note, 'First repair', 'Second repair', 'Problem needs another review'))
    assert t.records['engineering'].note not in text and t.records['safety'].note not in text
    with ZipFile(BytesIO(response.data)) as archive:
        assert len([name for name in archive.namelist() if name.startswith('xl/media/')]) == 3


def test_export_enforces_scopes_and_forged_team_filters_cannot_widen(evidence):
    t = evidence
    for kind in ('general', 'engineering', 'safety'):
        foreign = 'general' if kind == 'engineering' else 'engineering'
        _, workbook = workbook_response(t.clients[kind], '?status=all&inspection_team=' + foreign)
        assert exported_ids(workbook) == [t.records[kind].id]
    _, workbook = workbook_response(t.clients['manager'], '?status=all')
    assert set(exported_ids(workbook)) == {t.records[k].id for k in ('general', 'engineering')}
    _, workbook = workbook_response(t.clients['admin'], '?status=all&category=safety&inspection_team=engineering')
    assert exported_ids(workbook) == [t.records['safety'].id]
    assert t.clients['executor'].get(EXPORT).status_code == 403
    assert t.app.test_client().get(EXPORT).status_code == 302
    assert t.clients['general'].get(EXPORT + f'?point_id={t.points["engineering"].id}').status_code == 404


def test_export_dates_use_taipei_report_day_and_match_visible_issue_filters(evidence):
    t = evidence
    instants = (datetime(2026, 11, 7, 15, 59), datetime(2026, 11, 7, 16),
                datetime(2026, 11, 8, 15, 59), datetime(2026, 11, 8, 16))
    extra = [add_case(t, 'general', instant, i, own_point=True) for i, instant in enumerate(instants)]
    db.session.commit()
    query = '?status=all&date_from=2026-11-08&date_to=2026-11-08&inspection_team=general'
    context, _ = rendered(t.app, t.clients['manager'], '/issues' + query)
    expected = {t.records['general'].id, extra[1].id, extra[2].id}
    assert {row.id for row in context['records']} == expected
    _, workbook = workbook_response(t.clients['manager'], query)
    assert set(exported_ids(workbook)) == expected


def test_export_covers_all_filtered_pages_and_preserves_issue_order(evidence):
    t = evidence
    extra = [add_case(t, 'general', datetime(2026, 9, 1, 2) + timedelta(days=i), i) for i in range(51)]
    db.session.commit()
    query = '?status=all&inspection_team=general&date_from=&date_to='
    context, _ = rendered(t.app, t.clients['manager'], '/issues' + query)
    assert len(context['records']) == 50 and context['pagination']['total'] == 52
    _, workbook = workbook_response(t.clients['manager'], query + '&page=2')
    assert exported_ids(workbook) == [t.records['general'].id] + [row.id for row in reversed(extra)]


@pytest.mark.parametrize('query', ['?date_from=bad', '?date_from=2026-11-09&date_to=2026-11-01',
    '?status=invalid', '?inspection_team=invalid', '?floor=999'])
def test_export_invalid_filters_fail_closed(evidence, query):
    assert evidence.clients['admin'].get(EXPORT + query).status_code == 400


def test_export_case_limit_is_checked_before_loading_photo_bytes(evidence, monkeypatch):
    t = evidence
    for i in range(100):
        add_case(t, 'general', datetime(2026, 1, 1, 2) + timedelta(days=i), i)
    db.session.commit()
    def reject_build(*args, **kwargs):
        raise AssertionError('over-limit export must not build workbook')
    monkeypatch.setattr(issue_export, 'build_issue_workbook', reject_build)
    statements = []
    def record_sql(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(db.engine, 'before_cursor_execute', record_sql)
    try:
        response = t.clients['manager'].get(EXPORT + '?status=all&inspection_team=general&date_from=&date_to=')
    finally:
        event.remove(db.engine, 'before_cursor_execute', record_sql)
    assert response.status_code == 413 and '100' in response.text
    assert not any('patrol_inspection_photos.data' in sql or 'patrol_issue_event_photos.data' in sql for sql in statements)


def test_export_photo_byte_limit_is_checked_without_loading_blobs(evidence):
    t = evidence
    t.records['general'].photos[0].size_bytes = issue_export.MAX_SOURCE_PHOTO_BYTES + 1
    db.session.commit()
    statements = []
    def record_sql(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(db.engine, 'before_cursor_execute', record_sql)
    try:
        response = t.clients['manager'].get(EXPORT + '?inspection_team=general')
    finally:
        event.remove(db.engine, 'before_cursor_execute', record_sql)
    assert response.status_code == 413
    assert not any('patrol_inspection_photos.data' in sql or 'patrol_issue_event_photos.data' in sql for sql in statements)


def test_existing_resolution_photos_are_included_in_shared_storage_quota(evidence):
    t = evidence
    assert resolve(t.clients['manager'], t.records['engineering']).status_code == 302
    existing_bytes = (db.session.scalar(select(db.func.sum(InspectionPhoto.size_bytes)))
                      + db.session.scalar(select(db.func.sum(IssueEventPhoto.size_bytes))))
    t.app.config['PHOTO_STORAGE_LIMIT_BYTES'] = existing_bytes
    response = resolve(t.clients['manager'], t.records['general'])
    assert response.status_code == 409
    assert db.session.get(InspectionIssue, t.records['general'].id).status == 'open'
    assert db.session.query(IssueEvent).count() == 1
    assert db.session.query(IssueEventPhoto).count() == 1


def test_export_status_filters_and_empty_result_remain_valid_workbooks(evidence):
    t = evidence
    assert resolve(t.clients['manager'], t.records['general'], photos=False).status_code == 302
    _, workbook = workbook_response(t.clients['manager'], '?status=open')
    assert exported_ids(workbook) == [t.records['engineering'].id]
    _, workbook = workbook_response(t.clients['manager'], '?status=resolved')
    assert exported_ids(workbook) == [t.records['general'].id]
    _, workbook = workbook_response(t.clients['manager'], '?status=resolved&inspection_team=engineering')
    assert exported_ids(workbook) == []
    assert '沒有異常案件' in workbook['異常總表']['A6'].value


def test_export_photo_count_limit_includes_event_photos_before_blob_load(evidence):
    t, row = evidence, evidence.records['general']
    assert resolve(t.clients['manager'], row, photos=False).status_code == 302
    first, = events_for(row)
    first.photos.extend(IssueEventPhoto(data=b'not-decoded', size_bytes=11, width=1, height=1)
                        for _ in range(500))
    db.session.commit()
    statements = []
    def record_sql(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(db.engine, 'before_cursor_execute', record_sql)
    try:
        response = t.clients['manager'].get(EXPORT + '?status=all&inspection_team=general')
    finally:
        event.remove(db.engine, 'before_cursor_execute', record_sql)
    assert response.status_code == 413
    assert not any('patrol_inspection_photos.data' in sql or 'patrol_issue_event_photos.data' in sql for sql in statements)
