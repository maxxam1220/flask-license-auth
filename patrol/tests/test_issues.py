"""Issue lifecycle, privacy, read-only legacy compatibility and transaction tests."""
from datetime import datetime, timedelta, timezone
import csv
import io

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from test_app import application, seeded, app_module, db, login, rendered_contexts  # noqa: F401
from test_features import feature_point, clock, logged_browser, png, submit
from models import AuditLog, Inspection, InspectionIssue, InspectionPhoto, IssueEvent, Point, User
from issues import open_issue_counts


def abnormal(client, point, slot="pm", note="現場異常"):
    assert submit(client, point, slot, note=note, is_abnormal="on", photos=(png(), "issue.png")).status_code == 302
    return db.session.scalar(db.select(Inspection).where(Inspection.point_id == point.id, Inspection.slot == slot))


def admin_client(application):
    client = application.test_client()
    login(client, "manager")
    return client


def action(client, record, name="resolve", version=0, note="已處理現場問題"):
    return client.post(f"/admin/issues/{record.id}/{name}", data={"expected_event_id": str(version), "note": note})


def legacy_record(user, point, day=1, note="Legacy private note"):
    instant = datetime(2026, 1, 1, 4) + timedelta(days=day)
    row = Inspection(user_id=user.id, point_id=point.id, created_at=instant, period_key=instant.date().isoformat(),
                     frequency="daily", slot="any", category=point.category, point_code=point.code, point_name=point.name,
                     point_floor=point.floor, user_name=user.display_name, note=note, is_abnormal=True)
    db.session.add(row)
    db.session.flush()
    return row


def test_abnormal_checkin_opens_issue_atomically_and_normal_next_day_keeps_it(application, seeded, monkeypatch):
    point = feature_point()
    client = logged_browser(application, seeded)
    row = abnormal(client, point)
    assert row.issue.status == "open" and row.issue.opened_at == row.created_at
    assert row.issue.events == [] and len(row.photos) == 1
    clock(monkeypatch, 12, day=4)
    assert submit(client, point, period="2026-11-04", note="今天正常").status_code == 302
    assert db.session.query(InspectionIssue).count() == 1
    assert open_issue_counts() == {point.id: 1}
    with rendered_contexts(application) as contexts:
        client.get("/dashboard?category=safety&date=2026-11-04")
    context = contexts[-1][1]
    assert context["totals"] == {"total": 2, "done": 1, "pending": 1}
    assert context["cards"][0]["open_issue_count"] == 1
    normal = db.session.scalar(db.select(Inspection).where(Inspection.period_key == "2026-11-04"))
    with rendered_contexts(application) as contexts:
        client.get(f"/checkins/{normal.id}")
    assert contexts[-1][1]["point_open_issue_count"] == 1


def test_multiple_issues_only_clear_after_all_resolved_and_reopen_restores_label(application, seeded, monkeypatch):
    point = feature_point()
    client = logged_browser(application, seeded)
    clock(monkeypatch, 10)
    first = abnormal(client, point, "am", "上午原始備註")
    clock(monkeypatch, 12)
    second = abnormal(client, point, "pm", "下午原始備註")
    admin = admin_client(application)
    assert open_issue_counts() == {point.id: 2}
    assert action(admin, first).status_code == 302
    assert open_issue_counts() == {point.id: 1}
    first_event = db.session.scalar(db.select(IssueEvent).where(IssueEvent.inspection_id == first.id))
    assert action(admin, second, note="另一件已處理").status_code == 302
    assert open_issue_counts() == {}
    assert action(admin, first, "reopen", first_event.id, "問題再次出現").status_code == 302
    assert open_issue_counts() == {point.id: 1}
    db.session.refresh(first.issue)
    assert first.issue.status == "open" and first.issue.resolved_at is None
    assert first.issue.resolved_by_id is None and first.issue.resolved_by_name == first.issue.resolution_note == ""
    assert first.is_abnormal and second.is_abnormal
    assert first.note == "上午原始備註" and second.note == "下午原始備註"
    assert len(first.photos) == len(second.photos) == 1
    assert [event.action for event in first.issue.events] == ["resolved", "reopened"]


def test_duplicate_action_is_idempotent_and_stale_version_cannot_close_reopened_issue(application, seeded):
    point = feature_point()
    row = abnormal(logged_browser(application, seeded), point)
    admin = admin_client(application)
    assert action(admin, row).status_code == 302
    assert action(admin, row).status_code == 302
    assert db.session.query(IssueEvent).count() == 1
    resolved = db.session.scalar(db.select(IssueEvent))
    assert action(admin, row, "reopen", resolved.id, "需再次檢查").status_code == 302
    with rendered_contexts(application) as contexts:
        response = action(admin, row, version=0, note="舊分頁提交說明")
    assert response.status_code == 409
    assert contexts[-1][1]["issue_action_note"] == "舊分頁提交說明"
    assert contexts[-1][1]["issue_form_error"] and contexts[-1][1]["issue_version"] > resolved.id
    assert db.session.query(IssueEvent).count() == 2
    assert db.session.get(InspectionIssue, row.id).status == "open"
    assert db.session.query(AuditLog).filter(AuditLog.action.in_(["issue_resolved", "issue_reopened"])).count() == 2


def test_staff_only_reads_own_issue_history_and_only_admin_changes_it(application, seeded):
    point = feature_point()
    owner = logged_browser(application, seeded)
    row = abnormal(owner, point, note="OWNER-PRIVATE-NOTE")
    admin = admin_client(application)
    assert action(owner, row).status_code == 403
    assert owner.get("/issues").status_code == 403
    assert action(admin, row, note="ADMIN-HISTORY-DETAIL").status_code == 302
    response = owner.get(f"/records/{row.id}")
    assert response.status_code == 200 and b"ADMIN-HISTORY-DETAIL" in response.data
    other = application.test_client()
    login(other, "colleague")
    assert other.get(f"/records/{row.id}").status_code == 403
    with rendered_contexts(application) as contexts:
        response = other.get("/dashboard?category=safety")
    assert "OWNER-PRIVATE-NOTE" not in response.get_data(as_text=True)
    assert "ADMIN-HISTORY-DETAIL" not in response.get_data(as_text=True)
    assert contexts[-1][1]["cards"][0]["open_issue_count"] == 0


@pytest.mark.parametrize("note,version", [("", "0"), ("   ", "0"), ("x" * 2001, "0"), ("bad\x00note", "0"), ("說明", ""), ("說明", "-1"), ("說明", "9" * 100)])
def test_action_rejects_invalid_input_without_event_or_state_change(application, seeded, note, version):
    row = abnormal(logged_browser(application, seeded), feature_point())
    admin = admin_client(application)
    with rendered_contexts(application) as contexts:
        response = action(admin, row, version=version, note=note)
    assert response.status_code == 400
    assert contexts[-1][1]["issue_action_note"] == note
    assert db.session.get(InspectionIssue, row.id).status == "open"
    assert db.session.query(IssueEvent).count() == 0


def test_disabled_point_issue_can_be_found_and_resolved(application, seeded):
    point = feature_point()
    row = abnormal(logged_browser(application, seeded), point)
    point.active = False
    point.frequency = "weekly"
    db.session.commit()
    admin = admin_client(application)
    with rendered_contexts(application) as contexts:
        response = admin.get(f"/issues?point_id={point.id}&status=open")
    assert response.status_code == 200
    assert [record.id for record in contexts[-1][1]["records"]] == [row.id]
    assert action(admin, row).status_code == 302
    assert open_issue_counts() == {}


def test_csrf_required_for_issue_actions(application, seeded):
    row = abnormal(logged_browser(application, seeded), feature_point())
    admin = admin_client(application)
    application.config["CSRF_ENABLED"] = True
    assert action(admin, row).status_code == 400
    with admin.session_transaction() as session:
        token = session["csrf_token"]
    response = admin.post(f"/admin/issues/{row.id}/resolve", data={"expected_event_id": "0", "note": "驗證後處理", "csrf_token": token})
    assert response.status_code == 302


def test_admin_role_is_rechecked_under_lock_before_issue_mutation(application, seeded):
    row = abnormal(logged_browser(application, seeded), feature_point())
    admin = admin_client(application)
    manager_id = seeded["manager"].id
    injected = {"done": False}
    def demote_before_user_lock(state):
        statement = state.statement
        if not injected["done"] and state.is_select and getattr(statement, "_for_update_arg", None) is not None and "patrol_users" in str(statement):
            injected["done"] = True
            db.session.execute(db.update(User).where(User.id == manager_id).values(role="inspector"))
    event.listen(Session, "do_orm_execute", demote_before_user_lock)
    try:
        response = action(admin, row)
    finally:
        event.remove(Session, "do_orm_execute", demote_before_user_lock)
        db.session.rollback()
    assert injected["done"] and response.status_code == 403
    assert db.session.get(InspectionIssue, row.id).status == "open"
    assert db.session.query(IssueEvent).count() == 0


def test_event_insert_failure_rolls_back_issue_and_audit(application, seeded):
    row = abnormal(logged_browser(application, seeded), feature_point())
    admin = admin_client(application)
    def fail_event(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO patrol_issue_events"):
            raise RuntimeError("injected event write failure")
    event.listen(db.engine, "before_cursor_execute", fail_event)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            action(admin, row)
    finally:
        event.remove(db.engine, "before_cursor_execute", fail_event)
        db.session.rollback()
    assert db.session.get(InspectionIssue, row.id).status == "open"
    assert db.session.query(IssueEvent).count() == 0
    assert db.session.query(AuditLog).filter_by(action="issue_resolved").count() == 0


def test_issue_insert_failure_rolls_back_inspection_photo_and_checkin_audit(application, seeded):
    point = feature_point()
    client = logged_browser(application, seeded)
    def fail_issue(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO patrol_inspection_issues"):
            raise RuntimeError("injected issue write failure")
    event.listen(db.engine, "before_cursor_execute", fail_issue)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            submit(client, point, note="異常", is_abnormal="on", photos=(png(), "photo.png"))
    finally:
        event.remove(db.engine, "before_cursor_execute", fail_issue)
        db.session.rollback()
    assert db.session.query(Inspection).count() == db.session.query(InspectionPhoto).count() == db.session.query(InspectionIssue).count() == 0
    assert db.session.query(AuditLog).filter_by(action="checkin").count() == 0


def test_legacy_abnormal_visible_without_get_writes_and_can_be_resolved(application, seeded):
    point = seeded["daily"]
    row = legacy_record(seeded["inspector"], point)
    db.session.commit()
    assert open_issue_counts() == {point.id: 1}
    admin = admin_client(application)
    for url in ("/dashboard", "/records", f"/records/{row.id}", "/issues"):
        assert admin.get(url).status_code == 200
    assert db.session.query(InspectionIssue).count() == db.session.query(IssueEvent).count() == 0
    assert action(admin, row, note="處理交接期間異常").status_code == 302
    issue = db.session.get(InspectionIssue, row.id)
    assert issue.status == "resolved" and issue.opened_at == row.created_at
    assert db.session.query(IssueEvent).count() == 1 and open_issue_counts() == {}
    assert row.is_abnormal and row.note == "Legacy private note"


def test_paginated_issues_include_every_record_and_real_open_total_without_n_plus_one(application, seeded):
    first = legacy_record(seeded["inspector"], seeded["daily"], day=0)
    db.session.commit()
    user_id, point_id = seeded["inspector"].id, seeded["daily"].id
    admin = admin_client(application)
    def reads(url):
        statements = []
        def capture(conn, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)
        db.session.expunge_all()
        event.listen(db.engine, "before_cursor_execute", capture)
        try:
            with rendered_contexts(application) as contexts:
                response = admin.get(url)
        finally:
            event.remove(db.engine, "before_cursor_execute", capture)
        assert response.status_code == 200
        return len(statements), contexts[-1][1]
    small, _ = reads("/issues")
    user = db.session.get(User, user_id)
    point = db.session.get(Point, point_id)
    for day in range(1, 55):
        legacy_record(user, point, day=day)
    db.session.commit()
    large, context = reads("/issues")
    assert large <= small + 2
    assert len(context["records"]) == 50 and context["open_total"] == 55
    assert context["pagination"] == {"page": 1, "pages": 2, "total": 55, "per_page": 50}
    _, second = reads("/issues?page=2")
    assert len(second["records"]) == 5
    assert not {row.id for row in context["records"]} & {row.id for row in second["records"]}
    assert admin.get("/issues?page=3").status_code == 404
    assert admin.get("/issues?status=closed").status_code == 400


def test_csv_appends_resolution_fields_and_preserves_abnormal_snapshot(application, seeded):
    point = feature_point()
    owner = logged_browser(application, seeded)
    row = abnormal(owner, point, note="=original")
    admin = admin_client(application)
    assert action(admin, row, note="@resolution").status_code == 302
    output = owner.get("/records/export?abnormal=1").get_data(as_text=True).lstrip("\ufeff")
    lines = list(csv.reader(io.StringIO(output)))
    assert len(lines) == 2 and len(lines[0]) == len(lines[1]) == 16
    assert lines[1][9:12] == ["是", "'=original", "1"]
    assert lines[1][12] == "已結案" and lines[1][13] == "Manager Charlie"
    assert lines[1][14] and lines[1][15] == "'@resolution"
    assert row.note == "=original" and row.is_abnormal
