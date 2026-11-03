"""Regression coverage for safe return paths, expired forms and current authority."""
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from test_app import (  # noqa: F401: isolated fixtures
    application, seeded, app_module, db, login, approve_browser, record, rendered_contexts,
)
from models import Inspection, InspectionIssue, IssueEvent, Point, User


def source_query(location):
    return parse_qs(urlsplit(location).query, keep_blank_values=True)


def create_issue(user, point, day=0):
    instant = datetime(2026, 1, 1, 4) + timedelta(days=day)
    row = Inspection(user_id=user.id, point_id=point.id, created_at=instant, period_key=instant.date().isoformat(),
                     frequency="daily", slot="any", category=point.category, point_code=point.code, point_name=point.name,
                     point_floor=point.floor, user_name=user.display_name, is_abnormal=True, note="Original issue")
    row.issue = InspectionIssue(status="open", opened_at=instant)
    db.session.add(row)
    db.session.flush()
    return row


@pytest.mark.parametrize("source", [
    "/records?date_from=2026-11-01&date_to=2026-11-03&floor=1&category=uncategorized&abnormal=1&frequency=daily&user_id=1",
    "/issues?status=open&floor=1&category=uncategorized&point_id=1&page=2",
])
def test_detail_preserves_valid_list_return_context(application, seeded, source):
    row = record(seeded["inspector"], seeded["daily"])
    client = application.test_client()
    login(client, "manager")
    with rendered_contexts(application) as contexts:
        response = client.get(f"/records/{row.id}", query_string={"return_to": source})
    assert response.status_code == 200
    context = contexts[-1][1]
    assert urlsplit(context["back_url"]).path == urlsplit(source).path
    assert source_query(context["back_url"]) == source_query(source)
    assert context["back_label"] == ("返回異常追蹤" if source.startswith("/issues") else "返回巡檢紀錄")


@pytest.mark.parametrize("source", [
    "https://evil.example/records", "//evil.example/records", "/records#https://evil.example", "/devices",
    "/records?next=https://evil.example", "/records?floor=1&floor=2", "/records?floor=0", "/records?category=%00",
    "/records?date_from=2026-11-04&date_to=2026-11-03", "/records?date_from=2020-01-01&date_to=2026-11-03",
    "/issues?page=-1", "/issues?status=closed", "/issues?point_id=99999999999999", "/records?abnormal=maybe",
])
def test_invalid_return_target_falls_back_to_record_list(application, seeded, source):
    row = record(seeded["inspector"], seeded["daily"])
    client = application.test_client()
    login(client, "manager")
    with rendered_contexts(application) as contexts:
        response = client.get(f"/records/{row.id}", query_string={"return_to": source})
    assert response.status_code == 200
    assert contexts[-1][1]["back_url"] == "/records?category=uncategorized"


def test_staff_return_to_allows_own_issues_and_removes_other_user_filter(application, seeded):
    row = record(seeded["inspector"], seeded["daily"])
    client = application.test_client()
    login(client)
    with rendered_contexts(application) as contexts:
        client.get(f"/records/{row.id}", query_string={"return_to": "/issues?status=open"})
    assert contexts[-1][1]["back_url"] == "/issues?status=open"
    with rendered_contexts(application) as contexts:
        client.get(f"/records/{row.id}", query_string={"return_to": "/records?user_id=2&floor=1"})
    assert contexts[-1][1]["back_url"] == "/records?floor=1"


def test_resolve_reopen_and_error_keep_validated_return_target(application, seeded):
    row = create_issue(seeded["inspector"], seeded["daily"])
    db.session.commit()
    client = application.test_client()
    login(client, "manager")
    source = f"/issues?status=open&point_id={row.point_id}&page=2"
    for route, version, note in [("resolve", "0", "修復完成"), ("reopen", "1", "需再追蹤")]:
        if route == "reopen":
            version = str(db.session.scalar(db.select(IssueEvent.id)))
        response = client.post(f"/admin/issues/{row.id}/{route}", data={"expected_event_id": version, "note": note, "return_to": source})
        assert response.status_code == 302
        assert urlsplit(response.location).path == f"/records/{row.id}"
        assert source_query(response.location)["return_to"] == [source]
    with rendered_contexts(application) as contexts:
        response = client.post(f"/admin/issues/{row.id}/resolve", data={"expected_event_id": "0", "note": "", "return_to": source})
    assert response.status_code == 400 and contexts[-1][1]["back_url"] == source
    response = client.post(f"/admin/issues/{row.id}/resolve", data={"expected_event_id": str(db.session.scalar(db.select(db.func.max(IssueEvent.id)))),
        "note": "完成", "return_to": "https://evil.example/records"})
    assert response.status_code == 302 and "evil.example" not in response.location


def test_last_issue_on_second_page_resolves_then_return_clamps_to_last_page(application, seeded):
    rows = [create_issue(seeded["inspector"], seeded["daily"], day) for day in range(51)]
    db.session.commit()
    client = application.test_client()
    login(client, "manager")
    source = "/issues?status=open&category=uncategorized&floor=1&page=2"
    response = client.post(f"/admin/issues/{rows[0].id}/resolve", data={"expected_event_id": "0", "note": "最後一件處理完成", "return_to": source})
    assert response.status_code == 302
    with rendered_contexts(application) as contexts:
        client.get(response.location)
    response = client.get(contexts[-1][1]["back_url"])
    assert response.status_code == 302
    filters = source_query(response.location)
    assert filters["page"] == ["1"] and filters["status"] == ["open"] and filters["floor"] == ["1"]
    assert filters["category"] == ["uncategorized"]
    with rendered_contexts(application) as contexts:
        assert client.get(response.location).status_code == 200
    assert contexts[-1][1]["pagination"]["total"] == 50


def test_empty_issue_list_clamps_page_and_rejects_invalid_numbers(application, seeded):
    client = application.test_client()
    login(client, "manager")
    response = client.get("/issues?status=resolved&category=safety&page=999")
    assert response.status_code == 302 and source_query(response.location)["page"] == ["1"]
    assert source_query(response.location)["category"] == ["safety"]
    with rendered_contexts(application) as contexts:
        assert client.get(response.location).status_code == 200
    assert contexts[-1][1]["pagination"]["total"] == 0
    for page in ("no", "-1", "0", "9" * 30):
        assert client.get("/issues", query_string={"page": page}).status_code == 400


def test_concurrent_resolution_between_count_and_fetch_recovers_empty_last_page(application, seeded):
    rows = [create_issue(seeded["inspector"], seeded["daily"], day) for day in range(51)]
    db.session.commit()
    record_id, manager_id = rows[0].id, seeded["manager"].id
    client = application.test_client()
    login(client, "manager")
    injected = {"done": False}
    def close_before_fetch(state):
        statement = state.statement
        if (not injected["done"] and state.is_select and getattr(statement, "_limit_clause", None) is not None
                and "patrol_inspection_issues" in str(statement)):
            injected["done"] = True
            db.session.execute(db.update(InspectionIssue).where(InspectionIssue.inspection_id == record_id).values(
                status="resolved", resolved_at=datetime(2026, 11, 3, 4), resolved_by_id=manager_id,
                resolved_by_name="Manager", resolution_note="Concurrent completion"))
    event.listen(Session, "do_orm_execute", close_before_fetch)
    try:
        response = client.get("/issues?status=open&floor=1&page=2")
    finally:
        event.remove(Session, "do_orm_execute", close_before_fetch)
        db.session.rollback()
    assert injected["done"] and response.status_code == 302
    assert source_query(response.location)["page"] == ["1"]
    assert source_query(response.location)["status"] == ["open"] and source_query(response.location)["floor"] == ["1"]


def test_expired_checkin_session_reaches_safe_get_with_csrf_enabled(application, seeded):
    client = application.test_client()
    login(client)
    with client.session_transaction() as session:
        old_csrf = session["csrf_token"]
        session.clear()
    application.config["CSRF_ENABLED"] = True
    point = seeded["daily"]
    response = client.post(f"/c/{point.qr_token}/confirm", data={"csrf_token": old_csrf, "frequency": "daily", "slot": "any", "period_key": "2026-11-03"})
    assert response.status_code == 302
    assert urlsplit(response.location).path == "/login"
    assert source_query(response.location)["next"] == [f"/c/{point.qr_token}"]
    assert db.session.query(Inspection).count() == 0
    assert client.post("/login", data={"username": "inspector", "password": "anything"}).status_code == 400


def test_authenticated_invalid_csrf_still_fails_and_expired_issue_returns_to_detail(application, seeded):
    client = application.test_client()
    login(client, "manager")
    row = create_issue(seeded["inspector"], seeded["daily"])
    db.session.commit()
    application.config["CSRF_ENABLED"] = True
    assert client.post(f"/admin/issues/{row.id}/resolve", data={"note": "處理", "expected_event_id": "0"}).status_code == 400
    with client.session_transaction() as session:
        session.clear()
    source = "/issues?status=open&page=2"
    response = client.post(f"/admin/issues/{row.id}/resolve", data={"note": "處理", "expected_event_id": "0", "return_to": source})
    assert response.status_code == 302
    destination = source_query(response.location)["next"][0]
    assert urlsplit(destination).path == f"/records/{row.id}"
    assert source_query(destination)["return_to"] == [source]
    assert db.session.get(InspectionIssue, row.id).status == "open"


@pytest.mark.parametrize("mutation", ["create", "update", "rotate"])
@pytest.mark.parametrize("revocation", [{"role": "inspector"}, {"active": False}, {"auth_version": 2}])
def test_point_mutations_recheck_actor_after_lock(application, seeded, mutation, revocation):
    client = application.test_client()
    login(client, "manager")
    actor_id, point_id = seeded["manager"].id, seeded["daily"].id
    original_name, original_token = seeded["daily"].name, seeded["daily"].qr_token
    injected = {"done": False}
    def revoke_before_lock(state):
        if not injected["done"] and state.is_select and getattr(state.statement, "_for_update_arg", None) is not None and "patrol_users" in str(state.statement):
            injected["done"] = True
            db.session.execute(db.update(User).where(User.id == actor_id).values(**revocation).execution_options(synchronize_session=False))
    event.listen(Session, "do_orm_execute", revoke_before_lock)
    try:
        path = "/admin/points/create" if mutation == "create" else f"/admin/points/{point_id}/" + ("update" if mutation == "update" else "rotate-qr")
        response = client.post(path, data={"code": "1F-NEW99" if mutation == "create" else "1F-A01", "name": "Changed",
            "floor": "1", "frequency": "daily", "category": "uncategorized", "active": "on"})
    finally:
        event.remove(Session, "do_orm_execute", revoke_before_lock)
        db.session.rollback()
    assert injected["done"] and response.status_code == 403
    point = db.session.get(Point, point_id)
    assert point.name == original_name and point.qr_token == original_token
    assert db.session.scalar(db.select(Point).where(Point.code == "1F-NEW99")) is None


@pytest.mark.parametrize("posted_frequency", [None, "daily"])
def test_old_monday_form_cannot_silently_record_changed_weekly_frequency(application, seeded, monkeypatch, posted_frequency):
    monkeypatch.setattr(app_module, "now_utc", lambda: datetime(2026, 11, 2, 4, tzinfo=timezone.utc))
    client = application.test_client()
    login(client)
    approve_browser(client, seeded["inspector"])
    point = seeded["daily"]
    assert client.get(f"/c/{point.qr_token}").status_code == 200
    admin = application.test_client()
    login(admin, "manager")
    assert admin.post(f"/admin/points/{point.id}/update", data={"code": point.code, "name": point.name, "floor": "1",
        "frequency": "weekly", "category": "uncategorized", "active": "on"}).status_code == 302
    fields = {"slot": "any", "period_key": "2026-11-02", "note": "保留現場備註"}
    if posted_frequency is not None:
        fields["frequency"] = posted_frequency
    with rendered_contexts(application) as contexts:
        response = client.post(f"/c/{point.qr_token}/confirm", data=fields)
    assert response.status_code == 409
    assert contexts[-1][1]["note"] == "保留現場備註" and contexts[-1][1]["point"].frequency == "weekly"
    assert db.session.query(Inspection).count() == 0
    fields["frequency"] = "weekly"
    assert client.post(f"/c/{point.qr_token}/confirm", data=fields).status_code == 302
    assert db.session.scalar(db.select(Inspection.frequency)) == "weekly"
