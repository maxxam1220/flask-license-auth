"""Inspectors may resolve their own reports; other reporters stay private."""
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from test_app import application, seeded, db, login, rendered_contexts  # noqa: F401
from models import Inspection, InspectionIssue, InspectionPhoto, IssueEvent, User
from issues import IssueActionError, open_issue_counts, transition_issue


def make_case(user, point, day, *, legacy=False, resolved=False, note="Private issue"):
    instant = datetime(2026, 1, 1, 4) + timedelta(days=day)
    row = Inspection(user_id=user.id, point_id=point.id, created_at=instant, period_key=instant.date().isoformat(),
                     frequency="daily", slot="any", category=point.category, point_code=point.code,
                     point_name=point.name, point_floor=point.floor, user_name=user.display_name,
                     is_abnormal=True, note=note)
    if not legacy:
        row.issue = InspectionIssue(status="open", opened_at=instant)
        if resolved:
            row.issue.status = "resolved"
            row.issue.resolved_at = instant + timedelta(hours=1)
            row.issue.resolved_by_id = user.id
            row.issue.resolved_by_name = user.display_name
            row.issue.resolution_note = "Previously resolved"
            row.issue.events.append(IssueEvent(actor_id=user.id, actor_name=user.display_name, action="resolved",
                                               note="Previously resolved", created_at=instant + timedelta(hours=1)))
    db.session.add(row)
    db.session.flush()
    return row


@pytest.fixture
def cases(application, seeded):
    point = seeded["daily"]
    own = make_case(seeded["inspector"], point, 1, note="OWN-PRIVATE-NOTE")
    other = make_case(seeded["colleague"], point, 2, note="OTHER-SECRET-NOTE")
    own_legacy = make_case(seeded["inspector"], point, 3, legacy=True, note="OWN-LEGACY-NOTE")
    other_legacy = make_case(seeded["colleague"], point, 4, legacy=True, note="OTHER-LEGACY-SECRET")
    own_resolved = make_case(seeded["inspector"], point, 5, resolved=True)
    for row, payload in ((own, b"OWN-PHOTO-BYTES"), (other, b"OTHER-SECRET-PHOTO")):
        row.photos.append(InspectionPhoto(data=payload, size_bytes=len(payload), width=1, height=1))
    db.session.commit()
    return {"own": own, "other": other, "own_legacy": own_legacy,
            "other_legacy": other_legacy, "own_resolved": own_resolved}


def staff_client(application):
    client = application.test_client()
    login(client, "inspector")
    return client


def resolve(client, row, *, version="0", note="Original reporter resolved it", return_to=""):
    return client.post(f"/issues/{row.id}/resolve", data={
        "expected_event_id": str(version), "note": note, "return_to": return_to})


def test_own_issue_counts_lists_notes_and_photos_are_isolated(application, seeded, cases):
    user, point = seeded["inspector"], seeded["daily"]
    assert open_issue_counts(user_id=user.id) == {point.id: 2}
    assert open_issue_counts([point.id], user_id=user.id) == {point.id: 2}
    assert open_issue_counts([], user_id=user.id) == {}
    assert open_issue_counts() == {point.id: 4}
    client = staff_client(application)
    for query, expected in [("", {cases["own"].id, cases["own_legacy"].id}),
                            ("?status=resolved", {cases["own_resolved"].id}),
                            (f"?status=all&user_id={seeded['colleague'].id}",
                             {cases["own"].id, cases["own_legacy"].id, cases["own_resolved"].id})]:
        with rendered_contexts(application) as contexts:
            response = client.get("/issues" + query)
        assert response.status_code == 200
        context = contexts[-1][1]
        assert {row.id for row in context["records"]} == expected
        assert context["pagination"]["total"] == len(expected)
        assert context["open_total"] == 2
        assert "OTHER-SECRET" not in response.get_data(as_text=True)
        assert "OTHER-LEGACY-SECRET" not in response.get_data(as_text=True)
        assert seeded["colleague"].display_name not in response.get_data(as_text=True)
    assert client.get(f"/photos/{cases['own'].photos[0].id}").data == b"OWN-PHOTO-BYTES"
    assert client.get(f"/photos/{cases['other'].photos[0].id}").status_code == 403
    assert client.get(f"/records/{cases['other'].id}").status_code == 403
    assert client.get(f"/checkins/{cases['other'].id}").status_code == 403
    for key in ("own", "own_resolved"):
        with rendered_contexts(application) as contexts:
            response = client.get(f"/records/{cases[key].id}")
        assert response.status_code == 200
        assert contexts[-1][1]["can_manage_issue"] is True
        assert contexts[-1][1]["can_reopen_issue"] is False


@pytest.mark.parametrize("case_key", ["other", "other_legacy"])
@pytest.mark.parametrize("note,version", [("Forged update", "0"), ("", ""), ("bad\x00note", "-1")])
def test_forged_other_owner_post_is_403_before_validation_and_never_leaks_or_creates_issue(application, seeded, cases, case_key, note, version):
    client = staff_client(application)
    before_issues = db.session.query(InspectionIssue).count()
    before_events = db.session.query(IssueEvent).count()
    response = resolve(client, cases[case_key], note=note, version=version)
    assert response.status_code == 403
    assert cases[case_key].note not in response.get_data(as_text=True)
    assert db.session.query(InspectionIssue).count() == before_issues
    assert db.session.query(IssueEvent).count() == before_events
    if case_key == "other_legacy":
        assert db.session.get(InspectionIssue, cases[case_key].id) is None
    else:
        assert db.session.get(InspectionIssue, cases[case_key].id).status == "open"


@pytest.mark.parametrize("case_key", ["own", "own_legacy"])
def test_reporter_can_resolve_own_existing_or_legacy_issue_once(application, seeded, cases, case_key):
    row = cases[case_key]
    client = staff_client(application)
    before_note = row.note
    source = "/issues?status=open&category=safety&floor=1"
    response = resolve(client, row, return_to=source)
    assert response.status_code == 302
    assert parse_qs(urlsplit(response.location).query)["return_to"] == [source]
    issue = db.session.get(InspectionIssue, row.id)
    assert issue.status == "resolved" and issue.opened_at == row.created_at
    assert issue.resolved_by_id == seeded["inspector"].id
    assert issue.resolved_by_name == seeded["inspector"].display_name
    assert issue.resolution_note == "Original reporter resolved it"
    assert row.note == before_note and row.is_abnormal
    events = db.session.scalars(db.select(IssueEvent).where(IssueEvent.inspection_id == row.id)).all()
    assert len(events) == 1 and events[0].action == "resolved" and events[0].actor_id == seeded["inspector"].id
    assert resolve(client, row).status_code == 302
    assert db.session.query(IssueEvent).filter_by(inspection_id=row.id).count() == 1


def test_inspector_cannot_reopen_own_issue_but_admin_can(application, seeded, cases):
    row = cases["own_resolved"]
    version = row.issue.events[-1].id
    client = staff_client(application)
    assert client.post(f"/admin/issues/{row.id}/reopen", data={"expected_event_id": str(version), "note": "Trying to reopen"}).status_code == 403
    with pytest.raises(IssueActionError) as blocked:
        transition_issue(row.id, "open", seeded["inspector"], str(version), "Trying to reopen", datetime(2026, 11, 3, 4))
    assert blocked.value.status == 403
    assert db.session.get(InspectionIssue, row.id).status == "resolved"
    admin = application.test_client()
    login(admin, "manager")
    assert admin.post(f"/admin/issues/{row.id}/reopen", data={"expected_event_id": str(version), "note": "Administrator reopened"}).status_code == 302
    assert db.session.get(InspectionIssue, row.id).status == "open"
    assert resolve(client, row, version=version).status_code == 409
    assert db.session.get(InspectionIssue, row.id).status == "open"


def test_low_level_ownership_is_checked_before_parsing_note(application, seeded, cases):
    class MustNotParse:
        def strip(self):
            raise AssertionError("Unauthorized note was parsed")

    with pytest.raises(IssueActionError) as blocked:
        transition_issue(cases["other_legacy"].id, "resolved", seeded["inspector"], "", MustNotParse(), datetime(2026, 11, 3, 4))
    assert blocked.value.status == 403
    assert db.session.get(InspectionIssue, cases["other_legacy"].id) is None


@pytest.mark.parametrize("category", ["safety", "general"])
def test_author_is_rechecked_after_inspection_lock(application, seeded, cases, category):
    row = cases["own_legacy"]
    seeded["inspector"].patrol_category = row.category = category
    db.session.commit()
    client = staff_client(application)
    injected = {"done": False}
    def change_owner_before_lock(state):
        if (not injected["done"] and state.is_select and getattr(state.statement, "_for_update_arg", None) is not None
                and "FROM patrol_inspections" in str(state.statement)):
            injected["done"] = True
            db.session.execute(db.update(Inspection).where(Inspection.id == row.id).values(
                user_id=seeded["colleague"].id).execution_options(synchronize_session=False))
    event.listen(Session, "do_orm_execute", change_owner_before_lock)
    try:
        response = resolve(client, row)
    finally:
        event.remove(Session, "do_orm_execute", change_owner_before_lock)
        db.session.rollback()
    assert injected["done"] and response.status_code == 403
    assert db.session.get(InspectionIssue, row.id) is None


@pytest.mark.parametrize("revocation", [{"role": "inspector"}, {"active": False}, {"auth_version": 2}])
def test_changed_actor_authority_cannot_resolve_someone_elses_report(application, seeded, cases, revocation):
    client = application.test_client()
    login(client, "manager")
    actor_id = seeded["manager"].id
    injected = {"done": False}
    def revoke_before_lock(state):
        if (not injected["done"] and state.is_select and getattr(state.statement, "_for_update_arg", None) is not None
                and "FROM patrol_users" in str(state.statement)):
            injected["done"] = True
            db.session.execute(db.update(User).where(User.id == actor_id).values(**revocation).execution_options(synchronize_session=False))
    event.listen(Session, "do_orm_execute", revoke_before_lock)
    try:
        response = resolve(client, cases["own"])
    finally:
        event.remove(Session, "do_orm_execute", revoke_before_lock)
        db.session.rollback()
    assert injected["done"] and response.status_code == 403
    assert db.session.get(InspectionIssue, cases["own"].id).status == "open"


def test_own_list_pagination_filters_and_safe_return_never_count_other_owners(application, seeded):
    for day in range(1, 52):
        make_case(seeded["inspector"], seeded["daily"], day)
    for day in range(101, 106):
        make_case(seeded["colleague"], seeded["daily"], day, note="NOT-MY-REPORT")
    db.session.commit()
    client = staff_client(application)
    source = "/issues?status=open&floor=1&category=safety&page=2"
    with rendered_contexts(application) as contexts:
        response = client.get(source)
    assert response.status_code == 200
    context = contexts[-1][1]
    assert context["pagination"] == {"page": 2, "pages": 2, "total": 51, "per_page": 50}
    assert context["open_total"] == 51 and len(context["records"]) == 1
    row = context["records"][0]
    assert row.user_id == seeded["inspector"].id
    with rendered_contexts(application) as contexts:
        response = client.get(f"/records/{row.id}", query_string={"return_to": source})
    assert response.status_code == 200 and contexts[-1][1]["back_url"] == source
    response = resolve(client, row, return_to=source)
    assert response.status_code == 302
    assert parse_qs(urlsplit(response.location).query)["return_to"] == [source]
    response = client.get(source)
    assert response.status_code == 302 and parse_qs(urlsplit(response.location).query)["page"] == ["1"]
    with rendered_contexts(application) as contexts:
        client.get(response.location)
    assert contexts[-1][1]["pagination"]["total"] == 50 and contexts[-1][1]["open_total"] == 50
    assert all(item.user_id == seeded["inspector"].id for item in contexts[-1][1]["records"])
