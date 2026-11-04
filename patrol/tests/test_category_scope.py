"""Direct-route tests: UI filters are never the patrol authorization boundary."""
from datetime import date
from types import SimpleNamespace

import pytest
from sqlalchemy import event, update
from sqlalchemy.orm import Session

from models import Inspection, InspectionPhoto, IssueEvent, PointSchedule, User
from patrol_access import can_access_category
from test_app import application, seeded, approve_browser, db, login, rendered_contexts  # noqa: F401
from test_features import feature_point
from test_inspector_issues import make_case


def open_as(application, seeded, username="inspector"):
    client = application.test_client()
    login(client, username)
    approve_browser(client, seeded[username])
    return client


def render(application, client, route):
    with rendered_contexts(application) as contexts:
        response = client.get(route)
    assert response.status_code == 200
    return contexts[-1][1], response.get_data(as_text=True)


@pytest.fixture
def mixed(seeded):
    safety, user = seeded["daily"], seeded["inspector"]
    general = feature_point(frequency="daily", category="general", code="GENERAL-SECRET")
    general.name = "General private plant name"
    own = make_case(user, safety, 1, note="My safety observations")
    other = make_case(seeded["colleague"], safety, 2, note="Colleague private observations")
    foreign = make_case(user, general, 3, note="Former general observations")
    foreign.photos.append(InspectionPhoto(data=b"private-former-group", size_bytes=20, width=1, height=1))
    db.session.commit()
    return safety, general, own, other, foreign


def test_category_query_cannot_broaden_dashboard_missed_issues_records_or_exports(application, seeded, mixed):
    safety, general, own, _, foreign = mixed
    client = open_as(application, seeded)
    for category in ("", "general", "uncategorized"):
        params = f"category={category}"
        context, markup = render(application, client, "/dashboard?" + params)
        assert context["selected_category"] == "safety"
        assert {c["point"].id for c in context["cards"]} == {safety.id}
        assert [r.id for r in context["recent"]] == [own.id]
        assert context["open_issue_counts"] == {safety.id: 2}
        assert general.name not in markup and general.code not in markup
        date_filter = "&date_from=2026-01-01&date_to=2026-01-06"
        context, markup = render(application, client, "/issues?" + params)
        assert [r.id for r in context["records"]] == [own.id] and context["open_total"] == 1
        context, markup = render(application, client, "/records?" + params + date_filter)
        assert [r.id for r in context["records"]] == [own.id]
        context, _ = render(application, client, "/missed?" + params + date_filter)
        assert {r["category"] for r in context["occurrences"]} == {"safety"}
        assert general.id not in {r["point_id"] for r in context["point_summaries"]}
        for path in ("/records/export?", "/missed/export?"):
            response = client.get(path + params + date_filter)
            csv = response.get_data(as_text=True)
            assert response.status_code == 200 and safety.code in csv
            assert all(value not in csv for value in (general.name, general.code, foreign.note, "Colleague private observations"))


def test_general_team_dashboard_and_open_cases_follow_the_recorded_category(application, seeded, mixed):
    _, general, safety_case, _, team_case = mixed
    seeded["colleague"].patrol_category = "general"
    db.session.commit()
    client = open_as(application, seeded, "colleague")
    day = team_case.period_key
    dashboard, _ = render(application, client, f"/dashboard?date={day}&category=safety")
    assert [r.id for r in dashboard["recent"]] == [team_case.id]
    card = next(c for c in dashboard["cards"] if c["point"].id == general.id)
    assert card["latest"].id == team_case.id
    assert dashboard["totals"]["done"] == 1

    # Moving the point later must not hide the team's historical case or
    # expose the name used in its new category.
    general.category, general.name = "safety", "Current safety name"
    db.session.commit()
    issues, markup = render(application, client, f"/issues?point_id={general.id}&category=safety")
    assert [r.id for r in issues["records"]] == [team_case.id]
    assert issues["open_total"] == 1
    assert issues["selected_point"].name == team_case.point_name
    assert general.name not in markup and safety_case.note not in markup


def test_foreign_qr_id_photo_error_forms_and_binding_cannot_reveal_private_data(application, seeded, mixed):
    _, general, _, _, foreign = mixed
    client = open_as(application, seeded)
    client.get("/devices", query_string={"next": f"/c/{general.qr_token}"})
    with client.session_transaction() as session:
        assert "after_binding" not in session
    paths = (f"/c/{general.qr_token}", f"/issues?point_id={general.id}", f"/records/{foreign.id}",
             f"/checkins/{foreign.id}", f"/photos/{foreign.photos[0].id}")
    for path in paths:
        response = client.get(path)
        assert response.status_code == 404
        assert all(text not in response.get_data(as_text=True) for text in (general.name, foreign.note, "private-former-group"))
    for path, data in [(f"/c/{general.qr_token}/confirm", {"frequency": "daily"}),
                       (f"/issues/{foreign.id}/resolve", {"note": "", "expected_event_id": "bad"}),
                       (f"/admin/issues/{foreign.id}/resolve", {"note": "done", "expected_event_id": "0"})]:
        response = client.post(path, data=data)
        assert response.status_code == 404
        assert foreign.note not in response.get_data(as_text=True)
    assert db.session.query(Inspection).count() == 3 and foreign.issue.status == "open"
    assert not db.session.query(IssueEvent).count()


def test_admin_can_see_both_groups_and_uncategorized_but_staff_cannot_see_unassigned_points(application, seeded, mixed):
    _, general, _, _, foreign = mixed
    point = feature_point(category="uncategorized", code="UNASSIGNED-01")
    admin = open_as(application, seeded, "manager")
    staff = open_as(application, seeded)
    context, _ = render(application, admin, "/dashboard")
    assert {c["point"].category for c in context["cards"]} == {"safety", "general", "uncategorized"}
    assert admin.get(f"/c/{general.qr_token}").status_code == 200
    assert admin.get(f"/records/{foreign.id}").status_code == 200
    assert admin.get(f"/photos/{foreign.photos[0].id}").data == b"private-former-group"
    assert admin.get(f"/c/{point.qr_token}").status_code == 200
    assert staff.get(f"/c/{point.qr_token}").status_code == 404


def test_unassigned_inspector_gets_empty_lists_can_manage_devices_but_cannot_check_in(application, seeded, mixed):
    safety, _, own, _, _ = mixed
    user = seeded["inspector"]
    user.patrol_category = None
    db.session.commit()
    client = open_as(application, seeded)
    for path, key in [("/dashboard?category=safety", "cards"), ("/records?category=general", "records"),
                      ("/issues?category=safety", "records"), ("/missed?category=safety", "occurrences")]:
        ctx, _ = render(application, client, path)
        assert ctx[key] == []
        if "open_total" in ctx:
            assert ctx["open_total"] == 0
    for path in ["/records/export", "/missed/export"]:
        assert len(client.get(path).get_data(as_text=True).splitlines()) == 1
    assert client.get("/devices").status_code == 200
    assert client.get("/change-password").status_code == 200
    assert client.get(f"/records/{own.id}").status_code == 404
    assert client.post(f"/c/{safety.qr_token}/confirm", data={"frequency": "daily"}).status_code == 404
    assert not can_access_category(SimpleNamespace(role="inspector", patrol_category="untrusted"), "untrusted")


def test_history_uses_own_snapshot_without_exposing_the_new_teams_name(application, seeded, mixed):
    point, _, own, _, _ = mixed
    original_code, original_name = point.code, point.name
    point.category, point.code, point.name = "general", "NEW-FOREIGN", "New private general name"
    # The v4 rolling schema also permits historical schedules without labels.
    point.schedules.append(PointSchedule(effective_date=date(2026, 11, 2), category="general", frequency="daily",
                                         floor=point.floor, point_code=point.code, point_name=point.name, active=True))
    db.session.commit()
    admin = open_as(application, seeded, "manager")
    edit = {"category": "general", "frequency": point.frequency, "floor": str(point.floor),
            "code": point.code, "name": "Renamed after transfer", "active": "on"}
    assert admin.post(f"/admin/points/{point.id}/update", data=edit).status_code == 302
    old = point.schedules[0]
    assert (old.point_code, old.point_name, old.floor) == (None, None, None)
    client = open_as(application, seeded)
    ctx, markup = render(application, client, f"/issues?point_id={point.id}")
    assert (ctx["selected_point"].code, ctx["selected_point"].name) == (original_code, original_name)
    assert [r.id for r in ctx["records"]] == [own.id]
    for path in ("/dashboard?date=2026-11-01", "/missed?date_from=2026-11-01&date_to=2026-11-01",
                 f"/records/{own.id}", f"/checkins/{own.id}"):
        _, markup = render(application, client, path)
        assert point.name not in markup and point.code not in markup
        if path.startswith(("/dashboard", "/missed")):
            assert "樓層未記錄" in markup
    assert client.get(f"/c/{point.qr_token}").status_code == 404
    assert client.post(f"/issues/{own.id}/resolve", data={"expected_event_id": "0", "note": "handled"}).status_code == 302
    # Authorizations follow the account on subsequent requests, never the old
    # sign-in cookie or the fact that this user originally owned the report.
    seeded["inspector"].patrol_category = "general"
    db.session.commit()
    assert client.get(f"/records/{own.id}").status_code == 404
    assert client.get(f"/c/{point.qr_token}").status_code == 200


def test_cross_category_completion_satisfies_same_slot_without_exposing_old_receipt(application, seeded, mixed):
    point, _, _, _, _ = mixed
    actor = seeded["inspector"]
    client = open_as(application, seeded)
    assert client.post(f"/c/{point.qr_token}/confirm", data={"frequency": "daily", "note": "OLD-PRIVATE"}).status_code == 302
    point.category = actor.patrol_category = "general"
    db.session.commit()
    ctx, markup = render(application, client, f"/c/{point.qr_token}")
    assert ctx["existing"]["created_at"] is None and "OLD-PRIVATE" not in markup
    before = db.session.query(Inspection).count()
    response = client.post(f"/c/{point.qr_token}/confirm", data={"frequency": "daily"})
    assert response.status_code == 302 and response.location.endswith(f"/c/{point.qr_token}")
    assert db.session.query(Inspection).count() == before


@pytest.mark.parametrize("operation", ["checkin", "resolve"])
def test_locked_actor_category_is_rechecked_before_writing(application, seeded, mixed, operation):
    point, _, own, _, _ = mixed
    user_id = seeded["inspector"].id
    client = open_as(application, seeded)
    changed = []

    def transfer_on_actor_lock(state):
        if (not changed and state.is_select and getattr(state.statement, "_for_update_arg", None) is not None
                and any(getattr(column["entity"], "__name__", "") == "User" for column in state.statement.column_descriptions)):
            state.session.connection().execute(update(User).where(User.id == user_id).values(patrol_category="general"))
            changed.append(True)

    event.listen(Session, "do_orm_execute", transfer_on_actor_lock)
    try:
        response = (client.post(f"/c/{point.qr_token}/confirm", data={"frequency": "daily"})
                    if operation == "checkin" else client.post(f"/issues/{own.id}/resolve", data={"expected_event_id": "0", "note": "done"}))
    finally:
        event.remove(Session, "do_orm_execute", transfer_on_actor_lock)
    assert changed and response.status_code == 404
    assert own.issue.status == "open" and db.session.query(IssueEvent).count() == 0
    assert db.session.query(Inspection).count() == 3
