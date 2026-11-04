"""General-team attendance is readable by inspection category at submission."""
from datetime import datetime
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from app import normalise_return_to
from issues import open_issue_for
from models import DeviceBinding, Inspection, InspectionPhoto, IssueEvent, PatrolExecution, User, db
from test_app import application, rendered_contexts, seeded  # noqa: F401
from test_workflow_reports import context, csv_rows, open_as, point, values, workflow  # noqa: F401


DATES = "date_from=2026-11-01&date_to=2026-11-03"


@pytest.fixture
def reports(seeded, workflow):
    worker, reader, _, pair, _ = workflow
    def member(username, category):
        user = User(username=username, display_name=username, password_hash=reader.password_hash,
                    role="inspector", patrol_category=category)
        db.session.add(user)
        db.session.flush()
        db.session.add(DeviceBinding(user_id=user.id, token_hash=f"test-actor-{user.id}", status="approved"))
        db.session.flush()
        return user
    author, safety = member("general-at-submission", "general"), member("safety-only", "safety")
    first = PatrolExecution(**values(worker, pair, "am"))
    db.session.add(first)
    db.session.flush()
    incident = Inspection(**values(author, pair, "am"), workflow_mode="two_stage", execution_id=first.id,
                          note="General handover note", is_abnormal=True)
    incident.photos.append(InspectionPhoto(data=b"general-photo", size_bytes=13, width=1, height=1))
    open_issue_for(incident)
    direct_point = point("1F-DIRECT-REPORT", "spot", frequency="irregular")
    direct = Inspection(**values(worker, direct_point, "any"), workflow_mode="spot",
                        executor_visit=True, spot_request_id="1"*32)
    historical = Inspection(**(values(author, pair, "pm") | {
        "frequency": "daily", "slot": "any", "period_key": "2026-11-01", "created_at": datetime(2026,11,1),
        "user_name": "", "point_name": "", "point_code": ""}))
    other = Inspection(**values(safety, seeded["daily"], "any"), note="SAFETY-ONLY-REPORT")
    other.photos.append(InspectionPhoto(data=b"safety-photo", size_bytes=12, width=1, height=1))
    db.session.add_all([incident, direct, historical, other])
    db.session.commit()
    # All authorizations and report fallbacks must survive this transfer.
    author.patrol_category, author.active = "safety", False
    author.display_name = "PRIVATE-CURRENT-SAFETY-NAME"
    pair.category, pair.workflow_mode, pair.name, pair.code = "safety", "standard", "PRIVATE-CURRENT-POINT", "1F-SAFE-NEW"
    db.session.commit()
    return SimpleNamespace(worker=worker, reader=reader, author=author, safety=safety, pair=pair,
                           first=first, incident=incident, direct=direct, historical=historical, other=other)


def test_general_reads_both_stages_and_saved_names_without_exposing_other_categories(application, reports):
    r = reports
    client = open_as(application, r.reader)
    filters = DATES + "&category=safety"
    visible = context(application, client, "/records?" + filters)
    assert visible["filters"]["category"] == "general" and not visible["filters"]["user_id"]
    assert {v.id for v in visible["records"]} == {r.incident.id, r.direct.id, r.historical.id}
    assert {(u.id, u.display_name) for u in visible["users"]} == {
        (r.worker.id, r.worker.display_name), (r.author.id, r.incident.user_name)}
    for outcome, expected in (("0", r.historical), ("1", r.incident)):
        query = f"{filters}&abnormal={outcome}"
        assert [v.id for v in context(application, client, "/records?" + query)["records"]] == [expected.id]
        data = csv_rows(client.get("/records/export?" + query))
        assert len(data) == 2 and data[1][9] == ("是" if outcome == "1" else "否")
    reports_url = f"/records?{DATES}&user_id={r.author.id}&stage=inspection"
    assert [v.id for v in context(application, client, reports_url)["records"]] == [r.incident.id, r.historical.id]
    assert not context(application, client, f"/records?{filters}&user_id={r.safety.id}")["records"]
    assert client.get(f"/records?{filters}&user_id=invalid").status_code == 400
    html = client.get(reports_url).text
    csv_data = csv_rows(client.get(reports_url.replace("/records?", "/records/export?")))
    assert len(csv_data) == 3 and csv_data[1][10] == r.incident.note and csv_data[1][11] == "1"
    assert csv_data[2][0] == f"人員 {r.author.id}"
    assert csv_data[2][2:4] == [f"#{r.pair.id}", "歷史巡檢點"]
    for private in (r.author.display_name, r.pair.code, r.pair.name, r.other.note, r.safety.display_name):
        assert private not in html and private not in str(csv_data)
    first_url = f"/records?{DATES}&stage=execution&user_id={r.worker.id}"
    executions = context(application, client, first_url)
    assert [e.id for e in executions["executions"]] == [r.first.id] and executions["reviewed_execution_ids"] == {r.first.id}
    assert [(u.id, u.display_name) for u in executions["users"]] == [(r.worker.id, r.first.user_name)]
    assert len(csv_rows(client.get(first_url.replace("/records?", "/records/export?")))) == 2
    assert parse_qs(urlsplit(normalise_return_to(reports_url, r.reader)).query)["user_id"] == [str(r.author.id)]
    for url, source in ((f"/records/{r.incident.id}", reports_url), (f"/checkins/{r.incident.id}", reports_url),
                        (f"/executions/{r.first.id}/success", first_url)):
        with rendered_contexts(application) as contexts:
            response = client.get(url, query_string={"return_to": source})
        assert response.status_code == 200 and contexts[-1][1]["back_url"] == source
    visit = client.get(f"/records/{r.direct.id}", query_string={"return_to": reports_url})
    assert visit.status_code == 302 and parse_qs(urlsplit(visit.location).query)["return_to"] == [reports_url]
    assert context(application, client, visit.location)["stage"] == "visit"


def test_colleague_can_read_incident_and_photo_but_cannot_change_issue(application, reports):
    r = reports
    client = open_as(application, r.reader)
    detail = context(application, client, f"/records/{r.incident.id}")
    assert not detail["can_manage_issue"] and not detail["can_reopen_issue"]
    assert client.get(f"/photos/{r.incident.photos[0].id}").data == b"general-photo"
    for path in (f"/records/{r.other.id}", f"/checkins/{r.other.id}", f"/photos/{r.other.photos[0].id}"):
        assert client.get(path).status_code == 404
    for path in (f"/issues/{r.incident.id}/resolve", f"/admin/issues/{r.incident.id}/reopen"):
        assert client.post(path, data={"expected_event_id": "0", "note": "not the author"}).status_code == 403
    assert r.incident.issue.status == "open" and db.session.query(IssueEvent).count() == 0
    executor = open_as(application, r.worker)
    assert executor.get(f"/photos/{r.incident.photos[0].id}").status_code == 403
    assert [v.id for v in context(application, executor, f"/records?{DATES}&stage=inspection&user_id={r.author.id}")["records"]] == [r.direct.id]
    safety = open_as(application, r.safety)
    assert safety.get("/records?stage=execution").status_code == 403
    assert safety.get(f"/executions/{r.first.id}/success").status_code == 404
    assert safety.get(f"/checkins/{r.direct.id}").status_code == 404
    assert [v.id for v in context(application, safety, f"/records?{DATES}&category=general&user_id={r.author.id}")["records"]] == [r.other.id]
