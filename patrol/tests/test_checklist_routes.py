"""Online/offline checklist validation with isolated users and no production writes."""
import csv
import io
import json
from datetime import timedelta

import pytest
from werkzeug.datastructures import MultiDict

import app as patrol
from checklist_catalog import checklist_for_point
from checklist_records import checklist_snapshot, checklist_text
from models import Inspection, PatrolExecution, Point, User, db
from test_app import application, rendered_contexts
from test_daily2_anytime import anytime, form, rows
from test_offline_api import prepare, entry, sync, assert_error


def toilet(context, *, direct=False):
    point = context.direct_point if direct else context.pair_point
    point.name = "4M女廁所-甲"
    point.floor = 14
    if direct:
        point.code = "AB2-W01"
        point.frequency = "irregular"
        point.schedules[0].frequency = "irregular"
    db.session.commit()
    return point


def test_online_two_rounds_have_independent_checks_and_historical_snapshots(application, anytime):
    point = toilet(anytime)
    old = form(anytime.executor, anytime.paired)
    assert anytime.executor.post(anytime.paired + "/confirm", data=old).status_code == 400
    assert not rows(point, PatrolExecution)
    for choices in (["not-real"], ["toilet.soap", "toilet.soap"]):
        forged = MultiDict(old)
        forged.setlist("checklist", choices)
        assert anytime.executor.post(anytime.paired + "/confirm", data=forged).status_code == 400
    first = old | {"checklist": ["toilet.soap"]}
    assert anytime.executor.post(anytime.paired + "/confirm", data=first).status_code == 302
    assert anytime.executor.post(anytime.paired + "/confirm", data=first).status_code == 302
    assert len(rows(point, PatrolExecution)) == 1
    second = form(anytime.executor, anytime.paired)
    assert second["slot"] != first["slot"]
    response = anytime.executor.get(anytime.paired)
    assert 'value="toilet.soap" checked' not in response.text
    assert anytime.executor.post(anytime.paired + "/confirm", data=second).status_code == 400
    assert anytime.executor.post(anytime.paired + "/confirm", data=second | {"checklist": ["toilet.floor"]}).status_code == 302
    inspector = form(anytime.inspector, anytime.paired)
    assert anytime.inspector.post(anytime.paired + "/confirm", data=inspector).status_code == 400
    done = anytime.inspector.post(anytime.paired + "/confirm", data=inspector | {"checklist": ["toilet.mirror"]})
    assert done.status_code == 302
    record = rows(point)[0]
    assert checklist_snapshot(record)["selected"] == ["toilet.mirror"]
    assert checklist_snapshot(record.execution)["selected"] == ["toilet.soap"]
    assert "☑ 鏡面乾淨" in checklist_text(record) and "☐ 地面清潔" in checklist_text(record)
    point.name = "renamed after completion"
    db.session.commit()
    assert "鏡面乾淨" in checklist_text(record)
    csv_response = anytime.inspector.get("/records/export?date_from=2026-11-06&date_to=2026-11-06")
    data = list(csv.reader(io.StringIO(csv_response.data.decode("utf-8-sig"))))
    assert len(data) == 2 and "☑ 鏡面乾淨" in data[1][-2] and "☑ 洗手乳充足" in data[1][-1]


@pytest.mark.parametrize("stage", ["execute", "visit", "inspect"])
def test_offline_each_stage_rejects_empty_and_forged_then_keeps_receipt(application, anytime, stage):
    direct = stage != "execute"
    point = toilet(anytime, direct=direct)
    if stage == "visit":
        application.config["EXECUTOR_VISIT_CODES"] = frozenset({point.code})
    client = anytime.executor if stage != "inspect" else anytime.inspector
    url = anytime.direct if direct else anytime.paired
    prepared = prepare(client)
    assert prepared["checklist_version"] == 1
    definition = next(p["checklist"] for p in prepared["points"] if p["id"] == point.id)
    assert len(definition["items"]) == 7 and definition["items"][0]["label"]["id"]
    draft = entry(prepared, url, anytime.clock[0])
    for changes in ({}, {"checklist": []}, {"checklist": ["dining.a1"]}, {"checklist": ["toilet.soap"] * 2}):
        assert_error(sync(client, prepared, draft | changes), "invalid_checklist")
    accepted = draft | {"checklist": ["toilet.soap"]}
    assert sync(client, prepared, accepted).get_json()["status"] == "saved"
    point.name = "changed after receipt"
    db.session.commit()
    # ACK-lost replay resolves before current settings/checkbox validation.
    assert sync(client, prepared, accepted).get_json()["status"] == "already_synced"
    assert_error(sync(client, prepared, accepted | {"checklist": ["toilet.floor"]}), "payload_conflict")
    model = PatrolExecution if stage == "execute" else Inspection
    assert len(rows(point, model)) == 1
    assert checklist_snapshot(rows(point, model)[0])["selected"] == ["toilet.soap"]


def test_old_receipt_without_checklist_replays_after_point_becomes_toilet(application, anytime):
    prepared = prepare(anytime.executor)
    draft = entry(prepared, anytime.paired, anytime.clock[0])
    assert "checklist" not in draft
    assert sync(anytime.executor, prepared, draft).get_json()["status"] == "saved"
    toilet(anytime)
    assert sync(anytime.executor, prepared, draft).get_json()["status"] == "already_synced"
    assert_error(sync(anytime.executor, prepared, draft | {"checklist": []}), "payload_conflict")


def test_old_unsubmitted_grant_cannot_bypass_new_checklist(application, anytime):
    prepared = prepare(anytime.executor)
    draft = entry(prepared, anytime.paired, anytime.clock[0])
    toilet(anytime)
    assert_error(sync(anytime.executor, prepared, draft), "point_changed")
    assert not rows(anytime.pair_point, PatrolExecution)


@pytest.mark.parametrize("language", ["zh-Hant", "id", "vi"])
def test_checklist_language_and_scoped_profile(application, anytime, language):
    point = toilet(anytime)
    user = db.session.scalar(db.select(User).where(User.username == "exec"))
    user.ui_language, user.simple_executor_ui = language, True
    db.session.commit()
    response = anytime.executor.get(anytime.paired)
    assert response.status_code == 200
    for item in checklist_for_point(point)["items"]:
        assert item["label"][language] in response.text
    point.category = "safety"
    assert checklist_for_point(point) is None


def test_issues_default_week_and_explicit_all_dates(application, anytime):
    with rendered_contexts(application) as pages:
        response = anytime.admin.get("/issues")
    assert response.status_code == 200
    assert pages[-1][1]["filters"]["date_from"] == "2026-10-31"
    assert pages[-1][1]["filters"]["date_to"] == "2026-11-06"
    with rendered_contexts(application) as pages:
        response = anytime.admin.get("/issues?date_from=&date_to=")
    assert response.status_code == 200
    assert pages[-1][1]["filters"]["date_from"] == pages[-1][1]["filters"]["date_to"] == ""
    user = db.session.scalar(db.select(User).where(User.username == "admin"))
    assert patrol.normalise_return_to("/issues?status=open&date_from=&date_to=", user).endswith("date_from=&date_to=")


def test_issue_xlsx_includes_both_stage_checklist_snapshots(application, anytime):
    from openpyxl import load_workbook
    toilet(anytime)
    assert anytime.executor.post(anytime.paired + "/confirm", data=form(anytime.executor, anytime.paired) | {
        "checklist": ["toilet.soap"]}).status_code == 302
    assert anytime.inspector.post(anytime.paired + "/confirm", data=form(anytime.inspector, anytime.paired) | {
        "checklist": ["toilet.mirror"], "note": "需要補清潔", "is_abnormal": "1"}).status_code == 302
    response = anytime.admin.get("/issues/export.xlsx")
    assert response.status_code == 200
    workbook = load_workbook(io.BytesIO(response.data))
    cells = [cell.value for sheet in workbook for row in sheet for cell in row if isinstance(cell.value, str)]
    assert "巡檢點檢項目" in cells and "☑ 鏡面乾淨" in cells
    assert "對應執行點檢項目" in cells and "☑ 洗手乳充足" in cells
    assert any("☐ 地面清潔" in v for v in cells)


def test_corrupt_historical_snapshot_never_crashes_export_helpers():
    from types import SimpleNamespace
    for snapshot in ({"title": {}, "items": [], "selected": []},
                     {"title": {"zh-Hant": "點檢"}, "items": [{"id": "a", "label": {"zh-Hant": None}}], "selected": ["a"]}):
        record = SimpleNamespace(checklist_data=json.dumps(snapshot))
        assert checklist_snapshot(record) is None and checklist_text(record) == ""
