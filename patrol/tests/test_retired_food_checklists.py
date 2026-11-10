"""Retired food checklists disappear from new forms, not from saved evidence."""
import csv
import io

import pytest
from openpyxl import load_workbook

from checklist_catalog import checklist_for_point, retired_checklist_for_point, validate_checklist_definition
from checklist_records import checklist_snapshot, checklist_text, encode_checklist
from models import Inspection, PatrolExecution, User, db
from test_app import application
from test_daily2_anytime import anytime, context, form, rows
from test_offline_api import prepare, entry, sync


def food_point(a, name, *, direct=False):
    point = a.direct_point if direct else a.pair_point
    point.name, point.floor = name, 14
    point.schedules[0].point_name, point.schedules[0].floor = name, 14
    db.session.commit()
    return point


@pytest.mark.parametrize("name", ["員工餐廳", "餐廳", "廚房"])
@pytest.mark.parametrize("language", ["zh-Hant", "id", "vi"])
def test_food_execution_and_inspection_confirm_without_checklist(application, anytime, name, language):
    a = anytime
    point = food_point(a, name)
    executor = db.session.scalar(db.select(User).where(User.username == "exec"))
    executor.ui_language, executor.simple_executor_ui = language, True
    db.session.commit()
    original_token, original_mode, original_frequency = point.qr_token, point.workflow_mode, point.frequency
    assert not context(application, a.inspector, a.paired)[1]["can_confirm"]
    for client, model in ((a.executor, PatrolExecution), (a.inspector, Inspection)):
        page, shown = context(application, client, a.paired)
        assert shown["checkin_checklist"] is None and 'name="checklist"' not in page.text
        assert shown["can_confirm"]
        response = client.post(a.paired + "/confirm", data=form(client, a.paired))
        assert response.status_code == 302, response.text
        record = rows(point, model)[0]
        assert record.checklist_data == "" and checklist_snapshot(record) is None
    assert rows(point)[0].execution_id == rows(point, PatrolExecution)[0].id
    assert (point.qr_token, point.workflow_mode, point.frequency) == (original_token, original_mode, original_frequency)


@pytest.mark.parametrize("name", ["員工餐廳", "廚房"])
@pytest.mark.parametrize("stage", ["execute", "inspect"])
def test_new_offline_preparation_has_no_food_checklist(application, anytime, name, stage):
    a = anytime
    point = food_point(a, name, direct=stage == "inspect")
    client, url = (a.executor, a.paired) if stage == "execute" else (a.inspector, a.direct)
    prepared = prepare(client)
    configured = next(p for p in prepared["points"] if p["id"] == point.id)
    assert configured["checklist"] is None
    response = sync(client, prepared, entry(prepared, url, a.clock[0]))
    assert response.status_code == 200 and response.json["status"] == "saved", response.text
    record = rows(point, PatrolExecution if stage == "execute" else Inspection)[0]
    assert record.checklist_data == ""


def test_direct_kitchen_keeps_inspector_only_access_without_checklist(application, anytime):
    a = anytime
    point = food_point(a, "廚房", direct=True)
    assert a.executor.get(a.direct).status_code == 404
    assert all(p["id"] != point.id for p in prepare(a.executor)["points"])
    page, shown = context(application, a.inspector, a.direct)
    assert shown["checkin_checklist"] is None and 'name="checklist"' not in page.text
    response = a.inspector.post(a.direct + "/confirm", data=form(a.inspector, a.direct))
    assert response.status_code == 302 and rows(point)[0].checklist_data == ""


@pytest.mark.parametrize("name,item,expected", [
    ("員工餐廳", "dining.a1", "☑ A1 洗手槽(廚餘)"),
    ("廚房", "kitchen.b1", "☑ B1 洗碗區"),
])
def test_saved_food_checklists_remain_in_receipts_csv_and_issue_xlsx(application, anytime, name, item, expected):
    a = anytime
    point = food_point(a, name)
    execution_response = a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired))
    inspection_response = a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired) | {
        "is_abnormal": "1", "note": "Historical food checklist evidence"})
    assert execution_response.status_code == inspection_response.status_code == 302
    # Seed a genuine historical-format snapshot without reactivating current rules.
    encoded = encode_checklist(validate_checklist_definition(retired_checklist_for_point(point), [item]))
    execution, inspection = rows(point, PatrolExecution)[0], rows(point)[0]
    execution.checklist_data = inspection.checklist_data = encoded
    db.session.commit()
    assert checklist_for_point(point) is None
    for client, response, record in ((a.executor, execution_response, execution),
                                     (a.inspector, inspection_response, inspection)):
        page = client.get(response.location)
        assert page.status_code == 200 and 'class="checklist-snapshot"' in page.text
        assert expected in checklist_text(record)
    exported = a.admin.get("/records/export?date_from=2026-11-06&date_to=2026-11-06")
    data = list(csv.reader(io.StringIO(exported.data.decode("utf-8-sig"))))
    assert expected in data[1][-2] and expected in data[1][-1]
    xlsx = a.admin.get("/issues/export.xlsx")
    assert xlsx.status_code == 200
    workbook = load_workbook(io.BytesIO(xlsx.data))
    cells = [cell.value for sheet in workbook for row in sheet for cell in row if isinstance(cell.value, str)]
    assert sum(expected in value for value in cells) >= 2
    assert execution.checklist_data == inspection.checklist_data == encoded
