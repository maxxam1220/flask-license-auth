"""Historical slot deadlines and scoped reads for the general-affairs workflows."""
import csv
from datetime import date, datetime, timezone
import io

import pytest
from models import DeviceBinding, Inspection, PatrolExecution, Point, PointSchedule, User, db
from test_app import app_module, application, seeded, login, rendered_contexts  # noqa: F401

DAY = date(2026, 11, 2)
RANGE = "date_from=2026-11-02&date_to=2026-11-02&category=general"


def plan(point, day, mode, changed=None):
    point.schedules.append(PointSchedule(effective_date=day, active=True, frequency=point.frequency,
        category="general", workflow_mode=mode, floor=point.floor, point_code=point.code,
        point_name=point.name, workflow_changed_at=changed))


def point(code, mode):
    item = Point(code=code, name=code, floor=1, category="general", active=True, frequency="daily2",
                 workflow_mode=mode, schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
    plan(item, item.schedule_start, mode)
    db.session.add(item)
    db.session.flush()
    return item


@pytest.fixture
def workflow(seeded):
    worker = seeded["inspector"]
    worker.role, worker.patrol_category = "executor", "general"
    reviewer = seeded["colleague"]
    reviewer.patrol_category = "general"
    other = User(username="executor-two", display_name="PRIVATE-SECOND-EXECUTOR", role="executor",
                 patrol_category="general", password_hash=worker.password_hash, must_change_password=False)
    db.session.add(other)
    db.session.flush()
    for user in (worker, reviewer, other):
        db.session.add(DeviceBinding(user_id=user.id, token_hash=f"unused-report-fixture-{user.id}", status="approved"))
    scheduled, spot = point("1F-TWO", "two_stage"), point("1F-SPOT", "spot")
    db.session.commit()
    return worker, reviewer, other, scheduled, spot


def values(user, item, slot):
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == user.id))
    return dict(user_id=user.id, user_name=user.display_name, binding_id=binding.id, point_id=item.id,
                point_code=item.code, point_name=item.name, point_floor=item.floor, category=item.category, slot=slot,
                frequency=item.frequency, period_key=DAY.isoformat(), created_at=datetime(2026, 11, 2, 1 if slot=="am" else 7))


def open_as(app, user):
    client=app.test_client()
    assert login(client,user.username).status_code==302
    return client


def context(app, client, url):
    with rendered_contexts(app) as contexts:
        response=client.get(url)
    assert response.status_code==200
    return contexts[-1][1]


def csv_rows(response):
    assert response.status_code==200
    return list(csv.reader(io.StringIO(response.data.decode("utf-8-sig"))))


def test_spot_never_in_denominator_or_missed_and_two_stages_count_one_slot(application, workflow):
    worker, reviewer, _, pair, spot = workflow
    db.session.add(PatrolExecution(**values(worker,pair,"am")))
    for token in ("a"*64,"b"*64):
        db.session.add(Inspection(**values(reviewer,spot,"am"),workflow_mode="spot",spot_request_id=token))
    db.session.commit()
    client=open_as(application,reviewer)
    dash=context(application,client,"/dashboard?date=2026-11-02")
    assert dash["totals"]=={"done":0,"pending":2,"total":2}
    assert [p.id for p in dash["spot_points"]]==[spot.id]
    assert [s["stage_status"] for s in dash["cards"][0]["slots"]]==["awaiting_inspection","awaiting_execution"]
    missed=context(application,client,"/missed?"+RANGE)
    assert missed["totals"]=={"missed":2,"points":1}
    assert [(r["slot"], r["missing_stage_label"]) for r in missed["occurrences"]]==[("pm","未執行"),("am","已執行、未巡檢")]
    data=csv_rows(client.get("/missed/export?"+RANGE))
    assert [r[-2:] for r in data]==[["漏打次數","缺少階段"],["1","未執行"],["1","已執行、未巡檢"]]
    assert len(context(application,client,"/records?"+RANGE)["records"])==2


def test_only_own_execution_and_authorized_final_reports_can_export_paired_person(application, seeded, workflow):
    worker, reviewer, other, pair, _ = workflow
    own=PatrolExecution(**values(worker,pair,"am"))
    foreign=PatrolExecution(**values(other,pair,"pm"))
    db.session.add_all([own,foreign])
    db.session.flush()
    final=Inspection(**values(reviewer,pair,"pm"),workflow_mode="two_stage",execution_id=foreign.id,note="PRIVATE FINAL NOTE")
    db.session.add(final)
    db.session.commit()
    client=open_as(application,worker)
    result=context(application,client,f"/records?{RANGE}&user_id={other.id}")
    assert result["stage"]=="execution" and result["records"]==[] and [r.id for r in result["executions"]]==[own.id]
    assert not result["reviewed_execution_ids"]
    own_csv=csv_rows(client.get("/records/export?"+RANGE))
    assert own_csv[0][0]=="執行人員" and len(own_csv)==2
    assert other.display_name not in str(own_csv) and final.note not in str(own_csv)
    assert client.get("/records/export?stage=inspection").status_code==403
    dash=context(application,client,"/dashboard?date=2026-11-02")
    assert dash["totals"]=={"total":2,"done":1,"pending":1} and dash["spot_points"]==[]
    assert all(s["record"] is None for s in dash["cards"][0]["slots"])
    assert [e.id for e in dash["recent_executions"]]==[own.id] and not dash["recent"]
    reviewer_client=open_as(application,reviewer)
    assert reviewer_client.get("/records?stage=execution").status_code==403
    final_csv=csv_rows(reviewer_client.get("/records/export?"+RANGE))
    assert final_csv[-1][-2:]==[other.display_name,"2026-11-02 15:00:00"] and final.note in final_csv[-1]
    admin=open_as(application,seeded["manager"])
    all_rows=context(application,admin,"/records?stage=execution&"+RANGE)
    assert {e.id for e in all_rows["executions"]}=={own.id,foreign.id} and all_rows["reviewed_execution_ids"]=={foreign.id}


@pytest.mark.parametrize(("old","new","hour","expected"), [
    ("spot","two_stage",5,["pm"]), ("two_stage","spot",5,["am"]),
    ("spot","two_stage",4,["pm"]), ("spot","two_stage",3,["pm","am"]),
])
def test_workflow_changes_preserve_only_slots_that_existed_before_each_deadline(application, seeded, old, new, hour, expected):
    item=point("1F-SWITCH",old)
    item.workflow_mode=new
    plan(item, DAY, new, datetime(2026,11,2,hour))
    item.name="Renamed after switch"
    plan(item, DAY, new)
    db.session.commit()
    client=open_as(application,seeded["manager"])
    report=context(application,client,"/missed?"+RANGE)
    assert [r["slot"] for r in report["occurrences"]]==expected
    dash=context(application,client,"/dashboard?date=2026-11-02&category=general")
    assert dash["totals"]=={"total":len(expected),"done":0,"pending":len(expected)}
    assert {s["key"] for c in dash["cards"] for s in c["slots"]}==set(expected)


def test_completed_legacy_week_survives_midweek_switch_without_inventing_execution(application, seeded, monkeypatch):
    item=point("1F-OLD-WEEK","standard")
    item.frequency=item.schedules[0].frequency="weekly"
    owner=seeded["manager"]
    db.session.add(Inspection(user_id=owner.id, user_name=owner.display_name, point_id=item.id, point_name=item.name,
        point_code=item.code, point_floor=item.floor, frequency="weekly", category="general", period_key="2026-11-02",
        slot="any", workflow_mode="standard", created_at=datetime(2026,11,2,1)))
    item.workflow_mode="two_stage"
    plan(item,date(2026,11,4),"two_stage",datetime(2026,11,4,1))
    db.session.commit()
    monkeypatch.setattr(app_module,"now_utc",lambda:datetime(2026,11,9,0,tzinfo=timezone.utc))
    client=open_as(application,owner)
    dash=context(application,client,"/dashboard?date=2026-11-08&view=weekly&category=general")
    assert dash["totals"]=={"done":1,"pending":0,"total":1}
    assert dash["cards"][0]["point"].workflow_mode=="standard"
    missed=context(application,client,"/missed?date_from=2026-11-08&date_to=2026-11-08&category=general")
    assert not missed["occurrences"]
