"""Historical slot deadlines and scoped reads for the general-affairs workflows."""
import csv
from datetime import date, datetime, timedelta, timezone
import io

import pytest
from general_workflow import execution_deadline, execution_review_status
from missed import TAIPEI
from models import DeviceBinding, Inspection, InspectionPhoto, PatrolExecution, Point, PointSchedule, User, db
from test_app import app_module, application, seeded, login, rendered_contexts  # noqa: F401

DAY = date(2026, 11, 2)
RANGE = "date_from=2026-11-02&date_to=2026-11-02&category=general"


def plan(point, day, mode, changed=None, *, legacy=False):
    point.schedules.append(PointSchedule(effective_date=day, active=True, frequency=point.frequency,
        category="general", workflow_mode=mode, floor=point.floor, point_code=point.code,
        point_name=point.name, workflow_changed_at=changed, legacy_unscheduled=legacy))


def point(code, mode, *, legacy=False, frequency="daily2"):
    item = Point(code=code, name=code, floor=1, category="general", active=True, frequency=frequency,
                 workflow_mode=mode, schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
    plan(item, item.schedule_start, mode, legacy=legacy)
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
    scheduled, spot = point("1F-TWO", "two_stage"), point("1F-SPOT", "spot", legacy=True)
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


def test_legacy_spot_never_in_denominator_or_missed_and_two_stages_count_one_slot(application, workflow):
    worker, reviewer, _, pair, spot = workflow
    db.session.add(PatrolExecution(**values(worker,pair,"am")))
    for slot, token in (("am", "a"*64), ("pm", "b"*64)):
        db.session.add(Inspection(**values(reviewer,spot,slot), workflow_mode="spot", spot_request_id=token,
                                  legacy_unscheduled=True))
    db.session.commit()
    client=open_as(application,reviewer)
    dash=context(application,client,"/dashboard?date=2026-11-02")
    assert dash["totals"]=={"done":0,"pending":2,"total":2}
    assert [p.id for p in dash["spot_points"]]==[spot.id]
    assert [s["stage_status"] for s in dash["cards"][0]["slots"]]==["expired_unreviewed","expired_unexecuted"]
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
    assert len(csv_rows(client.get("/records/export?stage=inspection&" + RANGE))) == 1
    dash=context(application,client,"/dashboard?date=2026-11-02")
    assert dash["totals"]=={"total":2,"done":1,"pending":1} and dash["spot_points"]==[]
    assert all(s["record"] is None for s in dash["cards"][0]["slots"])
    assert [e.id for e in dash["recent_executions"]]==[own.id] and not dash["recent"]
    reviewer_client=open_as(application,reviewer)
    assert {r.id for r in context(application,reviewer_client,"/records?stage=execution")["executions"]} == {own.id,foreign.id}
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
    item=point("1F-SWITCH",old,legacy=old=="spot")
    item.workflow_mode=new
    plan(item, DAY, new, datetime(2026,11,2,hour), legacy=new=="spot")
    item.name="Renamed after switch"
    plan(item, DAY, new, legacy=new=="spot")
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


def test_scheduled_spot_counts_after_cutover_and_old_optional_receipt_does_not_cover_it(application, workflow):
    _, reviewer, _, _, item = workflow
    plan(item, DAY, "spot", datetime(2026,11,2,5))  # 13:00 Taipei: no retroactive AM duty
    before_cutover = values(reviewer,item,"pm") | {"created_at": datetime(2026,11,2,4,15)}
    db.session.add(Inspection(**before_cutover, workflow_mode="spot", spot_request_id="c"*64,
                              legacy_unscheduled=True))
    db.session.commit()
    client = open_as(application, reviewer)
    dash = context(application, client, "/dashboard?date=2026-11-02")
    card, = [c for c in dash["cards"] if c["point"].id == item.id]
    assert [(s["key"], s["status"]) for s in card["slots"]] == [("pm", "pending")]
    rows = context(application, client, "/missed?" + RANGE)["occurrences"]
    assert [r["slot"] for r in rows if r["point_id"] == item.id] == ["pm"]
    assert item.code in client.get("/records/export?" + RANGE).get_data(as_text=True)


def test_monthly_repeated_personal_reviews_one_team_slot_one_execution_private_receipts(application, seeded, workflow, monkeypatch):
    from urllib.parse import parse_qs, urlsplit
    worker, first_reviewer, second_reviewer, _, _ = workflow
    second_reviewer.role = "inspector"
    item = point("1F-MONTHLY", "two_stage", frequency="monthly")
    def fields(person, day):
        return values(person, item, "any") | {"period_key": "2026-11-01", "created_at": datetime(2026, 11, day, 1)}
    execution = PatrolExecution(**fields(worker, 1))
    db.session.add(execution)
    db.session.flush()
    reviews = []
    for person, day in ((first_reviewer, 2), (second_reviewer, 3), (second_reviewer, 8)):
        row = Inspection(**fields(person, day), workflow_mode="two_stage", execution_id=execution.id, note=f"private-{day}")
        db.session.add(row)
        reviews.append(row)
    item.floor = 2
    plan(item, date(2026,11,12), "two_stage")
    late = Inspection(**fields(first_reviewer, 13), workflow_mode="two_stage", execution_id=execution.id, note="private-new-floor")
    db.session.add(late)
    db.session.commit()
    monkeypatch.setattr(app_module, "now_utc", lambda: datetime(2026,11,30,16,tzinfo=timezone.utc))
    client = open_as(application, second_reviewer)
    dash = context(application, client, "/dashboard?view=monthly&date=2026-11-29")
    assert dash["totals"] == {"total": 1, "done": 1, "pending": 0}
    assert [f["floor"] for f in dash["floors"] if f["done"]] == [1]
    card, = dash["cards"]
    assert card["point"].floor == 1 and card["latest"].id == reviews[2].id
    for link in ("missed_query_url", "records_query_url"):
        query = parse_qs(urlsplit(dash[link]).query)
        assert (query["date_from"], query["date_to"], query["frequency"]) == (["2026-11-01"], ["2026-11-30"], ["monthly"])
    narrow = "date_from=2026-11-30&date_to=2026-11-30&frequency=monthly"
    assert not context(application, client, "/missed?" + narrow)["occurrences"]
    assert len(csv_rows(client.get("/missed/export?" + narrow))) == 1
    filters = "date_from=2026-11-01&date_to=2026-11-30&frequency=monthly"
    receipts = context(application, client, "/records?" + filters)["records"]
    assert [r.id for r in receipts] == [late.id, reviews[2].id, reviews[1].id, reviews[0].id]
    csv_data = csv_rows(client.get("/records/export?" + filters))
    assert len(csv_data) == 5 and "private-2" in str(csv_data) and "private-new-floor" in str(csv_data)
    admin = open_as(application, seeded["manager"])
    report = context(application, admin, "/records?stage=execution&" + filters)
    assert [e.id for e in report["executions"]] == [execution.id] and report["reviewed_execution_ids"] == {execution.id}
    execution_csv = csv_rows(admin.get("/records/export?stage=execution&" + filters))
    assert len(execution_csv) == 2 and execution_csv[1][-1] == "已巡檢"


def test_irregular_list_monthly_misses_and_exact_frequency_filters(application, seeded, workflow, monkeypatch):
    worker, reviewer, _, _, _ = workflow
    one = point("1F-IRREGULAR", "spot", frequency="irregular")
    two = point("1F-IRREG-TWO", "two_stage", frequency="irregular")
    month = point("1F-MONTH-END", "spot", frequency="monthly")
    db.session.add(Inspection(**values(reviewer,one,"any"), workflow_mode="spot", spot_request_id="d"*64))
    db.session.commit()
    monkeypatch.setattr(app_module, "now_utc", lambda: datetime(2026,11,30,16,tzinfo=timezone.utc))
    client = open_as(application, reviewer)
    dash = context(application, client, "/dashboard?view=monthly&date=2026-11-30")
    assert {p.id for p in dash["irregular_points"] if not p.legacy_unscheduled} == {one.id, two.id}
    assert dash["totals"] == {"total": 1, "done": 0, "pending": 1}
    worker_dash = context(application, open_as(application, worker), "/dashboard?view=monthly&date=2026-11-30")
    assert [p.id for p in worker_dash["irregular_points"]] == [two.id] and worker_dash["totals"]["total"] == 0
    filters = "date_from=2026-11-01&date_to=2026-11-30"
    row, = context(application, client, "/missed?" + filters + "&frequency=monthly")["occurrences"]
    assert (row["point_id"], row["due_date"], row["period_key"]) == (month.id, date(2026,11,30), "2026-11-01")
    assert not context(application, client, "/missed?" + filters + "&frequency=irregular")["occurrences"]
    csv_data = csv_rows(client.get("/records/export?" + filters + "&frequency=irregular"))
    assert len(csv_data) == 2 and csv_data[1][2:4] == [one.code, one.name]


def test_executor_direct_receipts_are_scoped_to_submission_role_in_every_read_path(application, seeded, workflow):
    executor, _, peer, scheduled, _ = workflow
    direct = point("1F-DIRECT", "spot", frequency="irregular")
    application.config["EXECUTOR_VISIT_CODES"] = {direct.code}
    first_stage = PatrolExecution(**values(executor, scheduled, "am"))
    # This same account was previously an inspector at the same point.
    old_fields = values(executor, direct, "any") | {"created_at": datetime(2026,11,1,1), "period_key": "2026-11-01"}
    old = Inspection(**old_fields, workflow_mode="spot", spot_request_id="e"*32, note="OLD-INSPECTOR-ONLY", is_abnormal=True)
    old.photos.append(InspectionPhoto(data=b"private image", size_bytes=13, width=1, height=1))
    visit = Inspection(**values(executor,direct,"any"), workflow_mode="spot", spot_request_id="f"*32, executor_visit=True)
    theirs = Inspection(**values(peer,direct,"any"), workflow_mode="spot", spot_request_id="b1"*16, executor_visit=True)
    db.session.add_all([first_stage, old, visit, theirs])
    db.session.commit()
    client = open_as(application, executor)
    filters = f"date_from=2026-11-01&date_to=2026-11-02&user_id={peer.id}&category=safety"
    direct_url = "/records?stage=inspection&" + filters
    assert [r.id for r in context(application, client, direct_url)["records"]] == [visit.id]
    assert [r.id for r in context(application, client, "/records?" + filters)["executions"]] == [first_stage.id]
    csv_data = csv_rows(client.get("/records/export?stage=inspection&" + filters))
    assert csv_data == [["簽到人員","樓層","點位編號","點位名稱","簽到時間（台北）"],
                        [executor.display_name,"1F",direct.code,direct.name,"2026-11-02 15:00:00"]]
    assert client.get(direct_url + "&abnormal=1").status_code == 400
    dash = context(application, client, "/dashboard")
    assert [r.id for r in dash["recent"]] == [visit.id] and [r.id for r in dash["recent_executions"]] == [first_stage.id]
    assert [p.id for p in dash["irregular_points"]] == [direct.id]
    assert context(application, client, f"/checkins/{visit.id}")["point_open_issue_count"] == 0
    for forbidden in (old, theirs):
        for route in (f"/records/{forbidden.id}", f"/checkins/{forbidden.id}"):
            assert client.get(route).status_code == 403
    assert client.get(f"/photos/{old.photos[0].id}").status_code == 403
    assert client.get("/issues").status_code == 403
    assert client.post(f"/issues/{old.id}/resolve", data={"note":"x","expected_event_id":"0"}).status_code == 403
    admin = open_as(application, seeded["manager"])
    admin_csv = csv_rows(admin.get("/records/export?date_from=2026-11-01&date_to=2026-11-02&category=general"))
    labels = admin_csv[0]
    visits = [r for r in admin_csv[1:] if r[labels.index("作業模式")] == "直接簽到"]
    assert len(visits) == 2 and all(r[9:16] == [""] * 7 for r in visits)
    assert any(r[labels.index("備註")] == old.note for r in admin_csv[1:])
    # Historical receipts remain available after an authorized point is renamed
    # or removed from the register. They use the role and fields at submission.
    direct.code = "1F-RENAMED"
    db.session.commit()
    application.config["EXECUTOR_VISIT_CODES"] = frozenset()
    assert context(application, client, f"/checkins/{visit.id}")["stage"] == "visit"
    response = client.get(f"/records/{visit.id}")
    assert response.status_code == 302 and response.location.endswith(f"/checkins/{visit.id}")
    assert [r.id for r in context(application, client, direct_url)["records"]] == [visit.id]
    assert not context(application, client, "/dashboard")["irregular_points"]


def test_executor_optional_dashboard_uses_exact_authorized_codes_and_current_workflow(application, workflow):
    executor, _, _, _, _ = workflow
    eligible = point("1F-AUTH-OK", "spot", frequency="irregular")
    custom = point("1F-AUTH-OTHER", "spot", frequency="irregular")
    wrong_case = point("1f-auth-case", "spot", frequency="irregular")
    wrong_schedule = point("1F-AUTH-SCHED", "spot", frequency="daily")
    different = point("1F-AUTH-CHANGED", "spot", frequency="irregular")
    historical = point("1F-AUTH-LEGACY", "spot", frequency="irregular", legacy=True)
    different.frequency = "daily"
    db.session.commit()
    application.config["EXECUTOR_VISIT_CODES"] = frozenset({
        eligible.code, wrong_case.code.upper(), wrong_schedule.code, different.code, historical.code})
    client = open_as(application, executor)
    dash = context(application, client, "/dashboard")
    assert [p.id for p in dash["irregular_points"]] == [eligible.id]
    assert custom.code not in client.get("/dashboard").get_data(as_text=True)


@pytest.mark.parametrize("frequency,period_key,slot,first_day,due_date,deadline", [
    ("weekly", "2026-11-30", "any", "2026-11-30", "2026-12-06", "2026-12-07T00:00"),
    ("monthly", "2026-12-01", "any", "2026-12-04", "2026-12-31", "2027-01-01T00:00"),
    ("daily2", "2026-11-02", "am", "2026-11-02", "2026-11-02", "2026-11-02T12:00"),
    ("daily", "2026-11-02", "any", "2026-11-02", "2026-11-02", "2026-11-03T00:00"),
])
def test_unreviewed_execution_at_deadline_matches_all_reports(application, workflow, monkeypatch, frequency, period_key,
                                                           slot, first_day, due_date, deadline):
    worker, reviewer, _, _, _ = workflow
    item = point("QA-BOUNDARY", "two_stage", frequency=frequency)
    first_time = datetime.fromisoformat(first_day + "T09:00").replace(tzinfo=TAIPEI).astimezone(timezone.utc).replace(tzinfo=None)
    execution = PatrolExecution(**(values(worker, item, slot) | {"created_at": first_time, "period_key": period_key}))
    db.session.add(execution)
    db.session.commit()
    end = datetime.fromisoformat(deadline).replace(tzinfo=TAIPEI).astimezone(timezone.utc)
    assert execution_deadline(frequency, period_key, slot) == end
    view = frequency if frequency in ("weekly", "monthly") else "daily"
    client = open_as(application, reviewer)
    by_visit = f"stage=execution&date_from={first_day}&date_to={first_day}&frequency={frequency}"
    by_due = f"date_from={due_date}&date_to={due_date}&frequency={frequency}"
    for instant, expired in ((end - timedelta(seconds=1), False), (end, True)):
        monkeypatch.setattr(app_module, "now_utc", lambda: instant)
        report = context(application, client, "/records?" + by_visit)
        assert report["execution_states"][execution.id] == ("expired" if expired else "pending")
        assert ("已到期、未巡檢" if expired else "已執行、待巡檢") in client.get("/records?" + by_visit).text
        data = csv_rows(client.get("/records/export?" + by_visit))
        row, = [r for r in data[1:] if r[2] == item.code]
        assert (row[6], row[-1]) == (period_key, "已到期、未巡檢" if expired else "待巡檢")
        dash = context(application, client, f"/dashboard?view={view}&date={due_date}")
        card, = [c for c in dash["cards"] if c["point"].id == item.id]
        entry, = [s for s in card["slots"] if s["key"] == slot]
        assert entry["stage_status"] == ("expired_unreviewed" if expired else "awaiting_inspection")
        missed = context(application, client, "/missed?" + by_due)["occurrences"]
        assert [r["missing_stage_label"] for r in missed if r["point_id"] == item.id] == (["已執行、未巡檢"] if expired else [])
        exported = csv_rows(client.get("/missed/export?" + by_due))
        assert [r[-1] for r in exported[1:] if r[4] == item.code] == (["已執行、未巡檢"] if expired else [])
    if frequency in ("weekly", "monthly"):
        following = end.astimezone(TAIPEI).date()
        current = context(application, client, f"/dashboard?view={view}&date={following}")
        card, = [c for c in current["cards"] if c["point"].id == item.id]
        assert card["slots"][0]["stage_status"] == "awaiting_execution" and card["slots"][0]["executed_at"] is None
    review_time = (end - timedelta(seconds=1)).replace(tzinfo=None)
    db.session.add(Inspection(**(values(reviewer,item,slot) | {"created_at": review_time, "period_key": period_key}),
                              workflow_mode="two_stage", execution_id=execution.id))
    db.session.commit()
    assert context(application, client, "/records?" + by_visit)["execution_states"][execution.id] == "done"
    assert not [r for r in context(application, client, "/missed?" + by_due)["occurrences"] if r["point_id"] == item.id]


@pytest.mark.parametrize("frequency,key,slot", [
    ("weekly","2026-11-03","any"), ("monthly","2026-11-04","any"), ("daily","2026-02-30","any"),
    ("daily2","2026-11-02","any"), ("unexpected","2026-11-02","any"), ("monthly","9999-12-01","any"),
])
def test_invalid_execution_snapshot_has_no_guessed_deadline(frequency, key, slot):
    assert execution_deadline(frequency, key, slot) is None
    instant = datetime(2026,11,3,4)
    assert execution_review_status(frequency, key, slot, False, instant) == "unknown"
    assert execution_review_status(frequency, key, slot, True, instant) == "done"
