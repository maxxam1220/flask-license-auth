"""Rendered per-round execution/review progress follows real attendance records."""
from datetime import timedelta
import re

from general_workflow import new_execution
from models import DeviceBinding, User, db
from test_app import application
from test_daily2_anytime import anytime, context, form, rows
from test_dashboard_stage_labels import point_card
from test_workflow_checkin import payload


def progress(client, code="1F-G00", day="2026-11-06"):
    card, summary = point_card(client, code, day)
    pieces = re.split(r'<div class="workflow-slot" data-round="(am|pm)">', card)
    rounds = {}
    for index in range(1, len(pieces), 2):
        fragment = pieces[index + 1]
        stages = re.findall(r'data-stage="(execution|inspection)" class="badge ([^"]+)">([^<]+)</span>', fragment)
        rounds[pieces[index]] = {
            "stages": {stage: (tone, text) for stage, tone, text in stages},
            "expired": "本次已到期" in fragment,
            "future": "尚未開始" in fragment,
        }
    assert set(rounds) == {"am", "pm"}
    return rounds, summary, card


def stage(execution, inspection):
    tones = {"未簽到": "badge-signin", "已簽到": "badge-done", "未巡檢": "badge-neutral",
             "待巡檢": "badge-review", "已巡檢": "badge-done"}
    return {"execution": (tones[execution], execution), "inspection": (tones[inspection], inspection)}


def test_both_rounds_keep_separate_stage_badges_for_every_role(application, anytime):
    a = anytime
    expected = [stage("未簽到", "未巡檢"), stage("未簽到", "未巡檢")]

    def check(summary):
        for actor in (a.admin, a.executor, a.inspector, a.peer):
            rounds, badges, card = progress(actor)
            assert badges == [summary]
            assert [rounds[slot]["stages"] for slot in ("am", "pm")] == expected
            assert not any(item["future"] or item["expired"] for item in rounds.values())
            assert "第 1 次" in card and "第 2 次" in card

    check(("badge-signin", "未簽到"))
    assert a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired)).status_code == 302
    expected[0] = stage("已簽到", "待巡檢")
    check(("badge-review", "已簽到、待巡檢"))
    assert a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired)).status_code == 302
    expected[1] = stage("已簽到", "待巡檢")
    check(("badge-review", "已簽到、待巡檢"))
    assert a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired)).status_code == 302
    expected[0] = stage("已簽到", "已巡檢")
    check(("badge-partial", "部分完成 1/2"))
    # Another person's first review is not the team's second review.
    assert a.peer.post(a.paired + "/confirm", data=form(a.peer, a.paired)).status_code == 302
    check(("badge-partial", "部分完成 1/2"))
    assert a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired)).status_code == 302
    expected[1] = stage("已簽到", "已巡檢")
    check(("badge-done", "已完成"))


def test_anytime_rounds_expire_together_but_future_has_no_stage_failure(application, anytime):
    a = anytime
    assert a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired)).status_code == 302
    a.clock[0] = a.clock[0].replace(hour=12)
    rounds, _, _ = progress(a.inspector)
    assert all(not item["expired"] for item in rounds.values())
    future, badges, _ = progress(a.inspector, day="2026-11-07")
    assert badges == [("badge-not_due", "尚未開始")]
    assert all(item["future"] and not item["stages"] and not item["expired"] for item in future.values())
    a.clock[0] = (a.clock[0] + timedelta(days=1)).replace(hour=0)
    for actor in (a.admin, a.executor, a.inspector, a.peer):
        expired, badges, _ = progress(actor)
        assert badges == [("badge-missed", "漏打 2 次")]
        assert expired["am"]["stages"] == {"execution": ("badge-done", "已簽到"),
                                            "inspection": ("badge-missed", "未巡檢")}
        assert expired["pm"]["stages"] == {"execution": ("badge-missed", "未簽到"),
                                            "inspection": ("badge-missed", "未巡檢")}
        assert all(item["expired"] and not item["future"] for item in expired.values())


def test_pre_cutover_history_keeps_original_noon_deadline(application, anytime):
    a = anytime
    a.clock[0] = (a.clock[0] - timedelta(days=1)).replace(hour=11, minute=59)
    assert a.executor.post(a.paired + "/confirm", data=payload(a.executor, a.paired)).status_code == 302
    a.clock[0] += timedelta(minutes=1)
    rounds, badges, _ = progress(a.inspector, day="2026-11-05")
    assert rounds["am"]["expired"] and not rounds["pm"]["expired"]
    assert rounds["am"]["stages"] == {"execution": ("badge-done", "已簽到"),
                                        "inspection": ("badge-missed", "未巡檢")}
    assert rounds["pm"]["stages"] == stage("未簽到", "未巡檢")
    assert badges == [("badge-signin", "未簽到"), ("badge-missed", "漏打 1 次")]


def test_preserved_second_round_execution_is_prioritized_over_unstarted_first(application, anytime):
    a = anytime
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == actor.id))
    db.session.add(new_execution(a.pair_point, actor, binding, "2026-11-06", "pm", a.clock[0]))
    db.session.commit()
    for viewer in (a.admin, a.executor, a.inspector, a.peer):
        rounds, badges, _ = progress(viewer)
        assert rounds["am"]["stages"] == stage("未簽到", "未巡檢")
        assert rounds["pm"]["stages"] == stage("已簽到", "待巡檢")
        assert badges == [("badge-review", "已簽到、待巡檢")]
    assert form(a.inspector, a.paired)["slot"] == "pm"


def test_changed_daily_record_is_not_described_as_two_completed_visits(application, anytime):
    a = anytime
    a.direct_point.frequency = a.direct_point.schedules[0].frequency = "daily"
    db.session.commit()
    assert a.inspector.post(a.direct + "/confirm", data=payload(a.inspector, a.direct)).status_code == 302
    a.direct_point.frequency = a.direct_point.schedules[0].frequency = "daily2"
    db.session.commit()
    response, current = context(application, a.inspector, a.direct)
    assert not current["can_confirm"] and current["daily2_existing_daily_record"]
    assert len(rows(a.direct_point)) == 1 and rows(a.direct_point)[0].slot == "any"
    assert "本人今日已有完成紀錄" in response.text
    assert "原有紀錄已計入今日打卡限制" in response.text
    assert "今日兩次皆完成" not in response.text and "今日兩次皆已完成" not in response.text


def test_first_execution_receipt_completion_only_describes_its_own_round(application, anytime):
    a = anytime
    execution = a.executor.post(a.paired + "/confirm", data=form(a.executor, a.paired))
    assert execution.status_code == 302
    assert a.inspector.post(a.paired + "/confirm", data=form(a.inspector, a.paired)).status_code == 302
    receipt = a.executor.get(execution.location)
    assert receipt.status_code == 200 and "本次已完成第二階段巡檢" in receipt.text
    assert "本期已完成第二階段巡檢" not in receipt.text
    rounds, badges, _ = progress(a.inspector)
    assert badges == [("badge-partial", "部分完成 1/2")]
    assert rounds["pm"]["stages"] == stage("未簽到", "未巡檢")
