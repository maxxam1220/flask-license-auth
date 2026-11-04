"""Role and timing regressions using test accounts only."""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
import re
from threading import Barrier

import app as patrol
from models import DeviceBinding, Inspection, PatrolExecution, Point, PointSchedule, User, db
from test_app import application, FIXED_NOW
from test_postgres_features import postgres_app


def team(app):
    members = []
    for name, role in (("exec", "executor"), ("inspect", "inspector"), ("peer", "inspector"), ("admin", "admin")):
        u = User(username=name, display_name=name, role=role, password_hash="unused", active=True,
                 patrol_category=None if role == "admin" else "general", must_change_password=False)
        db.session.add(u)
        db.session.flush()
        token = name + "-device"
        db.session.add(DeviceBinding(user_id=u.id, token_hash=patrol.hash_device_token(token), status="approved"))
        c = app.test_client()
        with c.session_transaction() as sess:
            sess.update(user_id=u.id, auth_version=u.auth_version, csrf_token=f"local-test-session-{u.id}")
        c.set_cookie("patrol_device", token)
        members.append(c)
    urls = []
    for i, mode in enumerate(("two_stage", "spot", "spot")):
        p = Point(code=f"1F-G0{i}", name=f"fixture {i}", floor=1, active=True, category="general", frequency="daily2", workflow_mode=mode,
                  schedule_start=date(2026, 1, 1))
        p.schedules.append(PointSchedule(effective_date=p.schedule_start, category="general", frequency=p.frequency, workflow_mode=mode, active=True))
        db.session.add(p)
        db.session.flush()
        urls.append("/c/" + p.qr_token)
    db.session.commit()
    return (*members, *urls)


def payload(c, url):
    r = c.get(url)
    assert r.status_code == 200
    data = dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', r.text))
    assert "stage" in data, r.status_code
    return data


def test_roles_order_receipt_and_time_slot(application, monkeypatch):
    now = FIXED_NOW - timedelta(minutes=1)
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    executor, inspector, peer, admin, url, spot, _ = team(application)
    post = url + "/confirm"
    assert executor.get(spot).status_code == 404
    first_form = payload(executor, url)
    forced = first_form | {"stage": "inspect"}
    assert inspector.post(post, data=forced).status_code == 409
    assert admin.post(post, data=first_form).status_code == 403
    assert executor.post(post, data=forced).status_code == 409
    assert executor.post(post, data=first_form | {"note":"not a stage one field"}).status_code == 400
    first = executor.post(post, data=first_form)
    assert first.status_code == 302 and "/executions/" in first.location
    assert executor.post(post, data=first_form).location == first.location
    assert executor.get(first.location).status_code == 200 and inspector.get(first.location).status_code == 403
    assert db.session.query(Inspection).count() == 0 and db.session.query(PatrolExecution).count() == 1
    final = payload(inspector, url)
    assert admin.post(post, data=final).status_code == 403
    u = db.session.scalar(db.select(User).where(User.username == "exec"))
    u.role = "inspector"
    db.session.commit()
    assert executor.get(first.location).status_code == 403
    assert executor.post(post, data=final).status_code == 409
    r = inspector.post(post, data=final | {"note":"test anomaly", "is_abnormal":"1"})
    assert r.status_code == 302 and inspector.get(r.location).status_code == 200
    log = db.session.scalar(db.select(Inspection))
    assert log.execution.user_id != log.user_id and log.is_abnormal and log.issue is not None
    assert peer.get(r.location).status_code == 403 and executor.get(r.location).status_code == 403
    peer_receipt = peer.post(post, data=payload(peer, url))
    assert peer_receipt.status_code == 302 and peer_receipt.location != r.location
    assert db.session.query(Inspection).count() == 2 and db.session.query(PatrolExecution).count() == 1
    assert {row.execution_id for row in db.session.scalars(db.select(Inspection))} == {log.execution_id}
    now += timedelta(minutes=1)
    assert inspector.post(post, data=final).status_code == 409  # stale AM form
    assert inspector.post(post, data=final | {"slot":"pm"}).status_code == 409  # cannot use AM execution for PM


def test_direct_checkins_are_personal_and_reset_at_taipei_midnight(application, monkeypatch):
    now = FIXED_NOW.replace(hour=15, minute=45)  # local 23:45
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    _, a, b, admin, _, url, other = team(application)
    a_form, b_form, admin_form = (payload(c, url) for c in (a,b,admin))
    assert b.post(url + "/confirm", data=a_form).status_code == 409  # cannot recycle another account's ticket
    saved = a.post(url + "/confirm", data=a_form)
    assert saved.status_code == 302
    assert a.post(url + "/confirm", data=a_form).location == saved.location
    changed = a.post(url + "/confirm", data=a_form | {"note":"duplicate edit","is_abnormal":"1"}, follow_redirects=True)
    assert "重送時更改的備註、異常或照片不會追加" in changed.text
    assert not db.session.scalar(db.select(Inspection)).is_abnormal
    for viewer, fields in ((b, b_form), (admin, admin_form)):
        assert viewer.post(url + "/confirm", data=fields).status_code == 302
        assert 'name="spot_ticket"' not in viewer.get(url).text
    assert b.post(other + "/confirm", data=payload(b, other)).status_code == 302
    now += timedelta(minutes=15)
    assert b.post(url + "/confirm", data=b_form).status_code == 409
    assert b.post(url + "/confirm", data=payload(b, url)).status_code == 302
    assert db.session.query(Inspection).count() == 5


def test_postgres_simultaneous_accounts_and_double_submit(postgres_app):
    with postgres_app.app_context():
        _, a, b, _, _, url, _ = team(postgres_app)
    candidates = [(a, payload(a, url)), (b, payload(b, url)), (a, payload(a, url))]
    gate = Barrier(len(candidates))
    def submit(item):
        c, data = item
        gate.wait(timeout=10)
        return c.post(url + "/confirm", data=data).status_code
    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        assert list(pool.map(submit, candidates)) == [302, 302, 302]
    with postgres_app.app_context():
        saved = db.session.scalars(db.select(Inspection)).all()
        assert len(saved) == 2 and len({r.user_id for r in saved}) == 2


def test_admin_configures_general_and_cannot_swap_an_open_execution(application):
    executor, _, _, admin, url, _, _ = team(application)
    fields = dict(floor="1", name="general spot", frequency="daily", category="general", code="1F-G99")
    assert admin.post("/admin/points/create", data=fields).status_code == 302
    added = db.session.scalar(db.select(Point).where(Point.code == "1F-G99"))
    assert added.workflow_mode == added.schedules[0].workflow_mode == "spot"
    assert admin.post("/admin/points/create", data=fields | {"code":"1F-G98","category":"safety","workflow_mode":"two_stage"}).status_code == 400
    assert admin.post("/admin/users/create", data={"username":"newexec","display_name":"test executor",
        "password":"only-test-password", "role":"general_executor"}).status_code == 302
    u = db.session.scalar(db.select(User).where(User.username == "newexec"))
    assert (u.role,u.patrol_category,u.must_change_password) == ("executor","general",True)
    assert executor.post(url + "/confirm", data=payload(executor,url)).status_code == 302
    pt = db.session.scalar(db.select(Point).where(Point.workflow_mode == "two_stage"))
    target = f"/admin/points/{pt.id}"
    assert admin.post(target + "/update", data=fields | {"code":pt.code,"workflow_mode":"spot","active":"on"}).status_code == 409
    assert admin.post(target + "/delete").status_code == 409
    assert pt.active and pt.workflow_mode == "two_stage" and pt.deleted_at is None

def test_weekly_shared_execution_but_personal_checkins_reset_daily(application, monkeypatch):
    now = FIXED_NOW
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    executor, a, b, _, url, _, _ = team(application)
    pt = db.session.scalar(db.select(Point).where(Point.workflow_mode == "two_stage"))
    pt.frequency = pt.schedules[0].frequency = "weekly"
    db.session.commit()
    assert executor.post(url + "/confirm", data=payload(executor, url)).status_code == 302
    old = payload(a, url)
    for viewer in (a, b):
        assert viewer.post(url + "/confirm", data=payload(viewer, url)).status_code == 302
    assert 'id="inspection-form"' not in a.get(url).text
    now += timedelta(days=1)
    assert a.post(url + "/confirm", data=old).status_code == 409
    assert a.post(url + "/confirm", data=payload(a, url)).status_code == 302
    assert db.session.query(PatrolExecution).count() == 1 and db.session.query(Inspection).count() == 3
    now += timedelta(days=7)
    assert 'id="inspection-form"' not in a.get(url).text


def test_monthly_and_irregular_direct_checks_without_execution(application, monkeypatch):
    now = FIXED_NOW.replace(day=29)
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    _, a, b, _, _, monthly, irregular = team(application)
    for url, frequency in ((monthly, "monthly"), (irregular, "irregular")):
        pt = db.session.scalar(db.select(Point).where(Point.qr_token == url.split("/")[-1]))
        pt.frequency = pt.schedules[0].frequency = frequency
    db.session.commit()
    for url in (monthly, irregular):
        for viewer in (a, b):
            assert viewer.post(url + "/confirm", data=payload(viewer, url)).status_code == 302
            assert 'id="inspection-form"' not in viewer.get(url).text
    now += timedelta(days=1)
    assert a.post(monthly + "/confirm", data=payload(a, monthly)).status_code == 302
    now += timedelta(days=1)
    assert a.post(monthly + "/confirm", data=payload(a, monthly)).status_code == 302
    months = db.session.scalars(db.select(Inspection).where(Inspection.frequency == "monthly").order_by(Inspection.id)).all()
    assert [r.period_key for r in months] == ["2026-11-01"]*3 + ["2026-12-01"]
    assert db.session.query(PatrolExecution).count() == 0
