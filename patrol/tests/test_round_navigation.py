"""Follow a second patrol round through a shared browser and a different period."""
from datetime import date
from urllib.parse import parse_qs, urlsplit

import pytest

from models import DeviceBinding, PointSchedule, db
from test_app import application, seeded, approve_browser, login, rendered_contexts
from test_frontend_navigation import Anchors


@pytest.mark.parametrize("first_state", ["approved", "pending"])
def test_another_login_does_not_evict_the_browsers_working_or_pending_binding(application, seeded, first_state):
    shared = application.test_client()
    login(shared)
    original = approve_browser(shared, seeded["inspector"])
    original.label, original.status = "Private Alpha Phone", first_state
    db.session.commit()
    cookie = shared.get_cookie("patrol_device").value
    shared.post("/logout")
    login(shared, "colleague")
    path = "/c/" + seeded["daily"].qr_token
    attempt = shared.post("/devices/request", data={"next": path, "label": "Second account"})
    assert shared.get_cookie("patrol_device").value == cookie
    assert parse_qs(urlsplit(attempt.location).query)["next"] == [path]
    page = shared.get(attempt.location)
    assert "其他帳號" in page.text and 'action="/devices/request"' not in page.text
    assert original.label not in page.text and seeded["inspector"].display_name not in page.text
    assert db.session.scalar(db.select(db.func.count(DeviceBinding.id))) == 1
    shared.post("/logout")
    login(shared)
    assert original.label in shared.get("/devices").text
    if first_state == "approved":
        assert 'id="inspection-form"' in shared.get(path).text
    shared.post(f"/devices/{original.id}/revoke")
    shared.post("/logout")
    login(shared, "colleague")
    assert 'action="/devices/request"' in shared.get("/devices").text
    shared.post("/devices/request", data={"label": "Second account"})
    assert shared.get_cookie("patrol_device").value != cookie
    assert db.session.scalar(db.select(DeviceBinding.status).where(DeviceBinding.user_id == seeded["colleague"].id)) == "pending"


def test_future_week_and_month_use_the_selected_periods_schedule(application, seeded):
    p = seeded["weekly"]
    p.frequency = "monthly"
    p.schedules.append(PointSchedule(effective_date=date(2026, 12, 1), frequency="monthly", active=True,
                                     category="safety", floor=p.floor, point_code=p.code, point_name=p.name))
    db.session.commit()
    client = application.test_client()
    login(client)
    for view, appears in (("weekly", False), ("monthly", True)):
        with rendered_contexts(application) as rendered:
            assert client.get("/dashboard", query_string={"view": view, "date": "2026-12-11"}).status_code == 200
        ctx = rendered[-1][1]
        assert any(c["point"].id == p.id for c in ctx["cards"]) == appears
        assert ctx["totals"]["total"] == 0 and ctx["missed_count"] == 0


@pytest.mark.parametrize("view,day,previous,following", [
    ("daily", "2026-01-01", "2025-12-31", "2026-01-02"),
    ("weekly", "2026-01-01", "2025-12-22", "2026-01-05"),
    ("monthly", "2024-03-31", "2024-02-01", "2024-04-01"),
    ("weekly", "2000-01-01", None, "2000-01-03"),
    ("monthly", "2100-12-31", "2100-11-01", None),
])
def test_step_between_periods_without_losing_filters(application, seeded, view, day, previous, following):
    client = application.test_client()
    login(client, "manager")
    params = dict(view=view, date=day, floor="1", category="safety")
    links = Anchors(client.get("/dashboard", query_string=params).text).links
    steps = {link["data-period-step"]: link["href"] for link in links if "data-period-step" in link}
    for direction, expected in (("prev", previous), ("next", following)):
        if expected is None:
            assert direction not in steps
            continue
        assert parse_qs(urlsplit(steps[direction]).query) == {k:[v] for k,v in (params | {"date":expected}).items()}
        assert client.get(steps[direction]).status_code == 200
    reset = next(link["href"] for link in links if "period-today" in link.get("class", "").split())
    assert parse_qs(urlsplit(reset).query) == {"view":[view], "floor":["1"], "category":["safety"]}
    assert "period-today" not in client.get(reset).text
