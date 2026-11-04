from datetime import datetime, timedelta

import pytest

from missed import TAIPEI
from test_app import application, actors_only, app_module, login, rendered_contexts
from test_features import feature_point


def page(app, client, url):
    with rendered_contexts(app) as rendered:
        response = client.get(url)
    assert response.status_code == 200
    return response.text, rendered[-1][1]


@pytest.mark.parametrize("frequency,view,day,cutoff", [
    ("daily2", "daily", "2026-11-03", "2026-11-03T12:00"),
    ("daily", "daily", "2026-11-03", "2026-11-04T00:00"),
    ("weekly", "weekly", "2026-11-03", "2026-11-09T00:00"),
    ("monthly", "monthly", "2026-11-03", "2026-12-01T00:00"),
])
def test_single_stage_dashboard_and_linked_missed_agree_at_cutoff(application, actors_only, monkeypatch, frequency, view, day, cutoff):
    point = feature_point(frequency=frequency, category="general")
    point.workflow_mode = point.schedules[0].workflow_mode = "spot"
    app_module.db.session.commit()
    client = application.test_client()
    login(client, "manager")
    stop = datetime.fromisoformat(cutoff).replace(tzinfo=TAIPEI)
    for delta, count in ((-1, 0), (0, 1)):
        monkeypatch.setattr(app_module, "now_utc", lambda: stop + timedelta(seconds=delta))
        html, dashboard = page(application, client, f"/dashboard?date={day}&view={view}&category=general&floor=11")
        _, missed = page(application, client, dashboard["missed_query_url"])
        assert len(missed["occurrences"]) == count
        assert dashboard["cards"][0]["missed_count"] == dashboard["missed_count"] == count
        assert ('class="badge badge-missed">漏打 1 次' in html) is bool(count)
        if count and frequency == "daily2":
            assert "已到期、未巡檢" in html and "待巡檢" in html  # PM remains open.


def test_removing_point_after_noon_keeps_only_expired_morning_on_dashboard(application, actors_only, monkeypatch):
    point = feature_point()
    client = application.test_client()
    login(client, "manager")
    monkeypatch.setattr(app_module, "now_utc", lambda: datetime(2026, 11, 3, 14, tzinfo=TAIPEI))
    assert client.post(f"/admin/points/{point.id}/delete").status_code == 302
    assert client.post(f"/admin/points/{point.id}/restore").status_code == 302
    html, dash = page(application, client, "/dashboard?date=2026-11-03&category=safety")
    _, missed = page(application, client, dash["missed_query_url"])
    assert [entry["slot"] for entry in missed["occurrences"]] == ["am"]
    assert len(dash["cards"]) == 1 and [s["key"] for s in dash["cards"][0]["slots"]] == ["am"]
    assert dash["missed_count"] == 1 and "漏打 1 次" in html
