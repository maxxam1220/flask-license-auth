"""Page through attendance, keep detail links scoped, and export all matching rows."""
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit

from models import Inspection, PatrolExecution, db
from test_app import application, seeded  # noqa: F401
from test_features import feature_point
from test_frontend_navigation import Anchors
from test_workflow_reports import context, csv_rows, open_as, point, values, workflow  # noqa: F401


def test_more_than_thousand_reports_page_through_ties_and_export_full_scope(application, seeded):
    author = seeded["inspector"]
    points = [seeded["daily"]] + [
        feature_point("daily", floor=1, code=f"TEST-{n:02}") for n in range(19)
    ]
    rows = []
    for n in range(51):
        instant = datetime(2026, 9, 1, 3) + timedelta(days=n)
        for item in points:
            rows.append(Inspection(point_id=item.id, user_id=author.id, user_name="Test worker",
                                   frequency="daily", category="safety", period_key=instant.date().isoformat(),
                                   point_code=item.code, point_name=item.name, point_floor=1, created_at=instant))
    db.session.add_all(rows)
    db.session.commit()
    ids = [row.id for row in reversed(rows)]
    base = ("/records?date_from=2026-09-01&date_to=2026-11-01&stage=inspection"
            f"&user_id={author.id}&category=safety&abnormal=0&floor=1&frequency=daily")
    client = open_as(application, seeded["manager"])
    second = client.get(base + "&page=2")
    links = Anchors(second.text).links
    older = next(a["href"] for a in links if a.get("rel") == "next")
    assert urlsplit(older).fragment == "record-results"
    assert parse_qs(urlsplit(older).query) == parse_qs(urlsplit(base + "&page=3").query)
    detail = next(a["href"] for a in links if urlsplit(a["href"]).path == f"/records/{ids[50]}")
    back = context(application, client, detail)["back_url"]
    assert parse_qs(urlsplit(back).query) == parse_qs(urlsplit(base + "&page=2").query)
    assert [r.id for r in context(application, client, back)["records"]] == ids[50:100]
    outside = client.get(base + "&page=999")
    assert outside.status_code == 302
    last = context(application, client, outside.location)
    assert last["pagination"] == dict(page=21, pages=21, total=1020, per_page=50)
    assert [r.id for r in last["records"]] == ids[1000:]
    export = next(a["href"] for a in links if urlsplit(a["href"]).path == "/records/export")
    assert len(csv_rows(client.get(export))) == 1021
    for bad in ("0", "-1", "none", "999999999999999"):
        assert client.get(base + "&page=" + bad).status_code == 400
    stranger = open_as(application, seeded["colleague"])
    assert context(application, stranger, base)["pagination"]["total"] == 0


def test_both_general_stages_keep_visible_totals_and_receipt_page(application, seeded, workflow):
    worker, reader, peer, scheduled, _ = workflow
    visit = point("TEST-VISIT", "spot", frequency="irregular")
    for n in range(53):
        actor = peer if n == 52 else worker
        instant = datetime(2026, 9, 1, 3) + timedelta(days=n)
        stamp = dict(period_key=instant.date().isoformat(), created_at=instant)
        db.session.add(PatrolExecution(**(values(actor, scheduled, "am") | stamp)))
        db.session.add(Inspection(**(values(actor, visit, "any") | stamp), workflow_mode="spot",
                                  executor_visit=True, spot_request_id=f"{n:032x}"))
    db.session.commit()
    base = "/records?date_from=2026-09-01&date_to=2026-11-01&floor=1&page=2"
    for actor, total in ((worker, 52), (reader, 53), (seeded["manager"], 53)):
        client = open_as(application, actor)
        for stage, key in (("execution", "executions"), ("inspection", "records")):
            url = base + "&stage=" + stage
            listing = context(application, client, url)
            assert listing["pagination"]["total"] == total and len(listing[key]) == total - 50
            receipt_id = listing[key][0].id
            target = f"/executions/{receipt_id}/success" if stage == "execution" else f"/checkins/{receipt_id}"
            links = Anchors(client.get(url).text).links
            receipt = next(a["href"] for a in links if urlsplit(a["href"]).path == target)
            back = context(application, client, receipt)["back_url"]
            assert parse_qs(urlsplit(back).query) == parse_qs(urlsplit(url).query)
