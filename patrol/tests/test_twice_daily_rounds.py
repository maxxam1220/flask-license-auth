"""Two daily team obligations stay separate even with several inspectors per shift."""
from datetime import datetime, timedelta

import pytest

import app as patrol
from models import Inspection, PatrolExecution, Point, db
from test_app import FIXED_NOW, application, rendered_contexts
from test_workflow_checkin import payload, team


@pytest.mark.parametrize("paired", [True, False], ids=["two-stage", "direct"])
def test_both_rounds_complete_independently(application, monkeypatch, paired):
    noon = FIXED_NOW  # 12:00 in Taipei.
    instant = noon - timedelta(seconds=1)
    monkeypatch.setattr(patrol, "now_utc", lambda: instant)
    executor, inspector, peer, _, pair_url, direct_url, _ = team(application)
    url = pair_url if paired else direct_url
    point = db.session.scalar(db.select(Point).where(Point.qr_token == url[3:]))
    point.created_at = datetime(2026, 1, 1)
    db.session.commit()

    for completed, slot in enumerate(("am", "pm"), start=1):
        if slot == "pm":
            instant = noon
        if paired:
            assert 'id="inspection-form"' not in inspector.get(url).text
            execution_form = payload(executor, url)
            assert execution_form["slot"] == slot
            execution = executor.post(url + "/confirm", data=execution_form)
            assert execution.status_code == 302 and execution.location.startswith("/executions/")
        else:
            assert executor.get(url).status_code == 404

        for actor in (inspector, peer):
            form = payload(actor, url)
            assert (form["stage"], form["slot"]) == ("inspect", slot)
            receipt = actor.post(url + "/confirm", data=form)
            assert receipt.status_code == 302 and receipt.location.startswith("/checkins/")
            assert actor.post(url + "/confirm", data=form).status_code == 302
        with rendered_contexts(application) as pages:
            assert inspector.get("/dashboard?view=daily").status_code == 200
        card = next(c for c in pages[-1][1]["cards"] if c["point"].id == point.id)
        assert len(card["slots"]) == 2
        assert sum(s["status"] == "done" for s in card["slots"]) == completed
        saved = db.session.scalars(db.select(Inspection).where(Inspection.point_id == point.id)).all()
        assert len(saved) == completed * 2
        assert len({(r.slot, r.user_id) for r in saved}) == len(saved)
        if paired:
            assert all(r.execution.slot == r.slot for r in saved)
        else:
            assert all(r.execution_id is None for r in saved)
    assert db.session.query(PatrolExecution).count() == (2 if paired else 0)
