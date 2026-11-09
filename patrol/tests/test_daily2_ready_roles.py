"""A same-day role change must not make ready and QR select different rounds."""
from datetime import datetime

import pytest

from missed import TAIPEI
from models import Inspection, PatrolExecution, Point, User, db
from test_app import app_module, application, rendered_contexts
from test_workflow_checkin import payload, team


@pytest.mark.parametrize("other_execution", [False, True])
def test_new_inspector_skips_own_execution_for_ready_and_confirmation(application, monkeypatch, other_execution):
    monkeypatch.setattr(app_module, "now_utc", lambda: datetime(2026, 11, 6, 9, tzinfo=TAIPEI))
    executor, _, peer, _, url, *_ = team(application)
    point = db.session.scalar(db.select(Point).where(Point.qr_token == url[3:]))
    point.created_at = datetime(2026, 1, 1)
    db.session.commit()  # Persist fixture state before request-owned activation transactions.
    own = db.session.scalar(db.select(User).where(User.username == "exec"))
    other = db.session.scalar(db.select(User).where(User.username == "peer"))
    old_form = payload(executor, url)
    assert old_form["slot"] == "am"
    assert executor.post(url + "/confirm", data=old_form).status_code == 302
    if other_execution:
        other.role = "executor"
        db.session.commit()
        second_form = payload(peer, url)
        assert second_form["slot"] == "pm"
        assert peer.post(url + "/confirm", data=second_form).status_code == 302
    # No session-version change here: independently verify the ticket's role
    # binding, in addition to the admin route's normal session revocation.
    own.role = "inspector"
    db.session.commit()
    with rendered_contexts(application) as templates:
        response = executor.get(url)
    assert response.status_code == 200
    context = templates[-1][1]
    assert context["current_slot"] == ("pm" if other_execution else "am")
    assert context["can_confirm"] is other_execution
    with rendered_contexts(application) as templates:
        response = executor.get("/ready")
    assert response.status_code == 200
    rows = [row for row in templates[-1][1]["ready_points"] if row["id"] == point.id]
    assert len(rows) == int(other_execution)
    if other_execution:
        assert rows[0]["status_label"] == "第 2 次 · 已簽到待巡檢"
    assert executor.post(url + "/confirm", data=old_form).status_code == 409
    assert db.session.query(PatrolExecution).count() == 1 + int(other_execution)
    assert db.session.query(Inspection).count() == 0
