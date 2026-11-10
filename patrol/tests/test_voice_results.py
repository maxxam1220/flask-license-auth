"""Speech markers follow authorized persisted outcomes, never a client success hint."""
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from itsdangerous import TimestampSigner, URLSafeTimedSerializer
import pytest

from models import DeviceBinding, Inspection, PatrolExecution, User, db
from test_app import application
from test_daily2_anytime import anytime
from test_workflow_checkin import payload


def marker(response):
    class Markers(HTMLParser):
        def __init__(self):
            super().__init__()
            self.items = []
            self.controls = 0
            self.in_dialog = False

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "dialog":
                self.in_dialog = True
            if "data-voice-result" in attrs:
                assert "hidden" in attrs
                self.items.append({"kind": attrs["data-voice-result"], "id": attrs["data-voice-result-id"],
                                   "auto": attrs["data-voice-auto"]})
            if "data-voice-controls" in attrs and not self.in_dialog:
                self.controls += 1

        def handle_endtag(self, tag):
            if tag == "dialog":
                self.in_dialog = False

    parsed = Markers()
    parsed.feed(response.text)
    assert len(parsed.items) <= 1
    if parsed.items:
        assert parsed.controls == 1
    return parsed.items[0] if parsed.items else None


def with_token(url, token):
    parts = urlsplit(url)
    return urlunsplit(parts._replace(query=urlencode({"voice_feedback": token})))


def token_from(response):
    return parse_qs(urlsplit(response.location).query)["voice_feedback"][0]


def direct_visit(application, a):
    point = a.direct_point
    application.config["EXECUTOR_VISIT_CODES"] = frozenset({point.code})
    point.schedules[0].point_code = point.code
    point.frequency = point.schedules[0].frequency = "irregular"
    db.session.commit()
    return a.executor, a.direct


@pytest.mark.parametrize("kind", ["execute", "inspect", "visit"])
@pytest.mark.parametrize("simple", [False, True])
def test_new_and_duplicate_results_are_distinct_and_history_is_replay_only(application, anytime, kind, simple):
    a = anytime
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.simple_executor_ui = simple
    db.session.commit()
    browser, point_url = ((a.executor, a.paired) if kind == "execute" else
                          (a.inspector, a.direct) if kind == "inspect" else direct_visit(application, a))
    initial = browser.get(point_url)
    assert marker(initial) is None  # Scanning an eligible point is not attendance.
    fields = payload(browser, point_url)
    saved = browser.post(point_url + "/confirm", data=fields)
    assert saved.status_code == 302
    first = marker(browser.get(saved.location))
    assert first["kind"] == "saved_" + kind and first["auto"] == "true"
    duplicate = browser.post(point_url + "/confirm", data=fields)
    repeated = marker(browser.get(duplicate.location))
    assert repeated["kind"] == "already_recorded" and repeated["auto"] == "true"
    assert first["id"] != repeated["id"]
    assert urlsplit(saved.location).path == urlsplit(duplicate.location).path
    assert db.session.query(Inspection).count() + db.session.query(PatrolExecution).count() == 1
    history = marker(browser.get(urlsplit(saved.location).path))
    assert history == {"kind": "receipt_confirmed", "id": ("execution:" if kind == "execute" else "inspection:") + "1", "auto": "false"}
    # Refresh uses the same event ID: the client can deduplicate it without
    # implying another write, and unrelated history parameters retain meaning.
    assert marker(browser.get(saved.location)) == first
    review = browser.get(urlsplit(saved.location).path + "?return_to=/records&from_scan=1")
    assert review.status_code == 200 and marker(review) == history


@pytest.mark.parametrize("invalid", ["tampered", "expired", "wrong-actor", "wrong-auth-version", "wrong-record", "wrong-type", "malformed-signed", "duplicate-query"])
def test_voice_token_is_cosmetic_short_lived_and_bound_to_authorized_receipt(application, anytime, monkeypatch, invalid):
    a = anytime
    saved = a.executor.post(a.paired + "/confirm", data=payload(a.executor, a.paired))
    token, target, browser = token_from(saved), urlsplit(saved.location).path, a.executor
    if invalid == "tampered":
        token += "tampered"
    elif invalid == "expired":
        timestamp = TimestampSigner.get_timestamp
        monkeypatch.setattr(TimestampSigner, "get_timestamp", lambda self: timestamp(self) + 121)
    elif invalid == "wrong-actor":
        browser = a.inspector  # A general inspector may read this execution, not inherit its actor's result.
    elif invalid == "wrong-auth-version":
        actor = db.session.scalar(db.select(User).where(User.username == "exec"))
        actor.auth_version += 1
        db.session.commit()
        with browser.session_transaction() as session:
            session["auth_version"] = actor.auth_version
    elif invalid == "wrong-record":
        second = a.executor.post(a.paired + "/confirm", data=payload(a.executor, a.paired))
        target = urlsplit(second.location).path
    elif invalid == "wrong-type":
        inspection = a.inspector.post(a.direct + "/confirm", data=payload(a.inspector, a.direct))
        target, browser = urlsplit(inspection.location).path, a.inspector
    elif invalid == "malformed-signed":
        token = URLSafeTimedSerializer(application.secret_key, salt="patrol-voice-feedback-v1").dumps({"kind": "saved_execute"})
    response = browser.get(with_token(target, token) + ("&voice_feedback=" + token if invalid == "duplicate-query" else ""))
    assert response.status_code == 200
    result = marker(response)
    assert result["kind"] == "receipt_confirmed" and result["auto"] == "false"


def test_valid_voice_token_never_bypasses_receipt_authority(application, anytime):
    a = anytime
    inspection = a.inspector.post(a.direct + "/confirm", data=payload(a.inspector, a.direct))
    response = a.executor.get(inspection.location)
    assert response.status_code == 403 and marker(response) is None
    missing = a.inspector.get(with_token("/checkins/999999", token_from(inspection)))
    assert missing.status_code == 404 and marker(missing) is None
    signed_hint = a.executor.get(a.direct + "?voice_feedback=" + token_from(inspection))
    assert signed_hint.status_code == 404
    assert marker(signed_hint)["kind"] == "point_unavailable"
    assert db.session.query(Inspection).count() == 1 and db.session.query(PatrolExecution).count() == 0


def test_confirmation_denials_describe_actual_stage_and_do_not_confirm_attendance(application, anytime):
    a = anytime
    waiting = marker(a.inspector.get(a.paired))
    assert waiting["kind"] == "waiting_execution" and waiting["auto"] == "scan"
    worker = db.session.scalar(db.select(User).where(User.username == "inspect"))
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == worker.id))
    binding.status = "pending"
    db.session.commit()
    assert marker(a.inspector.get(a.paired))["kind"] == "device_required"
    binding.status = "approved"
    db.session.commit()
    fields = payload(a.executor, a.paired)
    rejected = a.executor.post(a.paired + "/confirm", data=fields | {"stage": "inspect"})
    assert rejected.status_code == 409 and marker(rejected)["kind"] == "not_saved"
    assert marker(a.admin.get(a.paired))["kind"] == "point_unavailable"
    for denied_url in (a.direct, "/c/no-such-token"):
        denied = a.executor.get(denied_url)
        assert denied.status_code == 404
        assert marker(denied)["kind"] == "point_unavailable" and marker(denied)["auto"] == "scan"
    assert db.session.query(PatrolExecution).count() == db.session.query(Inspection).count() == 0


def test_unbound_confirm_and_csrf_error_never_claim_saved(application, anytime):
    a = anytime
    fields = payload(a.executor, a.paired)
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == actor.id))
    binding.status = "revoked"
    db.session.commit()
    denied = a.executor.post(a.paired + "/confirm", data=fields)
    assert denied.status_code == 403 and marker(denied)["kind"] == "device_required"
    application.config["CSRF_ENABLED"] = True
    invalid_csrf = a.executor.post(a.paired + "/confirm", data=fields | {"csrf_token": "bad"})
    assert invalid_csrf.status_code == 400 and marker(invalid_csrf)["kind"] == "not_saved"
    assert db.session.query(PatrolExecution).count() == 0


def test_completed_scan_and_preferences_do_not_create_new_attendance(application, anytime):
    a = anytime
    a.pair_point.frequency = a.pair_point.schedules[0].frequency = "weekly"
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.ui_language, actor.simple_executor_ui = "vi", True
    db.session.commit()
    saved = a.executor.post(a.paired + "/confirm", data=payload(a.executor, a.paired))
    actor.ui_language = "id"
    db.session.commit()
    assert marker(a.executor.get(saved.location))["kind"] == "saved_execute"
    page = a.executor.get(a.paired)
    assert '<html lang="id">' in page.text
    assert marker(page)["kind"] == "already_recorded" and marker(page)["auto"] == "scan"
    assert db.session.query(PatrolExecution).count() == 1
