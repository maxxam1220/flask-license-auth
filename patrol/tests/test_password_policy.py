"""Password policy boundaries through public account workflows, using SQLite only."""
from html.parser import HTMLParser
from urllib.parse import urlsplit

import pytest

from models import AuditLog, User, db
from test_app import PASSWORD, actors_only, application, login


@pytest.mark.parametrize("length", [5, 6, 256, 257])
@pytest.mark.parametrize("workflow", ["create", "reset", "change", "cli"])
def test_password_length_boundaries_preserve_account_workflows(application, actors_only, workflow, length):
    password = "Q" + "a" * (length - 1)
    accepted = 6 <= length <= 256
    worker = actors_only["inspector"]
    old_hash, old_version = worker.password_hash, worker.auth_version
    browser = application.test_client()
    other_browser = application.test_client()
    login(other_browser)
    if workflow == "create":
        login(browser, "manager")
        response = browser.post("/admin/users/create", data={
            "username": "six-char-worker", "display_name": "Boundary worker",
            "role": "safety", "password": password})
        account = db.session.scalar(db.select(User).where(User.username == "six-char-worker"))
        assert response.status_code == (302 if accepted else 400)
        assert (account is not None) == accepted
        if accepted:
            assert account.must_change_password and account.role == "inspector"
    elif workflow == "reset":
        login(browser, "manager")
        response = browser.post(f"/admin/users/{worker.id}/reset-password", data={"password": password})
        account = worker
        assert response.status_code == (302 if accepted else 400)
        assert worker.must_change_password == accepted
        assert worker.auth_version == old_version + int(accepted)
    elif workflow == "change":
        worker.must_change_password = True
        db.session.commit()
        login(browser)
        response = browser.post("/change-password", data={
            "current_password": PASSWORD, "new_password": password,
            "confirm_password": password, "next": "/devices"})
        account = worker
        assert response.status_code == (302 if accepted else 200)
        assert worker.must_change_password == (not accepted)
        assert worker.auth_version == old_version + int(accepted)
        if accepted:
            assert response.location == "/devices"
            assert browser.get("/devices").status_code == 200
    else:
        response = application.test_cli_runner().invoke(args=[
            "create-admin", "--username", "six-char-admin", "--name", "Boundary admin",
            "--password", password])
        account = db.session.scalar(db.select(User).where(User.username == "six-char-admin"))
        assert response.exit_code == (0 if accepted else 1)
        assert (account is not None) == accepted
        assert password not in response.output
        if accepted:
            assert account.role == "admin"

    if accepted:
        assert account.password_hash != password and account.check_password(password)
        fresh = application.test_client()
        result = fresh.post("/login", data={"username": account.username, "password": password})
        assert result.status_code == 302
        if workflow in ("create", "reset"):
            assert result.location == "/change-password"
        if workflow in ("reset", "change"):
            assert urlsplit(other_browser.get("/devices").location).path == "/login"
    else:
        assert worker.password_hash == old_hash and worker.auth_version == old_version
        assert db.session.query(AuditLog).count() == 0


@pytest.mark.parametrize("guard", ["current", "confirmation", "reuse"])
def test_six_character_password_keeps_change_guards(application, actors_only, guard):
    worker = actors_only["inspector"]
    worker.set_password("Old123")
    db.session.commit()
    original = worker.password_hash, worker.auth_version
    browser = application.test_client()
    assert browser.post("/login", data={"username": worker.username, "password": "Old123"}).status_code == 302
    fields = {"current_password": "Old123", "new_password": "New456", "confirm_password": "New456"}
    if guard == "current":
        fields["current_password"] = "Bad000"
    elif guard == "confirmation":
        fields["confirm_password"] = "Bad000"
    else:
        fields["new_password"] = fields["confirm_password"] = "Old123"
    response = browser.post("/change-password", data=fields)
    assert response.status_code == 200
    assert (worker.password_hash, worker.auth_version) == original
    assert worker.check_password("Old123") and browser.get("/devices").status_code == 200
    assert db.session.query(AuditLog).count() == 0


class PasswordInputs(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.inputs = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("autocomplete") == "new-password":
            self.inputs.append(attributes)


def test_password_forms_match_server_boundaries(application, actors_only):
    browser = application.test_client()
    login(browser, "manager")
    for path in ("/admin/users", "/change-password"):
        response = browser.get(path)
        assert response.status_code == 200
        fields = PasswordInputs(response.text).inputs
        assert len(fields) >= 2
        assert all(field.get("minlength") == "6" and field.get("maxlength") == "256" for field in fields)
        assert all(not field.get("value") for field in fields)
