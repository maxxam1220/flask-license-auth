import pytest
from werkzeug.security import generate_password_hash
from app import create_app
from models import User, db


@pytest.fixture
def clean_app(monkeypatch):
    monkeypatch.delenv("INITIAL_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("INITIAL_ADMIN_USERNAME", raising=False)
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "SQLALCHEMY_DATABASE_URI": "sqlite://"})
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_bootstrap_requires_configuration(clean_app):
    result = clean_app.test_cli_runner().invoke(args=["bootstrap-admin"])
    assert result.exit_code == 0
    assert db.session.query(User).count() == 0


def test_bootstrap_is_one_time_and_requires_password_change(clean_app, monkeypatch):
    password = "Temporary-password-for-test-1234"
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD_HASH", generate_password_hash(password))
    runner = clean_app.test_cli_runner()
    first = runner.invoke(args=["bootstrap-admin"])
    assert first.exit_code == 0, first.output
    admin = db.session.query(User).one()
    assert admin.role == "admin" and admin.must_change_password
    assert admin.check_password(password)
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD_HASH", generate_password_hash("Another-password-for-test"))
    assert runner.invoke(args=["bootstrap-admin"]).exit_code == 0
    db.session.refresh(admin)
    assert admin.check_password(password)
    assert db.session.query(User).count() == 1
    assert password not in first.output


def test_bootstrap_never_upgrades_existing_username(clean_app, monkeypatch):
    user = User(username="admin", display_name="Existing inspector", role="inspector")
    user.set_password("Existing-password-1234")
    db.session.add(user)
    db.session.commit()
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD_HASH", generate_password_hash("Another-password-for-test"))
    assert clean_app.test_cli_runner().invoke(args=["bootstrap-admin"]).exit_code != 0
    db.session.refresh(user)
    assert user.role == "inspector"
    assert user.check_password("Existing-password-1234")


def test_bootstrap_rejects_plaintext(clean_app, monkeypatch):
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD_HASH", "Never-store-this-plaintext-password")
    result = clean_app.test_cli_runner().invoke(args=["bootstrap-admin"])
    assert result.exit_code != 0
    assert db.session.query(User).count() == 0


def test_render_external_url_fallback(monkeypatch):
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://assigned-host.onrender.com")
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "SQLALCHEMY_DATABASE_URI": "sqlite://"})
    assert app.config["PUBLIC_BASE_URL"] == "https://assigned-host.onrender.com"
