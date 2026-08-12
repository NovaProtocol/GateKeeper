import pytest


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("MANAGE_PASSWORD", "test-manage-password")
    monkeypatch.setenv("BACKUP_CODE", "test-backup-code")
    monkeypatch.setenv("DB_DIR", str(tmp_path))

    from app import app as flask_app

    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def valid_code():
    return "test-backup-code"
