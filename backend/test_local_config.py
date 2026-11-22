import json
from pathlib import Path

import pytest

from backend import local_config


@pytest.fixture
def clean_environment(monkeypatch):
    for name in local_config.SETTINGS:
        monkeypatch.delenv(name, raising=False)


def test_config_loads_values_without_overriding_process_settings(tmp_path, monkeypatch, clean_environment):
    path = tmp_path / ".env.phishguard.json"
    local_config.save_settings({
        "GOOGLE_CLIENT_ID": "synthetic-file-id",
        "DEMO_EMAIL": "file@example.test",
        "PHISHGUARD_DB_PATH": "workspace-demo.db",
    }, path)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "synthetic-override")
    monkeypatch.setenv("DEMO_EMAIL", "")
    monkeypatch.setenv("PHISHGUARD_DB_PATH", "temporary-path")
    monkeypatch.delenv("PHISHGUARD_DB_PATH")
    local_config.load_local_config(path)
    assert local_config.os.environ["GOOGLE_CLIENT_ID"] == "synthetic-override"
    assert local_config.os.environ["DEMO_EMAIL"] == ""
    assert local_config.os.environ["PHISHGUARD_DB_PATH"] == "workspace-demo.db"


def test_bad_config_error_does_not_expose_values(tmp_path):
    path = tmp_path / ".env.phishguard.json"
    path.write_text('{"GOOGLE_CLIENT_SECRET":"synthetic-sensitive",', encoding="utf-8")
    with pytest.raises(ValueError) as error:
        local_config.read_settings(path)
    assert "synthetic-sensitive" not in str(error.value)


def fixture_export(path: Path, redirect: str):
    path.write_text(json.dumps({"web": {
        "client_id": "synthetic-client",
        "client_secret": "synthetic-secret",
        "redirect_uris": [redirect],
    }}), encoding="utf-8")


def test_provisioning_reuses_valid_export_and_session_secret(tmp_path, monkeypatch, clean_environment):
    path = tmp_path / ".env.phishguard.json"
    export = tmp_path / "synthetic-export.json"
    fixture_export(export, local_config.GMAIL_REDIRECT_URI)
    local_config.save_settings({"PHISHGUARD_SESSION_SECRET": "existing-synthetic"}, path)
    monkeypatch.setenv("DEMO_EMAIL", "demo@example.test")
    monkeypatch.setenv("PHISHGUARD_DB_PATH", "demo.db")
    local_config.provision_gmail(path, export=export, prompt=lambda _: pytest.fail("Unexpected prompt"))
    settings = local_config.read_settings(path)
    assert settings["PHISHGUARD_SESSION_SECRET"] == "existing-synthetic"
    assert settings["GOOGLE_REDIRECT_URI"] == local_config.GMAIL_REDIRECT_URI
    assert settings["GOOGLE_CLIENT_SECRET"] == "synthetic-secret"
    assert settings["DEMO_EMAIL"] == "demo@example.test"
    assert settings["PHISHGUARD_DB_PATH"] == "demo.db"


def test_missing_secret_generated_once_and_bad_export_refused(tmp_path, clean_environment):
    path = tmp_path / ".env.phishguard.json"
    export = tmp_path / "synthetic-export.json"
    fixture_export(export, "http://127.0.0.1:9999/gmail/callback")
    with pytest.raises(ValueError, match="exact local Gmail callback"):
        local_config.provision_gmail(path, export=export)
    assert not path.exists()
    fixture_export(export, local_config.GMAIL_REDIRECT_URI)
    local_config.provision_gmail(path, export=export)
    secret = local_config.read_settings(path)["PHISHGUARD_SESSION_SECRET"]
    assert secret
    local_config.provision_gmail(path, export=export)
    assert local_config.read_settings(path)["PHISHGUARD_SESSION_SECRET"] == secret


def test_demo_setup_can_run_without_oauth_and_preserves_saved_values(tmp_path, clean_environment):
    path = tmp_path / ".env.phishguard.json"
    values = iter(("capstone@example.test", "synthetic-demo-only"))
    local_config.provision_demo(path, prompt=lambda _: next(values))
    settings = local_config.read_settings(path)
    assert settings == {
        "DEMO_EMAIL": "capstone@example.test",
        "DEMO_PASSWORD": "synthetic-demo-only",
        "AI_MODEL_URL": "http://127.0.0.1:5001/predict",
    }
    settings["PHISHGUARD_SESSION_SECRET"] = "existing-synthetic-session"
    settings["PHISHGUARD_DB_PATH"] = "existing-demo.db"
    local_config.save_settings(settings, path)
    local_config.provision_demo(path, prompt=lambda _: pytest.fail("Unexpected prompt"))
    assert local_config.read_settings(path) == settings
