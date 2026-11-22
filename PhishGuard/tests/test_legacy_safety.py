"""Offline regressions for the separate legacy rules/Claude prototype."""
import importlib.util
from email.message import EmailMessage
from pathlib import Path
import socket
import sys
from types import SimpleNamespace

from cryptography.fernet import Fernet
import dotenv
import pytest


LEGACY_ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def blocked(*_args, **_kwargs):
        raise AssertionError("Network access is disabled in legacy prototype tests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


@pytest.fixture
def legacy_scanner():
    return load_module("legacy_phishguard_scanner_under_test", LEGACY_ROOT / "scanner.py")


@pytest.fixture
def legacy_app(tmp_path, monkeypatch, legacy_scanner):
    # Never load a developer's dotenv file or use the prototype's normal database.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *_args, **_kwargs: False)
    monkeypatch.setenv("SECRET_KEY", "synthetic-legacy-test-session-secret")
    monkeypatch.setenv("TOKEN_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv("SCAN_INTERVAL", "0")
    for name in ("ANTHROPIC_API_KEY", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
                 "MS_CLIENT_ID", "MS_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    providers = load_module("legacy_phishguard_providers_under_test", LEGACY_ROOT / "providers.py")
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "scanner", legacy_scanner)
    module = load_module("legacy_phishguard_app_under_test", LEGACY_ROOT / "app.py")
    module.app.config.update(TESTING=True)
    return module


@pytest.mark.parametrize("path", ["/scan/7", "/disconnect/7", "/msg/7/release"])
def test_mutations_reject_missing_csrf_even_before_a_session_exists(legacy_app, monkeypatch, path):
    calls = []
    monkeypatch.setattr(legacy_app, "scan_account", calls.append)
    response = legacy_app.app.test_client().post(path)
    assert response.status_code == 400
    assert calls == []


@pytest.mark.parametrize("expected, supplied", [("", ""), ("expected", ""), ("expected", "wrong")])
def test_mutations_reject_empty_or_mismatched_csrf(legacy_app, monkeypatch, expected, supplied):
    calls = []
    monkeypatch.setattr(legacy_app, "scan_account", calls.append)
    client = legacy_app.app.test_client()
    with client.session_transaction() as session:
        session["csrf"] = expected
    response = client.post("/scan/7", data={"csrf": supplied})
    assert response.status_code == 400
    assert calls == []


def test_page_csrf_allows_the_requested_action(legacy_app, monkeypatch):
    calls = []
    monkeypatch.setattr(legacy_app, "scan_account", calls.append)
    client = legacy_app.app.test_client()
    assert client.get("/").status_code == 200
    with client.session_transaction() as session:
        token = session["csrf"]
    assert isinstance(token, str) and token
    response = client.post("/scan/7", data={"csrf": token})
    assert response.status_code == 302
    assert calls == [7]


@pytest.mark.parametrize("body, subtype", [
    ("Inspect this malformed URL: http://[broken", "plain"),
    ('<a href="http://[broken">https://example.test/account</a>', "html"),
])
def test_malformed_urls_do_not_abort_message_analysis(legacy_scanner, monkeypatch, body, subtype):
    monkeypatch.setattr(legacy_scanner, "ask_claude", lambda *_args: None)
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["Subject"] = "Synthetic malformed link"
    message.set_content(body, subtype=subtype)
    result = legacy_scanner.analyze(message.as_bytes())
    assert result["subject"] == "Synthetic malformed link"
    assert result["ai"] is None
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100


def test_valid_ip_and_mismatched_link_checks_still_apply(legacy_scanner, monkeypatch):
    monkeypatch.setattr(legacy_scanner, "ask_claude", lambda *_args: None)
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["Subject"] = "Synthetic link comparison"
    message.set_content('<a href="http://192.0.2.7/login">https://example.test/account</a>', subtype="html")
    result = legacy_scanner.analyze(message.as_bytes())
    flags = [flag["t"] for flag in result["flags"]]
    assert any("Link to raw IP: 192.0.2.7" in flag for flag in flags)
    assert any("Link text shows example.test but goes to 192.0.2.7" in flag for flag in flags)


def test_claude_failure_does_not_log_private_exception_text(legacy_scanner, monkeypatch, capsys):
    sentinel = "SYNTHETIC_PRIVATE_EMAIL_AND_TOKEN_DO_NOT_LOG"

    def fail(**_kwargs):
        raise RuntimeError(sentinel)

    fake_client = SimpleNamespace(messages=SimpleNamespace(create=fail))
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=lambda: fake_client))
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["Subject"] = "Synthetic provider failure"
    assert legacy_scanner.ask_claude(message, "Synthetic body", []) is None
    output = capsys.readouterr()
    assert sentinel not in output.out + output.err
    assert "RuntimeError" in output.out + output.err
