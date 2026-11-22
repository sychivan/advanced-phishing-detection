import base64
import hashlib
import json
from email.message import EmailMessage
from urllib.parse import parse_qs, urlsplit
from unittest.mock import MagicMock, Mock, call

import pytest
import requests
from bs4 import BeautifulSoup
from flask import Flask

from backend.services import gmail


JSON_HEADERS = {"Accept": "application/json"}
TEST_EMAIL = "gmail-demo@example.test"
TEST_ACCESS = "synthetic-access-for-tests"
TEST_REDIRECT = "http://127.0.0.1:5000/gmail/callback"


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_SESSION_SECRET", "test-signing-secret")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", TEST_REDIRECT)
    app = Flask(__name__)
    app.config["TESTING"] = True
    gmail.configure(app)
    return app


@pytest.fixture
def connected(app, monkeypatch):
    client = app.test_client()
    consent = start_oauth(client)
    token_response = Mock(status_code=200)
    token_response.json.return_value = {
        "access_token": TEST_ACCESS,
        "expires_in": 3600,
        "scope": f"openid email {gmail.READ_SCOPE}",
    }
    exchange = Mock(return_value=token_response)
    profile = Mock(return_value={"email": TEST_EMAIL, "email_verified": True})
    monkeypatch.setattr(gmail.requests, "post", exchange)
    monkeypatch.setattr(gmail, "google_get", profile)

    result = client.get("/gmail/callback", query_string={"state": consent["state"][0], "code": "test-code"})
    return client, consent, exchange, profile, result


def start_oauth(client):
    redirect = client.get("/gmail/connect?view=dashboard")
    assert redirect.status_code == 302
    destination = urlsplit(redirect.location)
    assert destination.netloc == "accounts.google.com"
    return parse_qs(destination.query)


def json_scan(client, csrf=None):
    data = {} if csrf is None else {"csrf": csrf}
    return client.post("/gmail/scan", data=data, headers=JSON_HEADERS)


def raw_message(plain=None, html=None, *, subject="Sample mailbox message"):
    message = EmailMessage()
    message["From"] = "Synthetic Sender <sender@example.test>"
    message["Subject"] = subject
    if plain is not None:
        message.set_content(plain)
    if html is not None:
        message.add_alternative(html, subtype="html")
    return {"raw": base64.urlsafe_b64encode(message.as_bytes()).decode().rstrip("=")}


def test_oauth_state_pkce_and_private_session(app, connected):
    client, consent, exchange, profile, result = connected
    assert consent["redirect_uri"] == [TEST_REDIRECT]
    assert set(consent["scope"][0].split()) == {"openid", "email", gmail.READ_SCOPE}
    assert consent["code_challenge_method"] == ["S256"]
    assert result.status_code == 302
    assert result.location == "/gmail/app#/overview"
    assert result.headers["Referrer-Policy"] == "no-referrer"
    verifier = exchange.call_args.kwargs["data"]["code_verifier"]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert consent["code_challenge"] == [challenge]
    assert not exchange.call_args.kwargs["allow_redirects"]
    profile.assert_called_once_with("https://openidconnect.googleapis.com/v1/userinfo", TEST_ACCESS)

    with client.session_transaction() as cookie:
        assert set(cookie) == {"gmail_key"}
        assert app.extensions["gmail_connections"][cookie["gmail_key"]]["token"] == TEST_ACCESS

    status = client.get("/gmail/session")
    assert status.json["email"] == TEST_EMAIL
    assert set(status.json) == {"connected", "email", "csrf"}
    assert status.headers["Cache-Control"] == "no-store"
    assert app.test_client().get("/gmail/session").json == {"connected": False}

    replay = client.get("/gmail/callback", query_string={"state": consent["state"][0], "code": "test-code"})
    assert replay.status_code == 400
    assert exchange.call_count == 1


@pytest.mark.parametrize("failure", ["mismatch", "expired", "other-browser", "denied"])
def test_invalid_oauth_callbacks_never_exchange_code(app, monkeypatch, failure):
    exchange = Mock()
    monkeypatch.setattr(gmail.requests, "post", exchange)
    client = app.test_client()
    consent = start_oauth(client)
    query = {"state": consent["state"][0], "code": "test-code"}
    if failure == "mismatch":
        query["state"] = "different-state"
    elif failure == "expired":
        next(iter(app.extensions["gmail_pending"].values()))["expires"] = 0
    elif failure == "other-browser":
        client = app.test_client()
    else:
        query = {"state": consent["state"][0], "error": "access_denied"}

    assert client.get("/gmail/callback", query_string=query).status_code == 400
    assert client.get("/gmail/session").json == {"connected": False}
    exchange.assert_not_called()


@pytest.mark.parametrize("scope", [
    "email openid",
    f"email openid {gmail.READ_SCOPE} https://www.googleapis.com/auth/gmail.modify",
    f"email openid {gmail.READ_SCOPE} https://mail.google.com/",
])
def test_callback_requires_only_read_only_gmail_scope(app, monkeypatch, scope):
    client = app.test_client()
    consent = start_oauth(client)
    response = Mock(status_code=200)
    response.json.return_value = {"scope": scope, "access_token": TEST_ACCESS, "expires_in": 3600}
    monkeypatch.setattr(gmail.requests, "post", Mock(return_value=response))
    profile = Mock()
    monkeypatch.setattr(gmail, "google_get", profile)

    result = client.get("/gmail/callback", query_string={"state": consent["state"][0], "code": "test-code"})
    assert result.status_code == 403
    assert client.get("/gmail/session").json == {"connected": False}
    profile.assert_not_called()


def test_read_only_scan_explanations_and_reconnect(app, monkeypatch):
    client = app.test_client()
    message_ids = [f"synthetic-{index}" for index in range(5)]
    subjects = [f"Sample inbox message {index}" for index in range(5)]
    reasons = [[f"Synthetic V1 explanation {index}"] for index in range(5)]
    model = Mock(side_effect=[
        {"classification": "Phishing", "risk_score": 55 + index, "model_status": "connected",
         "reasons": explanation}
        for index, explanation in enumerate(reasons)
    ])
    monkeypatch.setattr(gmail, "analyse_with_ai", model)

    token_url = "https://oauth2.googleapis.com/token"
    profile_url = "https://openidconnect.googleapis.com/v1/userinfo"
    messages_url = f"{gmail.API}/messages"
    granted_scope = f"openid https://www.googleapis.com/auth/userinfo.email {gmail.READ_SCOPE}"
    replies = {
        ("POST", token_url): {"access_token": TEST_ACCESS, "expires_in": 300, "scope": granted_scope},
        ("GET", profile_url): {"email": TEST_EMAIL, "email_verified": True},
        ("GET", messages_url): {"messages": [{"id": message_id} for message_id in message_ids]},
        **{
            ("GET", f"{messages_url}/{message_id}"): raw_message(
                f"Synthetic message body {index}.", subject=subjects[index]
            )
            for index, message_id in enumerate(message_ids)
        },
    }

    def respond(method, url, **kwargs):
        payload = replies[(method.upper(), url)]
        response = MagicMock(status_code=200)
        response.__enter__.return_value = response
        response.json.return_value = payload
        response.iter_content.return_value = [json.dumps(payload).encode()]
        return response

    transport = Mock(side_effect=respond)
    monkeypatch.setattr(gmail.requests.Session, "request", transport)

    states = []

    def complete_oauth():
        state = start_oauth(client)["state"][0]
        states.append(state)
        callback = client.get("/gmail/callback", query_string={"state": state, "code": "synthetic-code"})
        assert callback.status_code == 302
        return client.get("/gmail/session").json["csrf"]

    old_csrf = complete_oauth()
    transport.reset_mock()
    scan = json_scan(client, old_csrf)
    assert scan.status_code == 200
    messages = scan.json["messages"]
    assert [item["subject"] for item in messages] == subjects
    assert [item["reasons"] for item in messages] == reasons
    assert [item["risk_score"] for item in messages] == list(range(55, 60))
    assert all("body" not in item for item in messages)
    assert all(model_call.kwargs == {"local_only": True} for model_call in model.call_args_list)

    get_options = dict(headers={"Authorization": f"Bearer {TEST_ACCESS}"}, timeout=10,
                       allow_redirects=False, stream=True)
    assert transport.call_args_list == [
        call(method="get", url=messages_url, params={"labelIds": "INBOX", "maxResults": 5, "fields": "messages(id)"},
             **get_options),
        *(call(method="get", url=f"{messages_url}/{message_id}", params={"format": "raw", "fields": "raw"},
               **get_options) for message_id in message_ids),
    ]

    transport.reset_mock()
    abandoned_state = start_oauth(client)["state"][0]
    assert app.extensions["gmail_pending"]
    disconnect = client.post("/gmail/disconnect", data={"csrf": old_csrf}, headers=JSON_HEADERS)
    assert disconnect.json == {"connected": False}
    assert client.get("/gmail/session").json == {"connected": False}
    assert not app.extensions["gmail_connections"]
    assert not app.extensions["gmail_pending"]
    assert json_scan(client, old_csrf).status_code == 401
    for invalid_state in (states[0], abandoned_state):
        callback = client.get("/gmail/callback", query_string={"state": invalid_state, "code": "synthetic-code"})
        assert callback.status_code == 400
    transport.assert_not_called()

    new_csrf = complete_oauth()
    assert new_csrf != old_csrf
    assert states[1] != states[0]
    transport.reset_mock()
    assert json_scan(client, old_csrf).status_code == 403
    assert client.post("/gmail/disconnect", data={"csrf": old_csrf}, headers=JSON_HEADERS).status_code == 403
    transport.assert_not_called()


def test_standalone_scan_shows_prediction_warning_and_row_explanations(connected, monkeypatch):
    client = connected[0]
    csrf = client.get("/gmail/session").json["csrf"]
    synthetic_reason = "<b>Untrusted explanation</b>"
    monkeypatch.setattr(gmail, "scan_messages", Mock(return_value=[
        {"subject": "First synthetic message", "classification": "Phishing", "risk_score": 75,
         "reasons": [synthetic_reason]},
        {"subject": "Second synthetic message", "classification": "Safe", "risk_score": 0, "reasons": []},
        {"subject": "Third synthetic message", "classification": "Unavailable", "risk_score": None,
         "reasons": ["No readable message text."]},
    ]))

    response = client.post("/gmail/scan", data={"csrf": csrf})
    assert response.status_code == 200
    page = BeautifulSoup(response.get_data(as_text=True), "html.parser")
    warning = page.select_one(".prediction-note").get_text(" ", strip=True)
    assert "V1 predictions can be wrong" in warning
    assert "Legitimate messages can be flagged" in warning
    assert "Scanning is read-only" in warning

    cards = page.select("article.card")
    assert [card.summary.get_text(strip=True) for card in cards] == [
        "Why this score?", "Why this score?", "Why no score?",
    ]
    assert "Prediction: Phishing" in cards[0].strong.get_text(strip=True)
    assert cards[0].details.li.get_text(strip=True) == synthetic_reason
    assert cards[0].details.find("b") is None
    assert "did not provide an explanation" in cards[1].details.li.get_text(strip=True)
    assert cards[2].details.li.get_text(strip=True) == "No readable message text."


def test_scan_requires_csrf_and_returns_at_most_five_results(connected, monkeypatch):
    client = connected[0]
    csrf = client.get("/gmail/session").json["csrf"]
    google = Mock(side_effect=[
        {"messages": [{"id": f"message-{number}"} for number in range(7)]},
        raw_message("Body from a plain alternative.", "<p>Alternative HTML body.</p>"),
        raw_message(" ", "<html><head><title>Hidden</title></head><p>Visible body</p><script>Hidden</script></html>"),
        {"raw": "invalid@@@"},
        raw_message(),
        raw_message("Last available message."),
    ])
    model = Mock(return_value={"classification": "Safe", "risk_score": 12, "model_status": "connected", "reasons": []})
    monkeypatch.setattr(gmail, "google_get", google)
    monkeypatch.setattr(gmail, "analyse_with_ai", model)

    assert json_scan(client).status_code == 403
    google.assert_not_called()
    response = json_scan(client, csrf)
    assert response.status_code == 200
    messages = response.json["messages"]
    assert [message["classification"] for message in messages] == ["Safe", "Safe", "Unavailable", "Unavailable", "Safe"]
    assert all("body" not in message for message in messages)
    assert google.call_count == 6
    assert google.call_args_list[0].kwargs == {"labelIds": "INBOX", "maxResults": 5, "fields": "messages(id)"}
    assert google.call_args_list[1].kwargs == {"format": "raw", "fields": "raw"}
    assert [call.args[0]["body"] for call in model.call_args_list] == [
        "Body from a plain alternative.", "Visible body", "Last available message.",
    ]
    assert all(call.kwargs == {"local_only": True} for call in model.call_args_list)


def test_revoked_gmail_grant_removes_session(app, connected, monkeypatch):
    client = connected[0]
    csrf = client.get("/gmail/session").json["csrf"]
    response = requests.Response()
    response.status_code = 401
    google = Mock(side_effect=requests.HTTPError(response=response))
    monkeypatch.setattr(gmail, "google_get", google)
    assert json_scan(client, csrf).status_code == 401
    assert client.get("/gmail/session").json == {"connected": False}
    assert not app.extensions["gmail_connections"]


def test_malformed_gmail_rows_keep_readable_results(connected, monkeypatch):
    client = connected[0]
    csrf = client.get("/gmail/session").json["csrf"]
    deleted = requests.Response()
    deleted.status_code = 404
    google = Mock(side_effect=[
        {"messages": [None, {}, {"id": "no-raw"}, {"id": "deleted"}, {"id": "readable"}]},
        {},
        requests.HTTPError(response=deleted),
        raw_message("Readable message."),
    ])
    model = Mock(return_value={"classification": "Safe", "risk_score": 12, "model_status": "connected", "reasons": []})
    monkeypatch.setattr(gmail, "google_get", google)
    monkeypatch.setattr(gmail, "analyse_with_ai", model)

    result = json_scan(client, csrf)
    assert result.status_code == 200
    assert [message["classification"] for message in result.json["messages"]] == ["Unavailable"] * 4 + ["Safe"]
    assert google.call_count == 4
    model.assert_called_once()


def test_expiry_and_disconnect_remove_gmail_connection(app, connected):
    client = connected[0]
    csrf = client.get("/gmail/session").json["csrf"]
    assert client.post("/gmail/disconnect", headers=JSON_HEADERS).status_code == 403
    assert client.post("/gmail/disconnect", data={"csrf": csrf}, headers=JSON_HEADERS).json == {"connected": False}
    assert not app.extensions["gmail_connections"]

    with client.session_transaction() as cookie:
        cookie["gmail_key"] = "expired-connection"
    app.extensions["gmail_connections"]["expired-connection"] = {"expires": 0}
    assert client.get("/gmail/session").json == {"connected": False}
    assert json_scan(client, csrf).status_code == 401
    assert not app.extensions["gmail_connections"]


def test_google_reader_bounds_response_and_blocks_redirects(monkeypatch):
    response = Mock(status_code=200)
    response.iter_content.return_value = [b"1" * 21]
    context = Mock()
    context.__enter__ = Mock(return_value=response)
    context.__exit__ = Mock(return_value=False)
    get = Mock(return_value=context)
    monkeypatch.setattr(gmail.requests, "get", get)
    monkeypatch.setattr(gmail, "MAX_GOOGLE_RESPONSE_BYTES", 20)
    with pytest.raises(ValueError, match="too large"):
        gmail.google_get(gmail.API, TEST_ACCESS)
    assert get.call_args.kwargs["allow_redirects"] is False
    assert get.call_args.kwargs["stream"] is True

    response.status_code = 302
    response.iter_content.reset_mock()
    with pytest.raises(ValueError, match="Unexpected"):
        gmail.google_get(gmail.API, TEST_ACCESS)
    response.iter_content.assert_not_called()


def test_development_access_log_redacts_query(monkeypatch):
    observed = []

    def capture(handler, code, size):
        observed.append((handler.path, handler.requestline, code, size))

    monkeypatch.setattr(gmail.WSGIRequestHandler, "log_request", capture)
    handler = object.__new__(gmail.GmailRequestHandler)
    handler.path = "/gmail/callback?state=synthetic&code=synthetic"
    handler.requestline = f"GET {handler.path} HTTP/1.1"

    handler.log_request(302, 0)

    assert observed == [("/gmail/callback", "GET /gmail/callback", 302, 0)]
    assert handler.path.endswith("code=synthetic")
