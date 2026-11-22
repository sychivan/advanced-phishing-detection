"""Read-only Gmail connection for the local PhishGuard demo."""
import base64
import hashlib
import json
import os
import secrets
import time
from email import policy
from email.errors import MessageError
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

import requests
from bs4 import BeautifulSoup
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.serving import WSGIRequestHandler

from .ai_service import analyse_with_ai
from .email_parser import extract_email_features

gmail = Blueprint("gmail", __name__, url_prefix="/gmail", template_folder="../templates")
READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
ALLOWED_GRANT_SCOPES = {READ_SCOPE, "openid", "email", "https://www.googleapis.com/auth/userinfo.email"}
API = "https://gmail.googleapis.com/gmail/v1/users/me"
BATCH_SIZE = 5
MAX_GOOGLE_RESPONSE_BYTES = 8 * 1024 * 1024
OAUTH_STATE_TTL = 600


class GmailRequestHandler(WSGIRequestHandler):
    """Keep OAuth callback query parameters out of development access logs."""

    def log_request(self, code="-", size="-"):
        path = getattr(self, "path", None)
        requestline = self.requestline
        try:
            if path is not None:
                self.path = path.partition("?")[0]
            self.requestline = requestline.partition("?")[0]
            super().log_request(code, size)
        finally:
            if path is not None:
                self.path = path
            self.requestline = requestline


def valid_redirect_uri(uri):
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return False
    return bool(
        parts.hostname
        and parts.path == "/gmail/callback"
        and parts.username is None
        and not parts.query
        and not parts.fragment
        and port != 0
        and (parts.scheme == "https" or (
            parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}
        ))
    )


def configure(app):
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "")
    redirect_valid = valid_redirect_uri(redirect_uri)
    app.config.update(
        SECRET_KEY=os.getenv("PHISHGUARD_SESSION_SECRET"),
        GMAIL_CLIENT_ID=os.getenv("GOOGLE_CLIENT_ID"),
        GMAIL_CLIENT_SECRET=os.getenv("GOOGLE_CLIENT_SECRET"),
        GMAIL_REDIRECT_URI=redirect_uri if redirect_valid else None,
        SESSION_COOKIE_NAME="phishguard_gmail_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=redirect_valid and urlsplit(redirect_uri).scheme == "https",
    )
    app.extensions["gmail_connections"] = {}
    app.extensions["gmail_pending"] = {}
    app.register_blueprint(gmail)


def gmail_configured():
    return all(current_app.config[key] for key in (
        "SECRET_KEY", "GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET", "GMAIL_REDIRECT_URI",
    ))


def remove_expired(records):
    now = time.monotonic()
    for key, record in records.copy().items():
        if record["expires"] <= now:
            records.pop(key, None)


def get_connection():
    connections = current_app.extensions["gmail_connections"]
    remove_expired(connections)
    key = session.get("gmail_key")
    connection = connections.get(key)
    if key and connection is None:
        session.pop("gmail_key", None)
    return connection


def page(error=None, status=200, messages=None):
    connection = get_connection() or {}
    return render_template("gmail.html", email=connection.get("email"),
                           csrf=connection.get("csrf"), error=error,
                           messages=messages), status


@gmail.after_request
def private_response(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@gmail.get("/")
def inbox():
    return page()


@gmail.get("/app")
def frontend():
    path = Path(current_app.root_path).parent / "phishguard-frontend.html"
    return send_file(path)


@gmail.get("/session")
def session_info():
    connection = get_connection()
    if not connection:
        return jsonify(connected=False)
    return jsonify(connected=True, email=connection["email"], csrf=connection["csrf"])


@gmail.get("/connect")
def connect():
    if not gmail_configured():
        return page("Gmail sign-in is not configured. See the project README.", 503)

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(32)
    pending = current_app.extensions["gmail_pending"]
    remove_expired(pending)
    pending.pop(session.get("gmail_state_key"), None)
    key = secrets.token_urlsafe(32)
    pending[key] = {
        "state": state, "verifier": verifier, "expires": time.monotonic() + OAUTH_STATE_TTL,
        "dashboard": request.args.get("view") == "dashboard",
    }
    session["gmail_state_key"] = key
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": current_app.config["GMAIL_CLIENT_ID"],
        "redirect_uri": current_app.config["GMAIL_REDIRECT_URI"],
        "response_type": "code",
        "scope": f"openid email {READ_SCOPE}",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }))


def google_get(url, token, **params):
    with requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params,
                      timeout=10, allow_redirects=False, stream=True) as response:
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError("Unexpected Google response")
        content = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content) > MAX_GOOGLE_RESPONSE_BYTES:
                raise ValueError("Google response is too large")
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Invalid Google response")
        return data


@gmail.get("/callback")
def callback():
    if not gmail_configured():
        return page("Gmail sign-in is not configured.", 503)
    pending = current_app.extensions["gmail_pending"].pop(session.pop("gmail_state_key", None), None)
    if not pending or pending["expires"] <= time.monotonic() or not secrets.compare_digest(
        pending["state"].encode(), request.args.get("state", "").encode()
    ):
        return page("Sign-in expired. Start again from Connect Gmail.", 400)
    code = request.args.get("code")
    if not code or request.args.get("error"):
        return page("Google did not grant access. Try connecting again.", 400)

    try:
        response = requests.post("https://oauth2.googleapis.com/token", data={
            "client_id": current_app.config["GMAIL_CLIENT_ID"],
            "client_secret": current_app.config["GMAIL_CLIENT_SECRET"],
            "redirect_uri": current_app.config["GMAIL_REDIRECT_URI"],
            "code": code,
            "code_verifier": pending["verifier"],
            "grant_type": "authorization_code",
        }, timeout=10, allow_redirects=False)
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError("Unexpected Google token response")
        grant = response.json()
        if not isinstance(grant, dict):
            raise ValueError("Invalid Google token response")
        scope = grant.get("scope")
        scopes = set(scope.split()) if isinstance(scope, str) else set()
        if READ_SCOPE not in scopes:
            return page("Allow read-only Gmail access to scan your inbox.", 403)
        if not scopes <= ALLOWED_GRANT_SCOPES:
            return page("Google returned additional permissions. Remove PhishGuard access in your Google Account and reconnect with read-only access.", 403)
        token = grant["access_token"]
        ttl = grant["expires_in"]
        if not isinstance(token, str) or not token.strip() or type(ttl) is not int or ttl <= 0:
            raise ValueError("Invalid Google access grant")
        expires = time.monotonic() + min(ttl, 3600)
        profile = google_get("https://openidconnect.googleapis.com/v1/userinfo", token)
        email = profile.get("email")
        if profile.get("email_verified") is not True or not isinstance(email, str) or not email.strip():
            return page("Google could not verify your email address.", 403)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return page("Could not connect to Google. Try again.", 502)

    connections = current_app.extensions["gmail_connections"]
    remove_expired(connections)
    connections.pop(session.get("gmail_key"), None)
    key = secrets.token_urlsafe(32)
    connections[key] = {
        "token": token, "email": email, "csrf": secrets.token_urlsafe(32),
        "expires": expires,
    }
    session["gmail_key"] = key
    if pending.get("dashboard"):
        return redirect(url_for("gmail.frontend") + "#/overview")
    return redirect(url_for("gmail.inbox"))


def scan_response(error=None, status=200, messages=None):
    if request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json":
        return jsonify(error=error, messages=messages), status
    return page(error=error, status=status, messages=messages)


def check_csrf(connection):
    return secrets.compare_digest(connection["csrf"].encode(), request.form.get("csrf", "").encode())


def unavailable_message(reason, sender="(Unknown sender)", subject="Unavailable message"):
    return {
        "sender": sender, "subject": subject, "classification": "Unavailable",
        "risk_score": None, "model_status": "unreadable_message", "reasons": [reason],
    }


def scan_message(token, message_id):
    if not isinstance(message_id, str) or not message_id:
        raise ValueError("Missing Gmail message ID")
    data = google_get(f"{API}/messages/{quote(message_id, safe='')}", token, format="raw", fields="raw")
    raw = data.get("raw")
    if not isinstance(raw, str) or not raw:
        raise ValueError("Missing raw Gmail message")
    message = BytesParser(policy=policy.default).parsebytes(
        base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    )
    subject = str(message.get("Subject", "(No subject)"))[:500]
    sender = str(message.get("From", "(Unknown sender)"))[:500]

    for content_type in ("plain", "html"):
        part = message.get_body(preferencelist=(content_type,))
        if part is None:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, MessageError):
            continue
        if not isinstance(content, str) or not content.strip():
            continue
        if content_type == "html":
            soup = BeautifulSoup(content, "html.parser")
            for element in soup(["script", "style", "head", "noscript"]):
                element.decompose()
            content = soup.get_text(" ", strip=True)
        body = content.strip()[:12000]
        if body:
            result = analyse_with_ai(extract_email_features(sender, subject, body), local_only=True)
            return {"sender": sender, "subject": subject, **result}

    return unavailable_message("No readable message text. Review this message in Gmail.", sender, subject)


def scan_messages(token):
    inbox = google_get(f"{API}/messages", token, labelIds="INBOX", maxResults=BATCH_SIZE,
                       fields="messages(id)")
    items = inbox.get("messages", [])
    if not isinstance(items, list):
        raise ValueError("Invalid Gmail inbox response")

    messages = []
    for item in items[:BATCH_SIZE]:
        try:
            message_id = item.get("id") if isinstance(item, dict) else None
            messages.append(scan_message(token, message_id))
        except requests.HTTPError as error:
            if error.response is None or error.response.status_code != 404:
                raise
            messages.append(unavailable_message("This message is no longer available in Gmail."))
        except (ValueError, TypeError, LookupError, MessageError):
            messages.append(unavailable_message("Could not read this message. Review it in Gmail."))
    return messages


@gmail.post("/scan")
def scan():
    connection = get_connection()
    if not connection:
        return scan_response("Connect Gmail to start scanning.", 401)
    if not check_csrf(connection):
        return scan_response("Invalid request. Reload the page and try again.", 403)

    try:
        messages = scan_messages(connection["token"])
    except requests.HTTPError as error:
        if error.response is not None and error.response.status_code == 401:
            current_app.extensions["gmail_connections"].pop(session.pop("gmail_key", None), None)
            return scan_response("Google ended this connection. Connect Gmail again.", 401)
        return scan_response("Gmail could not return the inbox. Try again.", 502)
    except (requests.RequestException, ValueError):
        return scan_response("Gmail could not return the inbox. Try again.", 502)

    return scan_response(messages=messages)


@gmail.post("/disconnect")
def disconnect():
    connection = get_connection()
    if not connection:
        return scan_response("Your connection expired. Connect Gmail again.", 401)
    if not check_csrf(connection):
        return scan_response("Invalid request. Reload the page and try again.", 403)
    current_app.extensions["gmail_connections"].pop(session.pop("gmail_key", None), None)
    current_app.extensions["gmail_pending"].pop(session.pop("gmail_state_key", None), None)
    if request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json":
        return jsonify(connected=False)
    return redirect(url_for("gmail.inbox"))
