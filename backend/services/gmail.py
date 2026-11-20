"""Read-only Gmail connection for the local PhishGuard demo."""
import base64
import hashlib
import os
import secrets
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

import requests
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, send_file, session, url_for

from .ai_service import analyse_with_ai
from .email_parser import extract_email_features

gmail = Blueprint("gmail", __name__, url_prefix="/gmail", template_folder="../templates")
READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
API = "https://gmail.googleapis.com/gmail/v1/users/me"
BATCH_SIZE = 5


def configure(app):
    app.config.update(
        SECRET_KEY=os.getenv("PHISHGUARD_SESSION_SECRET"),
        SESSION_COOKIE_NAME="phishguard_gmail_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=urlsplit(os.getenv("GOOGLE_REDIRECT_URI", "")).scheme == "https",
    )
    app.extensions["gmail_connections"] = {}
    app.register_blueprint(gmail)


def page(error=None, status=200, messages=None):
    return render_template("gmail.html", email=session.get("gmail_email"),
                           csrf=session.get("gmail_csrf"), error=error,
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
    connection = current_app.extensions["gmail_connections"].get(session.get("gmail_key"))
    if not connection or connection[1] <= time.time():
        return jsonify(connected=False)
    return jsonify(connected=True, email=session["gmail_email"], csrf=session["gmail_csrf"])


@gmail.get("/connect")
def connect():
    if not all(os.getenv(key) for key in (
        "PHISHGUARD_SESSION_SECRET", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI"
    )):
        return page("Gmail sign-in is not configured. See the project README.", 503)

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(32)
    session["gmail_pending"] = {
        "state": state, "verifier": verifier, "started": time.time(),
        "dashboard": request.args.get("view") == "dashboard",
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": os.environ["GOOGLE_REDIRECT_URI"],
        "response_type": "code",
        "scope": f"openid email {READ_SCOPE}",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }))


def google_get(url, token, **params):
    response = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=10)
    response.raise_for_status()
    return response.json()


@gmail.get("/callback")
def callback():
    if not current_app.secret_key:
        return page("Gmail sign-in is not configured.", 503)
    pending = session.pop("gmail_pending", None)
    if not pending or time.time() - pending["started"] > 600 or not secrets.compare_digest(
        pending["state"].encode(), request.args.get("state", "").encode()
    ):
        return page("Sign-in expired. Start again from Connect Gmail.", 400)
    code = request.args.get("code")
    if not code or request.args.get("error"):
        return page("Google did not grant access. Try connecting again.", 400)

    try:
        response = requests.post("https://oauth2.googleapis.com/token", data={
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uri": os.environ["GOOGLE_REDIRECT_URI"],
            "code": code,
            "code_verifier": pending["verifier"],
            "grant_type": "authorization_code",
        }, timeout=10)
        response.raise_for_status()
        grant = response.json()
        if READ_SCOPE not in grant.get("scope", "").split():
            return page("Allow read-only Gmail access to scan your inbox.", 403)
        token = grant["access_token"]
        profile = google_get("https://openidconnect.googleapis.com/v1/userinfo", token)
        if profile.get("email_verified") is not True or not profile.get("email"):
            return page("Google could not verify your email address.", 403)
        expires = time.time() + min(int(grant["expires_in"]), 3600)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return page("Could not connect to Google. Try again.", 502)

    connections = current_app.extensions["gmail_connections"]
    for key, (_, deadline) in connections.copy().items():
        if deadline <= time.time():
            connections.pop(key, None)
    connections.pop(session.get("gmail_key"), None)
    session.clear()
    key = secrets.token_urlsafe(32)
    connections[key] = token, expires
    session.update(gmail_key=key, gmail_email=profile["email"], gmail_csrf=secrets.token_urlsafe(32))
    if pending.get("dashboard"):
        return redirect(url_for("gmail.frontend") + "#/overview")
    return redirect(url_for("gmail.inbox"))


def scan_response(error=None, status=200, messages=None):
    if request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json":
        return jsonify(error=error, messages=messages), status
    return page(error=error, status=status, messages=messages)


def check_csrf():
    expected = session.get("gmail_csrf")
    return expected and secrets.compare_digest(expected.encode(), request.form.get("csrf", "").encode())


def scan_message(token, message_id):
    data = google_get(f"{API}/messages/{quote(message_id, safe='')}", token, format="raw")
    raw = data["raw"]
    message = BytesParser(policy=policy.default).parsebytes(
        base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    )
    subject = str(message.get("Subject", "(No subject)"))[:500]
    sender = str(message.get("From", "(Unknown sender)"))[:500]
    part = message.get_body(preferencelist=("plain", "html"))
    content = part.get_content() if part else ""
    body = content[:12000] if isinstance(content, str) else ""
    result = analyse_with_ai(extract_email_features(sender, subject, body))
    return {"sender": sender, "subject": subject, **result}


@gmail.post("/scan")
def scan():
    if not check_csrf():
        return scan_response("Connect Gmail to start scanning.", 403)

    connections = current_app.extensions["gmail_connections"]
    key = session.get("gmail_key")
    connection = connections.get(key)
    if not connection or connection[1] <= time.time():
        connections.pop(key, None)
        session.clear()
        return scan_response("Your connection expired. Connect Gmail again.", 401)

    token = connection[0]
    try:
        inbox_data = google_get(f"{API}/messages", token, labelIds="INBOX", maxResults=BATCH_SIZE)
        messages = [scan_message(token, item["id"]) for item in inbox_data.get("messages", [])[:BATCH_SIZE]]
    except requests.HTTPError as error:
        if error.response is not None and error.response.status_code == 401:
            connections.pop(key, None)
            session.clear()
            return scan_response("Google ended this connection. Connect Gmail again.", 401)
        return scan_response("Gmail could not return the inbox. Try again.", 502)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return scan_response("Could not read a Gmail message. Try again.", 502)

    return scan_response(messages=messages)


@gmail.post("/disconnect")
def disconnect():
    if not check_csrf():
        return scan_response("Invalid request. Reload the page and try again.", 403)
    current_app.extensions["gmail_connections"].pop(session.get("gmail_key"), None)
    session.clear()
    if request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json":
        return jsonify(connected=False)
    return redirect(url_for("gmail.inbox"))
