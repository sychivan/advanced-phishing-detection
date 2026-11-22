
import os
import math
import re
import secrets
import sqlite3
import sys
import time
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from services.ai_service import analyse_with_ai
from services.email_parser import extract_email_features
from services.gmail import GmailRequestHandler, configure as configure_gmail
from services.response_validator import validate_ai_response

ROOT_DIR = Path(__file__).resolve().parent.parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.local_config import load_local_config

load_local_config()

from database.storage import (
    save_model_response,
    list_messages,
    quarantine_message,
    restore_message,
    get_message_by_id,
    delete_message,
    submit_feedback,
    get_feedback,
    review_feedback
)

DEMO_EMAIL = os.getenv("DEMO_EMAIL")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

TOKEN_LIFETIME = 3600
MAX_SQLITE_ID = (1 << 63) - 1
active_tokens = {}
token_lock = Lock()


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200_000
configure_gmail(app)
origins = [
    origin.strip() for origin in os.getenv(
        "PHISHGUARD_CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500"
    ).split(",") if origin.strip()
]
if any("*" in origin for origin in origins):
    raise ValueError("PHISHGUARD_CORS_ORIGINS requires explicit origins")
origin_patterns = [re.compile(r"\A" + re.escape(origin) + r"\Z") for origin in origins]
CORS(
    app,
    resources={r"/api/.*": {"origins": origin_patterns}},
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
)


@app.after_request
def private_api_response(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(HTTPException)
def handle_http_error(error):
    response = error.get_response()
    if request.path.startswith("/api/"):
        response.set_data(app.json.dumps({"error": error.name, "message": error.name}))
        response.mimetype = "application/json"
    return response


def bearer_token():
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def require_auth(func):
    """Require a valid login token for protected API routes."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        token = bearer_token()
        if not token:
            return jsonify({
                "message": "Authentication required"
            }), 401

        with token_lock:
            authenticated = active_tokens.get(token, 0) > time.monotonic()
            if not authenticated:
                active_tokens.pop(token, None)
        if not authenticated:
            return jsonify({
                "message": "Invalid or expired token"
            }), 401

        return func(*args, **kwargs)

    return wrapper


def require_admin(func):
    """Require an authenticated demo administrator."""

    @wraps(func)
    @require_auth
    def wrapper(*args, **kwargs):
        if not ADMIN_EMAIL or DEMO_EMAIL != ADMIN_EMAIL:
            return jsonify({
                "message": "Admin access required"
            }), 403

        return func(*args, **kwargs)

    return wrapper


def require_record_id(func):
    """Reject IDs SQLite cannot represent before opening a database query."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if any(not 1 <= value <= MAX_SQLITE_ID for value in kwargs.values()):
            return jsonify({"message": "Record not found"}), 404
        return func(*args, **kwargs)

    return wrapper


def score_band(score):
    """Keep missing/invalid scores separate from a genuine low score of zero."""
    if type(score) not in (int, float) or not 0 <= score <= 100 or not math.isfinite(score):
        return "unscored"
    return "phishing" if score >= 70 else "suspicious" if score >= 40 else "safe"


@app.route("/api/feedback", methods=["POST"])
@require_auth
def create_feedback():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "message": "Invalid JSON request"
        }), 400

    analysis_id = data.get("analysis_id")
    suggested_label = data.get("suggested_label")

    if type(analysis_id) is not int or not 1 <= analysis_id <= MAX_SQLITE_ID:
        return jsonify({
            "message": "Valid analysis_id is required"
        }), 400

    if suggested_label not in ("Safe", "Phishing"):
        return jsonify({
            "message": "Suggested label must be Safe or Phishing"
        }), 400

    try:
        feedback_id = submit_feedback(
            analysis_id=analysis_id,
            submitted_by=DEMO_EMAIL,
            suggested_label=suggested_label
        )

        return jsonify({
            "message": "Feedback submitted successfully",
            "feedback_id": feedback_id,
            "review_status": "pending"
        }), 201

    except ValueError as error:
        return jsonify({
            "message": str(error)
        }), 400

    except Exception:
        app.logger.error("Failed to submit feedback")
        return jsonify({
            "message": "Unable to submit feedback"
        }), 500


@app.route("/api/feedback/<int:feedback_id>", methods=["GET"])
@require_auth
@require_record_id
def view_feedback(feedback_id):
    try:
        feedback = get_feedback(feedback_id)

        if feedback is None:
            return jsonify({
                "message": "Feedback not found"
            }), 404

        return jsonify(feedback), 200

    except Exception:
        app.logger.error("Failed to retrieve feedback")
        return jsonify({
            "message": "Unable to retrieve feedback"
        }), 500


@app.route("/api/feedback/<int:feedback_id>/review", methods=["POST"])
@require_admin
@require_record_id
def review_feedback_api(feedback_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "message": "Invalid JSON request"
        }), 400

    decision = data.get("decision")

    if decision not in ("approved", "rejected"):
        return jsonify({
            "message": "Decision must be approved or rejected"
        }), 400

    try:
        review_feedback(
            feedback_id=feedback_id,
            reviewed_by=ADMIN_EMAIL,
            decision=decision
        )

        return jsonify({
            "message": "Feedback reviewed successfully",
            "feedback_id": feedback_id,
            "review_status": decision
        }), 200

    except ValueError as error:
        return jsonify({
            "message": str(error)
        }), 400

    except Exception:
        app.logger.error("Failed to review feedback")
        return jsonify({
            "message": "Unable to review feedback"
        }), 500


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"message": "Invalid request"}), 400

    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({"message": "Invalid credentials"}), 401

    if not DEMO_EMAIL or not DEMO_PASSWORD:
        return jsonify({"message": "Demo login is not configured"}), 503

    if (
        secrets.compare_digest(email.encode("utf-8", errors="surrogatepass"), DEMO_EMAIL.encode("utf-8"))
        and secrets.compare_digest(
            password.encode("utf-8", errors="surrogatepass"), DEMO_PASSWORD.encode("utf-8")
        )
    ):
        token = secrets.token_urlsafe(32)
        with token_lock:
            now = time.monotonic()
            for expired in [key for key, deadline in active_tokens.items() if deadline <= now]:
                active_tokens.pop(expired)
            active_tokens[token] = now + TOKEN_LIFETIME

        return jsonify({
            "token": token,
            "user": {
                "email": email,
                "name": "PhishGuard Demo"
            }
        })

    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    with token_lock:
        active_tokens.pop(bearer_token(), None)

    return jsonify({"message": "Logged out successfully"})


@app.route("/")
def home():
    return jsonify({
        "message": "Advanced Phishing Detection Backend",
        "status": "running"
    })

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "success"})

@app.route("/api/analyse-email", methods=["POST"])
@require_auth
def analyse_email():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    sender = data.get("sender")
    subject = data.get("subject")
    body = data.get("body")

    if not all(isinstance(x, str) and x.strip()
               for x in [sender, subject, body]):
        return jsonify({
            "error": "Sender, subject and body are required"
        }), 400

    fields = {"sender": (sender, 500), "subject": (subject, 500), "body": (body, 12_000)}
    for name, (value, limit) in fields.items():
        try:
            value.encode("utf-8")
        except UnicodeError:
            return jsonify(error=f"{name} must contain valid Unicode"), 400
        if len(value) > limit:
            return jsonify(error=f"{name} must be at most {limit} characters"), 400

    features = extract_email_features(sender, subject, body)

    ai_result = analyse_with_ai(features, local_only=True)

    model_status = ai_result["model_status"]
    if model_status != "connected":
        status = {"not_connected": 503, "manual_review": 422}.get(model_status, 502)
        return jsonify(error=ai_result["reasons"][0], analysis_id=None, **ai_result), status

    try:
        ai_result = validate_ai_response(ai_result)
    except ValueError:
        return jsonify(error="Invalid AI model response", model_status="invalid_response"), 502

    try:
        analysis_id = save_model_response(sender, subject, body, ai_result)
    except (ValueError, OSError, sqlite3.Error):
        app.logger.error("Database save failed")
        return jsonify(error="Unable to save analysis", model_status="storage_error"), 500

    return jsonify(**ai_result, features=features, analysis_id=analysis_id)


@app.route("/api/stats", methods=["GET"])
@require_auth
def get_stats():
    try:
        inbox = list_messages("inbox")
        quarantine = list_messages("quarantine")
        messages = inbox + quarantine

        total = len(messages)

        counts = {name: 0 for name in ("safe", "suspicious", "phishing", "unscored")}
        for message in messages:
            counts[score_band(message.get("score"))] += 1

        # SQLite's created_at timestamps (exposed as receivedAt) use UTC as well.
        today = datetime.now(timezone.utc).date()
        daily = []

        for i in range(6, -1, -1):
            day = today - timedelta(days=i)
            day_messages = [
                m for m in messages
                if str(m.get("receivedAt", ""))[:10] == day.isoformat()
            ]

            daily.append({
                "date": day.isoformat(),
                "safe": sum(1 for m in day_messages if score_band(m.get("score")) in ("safe", "suspicious")),
                "phishing": sum(1 for m in day_messages if score_band(m.get("score")) == "phishing"),
                "unscored": sum(1 for m in day_messages if score_band(m.get("score")) == "unscored")
            })

        return jsonify({
            "total": total,
            **counts,
            "quarantined": len(quarantine),
            "daily": daily
        }), 200

    except Exception:
        app.logger.error("Failed to retrieve statistics")
        return jsonify({"error": "Unable to retrieve statistics"}), 500



@app.route("/api/messages/<int:message_id>/quarantine", methods=["POST"])
@require_auth
@require_record_id
def quarantine_email(message_id):
    try:
        message = quarantine_message(message_id)
        return jsonify(message), 200

    except ValueError as error:
        return jsonify({"error": str(error)}), 404

    except Exception:
        app.logger.error("Failed to quarantine email")
        return jsonify({"error": "Unable to quarantine email"}), 500


@app.route("/api/messages/<int:message_id>/restore", methods=["POST"])
@require_auth
@require_record_id
def restore_email(message_id):
    try:
        message = restore_message(message_id, submitted_by=DEMO_EMAIL)
        return jsonify(message), 200

    except ValueError as error:
        return jsonify({"error": str(error)}), 404

    except Exception:
        app.logger.error("Failed to restore email")
        return jsonify({"error": "Unable to restore email"}), 500


@app.route("/api/messages/<int:message_id>", methods=["GET"])
@require_auth
@require_record_id
def get_message(message_id):
    try:
        message = get_message_by_id(message_id)

        if message is None:
            return jsonify({"error": "Email not found"}), 404

        return jsonify(message), 200

    except Exception:
        app.logger.error("Failed to retrieve email")
        return jsonify({"error": "Unable to retrieve email"}), 500


@app.route("/api/messages/<int:message_id>", methods=["DELETE"])
@require_auth
@require_record_id
def delete_email(message_id):
    try:
        result = delete_message(message_id)
        return jsonify(result), 200

    except ValueError as error:
        return jsonify({"error": str(error)}), 404

    except Exception:
        app.logger.error("Failed to delete email")
        return jsonify({"error": "Unable to delete email"}), 500


@app.route("/api/messages", methods=["GET"])
@require_auth
def get_messages():
    status = request.args.get("status", "inbox")

    if status not in ("inbox", "quarantine"):
        return jsonify({"error": "Invalid status"}), 400

    try:
        messages = list_messages(status)
        return jsonify(messages), 200
    except Exception:
        app.logger.error("Failed to list messages")
        return jsonify({"error": "Unable to load messages"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, request_handler=GmailRequestHandler)
