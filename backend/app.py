
from services.response_validator import validate_ai_response
from services.email_parser import extract_email_features
from flask import Flask, jsonify, request
from flask_cors import CORS
from services.ai_service import analyse_with_ai
from services.gmail import configure as configure_gmail


import os
import secrets
from functools import wraps

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


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

active_tokens = set()


app = Flask(__name__)
configure_gmail(app)
CORS(
    app,
    resources={r"/api/*": {"origins": [
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ]}},
    supports_credentials=True
)

def require_auth(func):
    """Require a valid login token for protected API routes."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")

        if not auth.startswith("Bearer "):
            return jsonify({
                "message": "Authentication required"
            }), 401

        token = auth.removeprefix("Bearer ").strip()

        if not token or token not in active_tokens:
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

    if type(analysis_id) is not int or analysis_id <= 0:
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
        app.logger.exception("Failed to submit feedback")
        return jsonify({
            "message": "Unable to submit feedback"
        }), 500


@app.route("/api/feedback/<int:feedback_id>", methods=["GET"])
@require_auth
def view_feedback(feedback_id):
    try:
        feedback = get_feedback(feedback_id)

        if feedback is None:
            return jsonify({
                "message": "Feedback not found"
            }), 404

        return jsonify(feedback), 200

    except Exception:
        app.logger.exception("Failed to retrieve feedback")
        return jsonify({
            "message": "Unable to retrieve feedback"
        }), 500


@app.route("/api/feedback/<int:feedback_id>/review", methods=["POST"])
@require_admin
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
        app.logger.exception("Failed to review feedback")
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
        secrets.compare_digest(email, DEMO_EMAIL)
        and secrets.compare_digest(password, DEMO_PASSWORD)
    ):
        token = secrets.token_urlsafe(32)
        active_tokens.add(token)

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
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()

    active_tokens.discard(token)

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
    
    features = extract_email_features(sender, subject, body)

    # Analyse email using the connected AI model
    ai_result = analyse_with_ai(features)

    if ai_result.get("model_status") == "connected":
        try:
            ai_result = validate_ai_response(ai_result)
        except ValueError:
            return jsonify({
                "error": "Invalid AI model response",
                "model_status": "invalid_response"
            }), 502

        try:
            analysis_id = save_model_response(
                sender,
                subject,
                body,
                ai_result
            )
        except (ValueError, OSError) as error:
            app.logger.error("Database save failed: %s", error)
            return jsonify({
                "error": "Unable to save analysis",
                "model_status": "storage_error"
            }), 500

    
    return jsonify({
    "classification": ai_result["classification"],
    "risk_score": ai_result["risk_score"],
    "model_status": ai_result["model_status"],
    "reasons": ai_result["reasons"],
    "features": features,
    "analysis_id": analysis_id if ai_result["model_status"] == "connected" else None
})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        inbox = list_messages("inbox")
        quarantine = list_messages("quarantine")
        messages = inbox + quarantine

        total = len(messages)

        phishing = sum(
            1 for m in messages if m["score"] >= 70
        )
        suspicious = sum(
            1 for m in messages if 40 <= m["score"] < 70
        )
        safe = sum(
            1 for m in messages if m["score"] < 40
        )

        from collections import defaultdict
        from datetime import datetime, timedelta

        today = datetime.now().date()
        daily = []

        for i in range(6, -1, -1):
            day = today - timedelta(days=i)
            day_messages = [
                m for m in messages
                if m["receivedAt"][:10] == day.isoformat()
            ]

            daily.append({
                "date": day.isoformat(),
                "safe": sum(1 for m in day_messages if m["score"] < 70),
                "phishing": sum(1 for m in day_messages if m["score"] >= 70)
            })

        return jsonify({
            "total": total,
            "phishing": phishing,
            "suspicious": suspicious,
            "safe": safe,
            "quarantined": len(quarantine),
            "daily": daily
        }), 200

    except Exception:
        app.logger.exception("Failed to retrieve statistics")
        return jsonify({"error": "Unable to retrieve statistics"}), 500



@app.route("/api/messages/<int:message_id>/quarantine", methods=["POST"])
@require_auth
def quarantine_email(message_id):
    try:
        message = quarantine_message(message_id)
        return jsonify(message), 200

    except ValueError as error:
        return jsonify({"error": str(error)}), 404

    except Exception:
        app.logger.exception("Failed to quarantine email")
        return jsonify({"error": "Unable to quarantine email"}), 500


@app.route("/api/messages/<int:message_id>/restore", methods=["POST"])
@require_auth
def restore_email(message_id):
    try:
        message = restore_message(message_id)
        return jsonify(message), 200

    except ValueError as error:
        return jsonify({"error": str(error)}), 404

    except Exception:
        app.logger.exception("Failed to restore email")
        return jsonify({"error": "Unable to restore email"}), 500


@app.route("/api/messages/<int:message_id>", methods=["GET"])
def get_message(message_id):
    try:
        message = get_message_by_id(message_id)

        if message is None:
            return jsonify({"error": "Email not found"}), 404

        return jsonify(message), 200

    except Exception:
        app.logger.exception("Failed to retrieve email")
        return jsonify({"error": "Unable to retrieve email"}), 500


@app.route("/api/messages/<int:message_id>", methods=["DELETE"])
def delete_email(message_id):
    try:
        result = delete_message(message_id)
        return jsonify(result), 200

    except ValueError as error:
        return jsonify({"error": str(error)}), 404

    except Exception:
        app.logger.exception("Failed to delete email")
        return jsonify({"error": "Unable to delete email"}), 500


@app.route("/api/messages", methods=["GET"])
def get_messages():
    status = request.args.get("status", "inbox")

    if status not in ("inbox", "quarantine"):
        return jsonify({"error": "Invalid status"}), 400

    try:
        messages = list_messages(status)
        return jsonify(messages), 200
    except Exception:
        app.logger.exception("Failed to list messages")
        return jsonify({"error": "Unable to load messages"}), 500


if __name__ == "__main__":
    app.run(debug=not bool(os.getenv("GOOGLE_CLIENT_ID")), port=5000)
