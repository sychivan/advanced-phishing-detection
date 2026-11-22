from contextlib import closing
from pathlib import Path
import json
import math
import os
import sqlite3

DB_PATH = Path(os.environ.get("PHISHGUARD_DB_PATH") or Path(__file__).resolve().parent / "analysis.db")


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def save_analysis(sender, subject, body, model_version_id, result):
    """Save a successful model result and return its analysis ID."""
    if not all(
        isinstance(value, str) and value.strip()
        for value in (sender, subject, body)
    ):
        raise ValueError("Sender, subject and body are required")

    if not isinstance(result, dict):
        raise ValueError("Result must be a dictionary")

    if result.get("model_status") != "connected":
        raise ValueError("Only successful model results can be saved")

    classification = result.get("classification")
    if classification not in {"Safe", "Suspicious", "Phishing"}:
        raise ValueError("Invalid classification")

    score = result.get("risk_score")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 100
    ):
        raise ValueError("Score must be a finite number from 0 to 100")

    reasons = result.get("reasons")
    if not isinstance(reasons, list) or not all(
        isinstance(reason, str) for reason in reasons
    ):
        raise ValueError("Reasons must be a list of strings")

    with closing(connect()) as connection:
        with connection:
            email_id = connection.execute(
                """
                INSERT INTO emails (sender, subject, body)
                VALUES (?, ?, ?)
                """,
                (sender, subject, body),
            ).lastrowid

            analysis_id = connection.execute(
                """
                INSERT INTO analysis_results
                    (email_id, model_version_id, classification,
                     risk_score, reasons_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    email_id,
                    model_version_id,
                    classification,
                    score,
                    json.dumps(reasons),
                ),
            ).lastrowid

    return analysis_id


def get_analysis(analysis_id):
    """Retrieve one saved analysis, or None if it does not exist."""
    with closing(connect()) as connection:
        row = connection.execute(
            """
            SELECT a.*, e.sender, e.subject, e.body,
                   m.version AS model_version,
                   m.artifact_hash
            FROM analysis_results AS a
            JOIN emails AS e ON e.id = a.email_id
            JOIN model_versions AS m ON m.id = a.model_version_id
            WHERE a.id = ?
            """,
            (analysis_id,),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["reasons"] = json.loads(result.pop("reasons_json"))
    return result

def submit_feedback(analysis_id, submitted_by, suggested_label):
    """Store a suggested correction as pending feedback."""
    if not isinstance(submitted_by, str) or not submitted_by.strip():
        raise ValueError("Submitter identity is required")

    if suggested_label not in {"Safe", "Phishing"}:
        raise ValueError("Suggested label must be Safe or Phishing")

    with closing(connect()) as connection:
        with connection:
            exists = connection.execute(
                "SELECT 1 FROM analysis_results WHERE id = ?",
                (analysis_id,),
            ).fetchone()

            if exists is None:
                raise ValueError("Analysis does not exist")

            feedback_id = connection.execute(
                """
                INSERT INTO feedback
                    (analysis_id, submitted_by, suggested_label)
                VALUES (?, ?, ?)
                """,
                (analysis_id, submitted_by.strip(), suggested_label),
            ).lastrowid

    return feedback_id


def review_feedback(feedback_id, reviewed_by, decision):
    """Approve or reject feedback that is still pending."""
    if not isinstance(reviewed_by, str) or not reviewed_by.strip():
        raise ValueError("Reviewer identity is required")

    if decision not in {"approved", "rejected"}:
        raise ValueError("Decision must be approved or rejected")

    with closing(connect()) as connection:
        with connection:
            cursor = connection.execute(
                """
                UPDATE feedback
                SET review_status = ?,
                    reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE id = ? AND review_status = 'pending'
                """,
                (decision, reviewed_by.strip(), feedback_id),
            )

            if cursor.rowcount != 1:
                raise ValueError(
                    "Feedback does not exist or has already been reviewed"
                )


def get_feedback(feedback_id):
    """Return one feedback record, or None."""
    with closing(connect()) as connection:
        row = connection.execute(
            "SELECT * FROM feedback WHERE id = ?",
            (feedback_id,),
        ).fetchone()

    return dict(row) if row else None

def register_model(model_path, report_path):
    """Register a saved model and return its database ID."""
    import hashlib

    model_path = Path(model_path)
    report_path = Path(report_path)

    artifact_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    version = f"tfidf-logreg-{artifact_hash}"

    metrics = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(metrics, dict):
        raise ValueError("Evaluation report must be a JSON object")

    with closing(connect()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO model_versions
                    (version, artifact_hash, metrics_json)
                VALUES (?, ?, ?)
                ON CONFLICT(version) DO NOTHING
                """,
                (version, artifact_hash, json.dumps(metrics)),
            )

            row = connection.execute(
                """
                SELECT id, artifact_hash
                FROM model_versions
                WHERE version = ?
                """,
                (version,),
            ).fetchone()

            if row["artifact_hash"] != artifact_hash:
                raise ValueError("Registered model hash does not match")

    return row["id"]

def save_model_response(sender, subject, body, result):
    if not isinstance(result, dict):
        raise ValueError("Model response must be an object")

    if result.get("model_status") != "connected":
        raise ValueError("Only successful model predictions can be saved")

    version = result.get("model_version")
    artifact_hash = result.get("artifact_hash")

    if not isinstance(version, str) or not version.strip():
        raise ValueError("Model version is required")

    if not isinstance(artifact_hash, str) or not artifact_hash.strip():
        raise ValueError("Model artifact hash is required")

    with closing(connect()) as connection:
        model_row = connection.execute(
            """
            SELECT id
            FROM model_versions
            WHERE version = ? AND artifact_hash = ?
            """,
            (version, artifact_hash),
        ).fetchone()

    if model_row is None:
        raise ValueError("Prediction model is not registered")

    return save_analysis(
        sender, subject, body, model_row["id"], result
    )

def list_messages(status="inbox"):
    """Retrieve emails and their latest AI analysis."""

    if status not in ("inbox", "quarantine"):
        raise ValueError("Invalid email status")

    with closing(connect()) as connection:
        rows = connection.execute(
            """
            SELECT
                e.id,
                e.sender,
                e.subject,
                e.body,
                e.created_at,
                e.status,
                a.classification,
                a.risk_score,
                a.reasons_json
            FROM emails e
            LEFT JOIN analysis_results a
                ON a.id = (
                    SELECT MAX(a2.id)
                    FROM analysis_results a2
                    WHERE a2.email_id = e.id
                )
            WHERE e.status = ?
            ORDER BY e.created_at DESC, e.id DESC
            """,
            (status,)
        ).fetchall()

    messages = []

    for row in rows:
        sender = row["sender"]

        messages.append({
            "id": str(row["id"]),
            "from": {
                "name": sender.split("@")[0],
                "email": sender
            },
            "subject": row["subject"],
            "receivedAt": row["created_at"],
            "score": row["risk_score"] if row["risk_score"] is not None else 0,
            "preview": row["body"][:120],
            "body": row["body"],
            "status": row["status"],
            "signals": [],
            "links": []
        })

    return messages


def quarantine_message(message_id):
    """Move an email into quarantine."""

    with closing(connect()) as connection:
        with connection:
            cursor = connection.execute(
                """
                UPDATE emails
                SET status = 'quarantine'
                WHERE id = ? AND status = 'inbox'
                """,
                (message_id,)
            )

            if cursor.rowcount == 0:
                raise ValueError(
                    "Email not found or already quarantined"
                )

    return get_message_by_id(message_id)



def get_message_by_id(message_id):
    """Retrieve email details with latest AI analysis."""

    with closing(connect()) as connection:
        row = connection.execute(
            """
            SELECT
                e.id,
                e.sender,
                e.subject,
                e.body,
                e.created_at,
                e.status,
                a.classification,
                a.risk_score,
                a.reasons_json
            FROM emails AS e
            LEFT JOIN analysis_results AS a
                ON a.id = (
                    SELECT ar.id
                    FROM analysis_results AS ar
                    WHERE ar.email_id = e.id
                    ORDER BY ar.analysed_at DESC, ar.id DESC
                    LIMIT 1
                )
            WHERE e.id = ?
            """,
            (message_id,)
        ).fetchone()

    if row is None:
        return None

    reasons = []
    if row["reasons_json"]:
        try:
            parsed = json.loads(row["reasons_json"])
            if isinstance(parsed, list):
                reasons = [str(item) for item in parsed]
        except (json.JSONDecodeError, TypeError):
            reasons = []

    score = row["risk_score"]

    return {
        "id": str(row["id"]),
        "from": {
            "name": row["sender"].split("@")[0],
            "email": row["sender"]
        },
        "subject": row["subject"],
        "body": row["body"],
        "preview": (row["body"] or "")[:120],
        "receivedAt": row["created_at"],
        "status": row["status"],
        "score": score,
        "classification": row["classification"],
        "signals": reasons,
        "reasons": reasons
    }




def restore_message(message_id):
    """Restore a quarantined email and record false-positive feedback."""

    with closing(connect()) as connection:
        with connection:
            cursor = connection.execute(
                """
                UPDATE emails
                SET status = 'inbox'
                WHERE id = ? AND status = 'quarantine'
                """,
                (message_id,)
            )

            if cursor.rowcount == 0:
                raise ValueError(
                    "Email not found or not quarantined"
                )

            analysis = connection.execute(
                """
                SELECT id, classification
                FROM analysis_results
                WHERE email_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (message_id,)
            ).fetchone()

            if analysis and analysis["classification"] == "Phishing":
                existing = connection.execute(
                    """
                    SELECT id
                    FROM feedback
                    WHERE analysis_id = ?
                      AND suggested_label = 'Safe'
                      AND review_status = 'pending'
                    LIMIT 1
                    """,
                    (analysis["id"],)
                ).fetchone()

                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO feedback
                            (analysis_id, submitted_by, suggested_label)
                        VALUES (?, ?, ?)
                        """,
                        (
                            analysis["id"],
                            "demo_user",
                            "Safe"
                        )
                    )

    return get_message_by_id(message_id)



def delete_message(message_id):
    """Permanently delete an email and its analysis records."""

    with closing(connect()) as connection:
        with connection:
            cursor = connection.execute(
                "SELECT id FROM emails WHERE id = ?",
                (message_id,)
            )

            if cursor.fetchone() is None:
                raise ValueError("Email not found")

            connection.execute(
                """
                DELETE FROM feedback
                WHERE analysis_id IN (
                    SELECT id FROM analysis_results
                    WHERE email_id = ?
                )
                """,
                (message_id,)
            )

            connection.execute(
                "DELETE FROM analysis_results WHERE email_id = ?",
                (message_id,)
            )

            connection.execute(
                "DELETE FROM emails WHERE id = ?",
                (message_id,)
            )

    return {"ok": True}
