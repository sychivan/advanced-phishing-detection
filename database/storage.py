from contextlib import closing
from pathlib import Path
import json
import math
import sqlite3

DB_PATH = Path(__file__).resolve().parent / "analysis.db"


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