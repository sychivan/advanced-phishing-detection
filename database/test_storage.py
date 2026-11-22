"""Explicit saved-model SQLite smoke check; importing this module writes nothing."""

from contextlib import closing
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import sys
import tempfile

import joblib

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database.init_db import initialize_database


def run_check(db_path):
    """Save and retrieve one synthetic prediction at an explicitly chosen path."""
    model_path = ROOT / "ml/models/phishing_model.joblib"
    report_path = ROOT / "ml/reports/evaluation.json"
    model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    metrics = report_path.read_text(encoding="utf-8")
    if not isinstance(json.loads(metrics), dict):
        raise ValueError("Evaluation report must be a JSON object")
    model = joblib.load(model_path)

    sender = "demo@example.test"
    subject = "Account suspended"
    body = (
        "Your account has been suspended. "
        "Verify your password immediately to restore access."
    )
    text = f"{subject}\n{body}"
    phishing_index = list(model.classes_).index(1)
    score = float(model.predict_proba([text])[0, phishing_index]) * 100
    classification = "Phishing" if score >= 50 else "Safe"
    reasons = [
        "Local text classifier prediction.",
        "Sender authenticity and attachments have not been verified.",
    ]
    version = f"tfidf-logreg-{model_hash}"
    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            connection.execute(
                """
                INSERT INTO model_versions (version, artifact_hash, metrics_json)
                VALUES (?, ?, ?)
                ON CONFLICT(version) DO NOTHING
                """,
                (version, model_hash, metrics),
            )
            model_id, registered_hash = connection.execute(
                "SELECT id, artifact_hash FROM model_versions WHERE version = ?",
                (version,),
            ).fetchone()
            if registered_hash != model_hash:
                raise ValueError("Registered model hash does not match")
            email_id = connection.execute(
                "INSERT INTO emails (sender, subject, body) VALUES (?, ?, ?)",
                (sender, subject, body),
            ).lastrowid
            analysis_id = connection.execute(
                """
                INSERT INTO analysis_results
                    (email_id, model_version_id, classification, risk_score, reasons_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (email_id, model_id, classification, round(score, 2), json.dumps(reasons)),
            ).lastrowid
        saved = connection.execute(
            """
            SELECT a.id, e.subject, a.classification, a.risk_score, a.model_version_id
            FROM analysis_results AS a JOIN emails AS e ON e.id = a.email_id
            WHERE a.id = ?
            """,
            (analysis_id,),
        ).fetchone()

    assert saved is not None and saved[2] == classification
    assert saved[3] == round(score, 2) and saved[4] == model_id
    print("PASS: Saved and retrieved a synthetic prediction from the existing model")
    print("Analysis ID:", saved[0])
    print("Classification:", saved[2])
    print("Model score:", saved[3])


def main():
    configured_path = os.environ.get("PHISHGUARD_DB_PATH")
    if configured_path:
        run_check(Path(configured_path))
    else:
        # An accidental standalone run must never add data to the user's inbox.
        with tempfile.TemporaryDirectory(prefix="phishguard-sqlite-smoke-") as temp:
            run_check(Path(temp) / "analysis.sqlite3")


if __name__ == "__main__":
    main()
