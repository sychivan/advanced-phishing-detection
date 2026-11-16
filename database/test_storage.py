from contextlib import closing
from pathlib import Path
import hashlib
import json
import sqlite3

import joblib

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent

model_path = ROOT / "ml/models/phishing_model.joblib"
report_path = ROOT / "ml/reports/evaluation.json"

model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
metrics = report_path.read_text(encoding="utf-8")
json.loads(metrics)  # Check that the evaluation report is valid JSON.

model = joblib.load(model_path)

sender = "demo@example.com"
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

# Use the artifact hash to distinguish different trained models.
version = f"tfidf-logreg-{model_hash}"

with closing(sqlite3.connect(BASE / "analysis.db")) as connection:
    connection.execute("PRAGMA foreign_keys = ON")

    # Save all related records together, or roll them all back on failure.
    with connection:
        connection.execute(
            """
            INSERT INTO model_versions
                (version, artifact_hash, metrics_json)
            VALUES (?, ?, ?)
            ON CONFLICT(version) DO NOTHING
            """,
            (version, model_hash, metrics),
        )

        model_id = connection.execute(
            "SELECT id FROM model_versions WHERE version = ?",
            (version,),
        ).fetchone()[0]

        email_id = connection.execute(
            "INSERT INTO emails (sender, subject, body) VALUES (?, ?, ?)",
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
                model_id,
                classification,
                round(score, 2),
                json.dumps(reasons),
            ),
        ).lastrowid

    # Read the saved result after the transaction commits.
    saved = connection.execute(
        """
        SELECT a.id, e.subject, a.classification,
               a.risk_score, a.model_version_id
        FROM analysis_results AS a
        JOIN emails AS e ON e.id = a.email_id
        WHERE a.id = ?
        """,
        (analysis_id,),
    ).fetchone()

print("Successfully saved and retrieved:")
print("Analysis ID:", saved[0])
print("Subject:", saved[1])
print("Classification:", saved[2])
print("Model score:", saved[3])
print("Model version ID:", saved[4])