"""Explicit storage-helper checks using synthetic data and a disposable default."""

from contextlib import closing
from pathlib import Path
import hashlib
import os
import sqlite3
import sys
import tempfile

import joblib

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database import storage
from database.init_db import initialize_database


def run_check(db_path):
    """Run explicit checks; restore the caller's configured storage path afterward."""
    previous_path = storage.DB_PATH
    storage.DB_PATH = Path(db_path)
    try:
        initialize_database(storage.DB_PATH)
        model_path = ROOT / "ml/models/phishing_model.joblib"
        model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
        model_id = storage.register_model(model_path, ROOT / "ml/reports/evaluation.json")
        model = joblib.load(model_path)
        subject = "Project meeting"
        body = (
            "Hi team, our project meeting is at 10 tomorrow. "
            "Please bring your progress notes."
        )
        text = f"{subject}\n{body}"
        phishing_index = list(model.classes_).index(1)
        score = float(model.predict_proba([text])[0, phishing_index]) * 100
        result = {
            "classification": "Phishing" if score >= 50 else "Safe",
            "risk_score": round(score, 2),
            "model_status": "connected",
            "reasons": ["Text-only model prediction for a database test."],
        }
        analysis_id = storage.save_analysis(
            "teammate@example.test", subject, body, model_id, result
        )
        saved = storage.get_analysis(analysis_id)
        assert saved is not None
        assert saved["classification"] == result["classification"]
        assert saved["risk_score"] == result["risk_score"]
        assert saved["body"] == body
        assert saved["artifact_hash"] == model_hash
        assert saved["reasons"] == result["reasons"]
        print("PASS: Saved and retrieved the model prediction")
        print("Analysis ID:", analysis_id)
        print("Classification:", saved["classification"])
        print("Score:", saved["risk_score"])

        with closing(storage.connect()) as connection:
            before = connection.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
            missing_id = connection.execute(
                "SELECT COALESCE(MAX(id), 0) + 1 FROM model_versions"
            ).fetchone()[0]
        try:
            storage.save_analysis(
                "demo@example.test", subject, body, missing_id, result
            )
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("An invalid model reference was accepted")
        with closing(storage.connect()) as connection:
            after = connection.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
        assert before == after, "Failed save left a partial email record"
        print("PASS: Invalid model reference rejected; email insert rolled back")
    finally:
        storage.DB_PATH = previous_path


def main():
    configured_path = os.environ.get("PHISHGUARD_DB_PATH")
    if configured_path:
        run_check(Path(configured_path))
    else:
        with tempfile.TemporaryDirectory(prefix="phishguard-storage-check-") as temp:
            run_check(Path(temp) / "analysis.sqlite3")


if __name__ == "__main__":
    main()
