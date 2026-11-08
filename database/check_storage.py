from contextlib import closing
from pathlib import Path
import hashlib
import sqlite3

import joblib

from database.storage import connect, get_analysis, save_analysis

ROOT = Path(__file__).resolve().parent.parent
model_path = ROOT / "ml/models/phishing_model.joblib"
model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()

# Find the registered version matching this exact model file.
with closing(connect()) as connection:
    row = connection.execute(
        "SELECT id FROM model_versions WHERE artifact_hash = ?",
        (model_hash,),
    ).fetchone()

if row is None:
    raise RuntimeError("Register this model using test_storage.py first")

model_id = row["id"]
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

analysis_id = save_analysis(
    "teammate@example.com", subject, body, model_id, result
)
saved = get_analysis(analysis_id)

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

# A missing model reference should fail and roll back the email insert.
with closing(connect()) as connection:
    before = connection.execute(
        "SELECT COUNT(*) FROM emails"
    ).fetchone()[0]
    missing_id = connection.execute(
        "SELECT COALESCE(MAX(id), 0) + 1 FROM model_versions"
    ).fetchone()[0]

try:
    save_analysis(
        "demo@example.com", subject, body, missing_id, result
    )
except sqlite3.IntegrityError:
    pass
else:
    raise AssertionError("An invalid model reference was accepted")

with closing(connect()) as connection:
    after = connection.execute(
        "SELECT COUNT(*) FROM emails"
    ).fetchone()[0]

assert before == after, "Failed save left a partial email record"
print("PASS: Invalid model reference rejected; email insert rolled back")