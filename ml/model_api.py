import hashlib
from io import BytesIO
from pathlib import Path

import joblib
from flask import Flask, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200_000

BASE = Path(__file__).resolve().parent
model_bytes = (BASE / "models" / "phishing_model.joblib").read_bytes()
MODEL_HASH = hashlib.sha256(model_bytes).hexdigest()
MODEL_VERSION = f"tfidf-logreg-{MODEL_HASH}"
model = joblib.load(BytesIO(model_bytes))
phishing_index = list(model.classes_).index(1)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "model_status": "connected"})


@app.post("/predict")
def predict():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    features = data.get("features")
    if not isinstance(features, dict):
        return jsonify({"error": "features must be an object"}), 400

    subject = features.get("subject")
    body = features.get("body")

    if not all(isinstance(value, str) for value in [subject, body]):
        return jsonify({"error": "subject and body must be strings"}), 400

    if not body.strip():
        return jsonify({"error": "Email body is required"}), 400

    text = f"{subject.strip()}\n{body.strip()}".strip()
    vector = model.named_steps["tfidf"].transform([text])

    # Avoid classifying text with no recognised vocabulary as safe.
    if vector.nnz == 0:
        return jsonify({"error": "No recognised text; manual review required"}), 422

    score = float(model.predict_proba([text])[0, phishing_index]) * 100

    # Baseline threshold matching the binary model evaluated so far.
    classification = "Phishing" if score >= 50 else "Safe"

    # Identify actual terms contributing toward the model's decision.
    classifier = model.named_steps["classifier"]
    contributions = vector.multiply(classifier.coef_[0]).tocsr()
    terms = model.named_steps["tfidf"].get_feature_names_out()

    direction = 1 if classification == "Phishing" else -1
    ranked = sorted(
        zip(contributions.indices, contributions.data),
        key=lambda item: direction * item[1],
        reverse=True,
    )
    supporting = [
        str(terms[index])
        for index, value in ranked
        if direction * value > 0
    ][:4]

    reasons = [
        "Classification uses email text only; sender authenticity "
        "and attachments have not been verified."
    ]
    if supporting:
        reasons.append(
            "Text patterns contributing toward this prediction: "
            + ", ".join(supporting)
        )

    return jsonify({
        "classification": classification,
        "risk_score": round(score, 2),
        "model_status": "connected",
        "reasons": reasons,
        "model_version": MODEL_VERSION,
        "artifact_hash": MODEL_HASH,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
