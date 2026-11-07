
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON required"}), 400

    features = data.get("features")

    if not isinstance(features, dict):
        return jsonify({"error": "Features required"}), 400

    subject = str(features.get("subject", "")).lower()

    if "invalid" in subject:
        return jsonify({
            "classification": "Unknown",
            "risk_score": 150,
            "reasons": []
        })

    if "urgent" in subject:
        return jsonify({
            "classification": "Phishing",
            "risk_score": 91,
            "reasons": ["Urgent language detected"]
        })

    return jsonify({
        "classification": "Safe",
        "risk_score": 10,
        "reasons": ["No suspicious indicators detected"]
    })


if __name__ == "__main__":
    app.run(port=5001, debug=False)
