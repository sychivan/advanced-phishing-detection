from services.email_parser import extract_email_features
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

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

    # Temporary mock response.
    # The real ML model will be integrated later.
    return jsonify({
    "classification": "Phishing",
    "risk_score": 91,
    "model_status": "mock",
    "features": features,
    "reasons": [
        "Mock detection result - AI not integrated"
    ]
})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
