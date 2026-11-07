
def validate_ai_response(result):
    if not isinstance(result, dict):
        raise ValueError("AI response must be a JSON object")

    classification = result.get("classification")
    risk_score = result.get("risk_score")
    reasons = result.get("reasons", [])

    allowed = {"Phishing", "Safe", "Suspicious"}

    if classification not in allowed:
        raise ValueError("Invalid classification")

    if (
        isinstance(risk_score, bool)
        or not isinstance(risk_score, (int, float))
        or not 0 <= risk_score <= 100
    ):
        raise ValueError("Risk score must be between 0 and 100")

    if (
        not isinstance(reasons, list)
        or not all(isinstance(r, str) for r in reasons)
    ):
        raise ValueError("Reasons must be a list of strings")

    return {
        "classification": classification,
        "risk_score": risk_score,
        "model_status": "connected",
        "reasons": reasons
    }
