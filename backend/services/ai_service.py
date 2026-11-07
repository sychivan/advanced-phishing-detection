import os
import requests


def analyse_with_ai(features):
    model_url = os.getenv("AI_MODEL_URL")

    if not model_url:
        return {
            "classification": "Pending",
            "risk_score": None,
            "model_status": "not_connected",
            "reasons": [
                "AI model has not been connected yet"
            ]
        }

    try:
        response = requests.post(
            model_url,
            json={"features": features},
            timeout=15
        )
        response.raise_for_status()
        return response.json()

    except requests.RequestException:
        return {
            "classification": "Unavailable",
            "risk_score": None,
            "model_status": "error",
            "reasons": [
                "AI model service is unavailable"
            ]
        }