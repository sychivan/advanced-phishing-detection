import os
import requests
from .response_validator import validate_ai_response


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
        ai_data = response.json()
        validated_result = validate_ai_response(ai_data)
        return validated_result
    
    except requests.RequestException:
        return {
            "classification": "Unavailable",
            "risk_score": None,
            "model_status": "error",
            "reasons": [
                "AI model service is unavailable"
            ]
        }
    except (ValueError, TypeError):
        return {
        "classification": "Unavailable",
        "risk_score": None,
        "model_status": "invalid_response",
        "reasons": [
            "AI model returned an invalid response"
        ]
    }