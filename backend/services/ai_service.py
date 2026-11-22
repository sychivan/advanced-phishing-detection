import os
from urllib.parse import urlsplit

import requests
from .response_validator import validate_ai_response


def unavailable(status, reason, classification="Unavailable"):
    return {
        "classification": classification,
        "risk_score": None,
        "model_status": status,
        "reasons": [reason],
    }


def is_loopback_model(model_url):
    try:
        url = urlsplit(model_url)
        return (
            url.scheme in {"http", "https"}
            and url.hostname in {"127.0.0.1", "::1"}
            and url.port is not None
            and url.username is None
            and url.password is None
        )
    except ValueError:
        return False


def analyse_with_ai(features, *, local_only=False):
    model_url = os.getenv("AI_MODEL_URL")

    if not model_url:
        return unavailable("not_connected", "AI model has not been connected yet", "Pending")
    if local_only and not is_loopback_model(model_url):
        return unavailable("not_connected", "AI model must use a loopback IP address and explicit port")

    try:
        with requests.Session() as session:
            if local_only:
                session.trust_env = False
                features = {key: features[key] for key in ("subject", "body")}
            response = session.post(
                model_url, json={"features": features}, timeout=(3, 15), allow_redirects=False
            )
        if response.status_code == 422:
            return unavailable("manual_review", "No recognised text; manual review required", "Pending")
        if response.status_code != 200 and response.ok:
            return unavailable("invalid_response", "AI model returned an invalid response")
        response.raise_for_status()
    except requests.RequestException:
        return unavailable("error", "AI model service is unavailable")

    try:
        return validate_ai_response(response.json())
    except ValueError:
        return unavailable("invalid_response", "AI model returned an invalid response")
