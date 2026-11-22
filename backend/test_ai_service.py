import os
import unittest
from unittest.mock import patch

import requests

from services.ai_service import analyse_with_ai
from services.email_parser import extract_email_features


class TestModelClient(unittest.TestCase):
    def setUp(self):
        self.features = extract_email_features(
            "synthetic@example.test", "Project meeting", "See https://[broken and https://example.test"
        )
        self.model_url = "http://127.0.0.1:5001/predict"
        environment = patch.dict(os.environ, {"AI_MODEL_URL": self.model_url})
        environment.start()
        self.addCleanup(environment.stop)

    def test_invalid_url_does_not_prevent_feature_extraction(self):
        self.assertEqual(self.features["domains"], ["example.test"])

    @patch("services.ai_service.requests.Session")
    def test_local_model_request_only_sends_text_without_proxy_or_redirect(self, session_factory):
        session = session_factory.return_value.__enter__.return_value
        response = session.post.return_value
        response.status_code = 200
        response.json.return_value = {
            "classification": "Safe", "risk_score": 8, "reasons": [],
            "model_version": "test", "artifact_hash": "a" * 64,
        }
        result = analyse_with_ai(self.features, local_only=True)
        self.assertEqual(result["model_status"], "connected")
        self.assertIs(session.trust_env, False)
        session.post.assert_called_once_with(
            self.model_url, timeout=(3, 15), allow_redirects=False,
            json={"features": {"subject": self.features["subject"], "body": self.features["body"]}},
        )

    @patch("services.ai_service.requests.Session")
    def test_non_loopback_endpoint_does_not_receive_email(self, session_factory):
        with patch.dict(os.environ, {"AI_MODEL_URL": "https://example.test:443/predict"}):
            result = analyse_with_ai(self.features, local_only=True)
        self.assertEqual(result["model_status"], "not_connected")
        session_factory.assert_not_called()

    @patch("services.ai_service.requests.Session")
    def test_unusable_model_responses(self, session_factory):
        post = session_factory.return_value.__enter__.return_value.post
        response = post.return_value
        response.status_code = 422
        self.assertEqual(analyse_with_ai(self.features, local_only=True)["model_status"], "manual_review")
        response.status_code = 307
        self.assertEqual(analyse_with_ai(self.features, local_only=True)["model_status"], "invalid_response")
        response.status_code = 200
        response.json.return_value = {"classification": []}
        self.assertEqual(analyse_with_ai(self.features, local_only=True)["model_status"], "invalid_response")
        response.json.side_effect = requests.exceptions.JSONDecodeError("Invalid JSON", "", 0)
        self.assertEqual(analyse_with_ai(self.features, local_only=True)["model_status"], "invalid_response")
        post.side_effect = requests.Timeout
        self.assertEqual(analyse_with_ai(self.features, local_only=True)["model_status"], "error")
